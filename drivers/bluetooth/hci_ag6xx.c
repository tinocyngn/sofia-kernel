/*
 *
 *  Bluetooth HCI UART driver for ag6xx devices
 *
 *  Copyright (C) 2015 Intel Corporation
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/tty.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

#include "hci_uart.h"
#include "btintel.h"

struct ag6xx_data {
	struct sk_buff *rx_skb;
	struct sk_buff_head txq;
};

struct pbn_entry {
	__le32 addr;
	__le32 plen;
	__u8 data[0];
} __packed;

static int ag6xx_open(struct hci_uart *hu)
{
	struct ag6xx_data *ag6xx;

	BT_DBG("%s, hu %p", __func__, hu);

	ag6xx = kzalloc(sizeof(*ag6xx), GFP_KERNEL);
	if (!ag6xx)
		return -ENOMEM;

	skb_queue_head_init(&ag6xx->txq);

	hu->priv = ag6xx;
	return 0;
}

static int ag6xx_close(struct hci_uart *hu)
{
	struct ag6xx_data *ag6xx = hu->priv;

	BT_DBG("%s, hu %p", __func__, hu);

	skb_queue_purge(&ag6xx->txq);
	kfree_skb(ag6xx->rx_skb);
	kfree(ag6xx);

	hu->priv = NULL;
	return 0;
}

static int ag6xx_flush(struct hci_uart *hu)
{
	struct ag6xx_data *ag6xx = hu->priv;

	BT_DBG("%s, hu %p", __func__, hu);

	skb_queue_purge(&ag6xx->txq);
	return 0;
}

static struct sk_buff *ag6xx_dequeue(struct hci_uart *hu)
{
	struct ag6xx_data *ag6xx = hu->priv;
	struct sk_buff *skb;

	skb = skb_dequeue(&ag6xx->txq);
	if (!skb)
		return skb;

	/* Prepend skb with frame type */
	memcpy(skb_push(skb, 1), &bt_cb(skb)->pkt_type, 1);
	return skb;
}

static int ag6xx_enqueue(struct hci_uart *hu, struct sk_buff *skb)
{
	struct ag6xx_data *ag6xx = hu->priv;

	skb_queue_tail(&ag6xx->txq, skb);
	return 0;
}

static const struct h4_recv_pkt ag6xx_recv_pkts[] = {
	{ H4_RECV_ACL,    .recv = hci_recv_frame   },
	{ H4_RECV_SCO,    .recv = hci_recv_frame   },
	{ H4_RECV_EVENT,  .recv = hci_recv_frame   },
};

static int ag6xx_recv(struct hci_uart *hu, const void *data, int count)
{
	struct ag6xx_data *ag6xx = hu->priv;

	if (!test_bit(HCI_UART_REGISTERED, &hu->flags))
		return -EUNATCH;

	ag6xx->rx_skb = h4_recv_buf(hu->hdev, ag6xx->rx_skb, data, count,
				  ag6xx_recv_pkts, ARRAY_SIZE(ag6xx_recv_pkts));
	if (IS_ERR(ag6xx->rx_skb)) {
		int err = PTR_ERR(ag6xx->rx_skb);
		BT_ERR("%s: Frame reassembly failed (%d)",
		       hu->hdev->name, err);
		ag6xx->rx_skb = NULL;
		return err;
	}

	return count;
}

static int intel_mem_write(struct hci_dev *hdev, u32 addr, u32 plen,
			   const void *data)
{
	while (plen > 0) {
		struct sk_buff *skb;
		u8 cmd_param[253], fragment_len = (plen > 247) ? 247 : plen;
		__le32 leaddr = cpu_to_le32(addr);

		memcpy(cmd_param, &leaddr, 4);
		cmd_param[4] = 0;
		cmd_param[5] = fragment_len;
		memcpy(cmd_param + 6, data, fragment_len);

		skb = __hci_cmd_sync(hdev, 0xfc8e, fragment_len + 6, cmd_param,
				     HCI_INIT_TIMEOUT);
		if (IS_ERR(skb))
			return PTR_ERR(skb);
		kfree_skb(skb);

		plen -= fragment_len;
		data += fragment_len;
		addr += fragment_len;
	}

	return 0;
}

static int ag6xx_setup(struct hci_uart *hu)
{
	struct hci_dev *hdev = hu->hdev;
	struct sk_buff *skb;
	struct intel_version ver;
	const struct firmware *fw;
	const u8 *fw_ptr;
	char fwname[64];
	bool patched = false;
	int err;

	BT_DBG("%s", __func__);

	err = btintel_enter_mfg(hdev);
	if (err)
		return err;

	err = btintel_read_version(hdev, &ver);
	if (err)
		return err;

	btintel_version_info(hdev, &ver);

	/* The hardware platform number has a fixed value of 0x37 and
	 * for now only accept this single value.
	 */
	if (ver.hw_platform != INTEL_HARDWARE_PLATFORM) {
		BT_ERR("%s: Unsupported Intel hardware platform: 0x%X",
		       hu->hdev->name, ver.hw_platform);
		return -EINVAL;
	}
	else {
		BT_ERR("%s: Sucessfully got Intel hardware platform: 0x%X",
		       hu->hdev->name, ver.hw_platform);
	}

	/* Only the hardware variant iBT 2.1 (AG6XX) is supported by this firmware
	 * setup method.
	 */
	if (ver.hw_variant != INTEL_HARDWARE_VARIANT_IBT_2_1) {
		BT_ERR("%s: Unsupported Intel hardware variant: 0x%X",
		       hu->hdev->name, ver.hw_variant);
		return -EINVAL;
	}
	else {
		BT_ERR("%s: Sucessfully got Intel hardware variant: 0x%X",
		       hu->hdev->name, ver.hw_variant);
	}

	snprintf(fwname, sizeof(fwname), "intel/bddatahex");

	BT_INFO("%s: Trying to open FW (BDData) with name: %s", hu->hdev->name, fwname);

	err = request_firmware(&fw, fwname, &hdev->dev);
	if (err < 0) {
		BT_ERR("%s: failed to open Intel bddata file: %s (%d)",
		       hu->hdev->name, fwname, err);
		goto patch;
	}
	fw_ptr = fw->data;

	skb = __hci_cmd_sync_ev(hdev, CMD_WRITE_BD_DATA, fw->size, fw->data, HCI_EV_CMD_STATUS, HCI_CMD_TIMEOUT);
	if (IS_ERR(skb)) {
		BT_ERR("%s: Applying bddata failed (%ld)",
		       hu->hdev->name, PTR_ERR(skb));
		release_firmware(fw);
		return PTR_ERR(skb);
	}
	else {
		BT_INFO("%s: Sucessfully written BD Data", hu->hdev->name);
	}
	kfree_skb(skb);

	release_firmware(fw);

patch:
	/* fw_patch_num indicates the version of patch the device currently
	 * have. If there is no patch data in the device, it is always 0x00.
	 * So, if it is other than 0x00, no need to patch the device again.
	 */
	if (ver.fw_patch_num) {
		BT_INFO("%s: Intel device is already patched. patch num: %02x",
			hu->hdev->name, ver.fw_patch_num);
		patched = true;
		goto complete;
	}

	snprintf(fwname, sizeof(fwname), "intel/%x%x.pbn",
		ver.hw_variant, ver.hw_revision);

	BT_INFO("%s: Trying to open FW (PBN) with name: %s", hu->hdev->name, fwname);

	err = request_firmware(&fw, fwname, &hdev->dev);
	if (err < 0) {
		BT_ERR("%s: failed to open Intel patch file: %s(%d)",
		       hu->hdev->name, fwname, err);
		goto complete;
	}
	fw_ptr = fw->data;

	/* PBN file contains */
	while (fw->size > fw_ptr - fw->data) {
		struct pbn_entry *pbn = (void *)fw_ptr;

		if (pbn->addr == 0xffffffff) {
			BT_INFO("%s: Patching complete", hu->hdev->name);
			patched = true;
			break;
		}

		if (fw->data + fw->size <= pbn->data + pbn->plen) {
			BT_INFO("%s: Invalid patch len (%d)", hu->hdev->name, pbn->plen);
			break;
		}

		BT_INFO("%s: Patching %td/%zu", hu->hdev->name, (fw_ptr - fw->data),
				fw->size);

		err = intel_mem_write(hdev, pbn->addr, pbn->plen, pbn->data);
		if (err) {
			BT_INFO("%s: Patching failed", hu->hdev->name);
			break;
		}

		fw_ptr = pbn->data + pbn->plen;
	}

	release_firmware(fw);

complete:
	/* Exit manufacturing mode and reset */
	err = btintel_exit_mfg(hdev, true, patched);

	return err;
}

static const struct hci_uart_proto ag6xx_proto = {
	.id		= HCI_UART_AG6XX,
	.name		= "AG6XX",
	/*.manufacturer	= 2,*/
	.open		= ag6xx_open,
	.close		= ag6xx_close,
	.flush		= ag6xx_flush,
	.setup		= ag6xx_setup,
	.recv		= ag6xx_recv,
	.enqueue	= ag6xx_enqueue,
	.dequeue	= ag6xx_dequeue,
};

int __init ag6xx_init(void)
{
	return hci_uart_register_proto(&ag6xx_proto);
}

int __exit ag6xx_deinit(void)
{
	return hci_uart_unregister_proto(&ag6xx_proto);
}
