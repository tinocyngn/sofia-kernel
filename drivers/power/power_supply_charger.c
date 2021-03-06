/*
 * Backport from Linux 3.4
 * -------------------------------------------------------------------------
 *  Copyright (C) 2013 Intel Mobile Communications GmbH
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/power_supply.h>
#include <linux/thermal.h>
#include <linux/extcon.h>
#include <linux/power/battery_id.h>
#include <linux/notifier.h>
#include <linux/usb/otg.h>
#include "power_supply.h"
#include "power_supply_charger.h"
#include <linux/version.h>

#define psc_dbg_printk(fmt, ...) \
	pr_debug(fmt, ##__VA_ARGS__)

#define SYSFS_INPUT_VAL_LEN (1)

struct work_struct otg_work;
#define MAX_CHARGER_COUNT 5
#define ALGO_MIN_INTERVAL (30 * HZ)

static LIST_HEAD(algo_list);

struct power_supply_charger {
	bool is_cable_evt_reg;
	/*cache battery and charger properties */
	struct list_head chrgr_cache_lst;
	struct list_head batt_cache_lst;
	struct list_head evt_queue;
	struct work_struct algo_trigger_work;
	struct mutex evt_lock;
	unsigned long algo_timestamp;
};

struct charger_cable {
	struct work_struct work;
	struct notifier_block nb;
	struct power_supply_cable_props cable_props;
	enum power_supply_charger_cable_type psy_cable_type;
};

static struct power_supply_charger psy_chrgr;

static struct charger_cable cable_list[] = {
	{
	 .psy_cable_type = POWER_SUPPLY_CHARGER_TYPE_USB_SDP,
	 },
	{
	 .psy_cable_type = POWER_SUPPLY_CHARGER_TYPE_USB_CDP,
	 },
	{
	 .psy_cable_type = POWER_SUPPLY_CHARGER_TYPE_USB_DCP,
	 },
	{
	 .psy_cable_type = POWER_SUPPLY_CHARGER_TYPE_USB_ACA,
	 },
	{
	 .psy_cable_type = POWER_SUPPLY_CHARGER_TYPE_ACA_DOCK,
	 },
	{
	 .psy_cable_type = POWER_SUPPLY_CHARGER_TYPE_AC,
	 },
	{
	 .psy_cable_type = POWER_SUPPLY_CHARGER_TYPE_USB_FLOATING,
	 },
	{
	 .psy_cable_type = POWER_SUPPLY_CHARGER_TYPE_NONE,
	 },

};

static int get_supplied_by_list(struct power_supply *psy,
				struct power_supply *psy_lst[]);

static int otg_handle_notification(struct notifier_block *nb,
				   unsigned long event, void *data);
struct usb_phy *otg_xceiver;
struct notifier_block otg_nb = {
		   .notifier_call = otg_handle_notification,
		};
static void configure_chrgr_source(struct charger_cable *cable_lst);

struct charger_cable *get_cable(unsigned long usb_chrgr_type)
{

	switch (usb_chrgr_type) {
	case POWER_SUPPLY_CHARGER_TYPE_USB_SDP:
		pr_debug("%s:%d SDP\n", __FILE__, __LINE__);
		return &cable_list[0];
	case POWER_SUPPLY_CHARGER_TYPE_USB_CDP:
		pr_debug("%s:%d CDP\n", __FILE__, __LINE__);
		return &cable_list[1];
	case POWER_SUPPLY_CHARGER_TYPE_USB_DCP:
		pr_debug("%s:%d DCP\n", __FILE__, __LINE__);
		return &cable_list[2];
	case POWER_SUPPLY_CHARGER_TYPE_USB_ACA:
		pr_debug("%s:%d ACA\n", __FILE__, __LINE__);
		return &cable_list[3];
	case POWER_SUPPLY_CHARGER_TYPE_ACA_DOCK:
		pr_debug("%s:%d ACA DOCK\n", __FILE__, __LINE__);
		return &cable_list[4];
	case POWER_SUPPLY_CHARGER_TYPE_AC:
		pr_debug("%s:%d AC\n", __FILE__, __LINE__);
		return &cable_list[5];
	case POWER_SUPPLY_CHARGER_TYPE_USB_FLOATING:
		pr_debug("%s:%d USB FLOATING\n", __FILE__, __LINE__);
		return &cable_list[6];
	case POWER_SUPPLY_CHARGER_TYPE_NONE:
		pr_debug("%s:%d USB NONE\n", __FILE__, __LINE__);
		return &cable_list[7];

	}

	return NULL;
}


static void otg_event_worker(struct work_struct *work)
{
	configure_chrgr_source(cable_list);

}

static int otg_handle_notification(struct notifier_block *nb,
				   unsigned long event, void *data)
{

	struct power_supply_cable_props *cap;
	struct charger_cable *cable = NULL;

	cap = (struct power_supply_cable_props *)data;

	if (event != USB_EVENT_CHARGER && event != USB_EVENT_ENUMERATED
	&& event != USB_EVENT_NONE)
		return NOTIFY_DONE;

	cable = get_cable(cap->chrg_type);
	if (!cable) {

		pr_err("%s:%d Error in getting charger cable from get_cable\n",
				__FILE__, __LINE__);
		return -EINVAL;
	}

	switch (cap->chrg_evt) {
	case POWER_SUPPLY_CHARGER_EVENT_CONNECT:
		pr_debug("%s:%d Connected inlmt=%d\n",
				__FILE__, __LINE__, cap->ma);
		break;
	case POWER_SUPPLY_CHARGER_EVENT_UPDATE:
		pr_debug("%s:%d Connected\n", __FILE__, __LINE__);
		break;
	case POWER_SUPPLY_CHARGER_EVENT_DISCONNECT:
		pr_debug("%s:%d Disconnected inlmt=%d\n",
			__FILE__, __LINE__, cap->ma);
		break;
	case POWER_SUPPLY_CHARGER_EVENT_SUSPEND:
		pr_debug("%s:%d Suspended inlmt=%d\n",
			__FILE__, __LINE__, cap->ma);
		break;
	case POWER_SUPPLY_CHARGER_EVENT_RESUME:
		pr_debug("%s:%d Resumed inlmt=%d\n",
			__FILE__, __LINE__, cap->ma);
		break;
	default:
		pr_err("%s:%d Invalid event\n", __FILE__, __LINE__);
		break;
	}

	memcpy((void *)&cable->cable_props, (void *)cap,
			sizeof(cable->cable_props));
	schedule_work(&otg_work);

	return NOTIFY_OK;
}

int otg_register(void)
{
	int retval;

	otg_xceiver = usb_get_phy(USB_PHY_TYPE_USB2);
	if (!otg_xceiver) {
		pr_err("%s:%d failure to get otg transceiver\n",
					__FILE__, __LINE__);
		goto phy_get_failed;
	}

	retval = usb_register_notifier(otg_xceiver, &otg_nb);
	if (retval) {
		pr_err("%s:%d failure to register otg notifier\n",
			__FILE__, __LINE__);
		goto otg_reg_failed;
	}

	INIT_WORK(&otg_work, otg_event_worker);

	return 0;

otg_reg_failed:
	usb_put_phy(otg_xceiver);
phy_get_failed:
	return -EIO;
}

struct charging_algo *power_supply_get_charging_algo
		(struct power_supply *, struct ps_batt_chg_prof *);

static void init_charger_cables(struct charger_cable *cable_lst, int count)
{
	struct charger_cable *cable;

	otg_register();
	while (count--) {
		cable = cable_lst++;
		/* initialize cable instance */
		cable->cable_props.chrg_evt =
			POWER_SUPPLY_CHARGER_EVENT_DISCONNECT;
		cable->cable_props.ma = 0;
	}
}

static inline void get_cur_chrgr_prop(struct power_supply *psy,
				      struct charger_props *chrgr_prop)
{
	chrgr_prop->is_charging = IS_CHARGING_ENABLED(psy);
	chrgr_prop->name = psy->name;
	chrgr_prop->online = IS_ONLINE(psy);
	chrgr_prop->present = IS_PRESENT(psy);
	chrgr_prop->cable = CABLE_TYPE(psy);
	chrgr_prop->health = HEALTH(psy);
	chrgr_prop->tstamp = get_jiffies_64();

}

static inline int get_chrgr_prop_cache(struct power_supply *psy,
				       struct charger_props *chrgr_cache)
{

	struct charger_props *chrgr_prop;
	int ret = -ENODEV;

	list_for_each_entry(chrgr_prop, &psy_chrgr.chrgr_cache_lst, node) {
		if (!strcmp(chrgr_prop->name, psy->name)) {
			memcpy(chrgr_cache, chrgr_prop, sizeof(*chrgr_cache));
			ret = 0;
			break;
		}
	}

	return ret;
}

static void dump_charger_props(struct charger_props *props)
{
	psc_dbg_printk("%s:name=%s present=%d is_charging=%d health=%d online=%d cable=%lu tstamp=%lu\n",
		 __func__, props->name, props->present, props->is_charging,
		  props->health, props->online, props->cable, props->tstamp);
}

static void dump_battery_props(struct batt_props *props)
{
	psc_dbg_printk("%s:name=%s voltage_now=%ld current_now=%ld temperature=%d status=%ld health=%d tstamp=%lu algo_stat=%d ",
		 __func__, props->name, props->voltage_now, props->current_now,
		  props->temperature, props->status, props->health,
		   props->tstamp, props->algo_stat);
}

static inline void cache_chrgr_prop(struct charger_props *chrgr_prop_new)
{

	struct charger_props *chrgr_cache;

	list_for_each_entry(chrgr_cache, &psy_chrgr.chrgr_cache_lst, node) {
		if (!strcmp(chrgr_cache->name, chrgr_prop_new->name))
			goto update_props;
	}

	chrgr_cache = kzalloc(sizeof(*chrgr_cache), GFP_KERNEL);
	if (chrgr_cache == NULL) {
		pr_err("%s:%dError in allocating memory\n", __FILE__, __LINE__);
		return;
	}

	INIT_LIST_HEAD(&chrgr_cache->node);
	list_add_tail(&chrgr_cache->node, &psy_chrgr.chrgr_cache_lst);

	chrgr_cache->name = chrgr_prop_new->name;

update_props:
	chrgr_cache->is_charging = chrgr_prop_new->is_charging;
	chrgr_cache->online = chrgr_prop_new->online;
	chrgr_cache->health = chrgr_prop_new->health;
	chrgr_cache->present = chrgr_prop_new->present;
	chrgr_cache->cable = chrgr_prop_new->cable;
	chrgr_cache->tstamp = chrgr_prop_new->tstamp;
}


static inline bool is_chrgr_prop_changed(struct power_supply *psy)
{

	struct charger_props chrgr_prop_cache, chrgr_prop;

	get_cur_chrgr_prop(psy, &chrgr_prop);
	/* Get cached battery property. If no cached property available
	 *  then cache the new property and return true
	 */
	if (get_chrgr_prop_cache(psy, &chrgr_prop_cache)) {
		cache_chrgr_prop(&chrgr_prop);
		return true;
	}

	psc_dbg_printk("%s\n", __func__);
	dump_charger_props(&chrgr_prop);
	dump_charger_props(&chrgr_prop_cache);

	if (!IS_CHARGER_PROP_CHANGED(chrgr_prop, chrgr_prop_cache))
		return false;

	cache_chrgr_prop(&chrgr_prop);
	return true;
}
static void cache_successive_samples(long *sample_array, long new_sample)
{

	int i;

	for (i = 0; i < MAX_CUR_VOLT_SAMPLES - 1; ++i)
		*(sample_array + i) = *(sample_array + i + 1);

	*(sample_array + i) = new_sample;

}

static inline void cache_bat_prop(struct batt_props *bat_prop_new)
{

	struct batt_props *bat_cache;

	/* Find entry in cache list. If an entry is located update
	 * the existing entry else create new entry in the list */
	list_for_each_entry(bat_cache, &psy_chrgr.batt_cache_lst, node) {
		if (!strcmp(bat_cache->name, bat_prop_new->name))
			goto update_props;
	}

	bat_cache = kzalloc(sizeof(*bat_cache), GFP_KERNEL);
	if (bat_cache == NULL) {
		pr_err("%s:%dError in allocating memory\n", __FILE__, __LINE__);
		return;
	}
	INIT_LIST_HEAD(&bat_cache->node);
	list_add_tail(&bat_cache->node, &psy_chrgr.batt_cache_lst);

	bat_cache->name = bat_prop_new->name;

update_props:
	if (time_after(bat_prop_new->tstamp,
		(bat_cache->tstamp + DEF_CUR_VOLT_SAMPLE_JIFF)) ||
						bat_cache->tstamp == 0) {
		cache_successive_samples(bat_cache->voltage_now_cache,
						bat_prop_new->voltage_now);
		cache_successive_samples(bat_cache->current_now_cache,
						bat_prop_new->current_now);
		bat_cache->tstamp = bat_prop_new->tstamp;
	}

	bat_cache->voltage_now = bat_prop_new->voltage_now;
	bat_cache->current_now = bat_prop_new->current_now;
	bat_cache->health = bat_prop_new->health;
	bat_cache->capacity = bat_prop_new->capacity;
	bat_cache->temperature = bat_prop_new->temperature;
	bat_cache->status = bat_prop_new->status;
	bat_cache->algo_stat = bat_prop_new->algo_stat;
	bat_cache->throttle_state = bat_prop_new->throttle_state;
}

static inline int get_bat_prop_cache(struct power_supply *psy,
				     struct batt_props *bat_cache)
{

	struct batt_props *bat_prop;
	int ret = -ENODEV;

	list_for_each_entry(bat_prop, &psy_chrgr.batt_cache_lst, node) {
		if (!strcmp(bat_prop->name, psy->name)) {
			memcpy(bat_cache, bat_prop, sizeof(*bat_cache));
			ret = 0;
			break;
		}
	}

	return ret;
}

static inline void get_cur_bat_prop(struct power_supply *psy,
				    struct batt_props *bat_prop)
{
	struct batt_props bat_prop_cache;
	int ret;


	bat_prop->name = psy->name;
	bat_prop->voltage_now = VOLTAGE_NOW(psy) / 1000;
	bat_prop->current_now = CURRENT_NOW(psy) / 1000;
	bat_prop->temperature = TEMPERATURE(psy) / 10;
	bat_prop->status = STATUS(psy);
	bat_prop->health = HEALTH(psy);
	bat_prop->tstamp = get_jiffies_64();
	bat_prop->throttle_state = CURRENT_THROTTLE_STATE(psy);
	bat_prop->capacity  = CAPACITY(psy);
	bat_prop->algo_stat = PSY_ALGO_STAT_UNKNOWN;

	/* Populate cached algo data to new profile */
	ret = get_bat_prop_cache(psy, &bat_prop_cache);
	if (!ret)
		bat_prop->algo_stat = bat_prop_cache.algo_stat;
}

static inline bool is_batt_prop_changed(struct power_supply *psy)
{

	struct batt_props bat_prop_cache, bat_prop;

	/* Get cached battery property. If no cached property available
	 *  then cache the new property and return true
	 */
	get_cur_bat_prop(psy, &bat_prop);
	if (get_bat_prop_cache(psy, &bat_prop_cache)) {
		cache_bat_prop(&bat_prop);
		return true;
	}

	psc_dbg_printk("%s\n", __func__);
	dump_battery_props(&bat_prop);
	dump_battery_props(&bat_prop_cache);

	if (!IS_BAT_PROP_CHANGED(bat_prop, bat_prop_cache))
		return false;

	cache_bat_prop(&bat_prop);
	return true;
}

static inline bool is_supplied_to_has_ext_pwr_changed(struct power_supply *psy)
{
	int i;
	struct power_supply *psb;
	bool is_pwr_changed_defined = true;

	for (i = 0; i < psy->num_supplicants; i++) {
		psb =
		    power_supply_get_by_name(psy->
					     supplied_to[i]);
		if (psb && !psb->external_power_changed)
			is_pwr_changed_defined &= false;
	}

	return is_pwr_changed_defined;

}

static inline bool is_supplied_by_changed(struct power_supply *psy)
{

	int cnt;
	struct power_supply *chrgr_lst[MAX_CHARGER_COUNT];

	cnt = get_supplied_by_list(psy, chrgr_lst);
	while (cnt--) {
		if ((IS_CHARGER(chrgr_lst[cnt])) &&
			is_chrgr_prop_changed(chrgr_lst[cnt]))
			return true;
	}

	return false;
}

static inline bool is_trigger_charging_algo(struct power_supply *psy)
{

	/* trigger charging alorithm if battery or
	 * charger properties are changed. Also no need to
	 * invoke algorithm for power_supply_changed from
	 * charger, if all supplied_to has the ext_port_changed defined.
	 * On invoking the ext_port_changed the supplied to can send
	 * power_supplied_changed event.
	 */
	struct class_dev_iter iter;
	struct device *dev;
	struct power_supply *psc_instance;
	bool changed = false;

	class_dev_iter_init(&iter, power_supply_class, NULL, NULL);
	while ((dev = class_dev_iter_next(&iter))) {

		psc_instance = (struct power_supply *)dev_get_drvdata(dev);

		if (IS_CHARGER(psc_instance) &&
			is_chrgr_prop_changed(psc_instance))
						changed = true;

		if (IS_BATTERY(psc_instance) &&
			is_batt_prop_changed(psc_instance))
						changed = true;
	}
	class_dev_iter_exit(&iter);

	if (changed)
		return true;

	if (time_after(jiffies, ((psy_chrgr.algo_timestamp +
						ALGO_MIN_INTERVAL))))
		return true;

	return false;
}

static int get_supplied_by_list(struct power_supply *psy,
				struct power_supply *psy_lst[])
{
	struct class_dev_iter iter;
	struct device *dev;
	struct power_supply *pst;
	int cnt = 0, i, j;

	if (!IS_BATTERY(psy))
		return 0;

	/* Identify chargers which are supplying power to the battery */
	class_dev_iter_init(&iter, power_supply_class, NULL, NULL);
	while ((dev = class_dev_iter_next(&iter))) {
		pst = (struct power_supply *)dev_get_drvdata(dev);
		if (!IS_CHARGER(pst))
			continue;
		for (i = 0; i < pst->num_supplicants; i++) {
			if (!strcmp(pst->supplied_to[i], psy->name))
				psy_lst[cnt++] = pst;
		}
	}
	class_dev_iter_exit(&iter);

	if (cnt <= 1)
		return cnt;

	/*sort based on priority. 0 has the highest priority  */
	for (i = 0; i < cnt; ++i)
		for (j = 0; j < cnt; ++j)
			if (PRIORITY(psy_lst[j]) > PRIORITY(psy_lst[i]))
				swap(psy_lst[j], psy_lst[i]);

	return cnt;
}

static int get_battery_status(struct power_supply *psy)
{
	int cnt, status, ret;
	struct power_supply *chrgr_lst[MAX_CHARGER_COUNT];
	struct batt_props bat_prop;

	if (!IS_BATTERY(psy))
		return -EINVAL;

	if (!IS_PRESENT(psy))
		return POWER_SUPPLY_STATUS_UNKNOWN;

	status = POWER_SUPPLY_STATUS_DISCHARGING;

	ret = get_bat_prop_cache(psy, &bat_prop);
	if (ret)
		return status;

	cnt = get_supplied_by_list(psy, chrgr_lst);


	while (cnt--) {


		if (IS_PRESENT(chrgr_lst[cnt]))
			status = POWER_SUPPLY_STATUS_NOT_CHARGING;

		if (IS_CHARGING_CAN_BE_ENABLED(chrgr_lst[cnt]) &&
			(IS_HEALTH_GOOD(psy)) &&
				(IS_HEALTH_GOOD(chrgr_lst[cnt]))) {

			if ((bat_prop.algo_stat == PSY_ALGO_STAT_FULL) ||
				(bat_prop.algo_stat == PSY_ALGO_STAT_MAINT))
				status = POWER_SUPPLY_STATUS_FULL;
			else if (IS_CHARGING_ENABLED(chrgr_lst[cnt]))
				status = POWER_SUPPLY_STATUS_CHARGING;
		}
	}
	psc_dbg_printk("%s: Set status=%d for %s\n", __func__,
						status, psy->name);

	return status;
}

static void update_battery_status(struct power_supply *psy)
{
	int i;
	struct power_supply *psb;
	int status;

	if (NULL == psy)
		return;

	if (IS_BATTERY(psy)) {
		/* get_battery_status() can return error value instead of
		status! We *must* validate the return value */
		status = get_battery_status(psy);
		if (status < 0)
			return;

		set_status(psy, status);

	} else {
		for (i = 0; i < psy->num_supplicants; i++) {
			psb =
			    power_supply_get_by_name(psy->
						     supplied_to[i]);
			if (psb && IS_BATTERY(psb)) {
				/* get_battery_status() can return error value
				instead of status! We *must* validate the return
				value */
				status = get_battery_status(psb);
				if (status < 0)
					return;

				set_status(psb, status);
			}
		}
	}
}

static int trigger_algo(struct power_supply *psy)
{
	unsigned long cc = 0, cv = 0, cc_min;
	struct power_supply *chrgr_lst[MAX_CHARGER_COUNT];
	struct batt_props bat_prop;
	struct charging_algo *algo;
	struct ps_batt_chg_prof chrg_profile;
	int cnt, ret = -ENODATA;
	enum psy_algo_stat prev_algo_stat;


	if (psy->type != POWER_SUPPLY_TYPE_BATTERY)
		return 0;

	if (get_batt_prop(&chrg_profile)) {
		pr_err("Error in getting charge profile:%s:%d\n", __FILE__,
		       __LINE__);
		return -EINVAL;
	}


	if (get_bat_prop_cache(psy, &bat_prop)) {
		pr_err("Error in retrieving battery property:%s:%d\n", __FILE__,
				__LINE__);
		return -EINVAL;
	}


	algo = power_supply_get_charging_algo(psy, &chrg_profile);
	if (!algo) {
		pr_err("Error in getting charging algo!!\n");
		return -EINVAL;
	}

	prev_algo_stat = bat_prop.algo_stat;

	bat_prop.algo_stat = algo->get_next_cc_cv(bat_prop,
						chrg_profile, &cc, &cv);

	if (PSY_ALGO_STAT_FULL == bat_prop.algo_stat &&
		(PSY_ALGO_STAT_CHARGE == prev_algo_stat ||
			PSY_ALGO_STAT_MAINT == prev_algo_stat)) {

		int i, charger_output_vol_mv, sum = 0;

		/* Calculate average of charger output voltage */
		for (i = 0; i < MAX_CUR_VOLT_SAMPLES; i++)
			sum += bat_prop.voltage_now_cache[i];

		charger_output_vol_mv = sum / MAX_CUR_VOLT_SAMPLES;

		set_ps_int_property(psy, POWER_SUPPLY_PROP_VOLTAGE_FULL,
							charger_output_vol_mv);
	}


	if ((bat_prop.algo_stat == PSY_ALGO_STAT_CHARGE ||
		bat_prop.algo_stat == PSY_ALGO_STAT_MAINT) &&
					!IS_HEALTH_GOOD(psy)) {
		cc = 0;
		cv = 0;
		bat_prop.algo_stat = PSY_ALGO_STAT_NOT_CHARGE;
	}


	switch (bat_prop.algo_stat) {
	case PSY_ALGO_STAT_CHARGE:
		psc_dbg_printk("%s:Algo_status: Charging Enabled\n", __func__);
		break;
	case PSY_ALGO_STAT_FULL:
		psc_dbg_printk("%s:Algo_status: Battery is Full\n", __func__);
		break;
	case PSY_ALGO_STAT_MAINT:
		psc_dbg_printk("%s:Algo_status: Maintenance charging started\n",
			__func__);
		break;
	case PSY_ALGO_STAT_UNKNOWN:
		psc_dbg_printk("%s:Algo Status: unknown\n", __func__);
		break;
	case PSY_ALGO_STAT_NOT_CHARGE:
		psc_dbg_printk("%s:Algo Status: charging not enabled\n",
			__func__);
		break;
	}

	cache_bat_prop(&bat_prop);

	if (!cc || !cv)
		return -ENODATA;

	/* CC needs to be updated for all chargers which are supplying
	 *  power to this battery to ensure that the sum of CCs of all
	 * chargers are never more than the CC selected by the algo.
	 * The CC is set based on the charger priority.
	 */
	cnt = get_supplied_by_list(psy, chrgr_lst);

	while (cnt--) {
		if (!IS_PRESENT(chrgr_lst[cnt]) ||
			!IS_HEALTH_GOOD(chrgr_lst[cnt]))
				continue;

		cc_min = min_t(unsigned long, MAX_CC(chrgr_lst[cnt]), cc);
		cc -= cc_min;
		set_cc(chrgr_lst[cnt], cc_min);
		set_cv(chrgr_lst[cnt], cv);
		ret = 0;
	}

	return ret;
}

static inline void enable_supplied_by_charging
		(struct power_supply *psy, bool is_enable)
{
	struct power_supply *chrgr_lst[MAX_CHARGER_COUNT];
	int cnt;

	if (psy->type != POWER_SUPPLY_TYPE_BATTERY)
		return;
	/* Get list of chargers supplying power to this battery and
	 * disable charging for all chargers
	 */
	cnt = get_supplied_by_list(psy, chrgr_lst);
	if (cnt == 0)
		return;
	while (cnt--) {
		if (!IS_PRESENT(chrgr_lst[cnt]))
			continue;
		if (is_enable && IS_CHARGING_CAN_BE_ENABLED(chrgr_lst[cnt]) &&
						IS_HEALTH_GOOD(chrgr_lst[cnt]))
			enable_charging(chrgr_lst[cnt]);
		else
			disable_charging(chrgr_lst[cnt]);
	}
}

static void __power_supply_trigger_charging_handler(struct power_supply *psy)
{
	int i;
	struct power_supply *psb = NULL;


	mutex_lock(&psy_chrgr.evt_lock);

	if (is_trigger_charging_algo(psy)) {

		if (IS_BATTERY(psy)) {
			if (trigger_algo(psy))
				enable_supplied_by_charging(psy, false);
			else
				enable_supplied_by_charging(psy, true);


		} else if (IS_CHARGER(psy)) {
			for (i = 0; i < psy->num_supplicants; i++) {
				psb =
				    power_supply_get_by_name(psy->
							     supplied_to[i]);

				if (psb && IS_BATTERY(psb) && IS_PRESENT(psb)) {
					if (trigger_algo(psb) ||
							!IS_HEALTH_GOOD(psy)) {
						disable_charging(psy);
						break;
					} else if (IS_CHARGING_CAN_BE_ENABLED
								(psy)) {
						enable_charging(psy);
					}
				}
			}
		}
		psy_chrgr.algo_timestamp = jiffies;
		update_battery_status(psy);
	}
	mutex_unlock(&psy_chrgr.evt_lock);

}

static int __trigger_charging_handler(struct device *dev, void *data)
{
	struct power_supply *psy = dev_get_drvdata(dev);

	__power_supply_trigger_charging_handler(psy);

	return 0;
}

static void trigger_algo_psy_class(struct work_struct *work)
{

	class_for_each_device(power_supply_class, NULL, NULL,
			__trigger_charging_handler);

}

static bool is_cable_connected(void)
{
	int i;
	struct charger_cable *cable;

	for (i = 0; i < ARRAY_SIZE(cable_list); ++i) {
		cable = cable_list + i;
		if (IS_CABLE_ACTIVE(cable->cable_props.chrg_evt))
			return true;
	}
	return false;
}

void power_supply_trigger_charging_handler(struct power_supply *psy)
{

	if (!psy_chrgr.is_cable_evt_reg)
		return;

	if (!is_cable_connected()) {

		/* Required when booting without a charger cable present
		and battery supply power_supply_changed occurs before charger
		presence update. In this case battery status should be updated
		even though charging handling doesn't take place. */
		update_battery_status(psy);
		return;
	}

	if (psy)
		__power_supply_trigger_charging_handler(psy);
	else
		schedule_work(&psy_chrgr.algo_trigger_work);

}
EXPORT_SYMBOL(power_supply_trigger_charging_handler);

static inline int get_battery_thresholds(struct power_supply *psy,
	struct psy_batt_thresholds *bat_thresh)
{
	struct charging_algo *algo;
	struct ps_batt_chg_prof chrg_profile;


	/* FIXME: Get iterm only for supplied_to arguments*/
	if (get_batt_prop(&chrg_profile)) {
		pr_err("Error in getting charge profile:%s:%d\n", __FILE__,
		       __LINE__);
		return -EINVAL;
	}

	algo = power_supply_get_charging_algo(psy, &chrg_profile);
	if (!algo) {
		pr_err("Error in getting charging algo!!\n");
		return -EINVAL;
	}

	if (algo->get_batt_thresholds) {
		algo->get_batt_thresholds(chrg_profile, bat_thresh);
	} else {
		pr_err("Error in getting battery thresholds from %s:%s\n",
			algo->name, __func__);
		return -EINVAL;
	}
	return 0;
}

static int select_chrgr_cable(struct device *dev, void *data)
{
	struct power_supply *psy = dev_get_drvdata(dev);
	struct charger_cable *cable, *max_ma_cable = NULL;
	struct charger_cable *cable_lst = (struct charger_cable *)data;
	unsigned int max_ma = 0;
	int i;

	if (!IS_CHARGER(psy))
		return 0;

	mutex_lock(&psy_chrgr.evt_lock);

	/* get cable with maximum capability */
	for (i = 0; i < ARRAY_SIZE(cable_list); ++i) {
		cable = cable_lst + i;
		if ((!IS_CABLE_ACTIVE(cable->cable_props.chrg_evt)) ||
		    (!IS_SUPPORTED_CABLE(psy, cable->psy_cable_type)))
			continue;

		if (cable->cable_props.ma > max_ma) {
			max_ma_cable = cable;
			max_ma = cable->cable_props.ma;
		}
	}

	/* no cable connected. disable charging */
	if (!max_ma_cable) {

		if ((IS_CHARGER_ENABLED(psy) || IS_CHARGING_ENABLED(psy))) {
			disable_charging(psy);
			disable_charger(psy);
		}
		set_cc(psy, 0);
		set_cv(psy, 0);
		set_inlmt(psy, 0);
		switch_cable(psy, POWER_SUPPLY_CHARGER_TYPE_NONE);

		mutex_unlock(&psy_chrgr.evt_lock);

		/* Update battery status as charging algorithm will not
		run and update charger status when no charger cable is
		inserted */
		update_battery_status(psy);
		power_supply_changed(psy);
		return 0;
	}

	/* cable type changed.New cable connected or existing cable
	 * capabilities changed.switch cable and enable charger and charging
	 */

	if (CABLE_TYPE(psy) != max_ma_cable->psy_cable_type)
		switch_cable(psy, max_ma_cable->psy_cable_type);

	if (IS_CHARGER_CAN_BE_ENABLED(psy)) {
		struct psy_batt_thresholds bat_thresh;
		memset(&bat_thresh, 0, sizeof(bat_thresh));
		enable_charger(psy);
		set_inlmt(psy, max_ma_cable->cable_props.ma);
		if (!get_battery_thresholds(psy, &bat_thresh)) {
			SET_ITERM(psy, bat_thresh.iterm);
			SET_MIN_TEMP(psy, bat_thresh.temp_min);
			SET_MAX_TEMP(psy, bat_thresh.temp_max);
		}

	} else {

		disable_charger(psy);
	}


	mutex_unlock(&psy_chrgr.evt_lock);

	power_supply_trigger_charging_handler(NULL);
	/* Cable status is same as previous. No action to be taken */
	return 0;

}

static void configure_chrgr_source(struct charger_cable *cable_lst)
{

	class_for_each_device(power_supply_class, NULL,
			      cable_lst, select_chrgr_cable);

}

int psy_charger_throttle_charger(struct power_supply *psy,
					unsigned long state)
{
	int ret = 0;

	if (state > MAX_THROTTLE_STATE(psy))
		return -EINVAL;

	mutex_lock(&psy_chrgr.evt_lock);

	switch THROTTLE_ACTION(psy, state)
	{

		case PSY_THROTTLE_DISABLE_CHARGER:
			SET_MAX_CC(psy, 0);
			disable_charger(psy);
			break;
		case PSY_THROTTLE_DISABLE_CHARGING:
			SET_MAX_CC(psy, 0);
			disable_charging(psy);
			break;
		case PSY_THROTTLE_CC_LIMIT:
			SET_MAX_CC(psy, THROTTLE_CC_VALUE(psy, state));
			break;
		case PSY_THROTTLE_INPUT_LIMIT:
			set_inlmt(psy, THROTTLE_CC_VALUE(psy, state));
			break;
		default:
			pr_err("Invalid throttle action for %s\n", psy->name);
			ret = -EINVAL;
			break;
	}
	mutex_unlock(&psy_chrgr.evt_lock);

	/* Configure the driver based on new state */
	if (!ret)
		configure_chrgr_source(cable_list);
	return ret;
}
EXPORT_SYMBOL(psy_charger_throttle_charger);

int power_supply_register_charger(struct power_supply *psy)
{
	int ret = 0;

	if (!psy_chrgr.is_cable_evt_reg) {
		mutex_init(&psy_chrgr.evt_lock);
		init_charger_cables(cable_list, ARRAY_SIZE(cable_list));
		INIT_LIST_HEAD(&psy_chrgr.chrgr_cache_lst);
		INIT_LIST_HEAD(&psy_chrgr.batt_cache_lst);
		INIT_WORK(&psy_chrgr.algo_trigger_work, trigger_algo_psy_class);
		psy_chrgr.algo_timestamp = jiffies;
		psy_chrgr.is_cable_evt_reg = true;
	}
	return ret;
}
EXPORT_SYMBOL(power_supply_register_charger);

int power_supply_unregister_charger(struct power_supply *psy)
{
 /*TBD*/
	return 0;
}
EXPORT_SYMBOL(power_supply_unregister_charger);

int power_supply_register_charging_algo(struct charging_algo *algo)
{

	struct charging_algo *algo_new;

	algo_new = kzalloc(sizeof(*algo_new), GFP_KERNEL);
	if (algo_new == NULL) {
		pr_err("%s: Error allocating memory for algo!!", __func__);
		return -1;
	}
	memcpy(algo_new, algo, sizeof(*algo_new));

	list_add_tail(&algo_new->node, &algo_list);

	return 0;
}
EXPORT_SYMBOL(power_supply_register_charging_algo);

int power_supply_unregister_charging_algo(struct charging_algo *algo)
{
	struct charging_algo *algo_l, *tmp;

	list_for_each_entry_safe(algo_l, tmp, &algo_list, node) {
		if (!strcmp(algo_l->name, algo->name)) {
			list_del(&algo_l->node);
			kfree(algo_l);
		}
	}
	return 0;

}
EXPORT_SYMBOL(power_supply_unregister_charging_algo);

static struct charging_algo __attribute__ ((unused))
*get_charging_algo_byname(char *algo_name)
{
	struct charging_algo *algo;

	list_for_each_entry(algo, &algo_list, node) {
		if (!strcmp(algo->name, algo_name))
			return algo;
	}

	return NULL;
}

static struct charging_algo *get_charging_algo_by_type
		(enum batt_chrg_prof_type chrg_prof_type)
{
	struct charging_algo *algo;

	list_for_each_entry(algo, &algo_list, node) {
		if (algo->chrg_prof_type == chrg_prof_type)
			return algo;
	}

	return NULL;
}

struct charging_algo *power_supply_get_charging_algo
	(struct power_supply *psy, struct ps_batt_chg_prof *batt_prof)
{

	return get_charging_algo_by_type(batt_prof->chrg_prof_type);

}
EXPORT_SYMBOL_GPL(power_supply_get_charging_algo);
