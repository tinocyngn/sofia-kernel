/*
 ****************************************************************
 *
 *  Intel CIF ISP 2.0 driver - Image source interface
 *
 *  Copyright (C) 2014 Intel Mobile GmbH
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License Version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  You should have received a copy of the GNU General Public License Version 2
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Note:
 *     07/07/2014: initial version.
 *
 ****************************************************************
 */

#ifndef _CIF_ISP20_IMG_SRC_OPS_H
#define _CIF_ISP20_IMG_SRC_OPS_H

#include "cif_isp20_img_src_v4l2-subdev.h"

struct cif_isp20_img_src_ops {
	void * (*to_img_src)(
		CIF_ISP20_PLTFRM_DEVICE dev);
	int (*s_streaming)(
		void *img_src,
		bool enable);
	int (*s_power)(
		void *img_src,
		bool on);
	int (*enum_strm_fmts)(
		void *img_src,
		u32 index,
		struct cif_isp20_strm_fmt_desc *strm_fmt_desc);
	int (*s_strm_fmt)(
		void *img_src,
		struct cif_isp20_strm_fmt *strm_fmt);
	int (*g_ctrl)(
		void *img_src,
		int id,
		int *val);
	const char * (*g_name)(
		void *img_src);
	int (*s_ctrl)(
		void *img_src,
		int id,
		int val);
	int (*s_ext_ctrls)(
		void *img_src,
	    struct cif_isp20_img_src_ext_ctrl *ctrl);
	long (*ioctl)(
		void *img_src,
		unsigned int cmd,
		void *arg);
};

const struct {
	const char *device_type;
	struct cif_isp20_img_src_ops ops;
} cif_isp20_img_src_ops[] = {
	{
		.device_type = CIF_ISP20_IMG_SRC_V4L2_I2C_SUBDEV,
		.ops = {
			.to_img_src =
				cif_isp20_img_src_v4l2_i2c_subdev_to_img_src,
			.s_streaming =
				cif_isp20_img_src_v4l2_subdev_s_streaming,
			.s_power =
				cif_isp20_img_src_v4l2_subdev_s_power,
			.enum_strm_fmts =
				cif_isp20_img_src_v4l2_subdev_enum_strm_fmts,
			.s_strm_fmt =
				cif_isp20_img_src_v4l2_subdev_s_strm_fmt,
			.g_ctrl =
				cif_isp20_img_src_v4l2_subdev_g_ctrl,
			.g_name =
				cif_isp20_img_src_v4l2_subdev_g_name,
			.s_ctrl =
				cif_isp20_img_src_v4l2_subdev_s_ctrl,
			.s_ext_ctrls =
				cif_isp20_img_src_v4l2_subdev_s_ext_ctrls,
			.ioctl =
				cif_isp20_img_src_v4l2_subdev_ioctl
		}
	},
};

#endif
