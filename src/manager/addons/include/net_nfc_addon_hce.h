/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __NET_NFC_ADDON_HCE_H__
#define __NET_NFC_ADDON_HCE_H__

#include "net_nfc_typedef_internal.h"

#include "net_nfc_util_hce.h"
#include "net_nfc_server_hce.h"
#include "net_nfc_server_addon.h"

typedef struct _net_nfc_addon_hce_ops_t
{
	const char *name;

	net_nfc_addon_init init;
	net_nfc_addon_pause pause;
	net_nfc_addon_resume resume;
	net_nfc_addon_deinit deinit;

	const char *aid;
	net_nfc_server_hce_listener_cb listener;
}
net_nfc_addon_hce_ops_t;

#endif // __NET_NFC_ADDON_HCE_H__
