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

#include <glib.h>

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_hce.h"
#include "net_nfc_server_addon.h"

extern net_nfc_addon_ops_t net_nfc_addon_hce_ops;

net_nfc_addon_ops_t *addons[] = {
	&net_nfc_addon_hce_ops,
};
size_t addons_count = sizeof(addons) / sizeof(net_nfc_addon_ops_t *);

net_nfc_error_e net_nfc_addons_init(void)
{
	int i;

	DEBUG_ADDON_MSG(">>>");

	for (i = 0; i < addons_count; i++) {
		addons[i]->init();
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_addons_pause(void)
{
	int i;

	for (i = 0; i < addons_count; i++) {
		addons[i]->pause();
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_addons_resume(void)
{
	int i;

	for (i = 0; i < addons_count; i++) {
		addons[i]->resume();
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_addons_deinit(void)
{
	int i;

	DEBUG_ADDON_MSG(">>>");

	for (i = addons_count - 1; i >= 0; i--) {
		DEBUG_ADDON_MSG("deinit, index [%d]", i);
		addons[i]->deinit();
	}

	return NET_NFC_OK;
}
