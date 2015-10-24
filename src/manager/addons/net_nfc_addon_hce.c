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
#include "net_nfc_addon_hce.h"
#include "net_nfc_server_route_table.h"

#ifdef ADDON_HCE_NDEF
extern net_nfc_addon_hce_ops_t net_nfc_addon_hce_ndef_ops;
#endif
#ifdef ADDON_HCE_PPSE
extern net_nfc_addon_hce_ops_t net_nfc_addon_hce_ppse_ops;
#endif
#ifdef ADDON_HCE_TMONEY
extern net_nfc_addon_hce_ops_t net_nfc_addon_hce_tmoney_ops;
#endif

net_nfc_addon_hce_ops_t *hce_addons[] = {
#ifdef ADDON_HCE_NDEF
	&net_nfc_addon_hce_ndef_ops,
#endif
#ifdef ADDON_HCE_PPSE
	&net_nfc_addon_hce_ppse_ops,
#endif
#ifdef ADDON_HCE_TMONEY
	&net_nfc_addon_hce_tmoney_ops,
#endif
	NULL,
};

size_t hce_addons_count = (sizeof(hce_addons) / sizeof(net_nfc_addon_hce_ops_t *)) - 1;

static net_nfc_addon_hce_ops_t *selected_ops;


static void __process_command(net_nfc_target_handle_s *handle, data_s *data)
{
	net_nfc_apdu_data_t *apdu_data;

	apdu_data = net_nfc_util_hce_create_apdu_data();

	if (net_nfc_util_hce_extract_parameter(data, apdu_data) == NET_NFC_OK) {
		if (apdu_data->ins == NET_NFC_HCE_INS_SELECT) {
			if (apdu_data->p1 == NET_NFC_HCE_P1_SELECT_BY_NAME) {
				char aid[1024];
				int i;
				data_s temp = { apdu_data->data, apdu_data->lc };

				net_nfc_util_binary_to_hex_string(&temp, aid, sizeof(aid));

				for (i = 0; i < hce_addons_count; i++) {
					if (g_ascii_strcasecmp(hce_addons[i]->aid, aid) == 0) {
						selected_ops = hce_addons[i];
						break;
					}
				}

				if (i == hce_addons_count) {
					/** NOT FOUND??? */
					DEBUG_ERR_MSG("NOT FOUND???");
				}
			} else {

			}
		}

		if (selected_ops == NULL) {
			DEBUG_ERR_MSG("NOT SELECTED");
		} else {
			selected_ops->listener(handle,
				NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA,
				data, NULL);
		}
	}

	net_nfc_util_hce_free_apdu_data(apdu_data);
}

static void __hce_listener(net_nfc_target_handle_s *handle, int event,
	data_s *data, void *user_data)
{
	switch (event) {
	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED :
		INFO_MSG("NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED");
		break;

	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA :
		INFO_MSG("NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA");
		__process_command(handle, data);
		break;

	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_DEACTIVATED :
		INFO_MSG("NET_NFC_MESSAGE_ROUTING_HOST_EMU_DEACTIVATED");
		break;

	default :
		break;
	}
}

static void _nfc_addon_hce_init(void)
{
	int i;

	DEBUG_ADDON_MSG(">>>>");

	net_nfc_server_route_table_init();

	net_nfc_server_hce_start_hce_handler("nfc-manager", NULL,
		__hce_listener, NULL, NULL);

	for (i = 0; i < hce_addons_count; i++) {
		hce_addons[i]->init();
	}
}

static void _nfc_addon_hce_pause(void)
{
	int i;

	DEBUG_ADDON_MSG(">>>>");

	for (i = 0; i < hce_addons_count; i++) {
		hce_addons[i]->pause();
	}
}

static void _nfc_addon_hce_resume(void)
{
	int i;

	DEBUG_ADDON_MSG(">>>>");

	for (i = 0; i < hce_addons_count; i++) {
		hce_addons[i]->resume();
	}
}

static void _nfc_addon_hce_deinit(void)
{
	int i;

	DEBUG_ADDON_MSG(">>>>");

	for (i = 0; i < hce_addons_count; i++) {
		hce_addons[i]->deinit();
	}

	net_nfc_server_hce_stop_hce_handler("nfc-manager");
}

net_nfc_addon_ops_t net_nfc_addon_hce_ops = {
	.name = "HCE EMUL",
	.init = _nfc_addon_hce_init,
	.pause = _nfc_addon_hce_pause,
	.resume = _nfc_addon_hce_resume,
	.deinit = _nfc_addon_hce_deinit,
};
