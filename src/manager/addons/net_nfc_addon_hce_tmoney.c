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
#include "net_nfc_server_route_table.h"
#include "net_nfc_addon_hce.h"


#define ENDIAN_16(x)			((((x) >> 8) & 0x00FF) | (((x) << 8) & 0xFF00))

#define T_MONEY_AID			"D4100000030001" /*  00A4040007D410000003000100 */
#define T_MONEY_INS_READ		(uint8_t)0xCA

static const uint8_t tmoney_aid[] = { 0xD4, 0x10, 0x00, 0x00, 0x03, 0x00, 0x01 };
static uint8_t tmoney_response[] = {
	0x6F, 0x00,
//	0x6F, 0x31,
//	0xB0, 0x2F,
//	0x00, 0x10, 0x01, 0x08, 0x10, 0x10, 0x00, 0x09, 0x84, 0x60, 0x82, 0x99, 0x01, 0x06, 0x70, 0x79,
//	0x48, 0x20, 0x13, 0x03, 0x30, 0x20, 0x18, 0x03, 0x29, 0x01, 0x00, 0x00, 0x07, 0xA1, 0x20, 0x40,
//	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static uint8_t tmoney_uid[] = { 'T', 'i', 'z', 'e', 'n', '1', '2', '3' };

static bool selected;
static bool enabled;

static void __send_response(net_nfc_target_handle_s *handle, uint16_t sw, uint8_t *resp, size_t len)
{
	size_t total_len = sizeof(sw);
	size_t offset = 0;
	uint8_t *buffer;

	sw = ENDIAN_16(sw);

	if (resp != NULL && len > 0) {
		total_len += len;
	}

	buffer = g_malloc0(total_len);

	if (resp != NULL && len > 0) {
		memcpy(buffer + offset, resp, len);
		offset += len;
	}

	memcpy(buffer + offset, &sw, sizeof(sw));

	/* send */
	data_s temp = { buffer, total_len };

	net_nfc_server_hce_send_apdu_response(handle, &temp);

	g_free(buffer);
}

static void __process_command(net_nfc_target_handle_s *handle, data_s *cmd)
{
	net_nfc_apdu_data_t *apdu;

	apdu = net_nfc_util_hce_create_apdu_data();

	if (net_nfc_util_hce_extract_parameter(cmd, apdu) != NET_NFC_OK) {
		DEBUG_ERR_MSG("wrong length");
		__send_response(handle, NET_NFC_HCE_SW_WRONG_LENGTH, NULL, 0);
		goto END;
	}

	if (apdu->ins == NET_NFC_HCE_INS_SELECT) {
		if (apdu->lc < 2 || apdu->data == NULL) {
			DEBUG_ERR_MSG("wrong parameter");
			__send_response(handle, NET_NFC_HCE_SW_LC_INCONSIST_P1_TO_P2, NULL, 0);
			goto END;
		}

		if (apdu->p1 != NET_NFC_HCE_P1_SELECT_BY_NAME ||
			apdu->p2 != 0) {
			DEBUG_ERR_MSG("incorrect parameter");
			__send_response(handle, NET_NFC_HCE_SW_INCORRECT_P1_TO_P2, NULL, 0);
			goto END;
		}

		if (memcmp(apdu->data, tmoney_aid, MIN(sizeof(tmoney_aid), apdu->lc)) == 0) {
			DEBUG_SERVER_MSG("select tmoney applet");

			selected = true;

			__send_response(handle, NET_NFC_HCE_SW_SUCCESS, tmoney_response, sizeof(tmoney_response));
		} else {
			DEBUG_ERR_MSG("application not found");
			__send_response(handle, NET_NFC_HCE_SW_FILE_NOT_FOUND, NULL, 0);
		}
	} else if (apdu->ins == T_MONEY_INS_READ) {
		if (selected == false) {
			DEBUG_ERR_MSG("need to select applet");
			__send_response(handle, NET_NFC_HCE_SW_COMMAND_NOT_ALLOWED, NULL, 0);
			goto END;
		}

		if (apdu->p1 != 1 || apdu->p2 != 1) {
			DEBUG_ERR_MSG("incorrect parameter, p1 [%02X], p2 [%02X]", apdu->p1, apdu->p2);
			__send_response(handle, NET_NFC_HCE_SW_INCORRECT_P1_TO_P2, NULL, 0);
			goto END;
		}

		if (apdu->le == NET_NFC_HCE_INVALID_VALUE) {
			DEBUG_ERR_MSG("wrong parameter, lc [%d], data [%p], le [%d]", apdu->lc, apdu->data, apdu->le);
			__send_response(handle, NET_NFC_HCE_SW_LC_INCONSIST_P1_TO_P2, NULL, 0);
			goto END;
		}

		DEBUG_SERVER_MSG("tmoney read");

		__send_response(handle, NET_NFC_HCE_SW_SUCCESS,
			tmoney_uid,
			sizeof(tmoney_uid));
	} else {
		DEBUG_ERR_MSG("not supported");
		__send_response(handle, NET_NFC_HCE_SW_INS_NOT_SUPPORTED, NULL, 0);
	}

END :
	if (apdu != NULL) {
		net_nfc_util_hce_free_apdu_data(apdu);
	}
}

static void __nfc_addon_hce_tmoney_listener(net_nfc_target_handle_s *handle,
	int event, data_s *data, void *user_data)
{
	switch (event) {
	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED :
		INFO_MSG("NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED");
		selected = false;
		break;

	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA :
		INFO_MSG("NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA");
		__process_command(handle, data);
		break;

	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_DEACTIVATED :
		INFO_MSG("NET_NFC_MESSAGE_ROUTING_HOST_EMU_DEACTIVATED");
		selected = false;
		break;

	default :
		break;
	}
}

static void _plugin_hce_tmoney_enable(void)
{
	net_nfc_error_e result = NET_NFC_OK;

	if (enabled == false) {
		if (net_nfc_server_route_table_find_aid("nfc-manager",
			T_MONEY_AID) == NULL) {
			result = net_nfc_server_route_table_add_aid(NULL, "nfc-manager",
				NET_NFC_SE_TYPE_HCE,
				NET_NFC_CARD_EMULATION_CATEGORY_OTHER,
				T_MONEY_AID);
		}

		if (result == NET_NFC_OK) {
			enabled = true;
		} else {
			DEBUG_ERR_MSG("net_nfc_server_route_table_add_aid failed, [%d]", result);
		}
	}
}

static void _plugin_hce_tmoney_disable(void)
{
	if (enabled == true) {
		if (net_nfc_server_route_table_find_aid("nfc-manager",
			T_MONEY_AID) != NULL) {
			net_nfc_server_route_table_del_aid(NULL, "nfc-manager",
				T_MONEY_AID, false);
		}

		enabled = false;
	}
}
static void _nfc_plugin_hce_tmoney_init(void)
{
	DEBUG_ADDON_MSG(">>>>");

	_plugin_hce_tmoney_enable();
}

static void _nfc_plugin_hce_tmoney_pause(void)
{
	DEBUG_ADDON_MSG(">>>>");
}

static void _nfc_plugin_hce_tmoney_resume(void)
{
	DEBUG_ADDON_MSG(">>>>");
}

static void _nfc_plugin_hce_tmoney_deinit(void)
{
	DEBUG_ADDON_MSG(">>>>");

	_plugin_hce_tmoney_disable();
}

net_nfc_addon_hce_ops_t net_nfc_addon_hce_tmoney_ops = {
	.name = "HCE T-MONEY EMUL",
	.init = _nfc_plugin_hce_tmoney_init,
	.pause = _nfc_plugin_hce_tmoney_pause,
	.resume = _nfc_plugin_hce_tmoney_resume,
	.deinit = _nfc_plugin_hce_tmoney_deinit,

	.aid = T_MONEY_AID,
	.listener = __nfc_addon_hce_tmoney_listener,
};
