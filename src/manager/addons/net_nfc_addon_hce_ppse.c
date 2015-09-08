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


#define PPSE_INS_LOOPBACK		0xEE

#define ENDIAN_16(x)			((((x) >> 8) & 0x00FF) | (((x) << 8) & 0xFF00))

#define PPSE_AID			"325041592E5359532E4444463031" /* 00A404000E325041592E5359532E4444463031 */

/* "2PAY.SYS.DDF01" */
static uint8_t ppse_aid[] = { '2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1' };

static bool selected;

static size_t __put_tlv(uint8_t *out, size_t len,
	uint16_t t, uint16_t l, uint8_t *v)
{
	size_t offset = 0;

	/* t */
	if (t & 0xFF00) {
		out[offset++] = (t & 0xFF00) >> 8;
		out[offset++] = t & 0x00FF;
	} else {
		out[offset++] = t & 0x00FF;
	}

	/* l */
	if (l & 0xFF00) {
		out[offset++] = (l & 0xFF00) >> 8;
		out[offset++] = l & 0x00FF;
	} else {
		out[offset++] = l & 0x00FF;
	}

	/* v */
	memcpy(out + offset, v, l);
	offset += l;

	return offset;
}

static size_t __fill_fci(uint8_t *tlv, size_t len, data_s *aid, data_s *label,
	uint8_t priority)
{
	uint8_t result[1024] = { 0, };
	uint8_t temp[1024] = { 0, };
	size_t offset = 0, temp_len;

	/* aid */
	offset = __put_tlv(temp, sizeof(temp), 0x4F, aid->length, aid->buffer);

	/* label */
	offset += __put_tlv(temp + offset, sizeof(temp) - offset, 0x50,
		label->length, label->buffer);

	/* priority */
	offset += __put_tlv(temp + offset, sizeof(temp) - offset, 0x82,
		sizeof(priority), &priority);


	/* FCI issuer descretionary data */
	temp_len = __put_tlv(result, sizeof(result), 0xBF0C, offset, temp);

	/* DF name */
	offset = __put_tlv(temp, sizeof(temp), 0x84, sizeof(ppse_aid), ppse_aid);

	/* FCI proprietary template */
	offset += __put_tlv(temp + offset, sizeof(result) - offset, 0xA5,
		temp_len, result);


	offset = __put_tlv(result, sizeof(result), 0x6F, offset, temp);

	memcpy(tlv, result, offset);

	return offset;
}

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

		if (memcmp(apdu->data, ppse_aid, MIN(sizeof(ppse_aid), apdu->lc)) == 0) {
			uint8_t buffer[1024];
			size_t len;
			uint8_t temp_aid[] = { 0x12, 0x34, 0x56, 0x78, 0x90 };
			data_s aid = { temp_aid, sizeof(temp_aid) };
			uint8_t temp_label[] = { 'T', 'E', 'S', 'T' };
			data_s label = { temp_label, sizeof(temp_label) };

			DEBUG_SERVER_MSG("select ppse applet");

			len = __fill_fci(buffer, sizeof(buffer), &aid, &label, 1);

			selected = true;

			__send_response(handle, NET_NFC_HCE_SW_SUCCESS, buffer, len);
		} else {
			DEBUG_ERR_MSG("application not found");
			__send_response(handle, NET_NFC_HCE_SW_FILE_NOT_FOUND, NULL, 0);
		}
	} else if (apdu->ins == PPSE_INS_LOOPBACK) {
		if (selected == false) {
			DEBUG_ERR_MSG("need to select applet");
			__send_response(handle, NET_NFC_HCE_SW_COMMAND_NOT_ALLOWED, NULL, 0);
			goto END;
		}

		if (apdu->cla == 0x80) {
			DEBUG_ERR_MSG("wrong cla, cla [%02X]", apdu->cla);
			__send_response(handle, NET_NFC_HCE_SW_CLASS_NOT_SUPPORTED, NULL, 0);
			goto END;
		}

		if (apdu->p1 != 0 || apdu->p2 != 0) {
			DEBUG_ERR_MSG("incorrect parameter, p1 [%02X], p2 [%02X]", apdu->p1, apdu->p2);
			__send_response(handle, NET_NFC_HCE_SW_INCORRECT_P1_TO_P2, NULL, 0);
			goto END;
		}

		if (apdu->lc == NET_NFC_HCE_INVALID_VALUE ||
			apdu->lc == 0 || apdu->data == NULL ||
			apdu->le == NET_NFC_HCE_INVALID_VALUE) {
			DEBUG_ERR_MSG("wrong parameter, lc [%d], data [%p], le [%d]", apdu->lc, apdu->data, apdu->le);
			__send_response(handle, NET_NFC_HCE_SW_LC_INCONSIST_P1_TO_P2, NULL, 0);
			goto END;
		}

		DEBUG_SERVER_MSG("ppse loopback");

		if (apdu->le == 0) {
			apdu->le = 255;
		}

		__send_response(handle, NET_NFC_HCE_SW_SUCCESS,
			apdu->data,
			MIN(apdu->lc, apdu->le));
	} else {
		DEBUG_ERR_MSG("not supported");
		__send_response(handle, NET_NFC_HCE_SW_INS_NOT_SUPPORTED, NULL, 0);
	}

END :
	if (apdu != NULL) {
		net_nfc_util_hce_free_apdu_data(apdu);
	}
}

static void __nfc_addon_hce_ppse_listener(net_nfc_target_handle_s *handle,
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

static void _nfc_plugin_hce_ppse_init(void)
{
	DEBUG_ADDON_MSG(">>>>");

	net_nfc_server_route_table_add_aid(NULL, "nfc-manager",
		NET_NFC_SE_TYPE_HCE,
		NET_NFC_CARD_EMULATION_CATEGORY_OTHER,
		false, PPSE_AID);
}

static void _nfc_plugin_hce_ppse_pause(void)
{
	DEBUG_ADDON_MSG(">>>>");
}

static void _nfc_plugin_hce_ppse_resume(void)
{
	DEBUG_ADDON_MSG(">>>>");
}

static void _nfc_plugin_hce_ppse_deinit(void)
{
	DEBUG_ADDON_MSG(">>>>");

	net_nfc_server_route_table_del_aid(NULL, "nfc-manager", PPSE_AID, false);
}

net_nfc_addon_hce_ops_t net_nfc_addon_hce_ppse_ops = {
	.name = "HCE PPSE EMUL",
	.init = _nfc_plugin_hce_ppse_init,
	.pause = _nfc_plugin_hce_ppse_pause,
	.resume = _nfc_plugin_hce_ppse_resume,
	.deinit = _nfc_plugin_hce_ppse_deinit,

	.aid = PPSE_AID,
	.listener = __nfc_addon_hce_ppse_listener,
};
