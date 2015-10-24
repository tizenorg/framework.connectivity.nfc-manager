/*
  * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
  *
  * Licensed under the Flora License, Version 1.1 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://floralicense.org/license/
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

#include <glib.h>

#include "vconf.h"
#include <bluetooth.h>
#include <bluetooth_internal.h>

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_server_route_table.h"
#include "net_nfc_addon_hce.h"
#include "net_nfc_addon_hce_ndef.h"


#define MAPPING_VERSION			0x20

#define NDEF_FILE_CONTROL_TAG		0x04
#define PROPRIETARY_FILE_CONTROL_TAG	0x05

#define MAX_NDEF_LEN			0x1000
#define MAX_NDEF_DEF			0x10, 0x00

#define COND_ALL_ACCESS			0x00
#define COND_NO_ACCESS			0xFF

#define CC_FID				0xE1, 0x03
#define NDEF_FID			0xE1, 0x05

#define ENDIAN_16(x)			((((x) >> 8) & 0x00FF) | (((x) << 8) & 0xFF00))

#define NDEF_AID			"D2760000850101" /* 00A4040007D2760000850101 */

typedef struct _cc_data_t
{
	uint16_t cclen;
	uint8_t version;
	uint16_t mle;
	uint16_t mlc;
	struct
	{
		uint8_t tag;
		uint8_t len;
		uint16_t fid;
		uint16_t mndef;
		uint8_t rcond;
		uint8_t wcond;
	}
	cc;
	uint8_t tlv[0];
}
__attribute__((packed)) cc_data_t;

typedef struct _ndef_data_t
{
	uint16_t len;
	uint8_t data[0];
}
__attribute__((packed)) ndef_data_t;

static uint8_t ndef_aid[] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };
static uint8_t cc_fid[] = { CC_FID };
static uint8_t ndef_fid[] = { NDEF_FID };

static uint8_t cc_data[] = {
	0x00, 0x0F, /* cclen */
	MAPPING_VERSION, /* version */
	0x00, 0x3B, /* max lc */
	0x00, 0x34, /* max le */
	NDEF_FILE_CONTROL_TAG, /* tag */
	0x06, /* len */
	NDEF_FID, /* ndef fid */
	MAX_NDEF_DEF, /* max ndef len */
	COND_ALL_ACCESS, /* read right */
	COND_NO_ACCESS, /* write right */
};

static uint16_t ndef_len;
static ndef_data_t *ndef_data;

static uint8_t *selected_aid;
static uint8_t *selected_fid;

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

		if (apdu->p1 == NET_NFC_HCE_P1_SELECT_BY_NAME) {
			if (memcmp(apdu->data, ndef_aid,
				MIN(sizeof(ndef_aid), apdu->lc)) == 0) {
				DEBUG_SERVER_MSG("select ndef applet");

				/* bt on */
				/* fill bt address */

				selected_aid = ndef_aid;

				__send_response(handle, NET_NFC_HCE_SW_SUCCESS, NULL, 0);
			} else {
				DEBUG_ERR_MSG("application not found");
				__send_response(handle, NET_NFC_HCE_SW_FILE_NOT_FOUND, NULL, 0);
			}
		} else if (apdu->p1 == NET_NFC_HCE_P1_SELECT_BY_FID) {
			if (selected_aid == NULL) {
				DEBUG_ERR_MSG("need to select ndef applet");
				__send_response(handle, NET_NFC_HCE_SW_FILE_NOT_FOUND, NULL, 0);
				goto END;
			}

			if (apdu->lc != 2) {
				DEBUG_ERR_MSG("wrong parameter");
				__send_response(handle, NET_NFC_HCE_SW_INCORRECT_P1_TO_P2, NULL, 0);
				goto END;
			}

			if (memcmp(apdu->data, cc_fid,
				MIN(sizeof(cc_fid), apdu->lc)) == 0) {
				DEBUG_SERVER_MSG("select capability container");

				selected_fid = cc_fid;

				__send_response(handle, NET_NFC_HCE_SW_SUCCESS, NULL, 0);
			} else if (memcmp(apdu->data, ndef_fid,
				MIN(sizeof(ndef_fid), apdu->lc)) == 0) {
				DEBUG_SERVER_MSG("select ndef");

				selected_fid = ndef_fid;

				__send_response(handle, NET_NFC_HCE_SW_SUCCESS, NULL, 0);
			} else {
				DEBUG_ERR_MSG("application not found");
				__send_response(handle, NET_NFC_HCE_SW_FILE_NOT_FOUND, NULL, 0);
			}
		} else {

		}
	} else if (apdu->ins == NET_NFC_HCE_INS_READ_BINARY) {
		if (apdu->lc != NET_NFC_HCE_INVALID_VALUE ||
			apdu->data != NULL || apdu->le == NET_NFC_HCE_INVALID_VALUE) {
			DEBUG_ERR_MSG("wrong parameter, lc [%d], data [%p], le [%d]", apdu->lc, apdu->data, apdu->le);
			__send_response(handle, NET_NFC_HCE_SW_LC_INCONSIST_P1_TO_P2, NULL, 0);
			goto END;
		}

		if (selected_fid == cc_fid) {
			uint16_t offset;

			offset = apdu->p1 << 8 | apdu->p2;
			if (offset < sizeof(cc_data)) {
				/* send response */

				__send_response(handle, NET_NFC_HCE_SW_SUCCESS,
					cc_data + offset,
					MIN(sizeof(cc_data) - offset, apdu->le));
			} else {
				DEBUG_ERR_MSG("abnormal offset, [%d]", offset);
				__send_response(handle, NET_NFC_HCE_SW_INCORRECT_P1_TO_P2, NULL, 0);
			}
		} else if (selected_fid == ndef_fid) {
			uint16_t offset;

			offset = apdu->p1 << 8 | apdu->p2;
			if (offset < ndef_data->len + sizeof(*ndef_data)) {
				/* send response */

				__send_response(handle, NET_NFC_HCE_SW_SUCCESS,
					(uint8_t *)ndef_data + offset,
					MIN(ndef_data->len + sizeof(*ndef_data) - offset, apdu->le));
			} else {
				DEBUG_ERR_MSG("abnormal offset, [%d]", offset);
				__send_response(handle, NET_NFC_HCE_SW_INCORRECT_P1_TO_P2, NULL, 0);
			}
		} else {
			DEBUG_ERR_MSG("not supported");
			__send_response(handle, NET_NFC_HCE_SW_FUNC_NOT_SUPPORTED, NULL, 0);
		}
	} else if (apdu->ins == NET_NFC_HCE_INS_UPDATE_BINARY) {
		DEBUG_ERR_MSG("not supported");
		__send_response(handle, NET_NFC_HCE_SW_INS_NOT_SUPPORTED, NULL, 0);
	} else {
		DEBUG_ERR_MSG("not supported");
		__send_response(handle, NET_NFC_HCE_SW_INS_NOT_SUPPORTED, NULL, 0);
	}

END :
	if (apdu != NULL) {
		net_nfc_util_hce_free_apdu_data(apdu);
	}
}

static void __nfc_addon_hce_ndef_listener(net_nfc_target_handle_s *handle,
	int event, data_s *data, void *user_data)
{
	switch (event) {
	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED :
		INFO_MSG("NET_NFC_MESSAGE_ROUTING_HOST_EMU_ACTIVATED");
		selected_fid = NULL;
		selected_aid = NULL;
		break;

	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA :
		INFO_MSG("NET_NFC_MESSAGE_ROUTING_HOST_EMU_DATA");
		__process_command(handle, data);
		break;

	case NET_NFC_MESSAGE_ROUTING_HOST_EMU_DEACTIVATED :
		INFO_MSG("NET_NFC_MESSAGE_ROUTING_HOST_EMU_DEACTIVATED");
		selected_fid = NULL;
		selected_aid = NULL;
		break;

	default :
		break;
	}
}

static void __nfc_addon_hce_ndef_init(void)
{
	DEBUG_ADDON_MSG(">>>>");

	enabled = false;
	ndef_len = MAX_NDEF_LEN;
	ndef_data = g_malloc0(ndef_len);
}

static void __nfc_addon_hce_ndef_pause(void)
{
	DEBUG_ADDON_MSG(">>>>");
}

static void __nfc_addon_hce_ndef_resume(void)
{
	DEBUG_ADDON_MSG(">>>>");
}

static void __nfc_addon_hce_ndef_deinit(void)
{
	DEBUG_ADDON_MSG(">>>>");

	net_nfc_addon_hce_ndef_disable();

	g_free(ndef_data);
}

net_nfc_addon_hce_ops_t net_nfc_addon_hce_ndef_ops = {
	.name = "HCE NDEF EMUL",
	.init = __nfc_addon_hce_ndef_init,
	.pause = __nfc_addon_hce_ndef_pause,
	.resume = __nfc_addon_hce_ndef_resume,
	.deinit = __nfc_addon_hce_ndef_deinit,

	.aid = NDEF_AID,
	.listener = __nfc_addon_hce_ndef_listener,
};

void net_nfc_addon_hce_ndef_enable(void)
{
	net_nfc_error_e result = NET_NFC_OK;

	if (enabled == false) {
		if (net_nfc_server_route_table_find_aid("nfc-manager",
			NDEF_AID) == NULL) {
			result = net_nfc_server_route_table_add_aid(NULL, "nfc-manager",
				NET_NFC_SE_TYPE_HCE,
				NET_NFC_CARD_EMULATION_CATEGORY_OTHER,
				NDEF_AID);
		}

		if (result == NET_NFC_OK) {
			enabled = true;
		} else {
			DEBUG_ERR_MSG("net_nfc_server_route_table_add_aid failed, [%d]", result);
		}
	}
}

net_nfc_error_e net_nfc_addon_hce_ndef_set_data(data_s *data)
{
	if (data == NULL || data->buffer == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	if (data->length > (ndef_len - sizeof(*ndef_data))) {
		return NET_NFC_INSUFFICIENT_STORAGE;
	}

	ndef_data->len = ENDIAN_16((uint16_t)data->length);
	memcpy(ndef_data->data, data->buffer, data->length);

	return NET_NFC_OK;
}

void net_nfc_addon_hce_ndef_disable(void)
{
	if (enabled == true) {
		if (net_nfc_server_route_table_find_aid("nfc-manager",
			NDEF_AID) != NULL) {
			net_nfc_server_route_table_del_aid(NULL, "nfc-manager",
				NDEF_AID, false);
		}

		enabled = false;
	}
}
