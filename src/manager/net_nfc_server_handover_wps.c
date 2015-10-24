/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "wifi.h"

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_ndef_record.h"
#include "net_nfc_util_handover.h"
#include "net_nfc_server_handover_internal.h"
#include "net_nfc_server_llcp.h"


typedef struct _wps_process_context_t
{
	net_nfc_error_e result;
	net_nfc_carrier_config_s *config;
	net_nfc_server_handover_process_carrier_cb cb;
	void *user_param;
}
wps_process_context_t;

static char *_wps_get_string_property(net_nfc_carrier_config_s *config,
	uint16_t attr)
{
	char *result = NULL;
	uint16_t len = 0;
	uint8_t *buffer = NULL;
	net_nfc_error_e ret;

	ret = net_nfc_util_get_carrier_config_property(config,
		attr, &len, &buffer);
	if (ret == NET_NFC_OK) {
		result = g_strndup((char *)buffer, len);
	}

	return result;
}

static uint16_t _wps_get_short_property(net_nfc_carrier_config_s *config,
	uint16_t attr)
{
	uint16_t result = 0;
	uint16_t len = 0;
	uint8_t *buffer = NULL;
	net_nfc_error_e ret;

	ret = net_nfc_util_get_carrier_config_property(config,
		attr, &len, &buffer);
	if (ret == NET_NFC_OK) {
		result = htons(*(uint16_t *)buffer);
	}

	return result;
}

static char *_wps_get_mac_address(net_nfc_carrier_config_s *config)
{
	char *result = NULL;
	uint16_t len = 0;
	uint8_t *buffer = NULL;
	net_nfc_error_e ret;

	ret = net_nfc_util_get_carrier_config_property(config,
		NET_NFC_WIFI_ATTRIBUTE_MAC_ADDR, &len, &buffer);
	if (ret == NET_NFC_OK) {
		char temp[50];

		snprintf(temp, sizeof(temp), "%02X:%02X:%02X:%02X:%02X:%02X",
			buffer[0], buffer[1], buffer[2],
			buffer[3], buffer[4], buffer[5]);

		result = g_strdup(temp);
	}

	return result;
}

static wifi_security_type_e _wps_get_security_type(
	net_nfc_carrier_config_s *config)
{
	wifi_security_type_e result;
	uint16_t ret;

	ret = _wps_get_short_property(config,
		NET_NFC_WIFI_ATTRIBUTE_AUTH_TYPE);

	switch (ret) {
	case 1 : /* open */
		result = WIFI_SECURITY_TYPE_NONE;
		break;

	case 2 : /* WPA-Personal */
		result = WIFI_SECURITY_TYPE_WPA_PSK;
		break;

	case 4 : /* Shared */
		result = WIFI_SECURITY_TYPE_WEP;
		break;

	case 8 : /* WPA-Enterprise */
		result = WIFI_SECURITY_TYPE_EAP;
		break;

	case 16 : /* WPA2-Enterprise */
		result = WIFI_SECURITY_TYPE_EAP;
		break;

	case 32 : /* WPA2-Personal */
		result = WIFI_SECURITY_TYPE_WPA2_PSK;
		break;

	default :
		result = WIFI_SECURITY_TYPE_NONE;
		break;
	}

	return result;
}

static wifi_encryption_type_e _wps_get_encryption_type(
	net_nfc_carrier_config_s *config)
{
	wifi_encryption_type_e result;
	uint16_t ret;

	ret = _wps_get_short_property(config,
		NET_NFC_WIFI_ATTRIBUTE_ENC_TYPE);

	switch (ret) {
	case 1 : /* None */
		result = WIFI_ENCRYPTION_TYPE_NONE;
		break;

	case 2 : /* WEP */
		result = WIFI_ENCRYPTION_TYPE_WEP;
		break;

	case 4 : /* TKIP */
		result = WIFI_ENCRYPTION_TYPE_TKIP;
		break;

	case 8 : /* AES */
		result = WIFI_ENCRYPTION_TYPE_AES;
		break;

	case 12 : /* AES/TKIP */
		result = WIFI_ENCRYPTION_TYPE_TKIP_AES_MIXED;
		break;

	default :
		result = WIFI_SECURITY_TYPE_NONE;
		break;
	}

	return result;
}

net_nfc_error_e net_nfc_server_handover_wps_get_selector_carrier(
	net_nfc_server_handover_get_carrier_cb cb,
	void *user_param)
{
	net_nfc_error_e result = NET_NFC_NOT_SUPPORTED;

	/* generating selector record is not supported */

	if (cb != NULL) {
		cb(NET_NFC_NOT_SUPPORTED, NULL, user_param);
	}

	return result;
}

net_nfc_error_e net_nfc_server_handover_wps_get_requester_carrier(
	net_nfc_server_handover_get_carrier_cb cb,
	void *user_param)
{
	net_nfc_error_e result;
	net_nfc_ch_carrier_s *carrier = NULL;
	ndef_record_s *record = NULL;
	data_s type = { (uint8_t *)CH_CAR_RECORD_TYPE, CH_CAR_RECORD_TYPE_LEN };
	uint8_t buffer[sizeof(ch_hc_record_t) + CH_WIFI_WPS_MIME_LEN];
	data_s payload = { buffer, sizeof(buffer) };
	ch_hc_record_t *hc_buffer = (ch_hc_record_t *)buffer;

	hc_buffer->ctf = NET_NFC_RECORD_MIME_TYPE;
	hc_buffer->type_len = CH_WIFI_WPS_MIME_LEN;
	memcpy(hc_buffer->type, CH_WIFI_WPS_MIME, CH_WIFI_WPS_MIME_LEN);

	result = net_nfc_util_create_record(NET_NFC_RECORD_WELL_KNOWN_TYPE,
		&type, NULL, &payload, &record);

	result = net_nfc_util_create_handover_carrier(&carrier,
		NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE);

	result = net_nfc_util_append_handover_carrier_record(carrier, record);

	if (cb != NULL) {
		cb(result, carrier, user_param);
	}

	net_nfc_util_free_handover_carrier(carrier);

	net_nfc_util_free_record(record);

	return result;
}

static bool _wifi_found_ap_cb(wifi_ap_h ap, void *user_data)
{
	gpointer *context = (gpointer *)user_data;
	bool result;
	char *ssid = NULL;
	int ret;

	ret = wifi_ap_get_essid(ap, &ssid);
	if (ret == WIFI_ERROR_NONE && ssid != NULL) {
		DEBUG_MSG("ssid [%s]", ssid);

		if (g_strcmp0(ssid, (char *)context[0]) == 0) {
			DEBUG_MSG("found!! ssid [%s]", ssid);

			context[1] = ap;

			result = false;
		} else {
			result = true;
		}

		g_free(ssid);
	} else {
		DEBUG_ERR_MSG("wifi_ap_get_bssid failed, [%d]", ret);

		result = true;
	}

	return result;
}

static wifi_ap_h _wifi_search_ap(const char *ssid)
{
	gpointer context[2];

	context[0] = (gpointer)ssid;
	context[1] = NULL;

	wifi_foreach_found_aps(_wifi_found_ap_cb, &context);

	return (wifi_ap_h)context[1];
}

static bool _wifi_is_connected(wifi_ap_h ap)
{
	bool result;
	wifi_connection_state_e state = WIFI_CONNECTION_STATE_DISCONNECTED;
	int ret;

	ret = wifi_ap_get_connection_state(ap, &state);
	if (ret == WIFI_ERROR_NONE) {
		if (state == WIFI_CONNECTION_STATE_DISCONNECTED)
			result = false;
		else
			result = true;
	} else {
		result = false;
	}

	return result;
}

static void _wps_finish_do_connect(int result, wps_process_context_t *context)
{
	if (context != NULL) {
		if (context->cb != NULL) {
			data_s *data = NULL;
			data_s temp;

			if (result == NET_NFC_OK) {
				char *mac;

				mac = _wps_get_mac_address(context->config);
				if (mac != NULL) {
					temp.buffer = (uint8_t *)mac;
					temp.length = strlen(mac);

					data = &temp;
				}
			}

			context->cb(result,
				NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS,
				data,
				context->user_param);

			if (data != NULL) {
				net_nfc_util_clear_data(data);
			}
		}

		if (context->config != NULL) {
			net_nfc_util_free_carrier_config(context->config);
		}

		_net_nfc_util_free_mem(context);
	}
}

static void _wifi_connected_cb(wifi_error_e result, void *user_data)
{
	DEBUG_MSG("wifi_connect result [%d]", result);

	_wps_finish_do_connect(result, user_data);
}

static int __connect(wifi_ap_h ap, wps_process_context_t *context)
{
	int result;
	char *net_key;

	wifi_ap_set_security_type(ap, _wps_get_security_type(context->config));
	wifi_ap_set_encryption_type(ap, _wps_get_encryption_type(context->config));

	net_key = _wps_get_string_property(context->config,
		NET_NFC_WIFI_ATTRIBUTE_NET_KEY);
	wifi_ap_set_passphrase(ap, net_key);
	g_free(net_key);

	result = wifi_connect(ap, _wifi_connected_cb, context);

	return result;
}

static void _connect(wps_process_context_t *context)
{
	wifi_ap_h ap = NULL;
	int result;
	char *ssid;

	ssid = _wps_get_string_property(context->config,
		NET_NFC_WIFI_ATTRIBUTE_SSID);
	if (ssid != NULL) {
		ap = _wifi_search_ap(ssid);
		if (ap == NULL) {
			DEBUG_MSG("no ap found");

			result = wifi_ap_create(ssid, &ap);
			if (result == WIFI_ERROR_NONE) {
				result = __connect(ap, context);
				if (result != WIFI_ERROR_NONE) {
					DEBUG_ERR_MSG("__connect failed, [%d]", result);

					wifi_ap_destroy(ap);

					_wps_finish_do_connect(result, context);
				}
			} else {
				DEBUG_ERR_MSG("wifi_ap_create failed, [%d]", result);

				_wps_finish_do_connect(result, context);
			}
		} else if (_wifi_is_connected(ap) == false) {
			DEBUG_MSG("found ap, but not connected");

			result = __connect(ap, context);
			if (result != WIFI_ERROR_NONE) {
				DEBUG_ERR_MSG("wifi_connect failed, [%d]", result);

				_wps_finish_do_connect(result, context);
			}
		} else {
			DEBUG_ERR_MSG("ap exists");

			_wps_finish_do_connect(WIFI_ERROR_ALREADY_EXISTS, context);
		}

		g_free(ssid);
	} else {
		DEBUG_ERR_MSG("_wps_get_string_property failed");

		_wps_finish_do_connect(NET_NFC_ALLOC_FAIL, context);
	}
}

/* activation */
static void _wifi_scan_finished_cb(wifi_error_e result, void *user_data)
{
	DEBUG_MSG("_wifi_scan_finished_cb");

	if (result == WIFI_ERROR_NONE) {
		_connect(user_data);
	} else {
		DEBUG_ERR_MSG("_wifi_scan_finished_cb failed, [%d]", result);

		_wps_finish_do_connect(result, user_data);
	}
}

static void _wifi_activated_cb(wifi_error_e result, void *user_data)
{
	DEBUG_MSG("_wifi_activated_cb");

	if (result == WIFI_ERROR_NONE) {
		int ret;

		ret = wifi_scan(_wifi_scan_finished_cb, user_data);
		if (ret != WIFI_ERROR_NONE) {
			DEBUG_ERR_MSG("wifi_scan failed, [%d]", ret);
		}
	} else {
		DEBUG_ERR_MSG("wifi_activate failed, [%d]", result);

		_wps_finish_do_connect(result, user_data);
	}
}

static int _wifi_activate(wps_process_context_t *context)
{
	int result;

	result = wifi_initialize();
	if (result == WIFI_ERROR_NONE) {
		bool activated = false;

		result = wifi_is_activated(&activated);
		if (result == WIFI_ERROR_NONE) {
			if (activated == false) {
				DEBUG_MSG("wifi is off, try to activate");
				/* activate */
				result = wifi_activate(_wifi_activated_cb, context);
				if (result != WIFI_ERROR_NONE) {
					DEBUG_ERR_MSG("wifi_activate failed, [%d]", result);
				}
			} else {
				_connect(context);

				result = WIFI_ERROR_NONE;
			}
		} else {
			DEBUG_ERR_MSG("wifi_is_activated failed, [%d]", result);
		}
	} else {
		DEBUG_ERR_MSG("wifi_initialize failed, [%d]", result);
	}

	return result;
}

net_nfc_error_e net_nfc_server_handover_wps_do_connect(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_server_handover_process_carrier_cb cb,
	void *user_param)
{
	net_nfc_error_e result;
	wps_process_context_t *context = NULL;

	_net_nfc_util_alloc_mem(context, sizeof(*context));
	if (context != NULL) {
		context->cb = cb;
		context->user_param = user_param;

		result = net_nfc_util_create_carrier_config_from_config_record(
			&context->config, carrier->carrier_record);
		if (result == NET_NFC_OK) {
			result = _wifi_activate(context);
			if (result != NET_NFC_OK) {
				DEBUG_ERR_MSG("_wifi_activate failed, [%d]", result);

				net_nfc_util_free_carrier_config(context->config);
				_net_nfc_util_free_mem(context);
			}
		} else {
			DEBUG_ERR_MSG("net_nfc_util_create_carrier_config_from_config_record failed, [%d]", result);

			_net_nfc_util_free_mem(context);
		}
	} else {
		DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");

		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}
