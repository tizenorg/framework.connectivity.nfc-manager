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

#include "bluetooth-api.h"
#include "bluetooth-audio-api.h"
#include "bluetooth-hid-api.h"
#ifdef USE_SYSTEM_INFO
#include "system_info.h"
#endif

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_ndef_record.h"
#include "net_nfc_util_handover.h"
#include "net_nfc_util_handover_internal.h"
#include "net_nfc_server_handover_internal.h"
#include "net_nfc_server_llcp.h"
#include "net_nfc_app_util_internal.h"


typedef struct _net_nfc_handover_bt_get_context_t
{
	bool already_on;
	int step;
	net_nfc_error_e result;
	net_nfc_ch_carrier_s *carrier;
	net_nfc_server_handover_get_carrier_cb cb;
	void *user_param;
}
net_nfc_handover_bt_get_context_t;

typedef struct _net_nfc_handover_bt_process_context_t
{
	bool already_on;
	int step;
	net_nfc_error_e result;
	net_nfc_server_handover_process_carrier_cb cb;
	net_nfc_ch_carrier_s *carrier;
	data_s data;
	bluetooth_device_address_t addr;
	bluetooth_service_type_t service_mask;
	void *user_param;
}
net_nfc_handover_bt_process_context_t;

static uint8_t __bt_cod[] = { 0x0c, 0x02, 0x5a }; /* 0x5a020c */
#ifndef USE_SYSTEM_INFO
static const char *manufacturer = "Samsung Tizen";
#endif

static int _bt_get_carrier_record(net_nfc_handover_bt_get_context_t *context);
static int _bt_prepare_pairing(net_nfc_handover_bt_process_context_t *context);
static int _bt_do_pairing(net_nfc_handover_bt_process_context_t *context);


static net_nfc_error_e _bt_get_oob_data_from_config(
	net_nfc_carrier_config_s *config,
	bt_oob_data_t *oob)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	data_s hash = { NULL, 0 };
	data_s randomizer = { NULL, 0 };

	LOGD("[%s:%d] START", __func__, __LINE__);

	if (config == NULL || oob == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	memset(oob, 0, sizeof(bt_oob_data_t));

	result = net_nfc_util_get_carrier_config_property(config,
		NET_NFC_BT_ATTRIBUTE_OOB_HASH_C,
		(uint16_t *)&hash.length, &hash.buffer);
	if (result == NET_NFC_OK)
	{
		if (hash.length == 16)
		{
			INFO_MSG("hash found");

			NET_NFC_REVERSE_ORDER_16_BYTES(hash.buffer);

			oob->hash_len = MIN(sizeof(oob->hash), hash.length);
			memcpy(oob->hash, hash.buffer, oob->hash_len);
		}
		else
		{
			DEBUG_ERR_MSG("hash.length error : [%d] bytes", hash.length);
		}
	}

	result = net_nfc_util_get_carrier_config_property(config,
		NET_NFC_BT_ATTRIBUTE_OOB_HASH_R,
		(uint16_t *)&randomizer.length, &randomizer.buffer);
	if (result == NET_NFC_OK)
	{
		if (randomizer.length == 16)
		{
			INFO_MSG("randomizer found");

			NET_NFC_REVERSE_ORDER_16_BYTES(randomizer.buffer);

			oob->randomizer_len = MIN(sizeof(oob->randomizer),
				randomizer.length);
			memcpy(oob->randomizer, randomizer.buffer,
				oob->randomizer_len);
		}
		else
		{
			DEBUG_ERR_MSG("randomizer.length error : [%d] bytes", randomizer.length);
		}
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return result;
}

static void _bt_get_carrier_record_cb(
			int event,
			bluetooth_event_param_t *param,
			void *user_data)
{
	net_nfc_handover_bt_get_context_t *context =
		(net_nfc_handover_bt_get_context_t *)user_data;

	LOGD("[%s] START", __func__);

	if (context == NULL)
	{
		DEBUG_SERVER_MSG("user_data is null");
		LOGD("[%s] END", __func__);
		return;
	}

	switch (event)
	{
	case BLUETOOTH_EVENT_ENABLED :
		INFO_MSG("BLUETOOTH_EVENT_ENABLED");
		if (context->step == NET_NFC_LLCP_STEP_02)
		{
			_bt_get_carrier_record(context);
		}
		else
		{
			DEBUG_ERR_MSG("step is incorrect");
		}
		break;

	case BLUETOOTH_EVENT_DISABLED :
		INFO_MSG("BLUETOOTH_EVENT_DISABLED");
		break;

	default :
		DEBUG_MSG("unhandled bt event [%d], [%d]", event, param->result);
		break;
	}

	LOGD("[%s] END", __func__);
}

static void _append_oob_data(net_nfc_carrier_config_s *config)
{
	net_nfc_error_e result;
	bt_oob_data_t oob = { { 0 }, };

	/* get oob data, optional!!! */
	result = bluetooth_oob_read_local_data(&oob);
	if (result == BLUETOOTH_ERROR_NONE)
	{
		if (oob.hash_len == 16 && oob.randomizer_len == 16)
		{
			INFO_MSG("oob.hash_len [%d], oob.randomizer_len [%d]", oob.hash_len, oob.randomizer_len);

			NET_NFC_REVERSE_ORDER_16_BYTES(oob.hash);

			result = net_nfc_util_add_carrier_config_property(
				config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_C,
				oob.hash_len, oob.hash);
			if (result != NET_NFC_OK)
			{
				DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
			}

			NET_NFC_REVERSE_ORDER_16_BYTES(oob.randomizer);

			result = net_nfc_util_add_carrier_config_property(
				config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_R,
				oob.randomizer_len, oob.randomizer);
			if (result != NET_NFC_OK)
			{
				DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
			}
		}
		else
		{
			DEBUG_ERR_MSG("abnormal oob data, skip....");
		}
	}
	else
	{
		DEBUG_ERR_MSG("bluetooth_oob_read_local_data failed, skip.... [%d]", result);
	}
}

static net_nfc_error_e _bt_create_config_record(ndef_record_s **record)
{
	net_nfc_carrier_config_s *config = NULL;
	net_nfc_error_e result;

	if (record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*record = NULL;

	result = net_nfc_util_create_carrier_config(&config,
		NET_NFC_CONN_HANDOVER_CARRIER_BT);
	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_util_create_carrier_config failed [%d]", result);
		goto END;
	}

	/* add blutooth address, mandatory */
	bluetooth_device_address_t bt_addr = { { 0, } };

	result = bluetooth_get_local_address(&bt_addr);
	if (result != BLUETOOTH_ERROR_NONE)
	{
		DEBUG_ERR_MSG("bluetooth_get_local_address failed [%d]", result);
		result = NET_NFC_OPERATION_FAIL;
		goto END;
	}

	NET_NFC_REVERSE_ORDER_6_BYTES(bt_addr.addr);

	result = net_nfc_util_add_carrier_config_property(
		config, NET_NFC_BT_ATTRIBUTE_ADDRESS,
		sizeof(bt_addr.addr), bt_addr.addr);
	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
		goto END;
	}

	/* append cod */
	result = net_nfc_util_add_carrier_config_property(
		config, NET_NFC_BT_ATTRIBUTE_OOB_COD,
		sizeof(__bt_cod), __bt_cod);
	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
		goto END;
	}

	/* append oob */
	_append_oob_data(config);

	/* append device name */
	bluetooth_device_name_t bt_name = { { 0, } };

	result = bluetooth_get_local_name(&bt_name);
	if (result != BLUETOOTH_ERROR_NONE)
	{
		DEBUG_ERR_MSG("bluetooth_get_local_name failed [%d]", result);
		result = NET_NFC_OPERATION_FAIL;
		goto END;
	}

	if (strlen(bt_name.name) > 0) {
		result = net_nfc_util_add_carrier_config_property(
			config, NET_NFC_BT_ATTRIBUTE_NAME,
			strlen(bt_name.name), (uint8_t *)bt_name.name);
		if (result != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
			goto END;
		}
	} else {
		INFO_MSG("device name is empty, skip appending device name");
	}

	/* append manufacturer */
#ifdef USE_SYSTEM_INFO
	char *manufacturer = NULL;

	result = system_info_get_value_string(SYSTEM_INFO_KEY_MANUFACTURER, &manufacturer);
	if (result != SYSTEM_INFO_ERROR_NONE) {
		DEBUG_ERR_MSG("system_info_get_value_string failed [%d]", result);
		result = NET_NFC_OPERATION_FAIL;
		goto END;
	}
#endif
	if (manufacturer != NULL && strlen(manufacturer) > 0) {
		result = net_nfc_util_add_carrier_config_property(
			config, NET_NFC_BT_ATTRIBUTE_MANUFACTURER,
			strlen(manufacturer), (uint8_t *)manufacturer);
#ifdef USE_SYSTEM_INFO
		g_free(manufacturer);
#endif
		if (result != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
			goto END;
		}
	}

	result = net_nfc_util_handover_bt_create_record_from_config(record, config);
	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_util_create_ndef_record_with_carrier_config failed [%d]", result);
	}

END :
	if (config != NULL) {
		net_nfc_util_free_carrier_config(config);
	}

	return result;
}

static int _bt_get_carrier_record(net_nfc_handover_bt_get_context_t *context)
{
	LOGD("[%s:%d] START", __func__, __LINE__);

	if (context->result != NET_NFC_OK && context->result != NET_NFC_BUSY)
	{
		DEBUG_ERR_MSG("context->result is error"
			" [%d]", context->result);

		context->step = NET_NFC_LLCP_STEP_RETURN;
	}

	switch (context->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		DEBUG_MSG("STEP [1]");

		if (bluetooth_register_callback(
			_bt_get_carrier_record_cb,
			context) >= BLUETOOTH_ERROR_NONE)
		{
			context->step = NET_NFC_LLCP_STEP_02;
			context->result = NET_NFC_OK;

			if (bluetooth_check_adapter() !=
				BLUETOOTH_ADAPTER_ENABLED)
			{
				bluetooth_enable_adapter();
			}
			else
			{
				DEBUG_MSG("bluetooth is enabled already");
				context->already_on = true;

				/* do next step */
				g_idle_add((GSourceFunc)_bt_get_carrier_record,
					(gpointer)context);
			}
		}
		else
		{
			DEBUG_ERR_MSG("bluetooth_register_callback failed");

			context->step = NET_NFC_LLCP_STEP_RETURN;
			context->result = NET_NFC_OPERATION_FAIL;

			g_idle_add((GSourceFunc)_bt_get_carrier_record,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			ndef_record_s *record;

			DEBUG_MSG("STEP [2]");

			context->step = NET_NFC_LLCP_STEP_RETURN;

			/* append config to ndef message */
			context->result = _bt_create_config_record(
				&record);
			if (context->result == NET_NFC_OK) {
				net_nfc_util_append_handover_carrier_record(
					context->carrier, record);
			} else {
				DEBUG_ERR_MSG("_bt_create_config_record failed, [%d]", context->result);
			}

			/* complete and return to upper step */
			g_idle_add((GSourceFunc)_bt_get_carrier_record,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		{
			net_nfc_ch_carrier_s *carrier = NULL;

			DEBUG_MSG("STEP return");

			/* unregister current callback */
			bluetooth_unregister_callback();

			if (context->result == NET_NFC_OK) {
				carrier = context->carrier;
			}

			/* complete and return to upper step */
			context->cb(context->result, carrier,
				context->user_param);

			if (carrier != NULL) {
				net_nfc_util_free_handover_carrier(carrier);
			}

			_net_nfc_util_free_mem(context);
		}
		break;

	default :
		break;
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return 0;
}

net_nfc_error_e net_nfc_server_handover_bt_get_carrier(
	net_nfc_server_handover_get_carrier_cb cb,
	void *user_param)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_handover_bt_get_context_t *context = NULL;

	_net_nfc_util_alloc_mem(context, sizeof(*context));
	if (context != NULL) {
		context->cb = cb;
		context->user_param = user_param;
		context->step = NET_NFC_LLCP_STEP_01;

		/* TODO : check cps of bt */
		result = net_nfc_util_create_handover_carrier(&context->carrier,
			NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE);
		if (result == NET_NFC_OK) {
			g_idle_add((GSourceFunc)_bt_get_carrier_record,
				(gpointer)context);
		}
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}

static bool _bt_check_bond_device(bluetooth_device_address_t *address)
{
	bool result = false;
	int ret;
	GPtrArray *devinfo = NULL;

	LOGD("[%s] START", __func__);

	/* allocate the g_pointer_array */
	devinfo = g_ptr_array_new();

	ret = bluetooth_get_bonded_device_list(&devinfo);
	if (ret == BLUETOOTH_ERROR_NONE)
	{
		int i;
		bluetooth_device_info_t *ptr;

		DEBUG_SERVER_MSG("bond devices [%d]", devinfo->len);

		for (i = 0; i < devinfo->len; i++)
		{
			ptr = g_ptr_array_index(devinfo, i);
			if (ptr != NULL)
			{
				/* compare selector address */
				if (memcmp(&(ptr->device_address),
					address,
					sizeof(ptr->device_address)) == 0)
				{
					INFO_MSG("Found!!!");
					result = true;
					break;
				}
			}
		}

		/* free g_pointer_array */
		g_ptr_array_free(devinfo, TRUE);
	}
	else
	{
		DEBUG_ERR_MSG("bluetooth_get_bonded_device_list failed with [%d]", ret);
	}


	LOGD("[%s] END", __func__);

	return result;
}

static void _bt_prepare_pairing_cb(int event, bluetooth_event_param_t *param,
	void *user_data)
{
	net_nfc_handover_bt_process_context_t *context =
		(net_nfc_handover_bt_process_context_t *)user_data;

	LOGD("[%s] START", __func__);

	if (context == NULL)
	{
		DEBUG_SERVER_MSG("user_data is null");
		LOGD("[%s] END", __func__);
		return;
	}

	switch (event)
	{
	case BLUETOOTH_EVENT_ENABLED :
		INFO_MSG("BLUETOOTH_EVENT_ENABLED");
		if (context->step == NET_NFC_LLCP_STEP_02)
		{
			_bt_prepare_pairing(context);
		}
		else
		{
			DEBUG_ERR_MSG("step is incorrect");
		}
		break;

	case BLUETOOTH_EVENT_DISABLED :
		INFO_MSG("BLUETOOTH_EVENT_DISABLED");
		if (context->step == NET_NFC_LLCP_STEP_RETURN)
		{
			_bt_prepare_pairing(context);
		}
		else
		{
			DEBUG_ERR_MSG("step is incorrect");
		}
		break;

	default :
		DEBUG_SERVER_MSG("unhandled bt event [%d],"
				"[0x%04x]", event, param->result);
		break;
	}

	LOGD("[%s] END", __func__);
}

static int _bt_prepare_pairing(net_nfc_handover_bt_process_context_t *context)
{
	int ret;

	LOGD("[%s:%d] START", __func__, __LINE__);

	if (context->result != NET_NFC_OK && context->result != NET_NFC_BUSY)
	{
		DEBUG_ERR_MSG("context->result is error"
			" [%d]", context->result);
		context->step = NET_NFC_LLCP_STEP_RETURN;
	}

	switch (context->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		INFO_MSG("STEP [1]");

		ret = bluetooth_register_callback(
				_bt_prepare_pairing_cb,
				context);
		if (ret >= BLUETOOTH_ERROR_NONE)
		{
			/* next step */
			context->step = NET_NFC_LLCP_STEP_02;

			if (bluetooth_check_adapter() !=
				BLUETOOTH_ADAPTER_ENABLED)
			{
				context->result = NET_NFC_OK;

				ret = bluetooth_enable_adapter();
				if (ret != BLUETOOTH_ERROR_NONE)
				{
					DEBUG_ERR_MSG("bluetooth_enable_adapter failed, [%d]", ret);

					context->step = NET_NFC_STATE_ERROR;
					context->result = NET_NFC_OPERATION_FAIL;
				}
			}
			else
			{
				/* do next step */
				INFO_MSG("BT is enabled already, go next step");

				context->already_on = true;
				context->result = NET_NFC_OK;

				g_idle_add((GSourceFunc)_bt_prepare_pairing,
					(gpointer)context);
			}
		}
		else
		{
			DEBUG_ERR_MSG("bluetooth_register_callback failed, [%d]", ret);
			context->step = NET_NFC_STATE_ERROR;
			context->result = NET_NFC_OPERATION_FAIL;

			g_idle_add((GSourceFunc)_bt_prepare_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			net_nfc_carrier_config_s *config;
			data_s temp = { NULL, 0 };

			INFO_MSG("STEP [2]");

			net_nfc_util_create_carrier_config_from_config_record(
				&config, context->carrier->carrier_record);

			net_nfc_util_get_carrier_config_property(config,
				NET_NFC_BT_ATTRIBUTE_ADDRESS,
				(uint16_t *)&temp.length, &temp.buffer);
			if (temp.length == 6)
			{
				NET_NFC_REVERSE_ORDER_6_BYTES(temp.buffer);

				memcpy(context->addr.addr,
					temp.buffer,
					MIN(sizeof(context->addr.addr),
					temp.length));

				if (_bt_check_bond_device(
					&context->addr) == true)
				{
					INFO_MSG("already paired with [%02x:%02x:%02x:%02x:%02x:%02x]",
						context->addr.addr[0],
						context->addr.addr[1],
						context->addr.addr[2],
						context->addr.addr[3],
						context->addr.addr[4],
						context->addr.addr[5]);

					/* return */
					context->step = NET_NFC_LLCP_STEP_RETURN;
					context->result = NET_NFC_OK;
				}
				else
				{
					bt_oob_data_t oob = { { 0 } , };

					if (_bt_get_oob_data_from_config(
						config,
						&oob) == NET_NFC_OK)
					{
						/* set oob data */
						bluetooth_oob_add_remote_data(
								&context->addr,
								&oob);
					}

					/* pair and send response */
					context->step = NET_NFC_LLCP_STEP_RETURN;
					context->result = NET_NFC_OK;
				}
			}
			else
			{
				DEBUG_ERR_MSG("bluetooth address is invalid. [%d] bytes", temp.length);

				context->step = NET_NFC_STATE_ERROR;
				context->result = NET_NFC_OPERATION_FAIL;
			}

			net_nfc_util_free_carrier_config(config);

			g_idle_add((GSourceFunc)_bt_prepare_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_STATE_ERROR :
		INFO_MSG("STEP ERROR");

		context->step = NET_NFC_LLCP_STEP_RETURN;
		if (context->already_on == false)
		{
			bluetooth_disable_adapter();
		}
		else
		{
			g_idle_add((GSourceFunc)_bt_prepare_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		{
			data_s temp = { context->addr.addr,
				sizeof(context->addr.addr) };
			data_s *data = NULL;

			INFO_MSG("STEP return");

			/* unregister bluetooth callback */
			bluetooth_unregister_callback();

			if (context->result == NET_NFC_OK)
			{
				data = &temp;
			}

			context->cb(context->result,
				NET_NFC_CONN_HANDOVER_CARRIER_BT,
				data, context->user_param);

			/* release context */
			if (context->carrier != NULL)
			{
				net_nfc_util_free_handover_carrier(
					context->carrier);
			}

			net_nfc_util_clear_data(&context->data);
			_net_nfc_util_free_mem(context);
		}
		break;

	default :
		break;
	}

	LOGD("[%s:%d] END", __func__, __LINE__);

	return 0;
}

net_nfc_error_e net_nfc_server_handover_bt_prepare_pairing(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_server_handover_process_carrier_cb cb,
	void *user_param)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_handover_bt_process_context_t *context = NULL;

	_net_nfc_util_alloc_mem(context, sizeof(*context));
	if (context != NULL) {
		context->cb = cb;
		context->user_param = user_param;
		context->step = NET_NFC_LLCP_STEP_01;

		net_nfc_util_duplicate_handover_carrier(&context->carrier,
			carrier);

		g_idle_add((GSourceFunc)_bt_prepare_pairing,
			(gpointer)context);
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}

static bluetooth_service_type_t _bt_check_supported_profiles_by_uuid(
	char uuids[][BLUETOOTH_UUID_STRING_MAX],
	int no_of_service)
{
	unsigned int service = 0;
	char **parts = NULL;
	bluetooth_service_type_t service_mask = 0;
	int i = 0;

	if(uuids == NULL)
		return service_mask;

	for (i = 0; i < no_of_service; i++) {
		parts = g_strsplit(uuids[i], "-", -1);
		if (parts == NULL || parts[0] == NULL) {
			g_strfreev(parts);
			continue;
		}

		service = g_ascii_strtoull(parts[0], NULL, 16);
		g_strfreev(parts);
		switch (service) {
		case BLUETOOTH_HS_PROFILE_UUID:
			service_mask |= BLUETOOTH_HSP_SERVICE;
			break;
		case BLUETOOTH_HF_PROFILE_UUID:
			service_mask |= BLUETOOTH_HSP_SERVICE;
			break;
		case BLUETOOTH_AUDIO_SINK_UUID:
			service_mask |= BLUETOOTH_A2DP_SERVICE;
			break;
		case BLUETOOTH_HID_PROFILE_UUID:
			service_mask |= BLUETOOTH_HID_SERVICE;
			break;
		default:
			break;
		}
	}

	INFO_MSG("service_mask [%x]", service_mask);

	return service_mask;
}

static void __bt_get_name(ndef_record_s *record, char *name, uint32_t length)
{
	net_nfc_carrier_config_s *config;
	uint16_t len = 0;
	uint8_t *buf = NULL;

	net_nfc_util_handover_bt_create_config_from_record(
		&config, record);

	if (net_nfc_util_get_carrier_config_property(config,
		NET_NFC_BT_ATTRIBUTE_NAME,
		&len, &buf) == NET_NFC_OK) {
		len = MIN(len, length - 1);
		memcpy(name, buf, len);
		name[len] = 0;
	} else {
		net_nfc_util_get_carrier_config_property(config,
			NET_NFC_BT_ATTRIBUTE_ADDRESS,
			&len, &buf);

		snprintf(name, length,
			"%02X:%02X:%02X:%02X:%02X:%02X",
			buf[0], buf[1], buf[2],
			buf[3], buf[4], buf[5]);
	}

	_net_nfc_util_free_mem(config);
}

static void _bt_do_pairing_cb(int event,
	bluetooth_event_param_t *param, void *user_data)
{
	net_nfc_handover_bt_process_context_t *context =
		(net_nfc_handover_bt_process_context_t *)user_data;

	LOGD("[%s] START", __func__);

	if (context == NULL)
	{
		DEBUG_SERVER_MSG("user_data is null");
		LOGD("[%s] END", __func__);
		return;
	}

	switch (event)
	{
	case BLUETOOTH_EVENT_ENABLED :
		INFO_MSG("BLUETOOTH_EVENT_ENABLED");
		if (context->step == NET_NFC_LLCP_STEP_02)
		{
			_bt_do_pairing(context);
		}
		else
		{
			DEBUG_ERR_MSG("step is incorrect");
		}
		break;

	case BLUETOOTH_EVENT_DISABLED :
		INFO_MSG("BLUETOOTH_EVENT_DISABLED");
		if (context->step == NET_NFC_LLCP_STEP_RETURN)
		{
			_bt_do_pairing(context);
		}
		else
		{
			DEBUG_ERR_MSG("step is incorrect");
		}
		break;

	case BLUETOOTH_EVENT_BONDING_FINISHED :
		INFO_MSG("BLUETOOTH_EVENT_BONDING_FINISHED");

		if (param->result >= BLUETOOTH_ERROR_NONE) {
			bluetooth_device_info_t *device_info;

			device_info = param->param_data;

			context->service_mask =
				_bt_check_supported_profiles_by_uuid(
					device_info->uuids,
					device_info->service_index);
			context->result = NET_NFC_OK;
		} else {
			char name[512];

			DEBUG_ERR_MSG("bond failed, [%d]", param->result);

			__bt_get_name(context->carrier->carrier_record,
				name, sizeof(name));

			net_nfc_app_util_show_notification(IDS_SIGNAL_3, name);

			context->result = NET_NFC_OPERATION_FAIL;
			context->step = NET_NFC_STATE_ERROR;
		}

		_bt_do_pairing(context);
		break;

	default :
		DEBUG_MSG("unhandled bt event [%d], [%d]", event, param->result);
		break;
	}

	LOGD("[%s] END", __func__);
}

static void _bt_audio_callback(int event, bt_audio_event_param_t *param,
	void *user_data)
{
	net_nfc_handover_bt_process_context_t *context =
		(net_nfc_handover_bt_process_context_t *)user_data;

	switch (event) {
	case BLUETOOTH_EVENT_AG_AUDIO_CONNECTED :
	case BLUETOOTH_EVENT_AG_CONNECTED :
	case BLUETOOTH_EVENT_AV_CONNECTED :
		if (param->result == BLUETOOTH_ERROR_NONE) {
			INFO_MSG("connected device [%s]", (char *)(param->param_data));
			context->result = NET_NFC_OK;
		} else {
			char name[512];

			DEBUG_ERR_MSG("connecting failed, [%d]", param->result);

			__bt_get_name(context->carrier->carrier_record,
				name, sizeof(name));

			net_nfc_app_util_show_notification(IDS_SIGNAL_4, name);

			context->result = NET_NFC_OPERATION_FAIL;
			context->step = NET_NFC_STATE_ERROR;
		}

		bluetooth_audio_deinit();

		_bt_do_pairing(context);
		break;

	case BLUETOOTH_EVENT_AG_AUDIO_DISCONNECTED :
	case BLUETOOTH_EVENT_AG_DISCONNECTED :
	case BLUETOOTH_EVENT_AV_DISCONNECTED :
		if (param->result == BLUETOOTH_ERROR_NONE) {
			INFO_MSG("disconnected device [%s]", (char *)(param->param_data));
			context->result = NET_NFC_OK;
		} else {
			DEBUG_ERR_MSG("disconnecting failed, [%d]", param->result);
			context->result = NET_NFC_OPERATION_FAIL;
			context->step = NET_NFC_STATE_ERROR;
		}

		bluetooth_audio_deinit();

		_bt_do_pairing(context);
		break;

	default :
		DEBUG_ERR_MSG("bt op failed, [%d][%d]", event, param->result);
		break;
	}
}

static void _bt_hid_callback(int event,
	hid_event_param_t *param,
	void *user_data)
{
	net_nfc_handover_bt_process_context_t *context =
		(net_nfc_handover_bt_process_context_t *)user_data;

	switch (event) {
	case BLUETOOTH_HID_CONNECTED :
		if (param->result == BLUETOOTH_ERROR_NONE) {
			INFO_MSG("connected device [%s]", (char *)(param->param_data));

			context->result = NET_NFC_OK;
		} else {
			char name[512];

			DEBUG_ERR_MSG("connecting failed, [%d]", param->result);

			__bt_get_name(context->carrier->carrier_record,
				name, sizeof(name));

			net_nfc_app_util_show_notification(IDS_SIGNAL_4, name);

			context->result = NET_NFC_OPERATION_FAIL;
			context->step = NET_NFC_STATE_ERROR;
		}

		bluetooth_hid_deinit();

		_bt_do_pairing(context);
		break;

	case BLUETOOTH_HID_DISCONNECTED :
		if (param->result == BLUETOOTH_ERROR_NONE) {
			INFO_MSG("disconnected device [%s]", (char *)(param->param_data));

			context->result = NET_NFC_OK;
		} else {
			DEBUG_ERR_MSG("disconnecting failed, [%d]", param->result);

			context->result = NET_NFC_OPERATION_FAIL;
			context->step = NET_NFC_STATE_ERROR;
		}

		bluetooth_hid_deinit();

		_bt_do_pairing(context);
		break;

	default :
		DEBUG_ERR_MSG("bt op failed, [%d][%d]", event, param->result);
		break;
	}
}

static int _bt_do_pairing(net_nfc_handover_bt_process_context_t *context)
{
	int ret;

	if (context->result != NET_NFC_OK && context->result != NET_NFC_BUSY)
	{
		DEBUG_ERR_MSG("context->result is error [%d]", context->result);
	}

	switch (context->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		INFO_MSG("STEP [1]");

		ret = bluetooth_register_callback(
			_bt_do_pairing_cb, context);
		if (ret >= BLUETOOTH_ERROR_NONE)
		{
			/* next step */
			context->step = NET_NFC_LLCP_STEP_02;

			if (bluetooth_check_adapter() !=
				BLUETOOTH_ADAPTER_ENABLED)
			{
				context->result = NET_NFC_OK;

				ret = bluetooth_enable_adapter();
				if (ret != BLUETOOTH_ERROR_NONE)
				{
					DEBUG_ERR_MSG("bluetooth_enable_adapter failed, [%d]", ret);

					context->step = NET_NFC_STATE_ERROR;
					context->result = NET_NFC_OPERATION_FAIL;
				}
			}
			else
			{
				/* do next step */
				INFO_MSG("BT is enabled already, go next step");

				context->already_on = true;
				context->result = NET_NFC_OK;

				g_idle_add((GSourceFunc)_bt_do_pairing, (gpointer)context);
			}
		}
		else
		{
			DEBUG_ERR_MSG("bluetooth_register_callback failed, [%d]", ret);

			/* bluetooth handover is working already. skip new request */
			context->step = NET_NFC_LLCP_STEP_05;
			context->result = NET_NFC_OPERATION_FAIL;

			g_idle_add((GSourceFunc)_bt_do_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			net_nfc_carrier_config_s *config;
			data_s temp = { NULL, 0 };

			INFO_MSG("STEP [2]");

			net_nfc_util_handover_bt_create_config_from_record(
				&config, context->carrier->carrier_record);

			net_nfc_util_get_carrier_config_property(config,
				NET_NFC_BT_ATTRIBUTE_ADDRESS,
				(uint16_t *)&temp.length, &temp.buffer);
			if (temp.length == sizeof(context->addr.addr))
			{
				bluetooth_device_info_t device_info;

				NET_NFC_REVERSE_ORDER_6_BYTES(temp.buffer);

				memcpy(context->addr.addr,
					temp.buffer, temp.length);

				context->result = NET_NFC_OK;

				if (bluetooth_get_bonded_device(&context->addr,
					&device_info) == BLUETOOTH_ERROR_NONE)
				{
					INFO_MSG("already paired with [%02x:%02x:%02x:%02x:%02x:%02x]",
						context->addr.addr[0],
						context->addr.addr[1],
						context->addr.addr[2],
						context->addr.addr[3],
						context->addr.addr[4],
						context->addr.addr[5]);

					context->step = NET_NFC_LLCP_STEP_04;

					context->service_mask =
						_bt_check_supported_profiles_by_uuid(
							device_info.uuids,
							device_info.service_index);
#ifdef DISCONNECT_DEVICE
					gboolean connected = FALSE;

					bluetooth_is_device_connected(&context->addr,
							BLUETOOTH_HSP_SERVICE, &connected);
					if (connected)
						context->step = NET_NFC_LLCP_STEP_06;

					bluetooth_is_device_connected(&context->addr,
							BLUETOOTH_A2DP_SERVICE, &connected);
					if (connected)
						context->step = NET_NFC_LLCP_STEP_06;

					bluetooth_is_device_connected(&context->addr,
							BLUETOOTH_HID_SERVICE, &connected);
					if (connected)
						context->step = NET_NFC_LLCP_STEP_06;

					INFO_MSG("Check connected=[%d] " , connected );
#endif
				}
				else
				{
					bt_oob_data_t oob = { { 0 } , };

					if (_bt_get_oob_data_from_config(
						config, &oob) == NET_NFC_OK)
					{
						/* set oob data */
						bluetooth_oob_add_remote_data(
							&context->addr, &oob);
					}

					/* pair and send response */
					context->step = NET_NFC_LLCP_STEP_03;
				}
			}
			else
			{
				DEBUG_ERR_MSG("bluetooth address is invalid. [%d] bytes", temp.length);

				context->step = NET_NFC_STATE_ERROR;
				context->result = NET_NFC_OPERATION_FAIL;
			}

			net_nfc_util_free_carrier_config(config);

			g_idle_add((GSourceFunc)_bt_do_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_03 :
		INFO_MSG("STEP [3]");

		context->step = NET_NFC_LLCP_STEP_04;

		ret = bluetooth_bond_device(&context->addr);
		if (ret != BLUETOOTH_ERROR_NONE)
		{
			DEBUG_ERR_MSG("bluetooth_bond_device failed, [%d]", ret);

			context->step = NET_NFC_STATE_ERROR;
			context->result = NET_NFC_OPERATION_FAIL;

			g_idle_add((GSourceFunc)_bt_do_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_04 :
		INFO_MSG("STEP [4]");

		context->step = NET_NFC_LLCP_STEP_RETURN;

		if ((context->service_mask & BLUETOOTH_HSP_SERVICE) &&
			(context->service_mask & BLUETOOTH_A2DP_SERVICE)) {
			bluetooth_audio_init(_bt_audio_callback, context);
			bluetooth_audio_connect(&context->addr);
		} else if (context->service_mask & BLUETOOTH_A2DP_SERVICE) {
			bluetooth_audio_init(_bt_audio_callback, context);
			bluetooth_av_connect(&context->addr);
		} else if (context->service_mask & BLUETOOTH_HSP_SERVICE) {
			bluetooth_audio_init(_bt_audio_callback, context);
			bluetooth_ag_connect(&context->addr);
		}else if (context->service_mask & BLUETOOTH_HID_SERVICE) {
			bluetooth_hid_init(_bt_hid_callback, context);
			bluetooth_hid_connect((hid_device_address_t *)&context->addr);
		} else {
			g_idle_add((GSourceFunc)_bt_do_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_05 :
		INFO_MSG("STEP [5]");

		/* bluetooth handover is working already. skip new request */
		context->cb(context->result,
			NET_NFC_CONN_HANDOVER_CARRIER_BT,
			NULL, context->user_param);

		/* release context */
		if (context->carrier != NULL)
		{
			net_nfc_util_free_handover_carrier(context->carrier);
		}

		net_nfc_util_clear_data(&context->data);
		_net_nfc_util_free_mem(context);
		break;
#ifdef DISCONNECT_DEVICE
	case NET_NFC_LLCP_STEP_06 :
		INFO_MSG("STEP [6]");

		context->step = NET_NFC_LLCP_STEP_RETURN;

		if ((context->service_mask & BLUETOOTH_HSP_SERVICE) &&
			(context->service_mask & BLUETOOTH_A2DP_SERVICE)) {
			bluetooth_audio_init(_bt_audio_callback, context);
			bluetooth_audio_disconnect(&context->addr);
		} else if (context->service_mask & BLUETOOTH_A2DP_SERVICE) {
			bluetooth_audio_init(_bt_audio_callback, context);
			bluetooth_av_disconnect(&context->addr);
		} else if (context->service_mask & BLUETOOTH_HSP_SERVICE) {
			bluetooth_audio_init(_bt_audio_callback, context);
			bluetooth_ag_disconnect(&context->addr);
		} else if (context->service_mask & BLUETOOTH_HID_SERVICE) {
			bluetooth_hid_init(_bt_hid_callback, context);
			bluetooth_hid_disconnect((hid_device_address_t *)&context->addr);
		} else {
			g_idle_add((GSourceFunc)_bt_do_pairing,
				(gpointer)context);
		}
		break;
#endif
	case NET_NFC_STATE_ERROR :
		context->step = NET_NFC_LLCP_STEP_RETURN;
		if (context->already_on == false)
		{
			bluetooth_disable_adapter();
		}
		else
		{
			g_idle_add((GSourceFunc)_bt_do_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		{
			data_s temp = { context->addr.addr,
				sizeof(context->addr.addr) };
			data_s *data = NULL;

			INFO_MSG("STEP return");

			/* unregister bluetooth callback */
			bluetooth_unregister_callback();

			if (context->result == NET_NFC_OK)
			{
				data = &temp;
			}

			context->cb(context->result,
				NET_NFC_CONN_HANDOVER_CARRIER_BT,
				data, context->user_param);

			/* release context */
			if (context->carrier != NULL)
			{
				net_nfc_util_free_handover_carrier(
					context->carrier);
			}

			net_nfc_util_clear_data(&context->data);
			_net_nfc_util_free_mem(context);
		}
		break;

	default :
		break;
	}

	return 0;
}

net_nfc_error_e net_nfc_server_handover_bt_do_pairing(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_server_handover_process_carrier_cb cb,
	void *user_param)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_handover_bt_process_context_t *context = NULL;

	INFO_MSG("Call this function for bt pairing.");

	_net_nfc_util_alloc_mem(context, sizeof(*context));
	if (context != NULL) {
		context->cb = cb;
		context->user_param = user_param;
		context->step = NET_NFC_LLCP_STEP_01;

		net_nfc_util_duplicate_handover_carrier(&context->carrier,
			carrier);

		g_idle_add((GSourceFunc)_bt_do_pairing,
			(gpointer)context);
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}
