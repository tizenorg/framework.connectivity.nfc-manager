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

#include <bluetooth.h>
#include <bluetooth_internal.h>

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
	char remote_address[20];
	bt_service_class_t service_mask;
	void *user_param;
}
net_nfc_handover_bt_process_context_t;

typedef struct {
	unsigned char hash[16];
	unsigned char randomizer[16];
	unsigned int hash_len;
	unsigned int randomizer_len;
} net_nfc_handover_bt_oob_data_t;

static uint8_t __bt_cod[] = { 0x0c, 0x02, 0x5a }; /* 0x5a020c */
#ifndef USE_SYSTEM_INFO
static const char *manufacturer = "Samsung Tizen";
#endif

static int _bt_get_carrier_record(net_nfc_handover_bt_get_context_t *context);
static int _bt_prepare_pairing(net_nfc_handover_bt_process_context_t *context);
static int _bt_do_pairing(net_nfc_handover_bt_process_context_t *context);


static net_nfc_error_e _bt_get_oob_data_from_config(
	net_nfc_carrier_config_s *config,
	net_nfc_handover_bt_oob_data_t *oob)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	data_s hash = { NULL, 0 };
	data_s randomizer = { NULL, 0 };

	LOGD("[%s:%d] START", __func__, __LINE__);

	if (config == NULL || oob == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	memset(oob, 0, sizeof(net_nfc_handover_bt_oob_data_t));

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

static void _bt_carrier_record_cb(int result, bt_adapter_state_e adapter_state,
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

	switch (adapter_state)
	{
	case BT_ADAPTER_ENABLED :
		INFO_MSG("BT_ADAPTER_ENABLED");
		if (context->step == NET_NFC_LLCP_STEP_02)
		{
			_bt_get_carrier_record(context);
		}
		else
		{
			DEBUG_ERR_MSG("step is incorrect");
		}
		break;

	case BT_ADAPTER_DISABLED :
		INFO_MSG("BT_ADAPTER_DISABLED");
		break;

	default :
		DEBUG_MSG("unhandled bt event [%d], [%d]", adapter_state, result);
		break;
	}

	LOGD("[%s] END", __func__);
}

static void _append_oob_data(net_nfc_carrier_config_s *config)
{
	net_nfc_error_e result;
	unsigned char *hash;
	unsigned char *randomizer;
	int hash_len;
	int randomizer_len;

	/* get oob data, optional!!! */
	result = bt_adapter_get_local_oob_data(&hash, &randomizer, &hash_len, &randomizer_len);
	if (result == BT_ERROR_NONE)
	{
		if (hash_len == 16 && randomizer_len == 16)
		{
			INFO_MSG("oob.hash_len [%d], oob.randomizer_len [%d]", hash_len, randomizer_len);

			NET_NFC_REVERSE_ORDER_16_BYTES(hash);

			result = net_nfc_util_add_carrier_config_property(
				config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_C,
				hash_len, hash);
			if (result != NET_NFC_OK)
			{
				DEBUG_ERR_MSG("net_nfc_util_add_carrier_config_property failed [%d]", result);
			}

			NET_NFC_REVERSE_ORDER_16_BYTES(randomizer);

			result = net_nfc_util_add_carrier_config_property(
				config, NET_NFC_BT_ATTRIBUTE_OOB_HASH_R,
				randomizer_len, randomizer);
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
		DEBUG_ERR_MSG("bt oob_read_local_data failed, skip.... [%d]", result);
	}
}

static net_nfc_error_e _bt_create_config_record(ndef_record_s **record)
{
	char* bt_addr = NULL;
	char *bt_name = NULL;
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

	result = bt_adapter_get_address(&bt_addr);
	if (result != BT_ERROR_NONE)
	{
		DEBUG_ERR_MSG("bt_adapter_get_address failed [%d]", result);
		result = NET_NFC_OPERATION_FAIL;
		goto END;
	}

	NET_NFC_REVERSE_ORDER_6_BYTES(bt_addr);

	result = net_nfc_util_add_carrier_config_property(
		config, NET_NFC_BT_ATTRIBUTE_ADDRESS,
		strlen(bt_addr), bt_addr);
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
	result = bt_adapter_get_name(&bt_name);
	if (result != BT_ERROR_NONE)
	{
		DEBUG_ERR_MSG("bt_adapter_get_name failed [%d]", result);
		result = NET_NFC_OPERATION_FAIL;
		goto END;
	}

	if(bt_name == NULL)
	{
		result = NET_NFC_OPERATION_FAIL;
		goto END;
	}

	if (strlen(bt_name) > 0) {
		result = net_nfc_util_add_carrier_config_property(
			config, NET_NFC_BT_ATTRIBUTE_NAME,
			strlen(bt_name), (uint8_t *)bt_name);
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
	if (bt_name != NULL)
		free(bt_name);

	if (bt_addr != NULL)
		free(bt_addr);

	if (config != NULL) {
		net_nfc_util_free_carrier_config(config);
	}

	return result;
}

static int _bt_get_carrier_record(net_nfc_handover_bt_get_context_t *context)
{
	int ret;
	LOGD("[%s:%d] START", __func__, __LINE__);

	if (context->result != NET_NFC_OK && context->result != NET_NFC_BUSY)
	{
		DEBUG_ERR_MSG("context->result is error [%d]", context->result);

		context->step = NET_NFC_LLCP_STEP_RETURN;
	}

	switch (context->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		DEBUG_MSG("STEP [1]");

		ret = bt_initialize();
		ret = bt_adapter_set_state_changed_cb(_bt_carrier_record_cb, context);

		if (ret >= BT_ERROR_NONE)
		{
			bt_adapter_state_e adapter_state;
			context->step = NET_NFC_LLCP_STEP_02;
			context->result = NET_NFC_OK;

			ret = bt_adapter_get_state(&adapter_state);

			if (ret == BT_ADAPTER_DISABLED)
			{
				bt_adapter_enable();
			}
			else
			{
				DEBUG_MSG("BT is enabled already");
				context->already_on = true;

				/* do next step */
				g_idle_add((GSourceFunc)_bt_get_carrier_record, (gpointer)context);
			}
		}
		else
		{
			DEBUG_ERR_MSG("bt register_callback failed");

			context->step = NET_NFC_LLCP_STEP_RETURN;
			context->result = NET_NFC_OPERATION_FAIL;

			g_idle_add((GSourceFunc)_bt_get_carrier_record, (gpointer)context);
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

			bt_deinitialize();

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

static void _bt_prepare_pairing_cb(int result, bt_adapter_state_e adapter_state,
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

	switch (adapter_state)
	{
	case BT_ADAPTER_ENABLED :
		INFO_MSG("BT_ADAPTER_ENABLED");
		if (context->step == NET_NFC_LLCP_STEP_02)
		{
			_bt_prepare_pairing(context);
		}
		else
		{
			DEBUG_ERR_MSG("step is incorrect");
		}
		break;

	case BT_ADAPTER_DISABLED:
		INFO_MSG("BT_ADAPTER_DISABLED");
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
				"[0x%04x]", adapter_state, result);
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
		DEBUG_ERR_MSG("context->result is error [%d]", context->result);
		context->step = NET_NFC_LLCP_STEP_RETURN;
	}

	switch (context->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		INFO_MSG("STEP [1]");

		ret = bt_initialize();
		ret = bt_adapter_set_state_changed_cb(_bt_prepare_pairing_cb, context);

		if (ret >= BT_ERROR_NONE)
		{
			bt_adapter_state_e adapter_state;
			/* next step */
			context->step = NET_NFC_LLCP_STEP_02;

			ret = bt_adapter_get_state(&adapter_state);

			if (ret != BT_ADAPTER_DISABLED)
			{
				context->result = NET_NFC_OK;

				ret = bt_adapter_enable();
				if (ret != BT_ERROR_NONE)
				{
					DEBUG_ERR_MSG("bt_adapter_enable failed, [%d]", ret);

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
			DEBUG_ERR_MSG("bt_adapter_set_state_changed_cb failed, [%d]", ret);
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
				bt_device_info_s *device_info;

				NET_NFC_REVERSE_ORDER_6_BYTES(temp.buffer);
				sprintf(context->remote_address, "%02X:%02X:%02X:%02X:%02X:%02X",
								temp.buffer[0],
								temp.buffer[1],
								temp.buffer[2],
								temp.buffer[3],
								temp.buffer[4],
								temp.buffer[5]);

				if (bt_adapter_get_bonded_device_info(context->remote_address, &device_info) == BT_ERROR_NONE)
				{
					INFO_MSG("already paired with [%s]", context->remote_address);

					/* return */
					context->step = NET_NFC_LLCP_STEP_RETURN;
					context->result = NET_NFC_OK;
				}
				else
				{
					net_nfc_handover_bt_oob_data_t oob = { { 0 } , };

					if (_bt_get_oob_data_from_config(config, &oob) == NET_NFC_OK)
					{
						/* set oob data */
						bt_adapter_set_remote_oob_data(context->remote_address,
							oob.hash, oob.randomizer, oob.hash_len, oob.randomizer_len);
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
			bt_adapter_disable();
		}
		else
		{
			g_idle_add((GSourceFunc)_bt_prepare_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		{
			data_s temp = { context->remote_address, sizeof(context->remote_address) };
			data_s *data = NULL;

			INFO_MSG("STEP return");

			bt_deinitialize();

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

static void _bt_audio_connection_state_changed_cb(int result, bool connected,
	const char *remote_address, bt_audio_profile_type_e type, void *user_data)
{
	net_nfc_handover_bt_process_context_t *context =
			(net_nfc_handover_bt_process_context_t *)user_data;

	switch(type) {
	case BT_AUDIO_PROFILE_TYPE_AG :
	case BT_AUDIO_PROFILE_TYPE_HSP_HFP :
	case BT_AUDIO_PROFILE_TYPE_A2DP :
		if(connected == true)
		{
			if (result == BT_ERROR_NONE) {
				INFO_MSG("connected device [%s]", context->remote_address);
				context->result = NET_NFC_OK;
			} else {
				char name[512];

				DEBUG_ERR_MSG("connecting failed, [%d]", result);

				__bt_get_name(context->carrier->carrier_record, name, sizeof(name));

				net_nfc_app_util_show_notification(IDS_SIGNAL_4, name);

				context->result = NET_NFC_OPERATION_FAIL;
				context->step = NET_NFC_STATE_ERROR;
			}
		}
		else
		{
			if (result == BT_ERROR_NONE) {
				INFO_MSG("disconnected device [%s]", context->remote_address);
				context->result = NET_NFC_OK;
			} else {
				DEBUG_ERR_MSG("disconnecting failed, [%d]", result);
				context->result = NET_NFC_OPERATION_FAIL;
				context->step = NET_NFC_STATE_ERROR;
			}
		}

		bt_audio_deinitialize();
		_bt_do_pairing(context);
		break;
	default :
		DEBUG_ERR_MSG("bt op failed, [%d][%d]", type, result);
		break;
	}
}

void _bt_hid_host_connection_state_changed_cb(int result, bool connected,
	const char *remote_address, void *user_data)
{
	net_nfc_handover_bt_process_context_t *context =
		(net_nfc_handover_bt_process_context_t *)user_data;

	if(connected == true)
	{
		if (result == BT_ERROR_NONE) {
			INFO_MSG("connected device [%s]", context->remote_address);

			context->result = NET_NFC_OK;
		} else {
			char name[512];

			DEBUG_ERR_MSG("connecting failed, [%d]", result);

			__bt_get_name(context->carrier->carrier_record, name, sizeof(name));

			net_nfc_app_util_show_notification(IDS_SIGNAL_4, name);

			context->result = NET_NFC_OPERATION_FAIL;
			context->step = NET_NFC_STATE_ERROR;
		}
	}
	else
	{
		if (result == BT_ERROR_NONE) {
			INFO_MSG("disconnected device [%s]", context->remote_address);

			context->result = NET_NFC_OK;
		} else {
			DEBUG_ERR_MSG("disconnecting failed, [%d]", result);

			context->result = NET_NFC_OPERATION_FAIL;
			context->step = NET_NFC_STATE_ERROR;
		}
	}

	bt_hid_host_deinitialize();

	_bt_do_pairing(context);
}

void _bt_state_changed_cb(int result, bt_adapter_state_e adapter_state,
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

	switch (adapter_state)
	{
	case BT_ADAPTER_ENABLED :
		INFO_MSG("BT_ADAPTER_ENABLED");
		if (context->step == NET_NFC_LLCP_STEP_02)
		{
			_bt_do_pairing(context);
		}
		else
		{
			DEBUG_ERR_MSG("step is incorrect");
		}
		break;

	case BT_ADAPTER_DISABLED :
		INFO_MSG("BT_ADAPTER_DISABLED");
		if (context->step == NET_NFC_LLCP_STEP_RETURN)
		{
			_bt_do_pairing(context);
		}
		else
		{
			DEBUG_ERR_MSG("step is incorrect");
		}
		break;
	default :
		DEBUG_MSG("unhandled bt event [%d], [%d]", adapter_state, result);
		break;
	}
}

void _bt_bond_created_cb(int result, bt_device_info_s *device_info,
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

	if (result >= BT_ERROR_NONE) {
		bt_device_get_service_mask_from_uuid_list(device_info->service_uuid,
			device_info->service_count, &(context->service_mask));
		context->result = NET_NFC_OK;
	} else {
		char name[512];

		DEBUG_ERR_MSG("bond failed, [%d]", result);

 		if(result != BT_ERROR_RESOURCE_BUSY){
			__bt_get_name(context->carrier->carrier_record, name, sizeof(name));

			net_nfc_app_util_show_notification(IDS_SIGNAL_3, name);
		}

		context->result = NET_NFC_OPERATION_FAIL;
		context->step = NET_NFC_STATE_ERROR;
	}

	_bt_do_pairing(context);

	LOGD("[%s] END", __func__);
}

static int _bt_do_pairing(net_nfc_handover_bt_process_context_t *context)
{
	int ret;
	bt_adapter_state_e *adapter_state;

	if (context->result != NET_NFC_OK && context->result != NET_NFC_BUSY)
	{
		DEBUG_ERR_MSG("context->result is error [%d]", context->result);
	}

	switch (context->step)
	{
	case NET_NFC_LLCP_STEP_01 :
		INFO_MSG("STEP [1]");

		ret = bt_initialize();
		ret = bt_adapter_set_state_changed_cb(_bt_state_changed_cb, context);
		ret = bt_device_set_bond_created_cb(_bt_bond_created_cb, context);

		if (ret >= BT_ERROR_NONE)
		{
			/* next step */
			context->step = NET_NFC_LLCP_STEP_02;

			ret = bt_adapter_get_state(&adapter_state);

			if (adapter_state != BT_ADAPTER_ENABLED)
			{
				context->result = NET_NFC_OK;

				ret = bt_adapter_enable();
				if (ret != BT_ERROR_NONE)
				{
					DEBUG_ERR_MSG("bt adapter enable failed, [%d]", ret);

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
			DEBUG_ERR_MSG("bt set register_callback failed, [%d]", ret);

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
			if (temp.length == 6)
			{
				bt_device_info_s *device_info;

				NET_NFC_REVERSE_ORDER_6_BYTES(temp.buffer);
				sprintf(context->remote_address, "%02X:%02X:%02X:%02X:%02X:%02X",
								temp.buffer[0],
								temp.buffer[1],
								temp.buffer[2],
								temp.buffer[3],
								temp.buffer[4],
								temp.buffer[5]);

				context->result = NET_NFC_OK;

				if (bt_adapter_get_bonded_device_info(context->remote_address, &device_info) == BT_ERROR_NONE)
				{
					INFO_MSG("already paired with [%s]", context->remote_address);

					context->step = NET_NFC_LLCP_STEP_04;

					ret = bt_device_get_service_mask_from_uuid_list(device_info->service_uuid,
						device_info->service_count, &(context->service_mask));
#ifdef DISCONNECT_DEVICE
					gboolean connected = FALSE;
					bt_device_is_profile_connected(context->remote_address, BT_PROFILE_HSP, &connected);
					if (connected)
						context->step = NET_NFC_LLCP_STEP_06;

					bt_device_is_profile_connected(context->remote_address, BT_PROFILE_A2DP, &connected);
					if (connected)
						context->step = NET_NFC_LLCP_STEP_06;

					bt_device_is_profile_connected(context->remote_address, BT_PROFILE_HID, &connected);
					if (connected)
						context->step = NET_NFC_LLCP_STEP_06;

					INFO_MSG("Check connected=[%d] " , connected );
#endif
				}
				else
				{
					net_nfc_handover_bt_oob_data_t oob = { { 0 } , };

					if (_bt_get_oob_data_from_config(config, &oob) == NET_NFC_OK)
					{
						/* set oob data */
						bt_adapter_set_remote_oob_data(context->remote_address,
							oob.hash, oob.randomizer, oob.hash_len, oob.randomizer_len);
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

			g_idle_add((GSourceFunc)_bt_do_pairing, (gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_03 :
		INFO_MSG("STEP [3]");
		context->step = NET_NFC_LLCP_STEP_04;

		DEBUG_ERR_MSG("bt_device_create_bond : [%s]", context->remote_address);

		ret = bt_device_create_bond(context->remote_address);
		if (ret != BT_ERROR_NONE && ret != BT_ERROR_RESOURCE_BUSY)
		{
			DEBUG_ERR_MSG("bt_device_create_bond failed, [%d]", ret);

			context->step = NET_NFC_STATE_ERROR;
			context->result = NET_NFC_OPERATION_FAIL;

			g_idle_add((GSourceFunc)_bt_do_pairing,
				(gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_04 :
		INFO_MSG("STEP [4]");

		context->step = NET_NFC_LLCP_STEP_RETURN;

		if ((context->service_mask & BT_SC_HSP_SERVICE_MASK) &&
			(context->service_mask & BT_SC_A2DP_SERVICE_MASK))
		{

			bt_audio_initialize();
			bt_audio_set_connection_state_changed_cb(_bt_audio_connection_state_changed_cb, context);
			bt_audio_connect(context->remote_address, BT_AUDIO_PROFILE_TYPE_ALL);

		} else if (context->service_mask & BT_SC_A2DP_SERVICE_MASK) {

			bt_audio_initialize();
			bt_audio_set_connection_state_changed_cb(_bt_audio_connection_state_changed_cb, context);
			bt_audio_connect(context->remote_address, BT_AUDIO_PROFILE_TYPE_A2DP);

		} else if (context->service_mask & BT_SC_HSP_SERVICE_MASK) {

			bt_audio_initialize();
			bt_audio_set_connection_state_changed_cb(_bt_audio_connection_state_changed_cb, context);
			bt_audio_connect(context->remote_address, BT_AUDIO_PROFILE_TYPE_HSP_HFP);

		} else if (context->service_mask & BT_SC_HID_SERVICE_MASK) {
			bt_hid_host_initialize(_bt_hid_host_connection_state_changed_cb, context);
			bt_hid_host_connect(context->remote_address);

		} else {
			g_idle_add((GSourceFunc)_bt_do_pairing, (gpointer)context);
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


		if ((context->service_mask & BT_SC_HSP_SERVICE_MASK) &&
			(context->service_mask & BT_SC_A2DP_SERVICE_MASK))
		{

			bt_audio_initialize();
			bt_audio_set_connection_state_changed_cb(_bt_audio_connection_state_changed_cb, context);
			bt_audio_disconnect(context->remote_address, BT_AUDIO_PROFILE_TYPE_ALL);

		} else if (context->service_mask & BT_SC_A2DP_SERVICE_MASK) {

			bt_audio_initialize();
			bt_audio_set_connection_state_changed_cb(_bt_audio_connection_state_changed_cb, context);
			bt_audio_disconnect(context->remote_address, BT_AUDIO_PROFILE_TYPE_A2DP);

		} else if (context->service_mask & BT_SC_HSP_SERVICE_MASK) {

			bt_audio_initialize();
			bt_audio_set_connection_state_changed_cb(_bt_audio_connection_state_changed_cb, context);
			bt_audio_disconnect(context->remote_address, BT_AUDIO_PROFILE_TYPE_HSP_HFP);

		} else if (context->service_mask & BT_SC_HID_SERVICE_MASK) {
			bt_hid_host_initialize(_bt_hid_host_connection_state_changed_cb, context);
			bt_hid_host_disconnect(context->remote_address);

		} else {
			g_idle_add((GSourceFunc)_bt_do_pairing, (gpointer)context);
		}
		break;
#endif
	case NET_NFC_STATE_ERROR :
		context->step = NET_NFC_LLCP_STEP_RETURN;
		if (context->already_on == false)
		{
			bt_adapter_disable();
		}
		else
		{
			g_idle_add((GSourceFunc)_bt_do_pairing, (gpointer)context);
		}
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		{
			data_s temp = { context->remote_address, sizeof(context->remote_address) };
			data_s *data = NULL;

			INFO_MSG("STEP return");

			bt_deinitialize();

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

		net_nfc_util_duplicate_handover_carrier(&context->carrier, carrier);
		g_idle_add((GSourceFunc)_bt_do_pairing, (gpointer)context);

	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}
