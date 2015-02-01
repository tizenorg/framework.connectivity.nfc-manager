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

#include <glib-object.h>

#include "net_nfc_target_info.h"
#include "net_nfc_data.h"
#include "net_nfc_client_se.h"
#include "net_nfc_test_se.h"
#include "net_nfc_typedef.h"
#include "net_nfc_typedef_internal.h"
#include "net_nfc_test_util.h"

static void run_next_callback(gpointer user_data);

static void send_apdu_cb(net_nfc_error_e result, data_h data, void *user_data);

static void set_secure_element_cb(net_nfc_error_e result, void *user_data);

static void open_secure_element_cb(net_nfc_error_e result,
	net_nfc_target_handle_h handle, void *user_data);

static void close_secure_element_cb(net_nfc_error_e result, void *user_data);

static void get_atr_secure_element_cb(net_nfc_error_e result, data_h data,
	void *user_data);

static void se_set_event_cb(net_nfc_message_e event, void *user_data);

static void se_ese_detection_cb(net_nfc_target_handle_h handle,
				int dev_type, data_h data, void *user_data);

static void se_set_transaction_cb(net_nfc_se_type_e se_type,
				data_h aid,
				data_h param,
				void *user_data);

/*This handle would be intialized by open secure element callback function*/
static net_nfc_target_handle_h global_handle = NULL;

static void run_next_callback(gpointer user_data)
{
	if (user_data)
	{
		GCallback callback;

		callback = (GCallback)(user_data);
		callback();
	}
}

static void send_apdu_cb(net_nfc_error_e result, data_h data, void *user_data)
{
	g_print(" Send apdu data completed \n");
	print_received_data(data);
	run_next_callback(user_data);
}

static void set_secure_element_cb(net_nfc_error_e result, void* user_data)
{
	g_print("Set Secure Element completed : %d\n", result);
	run_next_callback(user_data);
}

static void open_secure_element_cb(net_nfc_error_e result,
	net_nfc_target_handle_h handle, void* user_data)
{
	g_print("Open secure element completed\n");
	// assigning received handle
	global_handle = handle;
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));
	run_next_callback(user_data);
}

static void close_secure_element_cb(net_nfc_error_e result, void* user_data)
{
	g_print("close secure element completed %d\n", result);
	run_next_callback(user_data);
}

static void get_atr_secure_element_cb(net_nfc_error_e result, data_h data,
	void* user_data)
{
	g_print("get atr completed\n");
	print_received_data(data);
	run_next_callback(user_data);
}

static void se_set_event_cb(net_nfc_message_e event, void* user_data)
{
	g_print("Event callback set successfully\n");
	g_print(" Event received %d", event);
}

static void se_ese_detection_cb(net_nfc_target_handle_h handle,
				int dev_type,
				data_h data,
				void *user_data)
{
	g_print("Set ese detection callback successfully\n");
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));
	g_print(" dev type  %d\n", dev_type);
	print_received_data(data);
}

static void se_set_transaction_cb(net_nfc_se_type_e se_type,
				data_h aid,
				data_h param,
				void *user_data)
{
	g_print("Set transaction callback successfully\n");
	g_print("*****displaying Aid data****\n");
	print_received_data(aid);
	g_print("*****displaying param data ****\n");
	print_received_data(param);
	run_next_callback(user_data);
}

void net_nfc_test_se_send_apdu(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	data_h apdu_data = NULL;
	uint8_t apdu_cmd[4] = {0x00, 0xA4, 0x00, 0x0C};

	net_nfc_create_data(&apdu_data, apdu_cmd, 4);

	result = net_nfc_client_se_send_apdu(global_handle,
				apdu_data,
				send_apdu_cb,
				user_data);

	net_nfc_free_data(apdu_data);

	if (result != NET_NFC_OK) {
		g_print("send apdu data failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_se_send_apdu_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	data_h apdu_data = NULL;
	uint8_t apdu_cmd[4] = {0x00, 0xA4, 0x00, 0x0C};
	data_h response = NULL;

	net_nfc_create_data(&apdu_data, apdu_cmd, 4);
	result = net_nfc_client_se_send_apdu_sync(global_handle,
				apdu_data,
				&response);

	g_print("Send apdu data sync completed %d\n", result);
	print_received_data(response);
	net_nfc_util_free_data(response);
	run_next_callback(user_data);
}

void net_nfc_test_se_set_secure_element_type(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_se_type_e se_type = NET_NFC_SE_TYPE_UICC;

	result = net_nfc_client_se_set_secure_element_type(
				se_type,
				set_secure_element_cb,
				user_data);
	if (result != NET_NFC_OK) {
		g_print("set secure element type failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_se_set_secure_element_type_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_se_type_e se_type = NET_NFC_SE_TYPE_UICC;

	result = net_nfc_client_se_set_secure_element_type_sync(se_type);

	g_print("set secure element type completed %d\n", result);
	run_next_callback(user_data);
}

void net_nfc_test_se_open_internal_secure_element(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_se_type_e se_type = NET_NFC_SE_TYPE_UICC;

	result = net_nfc_client_se_open_internal_secure_element(
				se_type,
				open_secure_element_cb,
				user_data);
	if (result != NET_NFC_OK) {
		g_print("open secure element failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_se_open_internal_secure_element_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_se_type_e se_type = NET_NFC_SE_TYPE_UICC;

	result = net_nfc_client_se_open_internal_secure_element_sync(
				se_type,
				&global_handle);

	g_print("open secure element completed %d\n", result);
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(global_handle));
	run_next_callback(user_data);
}

void net_nfc_test_se_close_internal_secure_element(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;

	result = net_nfc_client_se_close_internal_secure_element(
				global_handle,
				close_secure_element_cb,
				user_data);
	if (result != NET_NFC_OK) {
		g_print("close secure element failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_se_close_internal_secure_element_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;

	result = net_nfc_client_se_close_internal_secure_element_sync(global_handle);

	g_print("close secure element completed %d\n", result);
	run_next_callback(user_data);
}

void net_nfc_test_se_get_atr(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;

	result = net_nfc_client_se_get_atr(
				global_handle,
				get_atr_secure_element_cb,
				user_data);
	if (result != NET_NFC_OK) {
		g_print("close secure element failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_se_get_atr_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	data_h attr_data = NULL;

	result = net_nfc_client_se_get_atr_sync(
				global_handle,
				&attr_data);

	g_print("get atr data sync completed %d\n", result);
	print_received_data(attr_data);
	net_nfc_util_free_data(attr_data);
	run_next_callback(user_data);
}

void net_nfc_test_se_set_event_cb(gpointer data,
				gpointer user_data)
{
	net_nfc_client_se_set_event_cb(se_set_event_cb,
				user_data);

	g_print("set event callback successfully\n");
	run_next_callback(user_data);
}

void net_nfc_test_se_unset_event_cb(gpointer data,
				gpointer user_data)
{
	net_nfc_client_se_unset_event_cb();

	g_print("unset event callback successfully\n");
	run_next_callback(user_data);
}

void net_nfc_test_se_set_ese_detection_cb(gpointer data,
				gpointer user_data)
{
	net_nfc_client_se_set_ese_detection_cb(se_ese_detection_cb,
				user_data);

	g_print("set ese detection callback successfully\n");
	run_next_callback(user_data);
}

void net_nfc_test_se_unset_ese_detection_cb(gpointer data,
				gpointer user_data)
{
	net_nfc_client_se_unset_ese_detection_cb();

	g_print("unset ese detection callback successfully\n");
	run_next_callback(user_data);
}

void net_nfc_test_se_set_transaction_event_cb(gpointer data,
				gpointer user_data)
{
	net_nfc_client_se_set_transaction_event_cb(NET_NFC_SE_TYPE_UICC,
		se_set_transaction_cb, user_data);

	g_print("set transaction event callback successfully\n");
	run_next_callback(user_data);
}

void net_nfc_test_se_unset_transaction_event_cb(gpointer data,
				gpointer user_data)
{
	net_nfc_client_se_unset_transaction_event_cb(NET_NFC_SE_TYPE_UICC);

	g_print("unset transaction event callback successfully\n");
	run_next_callback(user_data);
}
