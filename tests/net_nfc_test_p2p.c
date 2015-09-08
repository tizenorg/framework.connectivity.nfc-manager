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

#include "net_nfc_client_p2p.h"
#include "net_nfc_test_p2p.h"
#include "net_nfc_test_util.h"
#include "net_nfc_target_info.h"
#include "net_nfc_typedef_internal.h"
#include "net_nfc_ndef_message.h"
#include "net_nfc_ndef_record.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_typedef.h"


static net_nfc_target_handle_h global_handle = NULL;

static void run_next_callback(gpointer user_data);

static void p2p_send(net_nfc_error_e result,
			void *user_data);

static void p2p_device_discovered(net_nfc_target_handle_h handle,
				void *user_data);


static void p2p_device_detached(void * user_data);

static void p2p_device_data_received(data_h p2p_data, void *user_data);

static void run_next_callback(gpointer user_data)
{
	if (user_data)
	{
		GCallback callback;

		callback = (GCallback)(user_data);

		callback();
	}
}

static void p2p_send(net_nfc_error_e result,
			void *user_data)
{
	g_print("P2P send  Completed %d\n", result);

	run_next_callback(user_data);
}

static void p2p_device_discovered(net_nfc_target_handle_h handle,
				void *user_data)
{
	g_print("Target is Discovered\n");
	global_handle = handle;

	g_print("Handle is %#x\n", GPOINTER_TO_UINT(global_handle));
	run_next_callback(user_data);
}

static void p2p_device_detached(void * user_data)
{
	g_print("Target is detached\n");

	run_next_callback(user_data);
}

static void p2p_device_data_received(data_h p2p_data, void *user_data)
{
	g_print("P2P data is received\n");

	print_received_data(p2p_data);
	run_next_callback(user_data);
}

void net_nfc_test_p2p_send(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	ndef_message_h msg = NULL;
	ndef_record_h record = NULL;
	data_h rawdata = NULL;

	net_nfc_create_ndef_message(&msg);
	net_nfc_create_uri_type_record(&record, "http://www.samsung.com", NET_NFC_SCHEMA_FULL_URI);
	net_nfc_append_record_to_ndef_message(msg, record);
	net_nfc_create_rawdata_from_ndef_message(msg, &rawdata);

	g_print("Handle is %#x\n", GPOINTER_TO_UINT(global_handle));

	result = net_nfc_client_p2p_send(global_handle,
				rawdata,
				p2p_send,
				user_data);
	net_nfc_free_data(rawdata);

	if (result != NET_NFC_OK) {
		g_print("p2p send failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_p2p_send_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	ndef_message_h msg = NULL;
	ndef_record_h record = NULL;
	data_h rawdata = NULL;

	net_nfc_create_ndef_message(&msg);
	net_nfc_create_uri_type_record(&record, "http://www.samsung.com", NET_NFC_SCHEMA_FULL_URI);
	net_nfc_append_record_to_ndef_message(msg, record);
	net_nfc_create_rawdata_from_ndef_message(msg, &rawdata);

	result = net_nfc_client_p2p_send_sync(global_handle, rawdata);
	net_nfc_free_data(rawdata);

	g_print(" P2P send sync result: %d\n", result);

	run_next_callback(user_data);
}

void net_nfc_test_p2p_set_device_discovered(gpointer data,
				gpointer user_data)
{
	net_nfc_client_p2p_set_device_discovered(p2p_device_discovered, user_data);

	g_print("Device Discovered set\n");
	g_print("Waiting for Device Discovered Signal\n");
}

void net_nfc_test_p2p_set_device_detached(gpointer data,
				gpointer user_data)
{
	net_nfc_client_p2p_set_device_detached(p2p_device_detached,
						user_data);

	run_next_callback(user_data);
}

void net_nfc_test_p2p_set_data_received(gpointer data,
				gpointer user_data)
{
	net_nfc_client_p2p_set_data_received(p2p_device_data_received,
						user_data);

	run_next_callback(user_data);
}

net_nfc_target_handle_h net_nfc_test_device_get_target_handle(void)
{
	return global_handle;
}
