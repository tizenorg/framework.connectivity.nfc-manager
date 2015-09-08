/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		 http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <glib-object.h>
#include"net_nfc_test_snep.h"
#include"net_nfc_typedef.h"
#include"net_nfc_target_info.h"
#include"net_nfc_client_snep.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_ndef_message.h"
#include "net_nfc_client_tag.h"
#include "net_nfc_ndef_record.h"

static net_nfc_target_info_h target_info = NULL;
static net_nfc_snep_handle_h snep_handle = NULL;

static void run_next_callback(gpointer user_data);

static void snep_tag_discovered_cb(net_nfc_target_info_h info,
			void *user_data);

static void snep_tag_detached_cb(void *user_data);

static void snep_start_server_cb(net_nfc_snep_handle_h target,
			net_nfc_snep_type_t event,
			net_nfc_error_e result,
			ndef_message_h msg,
			void *user_data);

static void snep_start_client_cb(net_nfc_snep_handle_h target,
			net_nfc_snep_type_t event,
			net_nfc_error_e result,
			ndef_message_h msg,
			void *user_data);

static void snep_send_request_cb(net_nfc_snep_handle_h target,
			net_nfc_snep_type_t event,
			net_nfc_error_e result,
			ndef_message_h msg,
			void *user_data);


static void snep_register_server_cb(net_nfc_snep_handle_h target,
				net_nfc_snep_type_t event,
				net_nfc_error_e result,
				ndef_message_h msg,
				void *user_data);

/******************************Callbacks*********************************************/


static void run_next_callback(gpointer user_data)
{
	if (user_data)
	{
		GCallback callback;

		callback = (GCallback)(user_data);
		callback();
	}
}

static void snep_tag_detached_cb(void *user_data)
{
	g_print("TagDetached\n");
}

static void snep_tag_discovered_cb(net_nfc_target_info_h info,
			void *user_data)
{
	g_print("TagDiscovered\n");

	net_nfc_duplicate_target_info(info, &target_info);
	run_next_callback(user_data);
}

static void snep_start_server_cb(net_nfc_snep_handle_h target,
			net_nfc_snep_type_t event,
			net_nfc_error_e result,
			ndef_message_h msg,
			void *user_data)
{

	snep_handle = target;

	g_print("snep_start_server_cb	Completed %d\n", event);
	g_print("snep_start_server_cb	Completed %d\n", result);

	net_nfc_util_print_ndef_message (msg);

	run_next_callback(user_data);

}

static void snep_start_client_cb(net_nfc_snep_handle_h target,
			net_nfc_snep_type_t event,
			net_nfc_error_e result,
			ndef_message_h msg,
			void *user_data)
{

	g_print("snep_start_client_cb Completed %d\n", event);
	g_print("snep_send_request_cb Completed %d\n", result);

	run_next_callback(user_data);
}


static void snep_send_request_cb(net_nfc_snep_handle_h target,
			net_nfc_snep_type_t event,
			net_nfc_error_e result,
			ndef_message_h msg,
			void *user_data)
{

	g_print("snep_send_request_cb Completed %d\n", event);
	g_print("snep_start_server_cb Completed %d\n", result);

	net_nfc_util_print_ndef_message (msg);

	run_next_callback(user_data);
}


static void snep_register_server_cb(net_nfc_snep_handle_h target,
				net_nfc_snep_type_t event,
				net_nfc_error_e result,
				ndef_message_h msg,
				void *user_data)
	{

		g_print("snep_register_server_cb Completed %d\n", event);
		g_print("snep_register_server_cb Completed %d\n", result);

		net_nfc_util_print_ndef_message (msg);

		run_next_callback(user_data);
	}

/*
static void snep_unregister_server_cb(net_nfc_snep_handle_h target,
				net_nfc_snep_type_t event,
				net_nfc_error_e result,
				ndef_message_h msg,
				void *user_data)
	{

		g_print("snep_register_server_cb Completed %d\n", event);
		g_print("snep_register_server_cb Completed %d\n", result);

		net_nfc_util_print_ndef_message (msg);

		run_next_callback(user_data);
	}
*/

/******************************API Calls*********************************************/

void net_nfc_test_snep_set_tag_discovered(gpointer data,
					gpointer user_data)
{
	g_print("Waiting for TagDiscovered Singal\n");

	net_nfc_client_tag_unset_tag_detached();
	net_nfc_client_tag_set_tag_detached(snep_tag_detached_cb, NULL);

	net_nfc_client_tag_unset_tag_discovered();
	net_nfc_client_tag_set_tag_discovered(snep_tag_discovered_cb, user_data);
}


void net_nfc_test_snep_start_server(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;

	result = net_nfc_client_snep_start_server(target_info->handle,
					"urn:nfc:xsn:samsung.com:testllcp",
					16,
					snep_start_server_cb,
					user_data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_start_server failed: %d\n", result);
		return;
	}

}


void net_nfc_test_snep_start_server_sync(gpointer data,
			gpointer user_data)
{
	/*

	net_nfc_error_e result;
	guint out_result;
	ndef_message_h msg=NULL;

	result = net_nfc_client_snep_start_server_sync(target_info->handle,
					"urn:nfc:xsn:samsung.com:testllcp",
					16,
					&out_result,
					msg);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_start_server failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	net_nfc_util_print_ndef_message (msg);
	run_next_callback(user_data);
*/

}


void net_nfc_test_snep_start_client(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result;

	result = net_nfc_client_snep_start_client(target_info->handle,
					"urn:nfc:xsn:samsung.com:testllcp",
					16,
					snep_start_client_cb,
					user_data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_start_client failed: %d\n", result);
		return;
	}
}


void net_nfc_test_snep_start_client_sync(gpointer data,
			gpointer user_data)
{
	/*

	net_nfc_error_e result;
	guint out_result;

	result = net_nfc_client_snep_start_client_sync(target_info->handle,
					"urn:nfc:xsn:samsung.com:testllcp",
					16,
					&out_result);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_start_client_sync failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_snep_start_client_sync out_result: %d\n", out_result);
	run_next_callback(user_data);
*/

}

void net_nfc_test_snep_send_client_request(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result= NET_NFC_OK;
	net_nfc_error_e error = NET_NFC_OK;
	ndef_message_h msg = NULL;
	ndef_record_h record = NULL;

	if( (error = net_nfc_create_uri_type_record(&record,
							"http://www.naver.com",
							NET_NFC_SCHEMA_FULL_URI)) == NET_NFC_OK)
		{
			if( (error = net_nfc_create_ndef_message(&msg)) == NET_NFC_OK)
			{
				if( (error = net_nfc_append_record_to_ndef_message(
							msg,
							record)) == NET_NFC_OK)
					{
						result = net_nfc_client_snep_send_client_request(
											target_info->handle,
											NET_NFC_SNEP_GET,
											msg,
											snep_send_request_cb,
											user_data);
					}
				}
		}

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_send_client_request failed: %d\n", result);
		return;
	}

}


void net_nfc_test_snep_send_client_request_sync(gpointer data,
			gpointer user_data)
{
	/*

	net_nfc_error_e result= NET_NFC_OK;
	net_nfc_error_e error = NET_NFC_OK;
	ndef_message_h msg = NULL;
	ndef_record_h record = NULL;
	ndef_message_h out_msg = NULL;
	guint out_result;

	if( (error = net_nfc_create_uri_type_record(&record,
							"http://www.naver.com",
							NET_NFC_SCHEMA_FULL_URI)) == NET_NFC_OK)
		{
			if( (error = net_nfc_create_ndef_message(&msg)) == NET_NFC_OK)
			{
				if( (error = net_nfc_append_record_to_ndef_message(
							msg,
							record)) == NET_NFC_OK)
					{
						result = net_nfc_client_snep_send_client_request_sync(
											target_info->handle,
											NET_NFC_SNEP_GET,
											msg,
											&out_result,
											out_msg);
					}
				}
		}

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_send_client_request_sync failed: %d\n", result);
		run_next_callback(user_data);
		return;
	}

	g_print(" net_nfc_test_snep_send_client_request_sync out_result: %d\n", out_result);

	net_nfc_util_print_ndef_message (msg);
	run_next_callback(user_data);
*/

}


void net_nfc_test_snep_register_server(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result= NET_NFC_OK;

	result = net_nfc_client_snep_register_server(
					"urn:nfc:xsn:samsung.com:testllcp",
					16,
					snep_register_server_cb,
					user_data);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_register_server failed: %d\n", result);
		return;
	}
}

void net_nfc_test_snep_unregister_server(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result= NET_NFC_OK;

	result = net_nfc_client_snep_unregister_server(
					"urn:nfc:xsn:samsung.com:testllcp",
					16);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_register_server failed: %d\n", result);
		return;
	}
}


void net_nfc_test_snep_stop_service(gpointer data,
			gpointer user_data)
{
/*
	net_nfc_error_e result= NET_NFC_OK;

	result = net_nfc_client_snep_register_server(
					"urn:nfc:xsn:samsung.com:testllcp",
					16);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_register_server failed: %d\n", result);
		return;
	}
*/
}


void net_nfc_test_snep_stop_service_sync(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e result= NET_NFC_OK;

	result = net_nfc_client_snep_stop_service_sync(
					target_info->handle,
					snep_handle);

	if(result != NET_NFC_OK)
	{
		g_print(" net_nfc_test_snep_register_server failed: %d\n", result);
		return;
	}
}


