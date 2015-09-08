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

#include "net_nfc_typedef_internal.h"
#include "net_nfc_client_tag.h"
#include "net_nfc_test_tag.h"

static void run_next_callback(gpointer user_data);
#if 0
static gchar *tag_type_to_string(net_nfc_target_type_e dev_type);
#endif
static void print_is_tag_connected(net_nfc_target_type_e dev_type);

static void print_get_current_tag_info(net_nfc_target_info_h info);

static void print_get_current_target_handle(net_nfc_target_handle_h handle);
#if 0
static void is_tag_connected_completed(net_nfc_error_e result,
				net_nfc_target_type_e dev_type,
				void *user_data);

static void get_current_tag_info_completed(net_nfc_error_e result,
				net_nfc_target_info_h info,
				void *user_data);

static void get_current_target_handle_completed(net_nfc_error_e result,
				net_nfc_target_handle_h handle,
				void *user_data);
#endif
static void tag_detached(void *user_data);

static void tag_discovered(net_nfc_target_info_h info,
				void *user_data);

static net_nfc_target_info_h global_info = NULL;


static void run_next_callback(gpointer user_data)
{
	if (user_data)
	{
		GCallback callback;

		callback = (GCallback)(user_data);

		callback();
	}
}
#if 0
static gchar *tag_type_to_string(net_nfc_target_type_e dev_type)
{
	switch(dev_type)
	{
		case NET_NFC_UNKNOWN_TARGET:
			return "Unknown Target";
		case NET_NFC_GENERIC_PICC:
			return "Generic PICC";
		case NET_NFC_ISO14443_A_PICC:
			return "ISO14443 PICC";
		case NET_NFC_ISO14443_4A_PICC:
			return "ISO14443 4A PICC";
		case NET_NFC_ISO14443_3A_PICC:
			return "ISO14443 3A PICC";
		case NET_NFC_MIFARE_MINI_PICC:
			return "Mifare mini PICC";
		case NET_NFC_MIFARE_1K_PICC:
			return "Mifare 1K PICC";
		case NET_NFC_MIFARE_4K_PICC:
			return "Mifare 4K PICC";
		case NET_NFC_MIFARE_ULTRA_PICC:
			return "Mifare Ultra PICC";
		case NET_NFC_MIFARE_DESFIRE_PICC:
			return "Mifare Desfire PICC";
		case NET_NFC_ISO14443_B_PICC:
			return "ISO14443 B PICC";
		case NET_NFC_ISO14443_4B_PICC:
			return "ISO14443 4B PICC";
		case NET_NFC_ISO14443_BPRIME_PICC:
			return "ISO14443 BPRIME PICC";
		case NET_NFC_FELICA_PICC:
			return "Felica PICC";
		case NET_NFC_JEWEL_PICC:
			return "Jewel PICC";
		case NET_NFC_ISO15693_PICC:
			return "ISO15693 PICC";
		case NET_NFC_NFCIP1_TARGET:
			return "NFCIP1 Target";
		case NET_NFC_NFCIP1_INITIATOR:
			return "NFCIP1 Initiator";
		default:
			break;
	}
	return "Invalid Target";
}
#endif
static void print_is_tag_connected(net_nfc_target_type_e dev_type)
{
	if (global_info)
	{
		net_nfc_target_type_e type;

		net_nfc_get_tag_type(global_info, &type);

		if(dev_type == type)
			g_print("DevType is same as Discovered tag\n");
	}
}

static void print_get_current_tag_info(net_nfc_target_info_h info)
{
	net_nfc_target_handle_h handle;

	if (global_info == NULL)
	{
		g_print("Discovered tag info does not exist\n");
		return;
	}

	if (info == NULL)
	{
		g_print("Current tag info does not exist\n");
		return;
	}

	net_nfc_get_tag_handle(info, &handle);
	print_get_current_target_handle(handle);

	return;
}

static void print_get_current_target_handle(net_nfc_target_handle_h handle)
{
	net_nfc_target_handle_h global_handle;
	guint global_handle_id;
	guint handle_id;

	net_nfc_get_tag_handle(global_info, &global_handle);

	global_handle_id = GPOINTER_TO_UINT(global_handle);
	handle_id = GPOINTER_TO_UINT(handle);

	g_print("Tag handle %x, Current Tag handle %x\n",
				global_handle_id,
				handle_id);
	if (global_handle_id == handle_id)
		g_print("Current Tag is matched discovered Tag\n");
}

static void tag_detached(void *user_data)
{
	g_print("TagDetached\n");
}
#if 0
static void is_tag_connected_completed(net_nfc_error_e result,
				net_nfc_target_type_e dev_type,
				void *user_data)
{
	g_print("IsTagConnected Completed %d\n", result);
	g_print("--- dev type : %s (%d)\n", tag_type_to_string(dev_type),
					dev_type);

	if (result == NET_NFC_OK)
		print_is_tag_connected(dev_type);
	else if (result == NET_NFC_NOT_CONNECTED)
		g_print("NET_NFC_NOT_CONNECTED\n");

	run_next_callback(user_data);
}

static void get_current_tag_info_completed(net_nfc_error_e result,
				net_nfc_target_info_h info,
				void *user_data)
{
	g_print("GetCurrentTagInfo Completed %d\n", result);

	if (result == NET_NFC_OK)
		print_get_current_tag_info(info);

	run_next_callback(user_data);
}

static void get_current_target_handle_completed(net_nfc_error_e result,
				net_nfc_target_handle_h handle,
				void *user_data)
{
	g_print("GetCurrentTargetHandle Completed %d\n", result);

	if (result == NET_NFC_OK)
		print_get_current_target_handle(handle);

	run_next_callback(user_data);
}
#endif

static void tag_discovered(net_nfc_target_info_h info,
				void *user_data)
{
	g_print("TagDiscovered\n");

	net_nfc_duplicate_target_info(info, &global_info);

	run_next_callback(user_data);
}


#if 0
void net_nfc_test_tag_is_tag_connected(gpointer data,
				gpointer user_data)
{
	net_nfc_client_tag_is_tag_connected(is_tag_connected_completed,
				user_data);
}

void net_nfc_test_tag_get_current_tag_info(gpointer data,
				gpointer user_data)
{
	net_nfc_client_tag_get_current_tag_info(get_current_tag_info_completed,
				user_data);
}

void net_nfc_test_tag_get_current_target_handle(gpointer data,
				gpointer user_data)
{
	net_nfc_client_tag_get_current_target_handle(
				get_current_target_handle_completed,
				user_data);
}
#endif
void net_nfc_test_tag_is_tag_connected_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;
	net_nfc_target_type_e dev_type;

	result = net_nfc_client_tag_is_tag_connected_sync(&dev_type);

	if (result == NET_NFC_OK)
		print_is_tag_connected(dev_type);
	else if (result == NET_NFC_NOT_CONNECTED)
		g_print("NET_NFC_NOT_CONNECTED\n");

	run_next_callback(user_data);
}

void net_nfc_test_tag_get_current_tag_info_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;
	net_nfc_target_info_h info;

	result = net_nfc_client_tag_get_current_tag_info_sync(&info);

	if (result == NET_NFC_OK)
		print_get_current_tag_info(info);

	run_next_callback(user_data);
}

void net_nfc_test_tag_get_current_target_handle_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result;
	net_nfc_target_handle_h handle;

	result = net_nfc_client_tag_get_current_target_handle_sync(&handle);

	if (result == NET_NFC_OK)
		print_get_current_target_handle(handle);

	run_next_callback(user_data);
}

void net_nfc_test_tag_set_tag_discovered(gpointer data,
				gpointer user_data)
{
	g_print("Waiting for TagDiscovered Signal\n");

	net_nfc_client_tag_unset_tag_detached();

	net_nfc_client_tag_set_tag_detached(tag_detached, NULL);

	net_nfc_client_tag_unset_tag_discovered();

	net_nfc_client_tag_set_tag_discovered(tag_discovered, user_data);
}

net_nfc_target_info_h net_nfc_test_tag_get_target_info(void)
{
	return global_info;
}

void net_nfc_test_tag_set_tag_detached(gpointer data,
				gpointer user_data)
{
	g_print("Waiting for TagDetached Singal\n");

	net_nfc_client_tag_set_tag_detached(tag_detached, NULL);
}

void net_nfc_test_tag_set_filter(gpointer data, gpointer user_data)
{
	net_nfc_event_filter_e filter = NET_NFC_ALL_ENABLE;

	net_nfc_client_tag_set_filter(filter);
}

void net_nfc_test_tag_get_filter(gpointer data, gpointer user_data)
{
	net_nfc_event_filter_e filter = NET_NFC_ALL_DISABLE;

	filter = net_nfc_client_tag_get_filter();

	g_print(" NFC tag filter = %d", filter);
}
