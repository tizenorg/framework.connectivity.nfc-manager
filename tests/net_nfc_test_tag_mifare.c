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


#include "net_nfc_tag_mifare.h"
#include "net_nfc_test_tag_mifare.h"
#include "net_nfc_target_info.h"
#include "net_nfc_typedef_internal.h"
#include "net_nfc_test_tag.h"
#include "net_nfc_test_util.h"


static net_nfc_target_handle_h tag_get_handle(void);

static void mifare_read_cb(net_nfc_error_e result,
				data_h resp_data,
				void *user_data);

static void mifare_write_block_cb(net_nfc_error_e result, void* user_data);

static void mifare_write_page_cb(net_nfc_error_e result, void* user_data);

static void mifare_write_mifare_incr_cb(net_nfc_error_e result, void* user_data);

static void mifare_write_mifare_decr_cb(net_nfc_error_e result, void* user_data);

static void mifare_write_mifare_transfer_cb(net_nfc_error_e result, void* user_data);

static void mifare_write_mifare_restore_cb(net_nfc_error_e result, void* user_data);

static void mifare_write_auth_keyA_cb(net_nfc_error_e result, void* user_data);

static void mifare_write_auth_keyB_cb(net_nfc_error_e result, void* user_data);


static net_nfc_target_handle_h tag_get_handle(void)
{
	net_nfc_target_info_h info = NULL;
	net_nfc_target_handle_h handle = NULL;

	info = net_nfc_test_tag_get_target_info();

	net_nfc_get_tag_handle(info, &handle);

	return handle;
}

static void run_next_callback(gpointer user_data)
{
	if (user_data)
	{
		GCallback callback;

		callback = (GCallback)(user_data);
		callback();
	}
}

static void mifare_read_cb(net_nfc_error_e result,
				data_h resp_data,
				void *user_data)
{
	g_print("mifare_read_cb Completed %d\n", result);
	print_received_data(resp_data);
	run_next_callback(user_data);
}

static void mifare_write_block_cb(net_nfc_error_e result, void* user_data)
{
	g_print("mifare_write_block_cb Completed %d\n", result);
	run_next_callback(user_data);
}

static void mifare_write_page_cb(net_nfc_error_e result, void* user_data)
{
	g_print("mifare_write_page_cb Completed %d\n", result);
	run_next_callback(user_data);
}

static void mifare_write_mifare_incr_cb(net_nfc_error_e result, void* user_data)
{
	g_print("mifare_write_mifare_incr_cb Completed %d\n", result);
	run_next_callback(user_data);
}

static void mifare_write_mifare_decr_cb(net_nfc_error_e result, void* user_data)
{
	g_print("mifare_write_mifare_decr_cb Completed %d\n", result);
	run_next_callback(user_data);
}

static void mifare_write_mifare_transfer_cb(net_nfc_error_e result, void* user_data)
{
	g_print("mifare_write_mifare_transfer_cb Completed %d\n", result);
	run_next_callback(user_data);
}

static void mifare_write_mifare_restore_cb(net_nfc_error_e result, void* user_data)
{
	g_print("mifare_write_mifare_restore_cb Completed %d\n", result);
	run_next_callback(user_data);
}

static void mifare_write_auth_keyA_cb(net_nfc_error_e result, void* user_data)
{
	g_print("mifare_write_auth_keyA_cb Completed %d\n", result);
	run_next_callback(user_data);
}

static void mifare_write_auth_keyB_cb(net_nfc_error_e result, void* user_data)
{
	g_print("mifare_write_auth_keyB_cb Completed %d\n", result);
	run_next_callback(user_data);
}


void net_nfc_test_tag_mifare_read(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e  result  = NET_NFC_OK;
	net_nfc_target_handle_h handle = NULL;
	uint8_t block_index = 0x04;

	handle = tag_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	result = net_nfc_client_mifare_read(handle,
				block_index,
				mifare_read_cb,
				user_data);
	if (result != NET_NFC_OK) {
		g_print("mifare read failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_tag_mifare_write_block(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e  result = NET_NFC_OK;
	net_nfc_target_handle_h handle = NULL;
	data_h write_data = NULL;
	// create 4 bytes data  mifare page size is 4 bytes
	uint8_t buffer_data [17] = "aaaabbbbccccdddd";

	net_nfc_create_data(&write_data, buffer_data, 16);

	uint8_t block_index = 0x04;

	handle = tag_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");
		net_nfc_free_data(write_data);
		run_next_callback(user_data);
		return;
	}
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	result = net_nfc_client_mifare_write_block(handle,
				block_index,
				write_data,
				mifare_write_block_cb,
				user_data);

	net_nfc_free_data(write_data);

	if (result != NET_NFC_OK) {
		g_print("mifare write block failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_tag_mifare_write_page(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e  result = NET_NFC_OK;
	net_nfc_target_handle_h handle = NULL;
	data_h write_data = NULL;
	// create 4 bytes data  mifare page size is 4 bytes
	uint8_t buffer_data [5] = "aaaa";

	net_nfc_create_data(&write_data, buffer_data, 4);

	uint8_t block_index = 0x04;

	handle = tag_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");
		net_nfc_free_data(write_data);
		run_next_callback(user_data);
		return;
	}
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	result = net_nfc_client_mifare_write_page(handle,
				block_index,
				write_data,
				mifare_write_page_cb,
				user_data);

	net_nfc_free_data(write_data);

	if (result != NET_NFC_OK) {
		g_print("mifare write page failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_tag_mifare_increment(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e  result = NET_NFC_OK;
	net_nfc_target_handle_h handle = NULL;
	int value = 1;
	uint8_t block_index = 0x05;

	handle = tag_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));
	result = net_nfc_client_mifare_increment(handle,
				block_index,
				value,
				mifare_write_mifare_incr_cb,
				user_data);
	if (result != NET_NFC_OK) {
		g_print("mifare increment failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_tag_mifare_decrement(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e  result = NET_NFC_OK;
	net_nfc_target_handle_h handle = NULL;
	int value = 1;
	uint8_t block_index = 0x05;

	handle = tag_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));
	result = net_nfc_client_mifare_decrement(handle,
				block_index,
				value,
				mifare_write_mifare_decr_cb,
				user_data);
	if (result != NET_NFC_OK) {
		g_print("mifare decrement failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_tag_mifare_transfer(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e  result = NET_NFC_OK;
	net_nfc_target_handle_h handle = NULL;
	uint8_t block_index = 0x08;

	handle = tag_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));
	result = net_nfc_client_mifare_transfer(handle,
				block_index,
				mifare_write_mifare_transfer_cb,
				user_data);
	if (result != NET_NFC_OK) {
		g_print("mifare transfer failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_tag_mifare_restore(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e  result = NET_NFC_OK;
	net_nfc_target_handle_h handle = NULL;
	uint8_t block_index = 0x08;

	handle = tag_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	result = net_nfc_client_mifare_restore(handle,
				block_index,
				mifare_write_mifare_restore_cb,
				user_data);
	if (result != NET_NFC_OK) {
		g_print("mifare restore failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_tag_mifare_authenticate_with_keyA(gpointer data,
			gpointer user_data)
{
	net_nfc_error_e  result = NET_NFC_OK;
	net_nfc_target_handle_h handle = NULL;
	data_h auth_key  = NULL;
	uint8_t sector_index = 0x02;

	handle = tag_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	result = net_nfc_client_mifare_create_default_key(&auth_key);
	g_print("default key create %d", result);

	result = net_nfc_client_mifare_authenticate_with_keyA(
				handle,
				sector_index,
				auth_key,
				mifare_write_auth_keyA_cb,
				user_data);

	net_nfc_free_data(auth_key);

	if (result != NET_NFC_OK) {
		g_print("mifare authenticate with key A failed %d\n", result);
		run_next_callback(user_data);
	}
}

void net_nfc_test_tag_mifare_authenticate_with_keyB(gpointer data,
				gpointer user_data)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_target_handle_h handle = NULL;
	data_h auth_key = NULL;
	uint8_t sector_index = 0x02;

	handle = tag_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}
	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	result = net_nfc_client_mifare_create_default_key(&auth_key);
	g_print("default key create %d", result);

	result = net_nfc_client_mifare_authenticate_with_keyB(
				handle,
				sector_index,
				auth_key,
				mifare_write_auth_keyB_cb,
				user_data);

	net_nfc_free_data(auth_key);

	if (result != NET_NFC_OK) {
		g_print("mifare authenticate with key B failed %d\n", result);
		run_next_callback(user_data);
	}
}
