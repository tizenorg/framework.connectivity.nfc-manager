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

#ifndef __NET_NFC_TEST_LLCP_H__
#define __NET_NFC_TEST_LLCP_H__

#include <glib.h>


void net_nfc_test_llcp_default_config(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_default_config_sync(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_get_local_config(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_custom_config(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_custom_config_sync(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_get_local_config(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_get_config_miu(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_get_config_wks(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_get_config_lto(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_get_config_option(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_set_config_miu(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_set_config_wks(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_set_config_lto(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_set_config_option(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_free_config(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_create_custom_socket_option(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_create_default_socket_option(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_get_local_socket_option(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_get_socket_option_miu(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_set_socket_option_miu(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_get_socket_option_rw(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_set_socket_option_rw(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_get_socket_option_type(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_set_socket_option_type(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_free_socket_option(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_listen(gpointer data,
				gpointer user_data);

void net_nfc_test_llcp_listen_sync(gpointer data,
				gpointer user_data);

void net_nfc_test_llcp_receive(gpointer data,
				gpointer user_data);

void net_nfc_test_llcp_receive_sync(gpointer data,
				gpointer user_data);

void net_nfc_test_llcp_receive_from(gpointer data,
				gpointer user_data);

void net_nfc_test_llcp_receive_from_sync(gpointer data,
				gpointer user_data);


void net_nfc_test_llcp_connect(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_connect_sync(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_connect_sap(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_connect_sap_sync(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_send(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_send_sync(gpointer data,
			gpointer user_data);


void net_nfc_test_llcp_send_to(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_send_to_sync(gpointer data,
			gpointer user_data);

void net_nfc_test_llcp_disconnect(gpointer func_data,
			gpointer user_data);

void net_nfc_test_llcp_disconnect_server(gpointer func_data,
			gpointer user_data);

void net_nfc_test_llcp_disconnect_sync(gpointer func_data,
			gpointer user_data);

#endif

