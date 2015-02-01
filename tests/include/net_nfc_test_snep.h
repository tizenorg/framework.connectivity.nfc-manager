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

#ifndef __NET_NFC_TEST_SNEP_H__
#define __NET_NFC_TEST_SNEP_H__

#include <glib.h>


void net_nfc_test_snep_set_tag_discovered(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_start_server(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_start_server_sync(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_start_client(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_start_client_sync(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_send_client_request(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_send_client_request_sync(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_register_server(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_unregister_server(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_stop_service(gpointer data,
			gpointer user_data);

void net_nfc_test_snep_stop_service_sync(gpointer data,
			gpointer user_data);
#endif

