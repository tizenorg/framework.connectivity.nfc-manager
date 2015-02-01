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
#ifndef __NET_NFC_SERVER_PROCESS_NPP_H__
#define __NET_NFC_SERVER_PROCESS_NPP_H__

#include <glib.h>

#include "net_nfc_typedef.h"
#include "net_nfc_typedef_internal.h"

typedef void (*net_nfc_server_npp_callback) (net_nfc_error_e result,
					data_s *data,
					gpointer user_data);

net_nfc_error_e net_nfc_server_npp_server(net_nfc_target_handle_s *handle,
					char *san,
					sap_t sap,
					net_nfc_server_npp_callback callback,
					gpointer user_data);

net_nfc_error_e net_nfc_server_npp_client(net_nfc_target_handle_s *handle,
					char *san,
					sap_t sap,
					data_s *data,
					net_nfc_server_npp_callback callback,
					gpointer user_data);

net_nfc_error_e net_nfc_server_npp_default_server_start(
					net_nfc_target_handle_s *handle);

net_nfc_error_e net_nfc_server_npp_default_client_start(
					net_nfc_target_handle_s *handle,
					data_s *data,
					int client,
					gpointer user_data);

net_nfc_error_e net_nfc_server_npp_default_server_register();

net_nfc_error_e net_nfc_server_npp_default_server_unregister();

#endif //__NET_NFC_SERVER_PROCESS_NPP_H__
