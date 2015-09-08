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
#ifndef __NET_NFC_SERVER_PROCESS_SNEP_H__
#define __NET_NFC_SERVER_PROCESS_SNEP_H__

#include "net_nfc_gdbus.h"
#include "net_nfc_typedef_internal.h"

#define SNEP_SAN 			"urn:nfc:sn:snep"
#define SNEP_SAP			4

typedef enum
{
	SNEP_REQ_CONTINUE		= 0x00,
	SNEP_REQ_GET			= 0x01,
	SNEP_REQ_PUT			= 0x02,
	SNEP_REQ_REJECT			= 0x7F,
	SNEP_RESP_CONT			= 0x80,
	SNEP_RESP_SUCCESS		= 0x81,
	SNEP_RESP_NOT_FOUND		= 0xC0,
	SNEP_RESP_EXCESS_DATA		= 0xC1,
	SNEP_RESP_BAD_REQ		= 0xC2,
	SNEP_RESP_NOT_IMPLEMENT		= 0xE0,
	SNEP_RESP_UNSUPPORTED_VER	= 0xE1,
	SNEP_RESP_REJECT		= 0xFF,
} snep_command_field_e;

typedef bool (*net_nfc_server_snep_listen_cb)(net_nfc_snep_handle_h handle,
			uint32_t type,
			uint32_t max_len,
			data_s *data,
			void *user_param);

typedef net_nfc_error_e (*net_nfc_server_snep_cb)(net_nfc_snep_handle_h handle,
			net_nfc_error_e result,
			uint32_t type,
			data_s *data,
			void *user_param);

net_nfc_error_e net_nfc_server_snep_server(
			net_nfc_target_handle_s *handle,
			const char *san,
			sap_t sap,
			net_nfc_server_snep_cb cb,
			void *user_param);

net_nfc_error_e net_nfc_server_snep_client(
			net_nfc_target_handle_s *handle,
			const char *san,
			sap_t sap,
			net_nfc_server_snep_cb cb,
			void *user_param);

net_nfc_error_e net_nfc_server_snep_server_send_get_response(
			net_nfc_snep_handle_h snep_handle,
			data_s *data);

net_nfc_error_e net_nfc_server_snep_client_request(
			net_nfc_snep_handle_h snep,
			uint8_t type,
			data_s *data,
			net_nfc_server_snep_cb cb,
			void *user_param);

net_nfc_error_e net_nfc_server_snep_default_server_start(
			net_nfc_target_handle_s *handle);

net_nfc_error_e net_nfc_server_snep_default_client_start(
			net_nfc_target_handle_s *handle,
			int type,
			data_s *data,
			int client,
			void *user_param);

net_nfc_error_e
net_nfc_server_snep_default_server_register_get_response_cb(
			net_nfc_server_snep_listen_cb cb,
			void *user_param);

net_nfc_error_e
net_nfc_server_snep_default_server_unregister_get_response_cb(
			net_nfc_server_snep_listen_cb cb);

net_nfc_error_e
net_nfc_server_snep_default_server_send_get_response(
			net_nfc_snep_handle_h snep_handle,
			data_s *data);

net_nfc_error_e net_nfc_server_snep_default_server_register();

net_nfc_error_e net_nfc_server_snep_default_server_unregister();

net_nfc_error_e net_nfc_server_snep_parse_get_request(data_s *request,
	size_t *max_len, data_s *message);

#endif //__NET_NFC_SERVER_PROCESS_SNEP_H__