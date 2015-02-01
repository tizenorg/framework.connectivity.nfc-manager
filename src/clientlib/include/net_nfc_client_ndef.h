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

#ifndef __NET_NFC_CLIENT_NDEF_H__
#define __NET_NFC_CLIENT_NDEF_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*net_nfc_client_ndef_read_completed)(net_nfc_error_e result,
		ndef_message_h message,
		void *user_data);

typedef void (*net_nfc_client_ndef_write_completed)(net_nfc_error_e result,
		void *user_data);

typedef void (*net_nfc_client_ndef_make_read_only_completed)(
		net_nfc_error_e result,
		void *user_data);

typedef void (*net_nfc_client_ndef_format_completed)(net_nfc_error_e result,
		void *user_data);

net_nfc_error_e net_nfc_client_ndef_read(net_nfc_target_handle_h handle,
		net_nfc_client_ndef_read_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_ndef_read_sync(net_nfc_target_handle_h handle,
		ndef_message_h *message);

net_nfc_error_e net_nfc_client_ndef_write(net_nfc_target_handle_h handle,
		ndef_message_h message,
		net_nfc_client_ndef_write_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_ndef_write_sync(net_nfc_target_handle_h handle,
		ndef_message_h message);

net_nfc_error_e net_nfc_client_ndef_make_read_only(
		net_nfc_target_handle_h handle,
		net_nfc_client_ndef_make_read_only_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_ndef_make_read_only_sync(
		net_nfc_target_handle_h handle);

net_nfc_error_e net_nfc_client_ndef_format(net_nfc_target_handle_h handle,
		data_h key,
		net_nfc_client_ndef_format_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_ndef_format_sync(
		net_nfc_target_handle_h handle,
		data_h key);

/* TODO : move to internal header */
net_nfc_error_e net_nfc_client_ndef_init(void);

void net_nfc_client_ndef_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_NDEF_H__
