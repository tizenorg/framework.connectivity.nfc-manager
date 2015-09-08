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

#ifndef __NET_NFC_CLIENT_SNEP_H__
#define __NET_NFC_CLIENT_SNEP_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*net_nfc_client_snep_event_cb) (
			net_nfc_snep_handle_h target,
			net_nfc_snep_type_t event,
			net_nfc_error_e result,
			ndef_message_h msg,
			void *user_data);

net_nfc_error_e net_nfc_client_snep_start_server(
			net_nfc_target_handle_h target,
			const char *san,
			sap_t sap,
			net_nfc_client_snep_event_cb callback,
			void *user_data);

net_nfc_error_e net_nfc_client_snep_start_client(
			net_nfc_target_handle_h target,
			const char *san,
			sap_t sap,
			net_nfc_client_snep_event_cb callback,
			void *user_data);

net_nfc_error_e net_nfc_client_snep_send_client_request(
			net_nfc_snep_handle_h handle,
			net_nfc_snep_type_t snep_type,
			ndef_message_h msg,
			net_nfc_client_snep_event_cb callback,
			void *user_data);

net_nfc_error_e net_nfc_client_snep_send_client_request_sync(
			net_nfc_target_handle_h target,
			net_nfc_snep_type_t snep_type,
			ndef_message_h msg,
			net_nfc_snep_type_t *resp_type,
			ndef_message_h *response);

net_nfc_error_e net_nfc_client_snep_stop_service(
			net_nfc_target_handle_h target,
			net_nfc_snep_handle_h service,
			net_nfc_client_snep_event_cb callback,
			void *user_data);

net_nfc_error_e net_nfc_client_snep_stop_service_sync(
			net_nfc_target_handle_h target,
			net_nfc_snep_handle_h service);

net_nfc_error_e net_nfc_client_snep_register_server(const char *san,
	sap_t sap,
	net_nfc_client_snep_event_cb callback,
	void *user_data);

net_nfc_error_e net_nfc_client_snep_unregister_server(const char *san,
	sap_t sap);

/* TODO : move to internal header */
net_nfc_error_e net_nfc_client_snep_init(void);

void net_nfc_client_snep_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_SNEP_H__
