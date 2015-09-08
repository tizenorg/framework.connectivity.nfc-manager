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
#ifndef __NET_NFC_CLIENT_MANAGER_H__
#define __NET_NFC_CLIENT_MANAGER_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*net_nfc_client_manager_set_active_completed)(
		net_nfc_error_e result,
		void *user_data);

typedef void (*net_nfc_client_manager_get_server_state_completed)(
		net_nfc_error_e result,
		unsigned int state,
		void *user_data);

typedef void (*net_nfc_client_manager_activated)(bool state,
		void *user_data);

void net_nfc_client_manager_set_activated(
		net_nfc_client_manager_activated callback,
		void *user_data);

void net_nfc_client_manager_unset_activated(void);

net_nfc_error_e net_nfc_client_manager_set_active(int state,
		net_nfc_client_manager_set_active_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_manager_set_active_sync(int state);

net_nfc_error_e net_nfc_client_manager_get_server_state(
		net_nfc_client_manager_get_server_state_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_manager_get_server_state_sync(
		unsigned int *state);

bool net_nfc_client_manager_is_activated(void);

/* TODO : move to internal header */
net_nfc_error_e net_nfc_client_manager_init(void);

void net_nfc_client_manager_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_MANAGER_H__
