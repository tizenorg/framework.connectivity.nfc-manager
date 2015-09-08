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

#ifndef __NET_NFC_CLIENT_SYSTEM_HANDLER_H__
#define __NET_NFC_CLIENT_SYSTEM_HANDLER_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*net_nfc_client_popup_set_state_callback)(
	net_nfc_error_e result,
	void *user_data);

net_nfc_error_e net_nfc_client_sys_handler_set_state(int state,
	net_nfc_client_popup_set_state_callback callback,
	void *user_data);

net_nfc_error_e net_nfc_client_sys_handler_set_state_force(int state,
	net_nfc_client_popup_set_state_callback callback,
	void *user_data);

net_nfc_error_e net_nfc_client_sys_handler_set_state_sync(int state);

net_nfc_error_e net_nfc_client_sys_handler_set_state_force_sync(int state);

net_nfc_error_e net_nfc_client_sys_handler_set_launch_popup_state(int enable);

net_nfc_error_e net_nfc_client_sys_handler_set_launch_popup_state_force(
	int enable);

net_nfc_error_e net_nfc_client_sys_handler_get_launch_popup_state(int *state);

/* TODO : move to internal header */
net_nfc_error_e net_nfc_client_sys_handler_init(void);

void net_nfc_client_sys_handler_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_SYSTEM_HANDLER_H__
