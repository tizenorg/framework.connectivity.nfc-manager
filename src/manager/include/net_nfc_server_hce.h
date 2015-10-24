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

#ifndef __NET_NFC_SERVER_HCE_H__
#define __NET_NFC_SERVER_HCE_H__

#include <gio/gio.h>

#include "net_nfc_typedef_internal.h"


/******************************************************************************/
typedef void (*net_nfc_server_hce_listener_cb)(net_nfc_target_handle_s *handle,
	int event, data_s *data, void *user_data);

typedef void (*net_nfc_server_hce_user_data_destroy_cb)(void *user_data);


/******************************************************************************/
net_nfc_error_e net_nfc_server_hce_start_hce_handler(const char *package,
	const char *id, net_nfc_server_hce_listener_cb listener,
	net_nfc_server_hce_user_data_destroy_cb destroy_cb, void *user_data);

net_nfc_error_e net_nfc_server_hce_stop_hce_handler(const char *package);

net_nfc_error_e net_nfc_server_hce_send_apdu_response(
	net_nfc_target_handle_s *handle, data_s *response);

/******************************************************************************/
/* internal */
gboolean net_nfc_server_hce_init(GDBusConnection *connection);
void net_nfc_server_hce_deinit(void);

void net_nfc_server_hce_apdu_received(void *info);

#endif //__NET_NFC_SERVER_SE_H__
