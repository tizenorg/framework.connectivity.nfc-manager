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
#ifndef __NET_NFC_SERVER_P2P_H__
#define __NET_NFC_SERVER_P2P_H__

#include <gio/gio.h>

#include "net_nfc_typedef_internal.h"

gboolean net_nfc_server_p2p_init(GDBusConnection *connection);

void net_nfc_server_p2p_deinit(void);

/* server side */
void net_nfc_server_p2p_detached(gpointer user_data);

void net_nfc_server_p2p_discovered(net_nfc_target_handle_h handle);

void net_nfc_server_p2p_received(data_h user_data);

void net_nfc_server_p2p_data_sent(net_nfc_error_e result, gpointer user_data);

#endif //__NET_NFC_SERVER_P2P_H__
