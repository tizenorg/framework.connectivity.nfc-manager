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

#ifndef __NET_NFC_SERVER_COMMON_H__
#define __NET_NFC_SERVER_COMMON_H__

#include <glib.h>

#include "net_nfc_typedef.h"

typedef void (*net_nfc_server_controller_func)(gpointer user_data);

gboolean net_nfc_server_controller_thread_init(void);

void net_nfc_server_controller_thread_deinit(void);

void net_nfc_server_controller_init(void);
#ifndef ESE_ALWAYS_ON
void net_nfc_server_controller_deinit(void);
#endif

gboolean net_nfc_server_controller_is_blocked();

gboolean net_nfc_server_controller_async_queue_push_force(
	net_nfc_server_controller_func func, gpointer user_data);

gboolean net_nfc_server_controller_async_queue_push(
	net_nfc_server_controller_func func, gpointer user_data);

gboolean net_nfc_server_controller_async_queue_push_and_block(
	net_nfc_server_controller_func func, gpointer user_data);

gboolean net_nfc_server_controller_async_queue_delayed_push_force(
	guint msec, net_nfc_server_controller_func func, gpointer user_data);

void net_nfc_server_restart_polling_loop(void);

void net_nfc_server_force_polling_loop(void);

void net_nfc_server_set_state(guint32 state);

void net_nfc_server_unset_state(guint32 state);

guint32 net_nfc_server_get_state(void);

void net_nfc_server_controller_run_dispatch_loop();
void net_nfc_server_controller_quit_dispatch_loop();

#endif //__NET_NFC_SERVER_COMMON_H__
