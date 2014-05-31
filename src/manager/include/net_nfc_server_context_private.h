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

#ifndef NET_NFC_SERVER_CONTEXT_H
#define NET_NFC_SERVER_CONTEXT_H

#include <unistd.h>

#include "net_nfc_typedef_private.h"

/* define */
typedef struct _net_nfc_client_info_t
{
	pid_t pid;
	pid_t pgid;
	int socket;
	GIOChannel *channel;
	uint32_t src_id;
	client_state_e state;
	//client_type_e client_type;
	net_nfc_launch_popup_state_e launch_popup_state;
	net_nfc_target_handle_s *target_handle;
} net_nfc_client_info_t;

typedef void (*net_nfc_server_for_each_client_cb)(net_nfc_client_info_t *client, void *user_param);

void net_nfc_server_deinit_client_context();
void net_nfc_server_add_client_context(pid_t pid, int socket, GIOChannel *channel, uint32_t src_id, client_state_e state);
void net_nfc_server_cleanup_client_context(int socket);
net_nfc_client_info_t *net_nfc_server_get_client_context(int socket);
int net_nfc_server_get_client_count();
void net_nfc_server_for_each_client_context(net_nfc_server_for_each_client_cb cb, void *user_param);

bool net_nfc_server_check_client_is_running(int socket);
client_state_e net_nfc_server_get_client_state(int socket);
void net_nfc_server_set_client_state(int socket, client_state_e state);
void net_nfc_server_set_launch_state(int socket, net_nfc_launch_popup_state_e popup_state);
net_nfc_launch_popup_state_e net_nfc_server_get_client_popup_state(pid_t pid);

#endif /* NET_NFC_SERVER_CONTEXT_H */
