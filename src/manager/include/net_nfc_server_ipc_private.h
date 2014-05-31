/*
  * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
  *
  * Licensed under the Flora License, Version 1.1 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://floralicense.org/license/
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

#ifndef NET_NFC_SERVER_IPC_H
#define NET_NFC_SERVER_IPC_H

#include <glib-object.h>

#include "net_nfc_typedef_private.h"

#ifdef SECURITY_SERVER
#define NET_NFC_MANAGER_OBJECT "nfc-manager"
#endif
#define NET_NFC_CLIENT_MAX 10

typedef struct net_nfc_server_info_t
{
	uint32_t server_src_id ;
	GIOChannel *server_channel ;
	int server_sock_fd ;
	uint32_t state;
	net_nfc_current_target_info_s *target_info;
}net_nfc_server_info_t;

bool net_nfc_server_ipc_initialize();
void net_nfc_server_ipc_finalize();

bool net_nfc_server_set_server_state(uint32_t state);
bool net_nfc_server_unset_server_state(uint32_t state);
uint32_t net_nfc_server_get_server_state();

int net_nfc_server_recv_message_from_client(int client_sock_fd, void* message, int length);
#ifdef BROADCAST_MESSAGE
bool net_nfc_broadcast_response_msg(int msg_type, ...);
bool net_nfc_send_response_msg(int socket, int msg_type, ...);
#else
bool net_nfc_send_response_msg(int msg_type, ...);
#endif
void net_nfc_server_set_tag_info(void *info);
bool net_nfc_server_is_target_connected(void *handle);
net_nfc_current_target_info_s *net_nfc_server_get_tag_info();
void net_nfc_server_free_current_tag_info();

#endif

