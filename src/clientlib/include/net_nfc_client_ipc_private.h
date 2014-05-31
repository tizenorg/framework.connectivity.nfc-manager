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


#ifndef NET_NFC_CLIENT_IPC_H
#define NET_NFC_CLIENT_IPC_H

#include "net_nfc_typedef.h"
#include "net_nfc_util_ipc.h"

net_nfc_error_e net_nfc_client_socket_initialize();
void net_nfc_client_socket_finalize();
bool net_nfc_client_is_connected();

net_nfc_error_e net_nfc_client_send_request(net_nfc_request_msg_t *msg, ...);
net_nfc_error_e net_nfc_client_send_request_sync(net_nfc_request_msg_t *msg, ...);

void _net_nfc_client_set_cookies(const char * cookie, size_t size);
void _net_nfc_client_free_cookies(void);

net_nfc_error_e _net_nfc_client_register_cb(net_nfc_response_cb cb);
net_nfc_error_e _net_nfc_client_unregister_cb(void);

#endif

