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


#ifndef NET_NFC_CLIENT_DISPATCHER_H
#define NET_NFC_CLIENT_DISPATCHER_H

#include "net_nfc_typedef.h"
#include "net_nfc_typedef_private.h"

#ifdef USE_GLIB_MAIN_LOOP
void net_nfc_client_call_dispatcher_in_g_main_loop(net_nfc_response_cb client_cb, net_nfc_response_msg_t* msg);
#elif USE_ECORE_MAIN_LOOP
void net_nfc_client_call_dispatcher_in_ecore_main_loop(net_nfc_response_cb client_cb, net_nfc_response_msg_t* msg);
#else
void net_nfc_client_call_dispatcher_in_current_context(net_nfc_response_cb client_cb, net_nfc_response_msg_t* msg);
#endif
net_nfc_error_e net_nfc_client_dispatch_sync_response(net_nfc_response_msg_t *msg);

#endif

