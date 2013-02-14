/*
  * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
  *
  * Licensed under the Flora License, Version 1.0 (the "License");
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


#ifndef __NET_NFC_SERVER_DISPATCHER__
#define __NET_NFC_SERVER_DISPATCHER__

#include "net_nfc_typedef_private.h"

void net_nfc_dispatcher_queue_push(net_nfc_request_msg_t* req_msg);
bool net_nfc_dispatcher_start_thread();
void net_nfc_dispatcher_cleanup_queue(void);
void net_nfc_dispatcher_put_cleaner(void);


#endif


