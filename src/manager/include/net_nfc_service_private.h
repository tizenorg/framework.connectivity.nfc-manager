/*
  * Copyright 2012  Samsung Electronics Co., Ltd
  *
  * Licensed under the Flora License, Version 1.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://www.tizenopensource.org/license
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

#ifndef NET_NFC_SERVICE_PRIVATE_H
#define NET_NFC_SERVICE_PRIVATE_H

#include "net_nfc_typedef_private.h"

bool net_nfc_service_slave_mode_target_detected(net_nfc_request_msg_t* msg);
bool net_nfc_service_standalone_mode_target_detected(net_nfc_request_msg_t* msg);
bool net_nfc_service_termination (net_nfc_request_msg_t* msg);

void net_nfc_service_target_detected_cb(void* info, void* user_context);
void net_nfc_service_se_transaction_cb(void* info, void* user_context);
void net_nfc_service_llcp_event_cb(void* info, void* user_context);

void net_nfc_service_msg_processing(data_s* data);

#endif
