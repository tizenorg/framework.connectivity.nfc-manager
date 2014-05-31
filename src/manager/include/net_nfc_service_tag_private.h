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


#ifndef NET_NFC_SERVICE_TAG_PRIVATE_H
#define NET_NFC_SERVICE_TAG_PRIVATE_H

#include "net_nfc_typedef_private.h"

data_s* net_nfc_service_tag_process(net_nfc_target_handle_s* handle, int devType, net_nfc_error_e* result);
void net_nfc_service_clean_tag_context(net_nfc_request_target_detected_t* stand_alone, net_nfc_error_e result);
void net_nfc_service_watch_dog(net_nfc_request_msg_t* req_msg);

void net_nfc_service_tag_make_readonly(net_nfc_request_msg_t *msg);
void net_nfc_service_tag_read_ndef(net_nfc_request_msg_t *msg);
void net_nfc_service_tag_write_ndef(net_nfc_request_msg_t *msg);
void net_nfc_service_tag_format_ndef(net_nfc_request_msg_t *msg);

#endif
