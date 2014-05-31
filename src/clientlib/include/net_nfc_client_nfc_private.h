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


#ifndef __NET_NFC_CLIENT_NET_NFC_PRIVATE_H__
#define __NET_NFC_CLIENT_NET_NFC_PRIVATE_H__

#include "net_nfc_typedef_private.h"

#ifdef __cplusplus
extern "C"
{
#endif

client_context_t *net_nfc_get_client_context();
bool net_nfc_tag_is_connected();
net_nfc_error_e net_nfc_send_init(void *context);
net_nfc_error_e net_nfc_send_deinit(void *context);

typedef bool (*net_nfc_client_cb)(net_nfc_message_e message, net_nfc_error_e result, void* user_param);

net_nfc_error_e net_nfc_util_release_tag_info(net_nfc_target_info_s *info);
bool net_nfc_util_check_tag_filter(net_nfc_target_type_e type);

/**
 @} */

#ifdef __cplusplus
}
#endif

#endif

