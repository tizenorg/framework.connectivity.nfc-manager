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


#ifndef NET_NFC_UTIL_ACCESS_CONTROL_PRIVATE_H
#define NET_NFC_UTIL_ACCESS_CONTROL_PRIVATE_H

#include "net_nfc_typedef_private.h"

bool net_nfc_util_access_control_is_initialized(void);
void net_nfc_util_access_control_initialize(void);
void net_nfc_util_access_control_update_list(void);
bool net_nfc_util_access_control_is_authorized_package(const char* pkg_name, uint8_t *aid, uint32_t length);
void net_nfc_util_access_control_release(void);

#endif
