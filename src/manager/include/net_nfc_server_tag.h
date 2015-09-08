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
#ifndef __NET_NFC_SERVER_TAG_H__
#define __NET_NFC_SERVER_TAG_H__

#include <gio/gio.h>

#include "net_nfc_typedef_internal.h"

gboolean net_nfc_server_tag_init(GDBusConnection *connection);

void net_nfc_server_tag_deinit(void);

void net_nfc_server_set_target_info(net_nfc_current_target_info_s *info);

net_nfc_current_target_info_s *net_nfc_server_get_target_info(void);

gboolean net_nfc_server_target_connected(net_nfc_target_handle_s *handle);

void net_nfc_server_free_target_info(void);

bool net_nfc_server_tag_target_detected(void *info);

#endif //__NET_NFC_SERVER_TAG_H__
