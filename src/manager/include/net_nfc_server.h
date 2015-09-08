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
#ifndef __NET_NFC_SERVER_H__
#define __NET_NFC_SERVER_H__

#include <unistd.h>

void net_nfc_server_gdbus_init(void);

void net_nfc_server_gdbus_deinit(void);

pid_t net_nfc_server_gdbus_get_pid(const char *name);

#endif //__NET_NFC_SERVER_H__
