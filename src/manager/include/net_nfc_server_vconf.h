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
#ifndef __NET_NFC_SERVER_VCONF_H__
#define __NET_NFC_SERVER_VCONF_H__

void net_nfc_server_vconf_init(void);

void net_nfc_server_vconf_deinit(void);

bool net_nfc_check_csc_vconf(void);

bool net_nfc_check_start_polling_vconf(void);

#endif //__NET_NFC_SERVER_VCONF_H__
