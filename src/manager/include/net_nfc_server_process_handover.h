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

#ifndef __NET_NFC_SERVER_PROCESS_HANDOVER_H__
#define __NET_NFC_SERVER_PROCESS_HANDOVER_H__

#include "net_nfc_typedef_internal.h"

net_nfc_error_e net_nfc_server_handover_default_server_start(
					net_nfc_target_handle_s *handle);

net_nfc_error_e net_nfc_server_handover_default_client_start(
					net_nfc_target_handle_s *handle,
					void *user_data);

net_nfc_error_e net_nfc_server_handover_default_server_register();

net_nfc_error_e net_nfc_server_handover_default_server_unregister();

#endif //__NET_NFC_SERVER_PROCESS_HANDOVER_H__
