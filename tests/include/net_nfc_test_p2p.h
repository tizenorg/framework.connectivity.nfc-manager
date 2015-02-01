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

#ifndef __NET_NFC_TEST_P2P_H__
#define __NET_NFC_TEST_P2P_H__


#include <glib.h>
#include "net_nfc_target_info.h"

void net_nfc_test_p2p_send(gpointer data,
				gpointer user_data);

void net_nfc_test_p2p_send_sync(gpointer data,
				gpointer user_data);

void net_nfc_test_p2p_set_device_discovered(gpointer data,
				gpointer user_data);

void net_nfc_test_p2p_set_device_detached(gpointer data,
				gpointer user_data);

void net_nfc_test_p2p_set_data_received(gpointer data,
				gpointer user_data);

void net_nfc_test_p2p_unset_device_discovered(gpointer data,
				gpointer user_data);

void net_nfc_test_p2p_unset_device_detached(gpointer data,
				gpointer user_data);

void net_nfc_test_p2p_unset_data_received(gpointer data,
				gpointer user_data);

net_nfc_target_handle_h net_nfc_test_device_get_target_handle(void);

#endif

