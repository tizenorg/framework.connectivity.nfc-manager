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
#ifndef __NET_NFC_TEST_TAG_H__
#define __NET_NFC_TEST_TAG_H__

#include <glib.h>

#include "net_nfc_target_info.h"
#if 0
void net_nfc_test_tag_is_tag_connected(gpointer data,
		gpointer user_data);

void net_nfc_test_tag_get_current_tag_info(gpointer data,
		gpointer user_data);

void net_nfc_test_tag_get_current_target_handle(gpointer data,
		gpointer user_data);
#endif
void net_nfc_test_tag_is_tag_connected_sync(gpointer data,
		gpointer user_data);

void net_nfc_test_tag_get_current_tag_info_sync(gpointer data,
		gpointer user_data);

void net_nfc_test_tag_get_current_target_handle_sync(gpointer data,
		gpointer user_data);

/* waiting for signal */
void net_nfc_test_tag_set_tag_discovered(gpointer data,
		gpointer user_data);

net_nfc_target_info_h net_nfc_test_tag_get_target_info(void);

void net_nfc_test_tag_set_tag_detached(gpointer data,
		gpointer user_data);

void net_nfc_test_tag_set_filter(gpointer data,
		gpointer user_data);

void net_nfc_test_tag_get_filter(gpointer data,
		gpointer user_data);


#endif //__NET_NFC_TEST_TAG_H__
