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

#ifndef __NET_NFC_TEST_TAG_MIFARE_H__
#define __NET_NFC_TEST_TAG_MIFARE_H__

#include <glib.h>


void net_nfc_test_tag_mifare_read(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_authenticate_with_keyA(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_authenticate_with_keyB(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_write_block(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_write_page(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_increment(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_decrement(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_transfer(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_restore(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_create_default_key(gpointer data,
				gpointer user_data);

void net_nfc_test_tag_mifare_create_net_nfc_forum_key(gpointer data,
				gpointer user_data);

#endif

