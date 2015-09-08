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
#ifndef __NET_NFC_TEST_SE_H__
#define __NET_NFC_TEST_SE_H__

#include <glib.h>


void net_nfc_test_se_send_apdu(gpointer data,
				gpointer user_data );

void net_nfc_test_se_send_apdu_sync(gpointer data,
				gpointer user_data);

void net_nfc_test_se_set_secure_element_type(gpointer data,
				gpointer user_data);

void net_nfc_test_se_set_secure_element_type_sync(gpointer data,
				gpointer user_data);

void net_nfc_test_se_open_internal_secure_element(gpointer data,
				gpointer user_data);

void net_nfc_test_se_open_internal_secure_element_sync(gpointer data,
				gpointer user_data);

void net_nfc_test_se_close_internal_secure_element(gpointer data,
				gpointer user_data);

void net_nfc_test_se_close_internal_secure_element_sync(gpointer data,
				gpointer user_data);

void net_nfc_test_se_get_atr(gpointer data,
				gpointer user_data);

void net_nfc_test_se_get_atr_sync(gpointer data,
				gpointer user_data);

void net_nfc_test_se_set_event_cb(gpointer data,
				gpointer user_data);

void net_nfc_test_se_unset_event_cb(gpointer data,
				gpointer user_data);

void net_nfc_test_se_set_ese_detection_cb(gpointer data,
				gpointer user_data);

void net_nfc_test_se_unset_ese_detection_cb(gpointer data,
					gpointer user_data);

void net_nfc_test_se_set_transaction_event_cb(gpointer data,
				gpointer user_data);

void net_nfc_test_se_unset_transaction_event_cb(gpointer data,
				gpointer user_data);

#endif
