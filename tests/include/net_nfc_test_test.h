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
#ifndef __NET_NFC_TEST_TEST_H__
#define __NET_NFC_TEST_TEST_H__

#include <glib.h>

void net_nfc_test_test_sim_test(gpointer data,
		gpointer user_data);

void net_nfc_test_test_prbs_test(gpointer data,
		gpointer user_data);

void net_nfc_test_test_get_firmware_version(gpointer data,
		gpointer user_data);

void net_nfc_test_test_set_ee_data(gpointer data,
		gpointer user_data);

void net_nfc_test_test_ese_test(gpointer data,
		gpointer user_data);

void net_nfc_test_test_sim_test_sync(gpointer data,
		gpointer user_data);

void net_nfc_test_test_prbs_test_sync(gpointer data,
		gpointer user_data);

void net_nfc_test_test_get_firmware_version_sync(gpointer data,
		gpointer user_data);

void net_nfc_test_test_set_ee_data_sync(gpointer data,
		gpointer user_data);

void net_nfc_test_test_ese_test_sync(gpointer data,
		gpointer user_data);

#endif //__NET_NFC_TEST_TEST_H__
