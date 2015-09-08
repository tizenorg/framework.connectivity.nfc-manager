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

#ifndef __NET_NFC_CLIENT_TEST_H__
#define __NET_NFC_CLIENT_TEST_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*net_nfc_client_test_sim_test_completed)(net_nfc_error_e result,
							void *user_data);

typedef void (*net_nfc_client_test_prbs_test_completed)(
							net_nfc_error_e result,
							void *user_data);

typedef void (*net_nfc_client_test_get_firmware_version_completed)(
							net_nfc_error_e result,
							char *version,
							void *user_data);
typedef void (*net_nfc_client_test_set_ee_data_completed)(
							net_nfc_error_e result,
							void *user_data);

typedef void (*net_nfc_client_test_ese_test_completed)(net_nfc_error_e result,
							void *user_data);


net_nfc_error_e net_nfc_client_test_sim_test(
			net_nfc_client_test_sim_test_completed callback,
			void *user_data);

net_nfc_error_e net_nfc_client_test_sim_test_sync(void);

net_nfc_error_e net_nfc_client_test_prbs_test(uint32_t tech,
			uint32_t rate,
			net_nfc_client_test_prbs_test_completed callback,
			void *user_data);

net_nfc_error_e net_nfc_client_test_prbs_test_sync(uint32_t tech,
						uint32_t rate);

net_nfc_error_e net_nfc_client_test_get_firmware_version(
		net_nfc_client_test_get_firmware_version_completed callback,
		void *user_data);

net_nfc_error_e net_nfc_client_test_get_firmware_version_sync(char **version);

net_nfc_error_e net_nfc_client_test_set_ee_data(int mode,
			int reg_id,
			data_h data,
			net_nfc_client_test_set_ee_data_completed callback,
			void *user_data);

net_nfc_error_e net_nfc_client_test_set_ee_data_sync(int mode,
						int reg_id,
						data_h data);

net_nfc_error_e net_nfc_client_test_ese_test(
			net_nfc_client_test_sim_test_completed callback,
			void *user_data);

net_nfc_error_e net_nfc_client_test_ese_test_sync(void);



net_nfc_error_e net_nfc_client_test_set_se_tech_type_sync(net_nfc_se_type_e type, int tech);

/* TODO : move to internal header */
net_nfc_error_e net_nfc_client_test_init(void);

void net_nfc_client_test_deinit(void);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_TEST_H__
