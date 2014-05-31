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

#ifndef NET_NFC_TEST_H_
#define NET_NFC_TEST_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "net_nfc_typedef.h"

net_nfc_error_e net_nfc_sim_test(void);
net_nfc_error_e net_nfc_prbs_test(int tech, int rate);

net_nfc_error_e net_nfc_get_firmware_version(void);

void net_nfc_test_read_test_cb(net_nfc_message_e message, net_nfc_error_e result, void *data, void *user_param, void *trans_data);
void net_nfc_test_sim_test_cb(net_nfc_message_e message, net_nfc_error_e result, void *data, void *user_param, void *trans_data);

net_nfc_error_e net_nfc_set_eedata_register(int mode, int reg_id, uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* NET_NFC_TEST_H_ */
