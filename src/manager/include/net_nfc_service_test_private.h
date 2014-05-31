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

#ifndef NET_NFC_SERVICE_TEST_PRIVATE_H
#define NET_NFC_SERVICE_TEST_PRIVATE_H

#include "net_nfc_typedef_private.h"

void net_nfc_service_test_sim_test(net_nfc_request_msg_t *msg);
void net_nfc_service_test_get_firmware_version(net_nfc_request_msg_t *msg);
void net_nfc_service_test_prbs_test(net_nfc_request_msg_t *msg);
void net_nfc_service_test_set_eedata(net_nfc_request_msg_t *msg);

#endif
