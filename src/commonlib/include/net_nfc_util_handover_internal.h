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

#ifndef __NET_NFC_UTIL_HANDOVER_INTERNAL_H__
#define __NET_NFC_UTIL_HANDOVER_INTERNAL_H__

#include "net_nfc_typedef_internal.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Bluetooth */
bool net_nfc_util_handover_bt_check_carrier_record(ndef_record_s *record);

net_nfc_error_e net_nfc_util_handover_bt_create_record_from_config(
	ndef_record_s **record, net_nfc_carrier_config_s *config);

net_nfc_error_e net_nfc_util_handover_bt_create_config_from_record(
	net_nfc_carrier_config_s **config, ndef_record_s *record);


/* Wifi protected setup */
bool net_nfc_util_handover_wps_check_carrier_record(ndef_record_s *record);

net_nfc_error_e net_nfc_util_handover_wps_create_record_from_config(
	ndef_record_s **record, net_nfc_carrier_config_s *config);

net_nfc_error_e net_nfc_util_handover_wps_create_config_from_record(
	net_nfc_carrier_config_s **config, ndef_record_s *record);

/* Wifi direct setup */
bool net_nfc_util_handover_wfd_check_carrier_record(ndef_record_s *record);

net_nfc_error_e net_nfc_util_handover_wfd_create_record_from_config(
	ndef_record_s **record, net_nfc_carrier_config_s *config);

net_nfc_error_e net_nfc_util_handover_wfd_create_config_from_record(
	net_nfc_carrier_config_s **config, ndef_record_s *record);

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_UTIL_HANDOVER_INTERNAL_H__
