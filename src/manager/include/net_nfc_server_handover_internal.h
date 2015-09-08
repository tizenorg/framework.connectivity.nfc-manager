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

#ifndef __NET_NFC_SERVER_HANDOVER_INTERNAL_H__
#define __NET_NFC_SERVER_HANDOVER_INTERNAL_H__

#include "net_nfc_typedef_internal.h"

typedef void (*net_nfc_server_handover_get_carrier_cb)(
	net_nfc_error_e result,
	net_nfc_ch_carrier_s *carrier,
	void *user_param);

typedef void (*net_nfc_server_handover_process_carrier_cb)(
	net_nfc_error_e result,
	net_nfc_conn_handover_carrier_type_e type,
	data_s *data,
	void *user_param);

typedef struct _ch_hc_record_t
{
	uint8_t rfu : 5;
	uint8_t ctf : 3;
	uint8_t type_len;
	uint8_t type[0];
}
__attribute__((packed)) ch_hc_record_t;


/* alternative carrier functions */
/* bluetooth */
net_nfc_error_e net_nfc_server_handover_bt_get_carrier(
	net_nfc_server_handover_get_carrier_cb cb, void *user_param);

net_nfc_error_e net_nfc_server_handover_bt_prepare_pairing(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_server_handover_process_carrier_cb cb,
	void *user_param);

net_nfc_error_e net_nfc_server_handover_bt_do_pairing(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_server_handover_process_carrier_cb cb,
	void *user_param);

/* Wifi protected setup */
net_nfc_error_e net_nfc_server_handover_wps_get_selector_carrier(
	net_nfc_server_handover_get_carrier_cb cb,
	void *user_param);

net_nfc_error_e net_nfc_server_handover_wps_get_requester_carrier(
	net_nfc_server_handover_get_carrier_cb cb,
	void *user_param);

net_nfc_error_e net_nfc_server_handover_wps_do_connect(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_server_handover_process_carrier_cb cb,
	void *user_param);

/* wifi-direct */
net_nfc_error_e net_nfc_server_handover_wfd_do_pairing(
	net_nfc_ch_carrier_s *carrier,
	net_nfc_server_handover_process_carrier_cb cb,
	void *user_param);


#endif //__NET_NFC_SERVER_HANDOVER_INTERNAL_H__
