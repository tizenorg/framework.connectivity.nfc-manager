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

#ifndef __NET_NFC_UTIL_HCE_H__
#define __NET_NFC_UTIL_HCE_H__

#include "net_nfc_typedef_internal.h"

#define NET_NFC_HCE_INS_SELECT			(uint8_t)0xA4
#define NET_NFC_HCE_INS_READ_BINARY		(uint8_t)0xB0
#define NET_NFC_HCE_INS_UPDATE_BINARY		(uint8_t)0xD6

#define NET_NFC_HCE_P1_SELECT_BY_FID		(uint8_t)0x00
#define NET_NFC_HCE_P1_SELECT_BY_NAME		(uint8_t)0x04

#define NET_NFC_HCE_P2_SELECT_FIRST_OCC		(uint8_t)0x0C


#define NET_NFC_HCE_SW_SUCCESS			(uint16_t)0x9000
#define NET_NFC_HCE_SW_SUCCESS			(uint16_t)0x9000

#define NET_NFC_HCE_SW_WRONG_LENGTH		(uint16_t)0x6700
#define NET_NFC_HCE_SW_COMMAND_NOT_ALLOWED	(uint16_t)0x6900
#define NET_NFC_HCE_SW_SECURITY_FAILED		(uint16_t)0x6982
#define NET_NFC_HCE_SW_FUNC_NOT_SUPPORTED	(uint16_t)0x6A81
#define NET_NFC_HCE_SW_FILE_NOT_FOUND		(uint16_t)0x6A82
#define NET_NFC_HCE_SW_INCORRECT_P1_TO_P2	(uint16_t)0x6A86
#define NET_NFC_HCE_SW_LC_INCONSIST_P1_TO_P2	(uint16_t)0x6A87
#define NET_NFC_HCE_SW_REF_DATA_NOT_FOUND	(uint16_t)0x6A88
#define NET_NFC_HCE_SW_WRONG_PARAMETER		(uint16_t)0x6B00
#define NET_NFC_HCE_SW_INS_NOT_SUPPORTED	(uint16_t)0x6D00
#define NET_NFC_HCE_SW_CLASS_NOT_SUPPORTED	(uint16_t)0x6E00

#define NET_NFC_HCE_INVALID_VALUE		(uint16_t)0xFFFF

typedef struct _net_nfc_apdu_data_t
{
	uint16_t cla;
	uint16_t ins;
	uint16_t p1;
	uint16_t p2;
	uint16_t lc;
	uint8_t *data;
	uint16_t le;
}
net_nfc_apdu_data_t;


net_nfc_apdu_data_t *net_nfc_util_hce_create_apdu_data();

void net_nfc_util_hce_free_apdu_data(net_nfc_apdu_data_t *apdu_data);

net_nfc_error_e net_nfc_util_hce_extract_parameter(data_s *apdu,
	net_nfc_apdu_data_t *apdu_data);

net_nfc_error_e net_nfc_util_hce_generate_apdu(net_nfc_apdu_data_t *apdu_data,
	data_s **apdu);

#endif //__NET_NFC_UTIL_HCE_H__
