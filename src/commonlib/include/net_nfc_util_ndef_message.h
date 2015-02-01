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

#ifndef __NET_NFC_UTIL_NDEF_MESSAGE_H__
#define __NET_NFC_UTIL_NDEF_MESSAGE_H__

#include "net_nfc_typedef_internal.h"

/**
 * \brief These are the flags specifying the content, structure or purpose of a NDEF Record.
 * \name NDEF Record Header Flags
 *
 * Flags of the first record byte, as defined by the NDEF specification.
 *
 */
/*@{*/
#define NET_NFC_NDEF_RECORD_MASK_MB		0x80	/**< This marks the begin of a NDEF Message. */
#define NET_NFC_NDEF_RECORD_MASK_ME		0x40	/**< Set if the record is at the Message End. */
#define NET_NFC_NDEF_RECORD_MASK_CF		0x20	/**< Chunk Flag: The record is a record chunk only. */
#define NET_NFC_NDEF_RECORD_MASK_SR		0x10	/**< Short Record: Payload Length is encoded in ONE byte only. */
#define NET_NFC_NDEF_RECORD_MASK_IL		0x08	/**< The ID Length Field is present. */
#define NET_NFC_NDEF_RECORD_MASK_TNF		0x07	/**< Type Name Format. */
/*@}*/

/* Internal:
 * NDEF Record #defines for constant value
 */

#define NET_NFC_NDEF_TNF_EMPTY			0x00	/**< Empty Record, no type, ID or payload present. */
#define NET_NFC_NDEF_TNF_NFCWELLKNOWN		0x01	/**< NFC well-known type (RTD). */
#define NET_NFC_NDEF_TNF_MEDIATYPE		0x02	/**< Media Type. */
#define NET_NFC_NDEF_TNF_ABSURI			0x03	/**< Absolute URI. */
#define NET_NFC_NDEF_TNF_NFCEXT			0x04	/**< Nfc External Type (following the RTD format). */
#define NET_NFC_NDEF_TNF_UNKNOWN		0x05	/**< Unknown type; Contains no Type information. */
#define NET_NFC_NDEF_TNF_UNCHANGED		0x06	/**< Unchanged: Used for Chunked Records. */
#define NET_NFC_NDEF_TNF_RESERVED		0x07	/**< RFU, must not be used. */

typedef void (*net_nfc_foreach_ndef_records_cb)(ndef_record_s *record,
	void *user_data);
/*
 convert rawdata into ndef message structure
 */
net_nfc_error_e net_nfc_util_convert_rawdata_to_ndef_message(data_s *rawdata, ndef_message_s *ndef);

/*
 this util function converts into rawdata from ndef message structure
 */
net_nfc_error_e net_nfc_util_convert_ndef_message_to_rawdata(ndef_message_s *ndef, data_s *rawdata);

/*
 get total bytes of ndef message in serial form
 */
uint32_t net_nfc_util_get_ndef_message_length(ndef_message_s *message);

/*
 free ndef message. this function also free any defined buffer insdie structures
 */
net_nfc_error_e net_nfc_util_free_ndef_message(ndef_message_s *msg);

/*
 append record into ndef message
 */
net_nfc_error_e net_nfc_util_append_record(ndef_message_s *msg, ndef_record_s *record);

/*
 print out ndef structure value with printf function. this is for just debug purpose
 */
void net_nfc_util_print_ndef_message(ndef_message_s *msg);

net_nfc_error_e net_nfc_util_create_ndef_message(ndef_message_s **ndef_message);

net_nfc_error_e net_nfc_util_search_record_by_type(ndef_message_s *ndef_message, net_nfc_record_tnf_e tnf, data_s *type, ndef_record_s **record);

net_nfc_error_e net_nfc_util_append_record_by_index(ndef_message_s *ndef_message, int index, ndef_record_s *record);

net_nfc_error_e net_nfc_util_get_record_by_index(ndef_message_s *ndef_message, int index, ndef_record_s **record);

net_nfc_error_e net_nfc_util_remove_record_by_index(ndef_message_s *ndef_message, int index);

net_nfc_error_e net_nfc_util_search_record_by_id(ndef_message_s *ndef_message, data_s *id, ndef_record_s **record);

void net_nfc_util_foreach_ndef_records(ndef_message_s *msg,
	net_nfc_foreach_ndef_records_cb func, void *user_data);

net_nfc_error_e net_nfc_util_check_ndef_message_rawdata(data_s *rawdata);

#endif //__NET_NFC_UTIL_NDEF_MESSAGE_H__
