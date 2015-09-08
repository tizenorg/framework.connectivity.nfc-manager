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
#ifndef __NET_NFC_UTIL_NDEF_RECORD_H__
#define __NET_NFC_UTIL_NDEF_RECORD_H__

#include "net_nfc_typedef_internal.h"

/*
 create record structure with basic info
 */
net_nfc_error_e net_nfc_util_create_record(net_nfc_record_tnf_e recordType, data_s *typeName, data_s *id, data_s *payload, ndef_record_s **record);

/*
 create text type record
 */
net_nfc_error_e net_nfc_util_create_text_type_record(const char *text, const char *lang_code_str, net_nfc_encode_type_e encode, ndef_record_s **record);

/*
 this utility function help to create uri type record
 */
net_nfc_error_e net_nfc_util_create_uri_type_record(const char *uri, net_nfc_schema_type_e protocol_schema, ndef_record_s **record);

/*
 free ndef record. it free all the buffered data
 */
net_nfc_error_e net_nfc_util_free_record(ndef_record_s *record);

/*
 convert schema enum value to character string.
 */
net_nfc_error_e net_nfc_util_set_record_id(ndef_record_s *record, uint8_t *data, int length);

/*
 get total bytes of ndef record in serial form
 */
uint32_t net_nfc_util_get_record_length(ndef_record_s *record);

/*
 create uri string from record
 */
net_nfc_error_e net_nfc_util_create_uri_string_from_uri_record(ndef_record_s *record, char **uri);

#endif //__NET_NFC_UTIL_NDEF_RECORD_H__
