/*
  * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
  *
  * Licensed under the Flora License, Version 1.1 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://floralicense.org/license/
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */


#include "net_nfc_util_sign_record.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_sign_records(ndef_message_h msg, int begin_index, int end_index, char *cert_file, char *password)
{
	return net_nfc_util_sign_records((ndef_message_s *)msg, begin_index, end_index, cert_file, password);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_sign_ndef_message(ndef_message_h msg, char *cert_file, char *password)
{
	return net_nfc_util_sign_ndef_message((ndef_message_s *)msg, cert_file, password);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_verify_signature_ndef_message(ndef_message_h msg)
{
	return net_nfc_util_verify_signature_ndef_message((ndef_message_s *)msg);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_verify_signature_records(ndef_record_h begin_record, ndef_record_h sign_record)
{
	return net_nfc_util_verify_signature_records((ndef_record_s *)begin_record, (ndef_record_s *)sign_record);
}
