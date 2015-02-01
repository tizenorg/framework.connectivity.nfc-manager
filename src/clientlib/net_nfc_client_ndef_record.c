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

#include "net_nfc_ndef_record.h"
#include "net_nfc_ndef_message.h"
#include "net_nfc_data.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_ndef_record.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_record(ndef_record_h *record,
	net_nfc_record_tnf_e tnf, data_h typeName, data_h id, data_h payload)
{
	return net_nfc_util_create_record(tnf, (data_s *)typeName,
		(data_s *)id, (data_s *)payload, (ndef_record_s **)record);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_text_type_record(ndef_record_h *record,
	const char *text, const char *language_code_str,
	net_nfc_encode_type_e encode)
{
	return net_nfc_util_create_text_type_record(text, language_code_str,
		encode, (ndef_record_s **)record);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_uri_type_record(ndef_record_h *record,
	const char *uri, net_nfc_schema_type_e protocol_schema)
{
	return net_nfc_util_create_uri_type_record(uri, protocol_schema,
		(ndef_record_s **)record);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_free_record(ndef_record_h record)
{
	return net_nfc_util_free_record((ndef_record_s *)record);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_record_payload(ndef_record_h record,
	data_h *payload)
{
	ndef_record_s *struct_record = (ndef_record_s *)record;

	if (record == NULL || payload == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*payload = (data_h)&(struct_record->payload_s);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_record_type(ndef_record_h record, data_h *type)
{
	ndef_record_s *struct_record = (ndef_record_s *)record;

	if (record == NULL || type == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*type = (data_h)&(struct_record->type_s);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_record_id(ndef_record_h record, data_h *id)
{
	ndef_record_s *struct_record = (ndef_record_s *)record;

	if (record == NULL || id == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*id = (data_h)&(struct_record->id_s);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_record_tnf(ndef_record_h record,
	net_nfc_record_tnf_e *TNF)
{
	ndef_record_s *struct_record = (ndef_record_s *)record;

	if (record == NULL || TNF == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*TNF = (net_nfc_record_tnf_e)struct_record->TNF;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_set_record_id(ndef_record_h record, data_h id)
{
	data_s *tmp_id = (data_s *)id;

	if (record == NULL || tmp_id == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	return net_nfc_util_set_record_id((ndef_record_s *)record,
		tmp_id->buffer, tmp_id->length);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_record_flags(ndef_record_h record, uint8_t *flag)
{
	ndef_record_s *struct_record = (ndef_record_s *)record;

	if (record == NULL || flag == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*flag = struct_record->MB;
	*flag <<= 1;
	*flag += struct_record->ME;
	*flag <<= 1;
	*flag += struct_record->CF;
	*flag <<= 1;
	*flag += struct_record->SR;
	*flag <<= 1;
	*flag += struct_record->IL;
	*flag <<= 3;
	*flag += struct_record->TNF;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API uint8_t net_nfc_get_record_mb(uint8_t flag)
{
	return ((flag >> 7) & 0x01);
}

NET_NFC_EXPORT_API uint8_t net_nfc_get_record_me(uint8_t flag)
{
	return ((flag >> 6) & 0x01);
}

NET_NFC_EXPORT_API uint8_t net_nfc_get_record_cf(uint8_t flag)
{
	return ((flag >> 5) & 0x01);
}

NET_NFC_EXPORT_API uint8_t net_nfc_get_record_sr(uint8_t flag)
{
	return ((flag >> 4) & 0x01);
}

NET_NFC_EXPORT_API uint8_t net_nfc_get_record_il(uint8_t flag)
{
	return ((flag >> 3) & 0x01);
}

static bool _is_text_record(ndef_record_h record)
{
	bool result = false;
	data_h type;

	if ((net_nfc_get_record_type(record, &type) == NET_NFC_OK) &&
		(strncmp((char *)net_nfc_get_data_buffer(type),
			TEXT_RECORD_TYPE,
			net_nfc_get_data_length(type)) == 0))
		result = true;

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_text_string_from_text_record(
	ndef_record_h record, char **buffer)
{
	net_nfc_error_e result;
	data_h payload;

	if (record == NULL || buffer == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*buffer = NULL;

	if (_is_text_record(record) == false)
	{
		DEBUG_ERR_MSG("record type is not matched");

		return NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE;
	}

	result = net_nfc_get_record_payload(record, &payload);
	if (result == NET_NFC_OK)
	{
		uint8_t *buffer_temp = net_nfc_get_data_buffer(payload);
		uint32_t buffer_length = net_nfc_get_data_length(payload);

		int controllbyte = buffer_temp[0];
		int lang_code_length = controllbyte & 0x3F;
		int index = lang_code_length + 1;
		int text_length = buffer_length - (lang_code_length + 1);

		char *temp = NULL;

		_net_nfc_util_alloc_mem(temp, text_length + 1);
		if (temp != NULL)
		{
			memcpy(temp, &(buffer_temp[index]), text_length);

			DEBUG_CLIENT_MSG("text = [%s]", temp);

			*buffer = temp;
		}
		else
		{
			result = NET_NFC_ALLOC_FAIL;
		}
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_languange_code_string_from_text_record(
	ndef_record_h record, char **lang_code_str)
{
	net_nfc_error_e result;
	data_h payload;

	if (record == NULL || lang_code_str == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*lang_code_str = NULL;

	if (_is_text_record(record) == false)
	{
		DEBUG_ERR_MSG("record type is not matched");

		return NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE;
	}

	result = net_nfc_get_record_payload(record, &payload);
	if (result == NET_NFC_OK)
	{
		uint8_t *buffer_temp = net_nfc_get_data_buffer(payload);
		char *buffer = NULL;

		int controllbyte = buffer_temp[0];
		int lang_code_length = controllbyte & 0x3F;
		int index = 1;

		_net_nfc_util_alloc_mem(buffer, lang_code_length + 1);
		if (buffer != NULL)
		{
			memcpy(buffer, &(buffer_temp[index]), lang_code_length);

			DEBUG_CLIENT_MSG("language code = [%s]", buffer);

			*lang_code_str = buffer;
		}
		else
		{
			result = NET_NFC_ALLOC_FAIL;
		}
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_encoding_type_from_text_record(ndef_record_h record,
	net_nfc_encode_type_e *encoding)
{
	net_nfc_error_e result;
	data_h payload;

	if (record == NULL || encoding == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*encoding = NET_NFC_ENCODE_UTF_8;

	if (_is_text_record(record) == false)
	{
		DEBUG_ERR_MSG("record type is not matched");

		return NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE;
	}

	result = net_nfc_get_record_payload(record, &payload);
	if (result == NET_NFC_OK)
	{
		uint8_t *buffer_temp = net_nfc_get_data_buffer(payload);

		int controllbyte = buffer_temp[0];

		if ((controllbyte & 0x80) == 0x80)
		{
			*encoding = NET_NFC_ENCODE_UTF_16;
		}
	}

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_create_uri_string_from_uri_record(ndef_record_h record,
	char **uri)
{
	return net_nfc_util_create_uri_string_from_uri_record(
		(ndef_record_s *)record, uri);
}
