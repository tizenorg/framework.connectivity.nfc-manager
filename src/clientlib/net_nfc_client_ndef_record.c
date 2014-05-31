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
#include "net_nfc_debug_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_ndef_record.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_record(ndef_record_h* record, net_nfc_record_tnf_e tnf, data_h typeName, data_h id, data_h payload)
{
	return net_nfc_util_create_record(tnf, (data_s*)typeName, (data_s*)id, (data_s*)payload, (ndef_record_s**)record);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_text_type_record(ndef_record_h* record, const char* text, const char* language_code_str, net_nfc_encode_type_e encode)
{
	return net_nfc_util_create_text_type_record(text, language_code_str, encode, (ndef_record_s**)record);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_uri_type_record(ndef_record_h* record, const char* uri, net_nfc_schema_type_e protocol_schema)
{
	return net_nfc_util_create_uri_type_record(uri, protocol_schema, (ndef_record_s**)record);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_free_record(ndef_record_h record)
{
	return net_nfc_util_free_record((ndef_record_s*)record);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_record_payload(ndef_record_h record, data_h * payload)
{
	if (record == NULL || payload == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	ndef_record_s * struct_record = (ndef_record_s *)record;

	*payload = (data_h)&(struct_record->payload_s);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_record_type(ndef_record_h record, data_h * type)
{
	if (record == NULL || type == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	ndef_record_s * struct_record = (ndef_record_s *)record;

	*type = (data_h)&(struct_record->type_s);

	return NET_NFC_OK;

}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_record_id(ndef_record_h record, data_h * id)
{
	if (record == NULL || id == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	ndef_record_s * struct_record = (ndef_record_s *)record;

	*id = (data_h)&(struct_record->id_s);

	return NET_NFC_OK;

}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_record_tnf(ndef_record_h record, net_nfc_record_tnf_e * TNF)
{
	if (record == NULL || TNF == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	ndef_record_s * struct_record = (ndef_record_s *)record;

	*TNF = (net_nfc_record_tnf_e)struct_record->TNF;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_record_id(ndef_record_h record, data_h id)
{

	ndef_record_s * record_private = (ndef_record_s *)record;
	data_s * id_private = (data_s *)id;

	if (id_private == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	return net_nfc_util_set_record_id(record_private, id_private->buffer, id_private->length);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_record_flags(ndef_record_h record, uint8_t * flag)
{
	if (record == NULL || flag == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	ndef_record_s * struct_record = (ndef_record_s *)record;

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
	return (flag & 0x80) >> 7;
}

NET_NFC_EXPORT_API uint8_t net_nfc_get_record_me(uint8_t flag)
{
	return (flag & 0x40) >> 6;
}

NET_NFC_EXPORT_API uint8_t net_nfc_get_record_cf(uint8_t flag)
{
	return (flag & 0x20) >> 5;
}

NET_NFC_EXPORT_API uint8_t net_nfc_get_record_il(uint8_t flag)
{
	return (flag & 0x10) >> 4;
}

NET_NFC_EXPORT_API uint8_t net_nfc_get_record_sr(uint8_t flag)
{
	return (flag & 0x08) >> 3;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_text_string_from_text_record(ndef_record_h record, char** buffer)
{
	if (record == NULL || buffer == NULL)
		return NET_NFC_ALLOC_FAIL;

	data_h payload;
	data_h rec_type;

	if (net_nfc_get_record_type(record, &rec_type) == NET_NFC_OK)
	{
		if (strncmp((char *)net_nfc_get_data_buffer(rec_type), TEXT_RECORD_TYPE, 1) != 0)
		{
			DEBUG_CLIENT_MSG("record type is not matched");
			return NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE;
		}
	}

	if (net_nfc_get_record_payload(record, &payload) == NET_NFC_OK)
	{
		uint8_t *buffer_temp;
		uint32_t buffer_length = net_nfc_get_data_length(payload);

		buffer_temp = net_nfc_get_data_buffer(payload);
		if (NULL == buffer_temp)
			return NET_NFC_NO_DATA_FOUND;

		int controllbyte = buffer_temp[0];
		int lang_code_length = controllbyte & 0x3F;
		int index = lang_code_length + 1;
		int text_length = buffer_length - (lang_code_length + 1);

		if ((*buffer = (char *)calloc(1, text_length + 1)) != NULL)
		{
			memcpy(*buffer, &(buffer_temp[index]), text_length);
			DEBUG_CLIENT_MSG("text = [%s]", *buffer);
		}
		else
		{
			return NET_NFC_ALLOC_FAIL;
		}
	}

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_languange_code_string_from_text_record(ndef_record_h record, char** lang_code_str)
{
	if (record == NULL || lang_code_str == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	data_h payload;
	data_h rec_type;

	if (net_nfc_get_record_type(record, &rec_type) == NET_NFC_OK)
	{
		if (strncmp((char *)net_nfc_get_data_buffer(rec_type), TEXT_RECORD_TYPE, 1) != 0)
		{
			DEBUG_CLIENT_MSG("record type is not matched");
			return NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE;
		}
	}

	if (net_nfc_get_record_payload(record, &payload) == NET_NFC_OK)
	{
		char *buffer = NULL;
		uint8_t *buffer_temp;

		buffer_temp = net_nfc_get_data_buffer(payload);
		if (NULL == buffer_temp)
			return NET_NFC_NO_DATA_FOUND;

		int controllbyte = buffer_temp[0];
		int lang_code_length = controllbyte & 0x3F;
		int index = 1;

		if ((buffer = (char *)calloc(1, lang_code_length + 1)) != NULL)
		{
			memcpy(buffer, &(buffer_temp[index]), lang_code_length);
			DEBUG_CLIENT_MSG("language code = [%s]", buffer);

			*lang_code_str = buffer;
		}
		else
		{
			return NET_NFC_ALLOC_FAIL;
		}
	}

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_encoding_type_from_text_record(ndef_record_h record, net_nfc_encode_type_e * encoding)
{
	if (record == NULL || encoding == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	data_h payload;
	data_h rec_type;

	if (net_nfc_get_record_type(record, &rec_type) == NET_NFC_OK)
	{
		if (strncmp((char *)net_nfc_get_data_buffer(rec_type), TEXT_RECORD_TYPE, 1) != 0)
		{
			DEBUG_CLIENT_MSG("record type is not matched");
			return NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE;
		}
	}

	if (net_nfc_get_record_payload(record, &payload) == NET_NFC_OK)
	{
		uint8_t *buffer_temp;

		buffer_temp = net_nfc_get_data_buffer(payload);
		if (NULL == buffer_temp)
			return NET_NFC_NO_DATA_FOUND;

		int controllbyte = buffer_temp[0];

		if ((controllbyte & 0x80) == 0x80)
		{
			*encoding = NET_NFC_ENCODE_UTF_16;
		}
		else
		{
			*encoding = NET_NFC_ENCODE_UTF_8;
		}
	}

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_uri_string_from_uri_record(ndef_record_h record, char **uri)
{
	return net_nfc_util_create_uri_string_from_uri_record((ndef_record_s *)record, uri);
}
