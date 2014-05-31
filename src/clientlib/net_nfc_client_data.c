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

#include <string.h>

#include "net_nfc_data.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_util_private.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_data_only(data_h* data)
{
	return net_nfc_create_data(data, NULL, 0);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_create_data(data_h* data, const uint8_t* bytes, const uint32_t length)
{
	data_s *data_private = NULL;

	if (data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_alloc_mem(data_private, sizeof(data_s));
	if (data_private == NULL)
		return NET_NFC_ALLOC_FAIL;

	if (length > 0)
	{
		_net_nfc_util_alloc_mem(data_private->buffer, length);
		if (data_private->buffer == NULL)
		{
			_net_nfc_util_free_mem(data_private);
			return NET_NFC_ALLOC_FAIL;
		}

		data_private->length = length;

		if (bytes != NULL)
		{
			memcpy(data_private->buffer, bytes, length);
		}
	}

	*data = (data_h)data_private;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_data(const data_h data, uint8_t** bytes, uint32_t * length)
{
	if (data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	data_s * data_private = (data_s *)data;

	*bytes = data_private->buffer;
	*length = data_private->length;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_data(const data_h data, const uint8_t* bytes, const uint32_t length)
{
	if (data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	data_s * data_private = (data_s *)data;

	if (data_private->buffer == bytes && data_private->length == length)
	{
		return NET_NFC_OK;
	}

	if (data_private->buffer != NULL)
	{
		_net_nfc_util_free_mem(data_private->buffer);
	}

	if (length <= 0)
	{
		data_private->buffer = NULL;
		data_private->length = 0;
		return NET_NFC_OK;
	}

	if (length > 0)
	{
		_net_nfc_util_alloc_mem((data_private)->buffer, length);
	}

	if (bytes != NULL)
	{
		memcpy(data_private->buffer, bytes, length);
	}

	data_private->length = length;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API uint32_t net_nfc_get_data_length(const data_h data)
{
	if (data == NULL)
	{
		return 0;
	}
	data_s * data_private = (data_s *)data;

	return data_private->length;
}

NET_NFC_EXPORT_API uint8_t * net_nfc_get_data_buffer(const data_h data)
{
	if (data == NULL)
	{
		return NULL;
	}
	data_s * data_private = (data_s *)data;

	return data_private->buffer;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_free_data(data_h data)
{
	if (data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	data_s * data_private = (data_s *)data;

	if (data_private->buffer != NULL)
	{
		_net_nfc_util_free_mem(data_private->buffer);
	}
	_net_nfc_util_free_mem(data_private);

	return NET_NFC_OK;
}

