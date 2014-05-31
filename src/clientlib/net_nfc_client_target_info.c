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

#include <stdbool.h>

#include "net_nfc_typedef_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_data.h"
#include "net_nfc_target_info.h"
#include "net_nfc_util_private.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_tag_type(net_nfc_target_info_h target_info, net_nfc_target_type_e * type)
{
	if (target_info == NULL || type == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_target_info_s * target_info_private = (net_nfc_target_info_s*)target_info;

	*type = target_info_private->devType;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_tag_handle(net_nfc_target_info_h target_info, net_nfc_target_handle_h * handle)
{
	if (target_info == NULL || handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_target_info_s * target_info_private = (net_nfc_target_info_s*)target_info;

	*handle = (net_nfc_target_handle_h)target_info_private->handle;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_tag_ndef_support(net_nfc_target_info_h target_info, bool * is_support)
{
	if (target_info == NULL || is_support == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_target_info_s * target_info_private = (net_nfc_target_info_s*)target_info;

	*is_support = (bool)target_info_private->is_ndef_supported;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_tag_max_data_size(net_nfc_target_info_h target_info, uint32_t * max_size)
{
	if (target_info == NULL || max_size == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_target_info_s * target_info_private = (net_nfc_target_info_s*)target_info;

	*max_size = target_info_private->maxDataSize;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_tag_actual_data_size(net_nfc_target_info_h target_info, uint32_t * actual_data)
{
	if (target_info == NULL || actual_data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}
	net_nfc_target_info_s * target_info_private = (net_nfc_target_info_s*)target_info;

	*actual_data = target_info_private->actualDataSize;
	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_tag_info_keys(net_nfc_target_info_h target_info, char ***keys, int* number_of_keys)
{
	if (keys == NULL || number_of_keys == NULL || target_info == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_target_info_s* handle = (net_nfc_target_info_s*)target_info;

	if (handle->tag_info_list == NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	if (handle->number_of_keys <= 0)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	int i = 0;

	if (handle->keylist != NULL)
	{
		*keys = handle->keylist;
		return NET_NFC_OK;
	}

	_net_nfc_util_alloc_mem(*keys, handle->number_of_keys * sizeof(char *));
	if (*keys == NULL)
		return NET_NFC_ALLOC_FAIL;

	net_nfc_tag_info_s* tag_info = handle->tag_info_list;

	for (; i < handle->number_of_keys; i++, tag_info++)
	{
		(*keys)[i] = tag_info->key;
	}

	*number_of_keys = handle->number_of_keys;

	DEBUG_CLIENT_MSG("number of keys = [%d]", handle->number_of_keys);

	handle->keylist = *keys;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_tag_info_value(net_nfc_target_info_h target_info, const char* key, data_h* value)
{
	if (target_info == NULL || key == NULL || value == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	net_nfc_target_info_s* handle = (net_nfc_target_info_s*)target_info;

	if (handle->tag_info_list == NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	int i = 0;

	net_nfc_tag_info_s* tag_info = handle->tag_info_list;

	for (; i < handle->number_of_keys; i++, tag_info++)
	{
		if (strcmp(key, tag_info->key) == 0)
		{
			if (tag_info->value == NULL)
			{
				return NET_NFC_NO_DATA_FOUND;
			}
			else
			{
				*value = tag_info->value;
				break;
			}
		}
	}

	if (i == handle->number_of_keys)
		return NET_NFC_NOT_SUPPORTED;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_duplicate_target_info(net_nfc_target_info_h origin, net_nfc_target_info_h *result)
{
	net_nfc_target_info_s *handle = (net_nfc_target_info_s *)origin;
	net_nfc_target_info_s *temp = NULL;

	if (handle == NULL || result == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_alloc_mem(temp, sizeof(net_nfc_target_info_s));
	if (temp == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	temp->ndefCardState = handle->ndefCardState;
	temp->actualDataSize = handle->actualDataSize;
	temp->maxDataSize = handle->maxDataSize;
	temp->devType = handle->devType;
	temp->handle = handle->handle;
	temp->is_ndef_supported = handle->is_ndef_supported;
	temp->number_of_keys = handle->number_of_keys;

	if (temp->number_of_keys > 0)
	{
		int i;

		_net_nfc_util_alloc_mem(temp->tag_info_list, temp->number_of_keys * sizeof(net_nfc_tag_info_s));
		if (temp->tag_info_list == NULL)
		{
			_net_nfc_util_free_mem(temp);
			return NET_NFC_ALLOC_FAIL;
		}

		for (i = 0; i < handle->number_of_keys; i++)
		{
			if (handle->tag_info_list[i].key != NULL)
				_net_nfc_util_strdup(temp->tag_info_list[i].key, handle->tag_info_list[i].key);

			if (handle->tag_info_list[i].value != NULL)
			{
				data_s *data = (data_s *)handle->tag_info_list[i].value;

				net_nfc_create_data(&temp->tag_info_list[i].value, data->buffer, data->length);
			}
		}
	}

	if (handle->raw_data.buffer != NULL && handle->raw_data.length > 0)
	{
		net_nfc_util_alloc_data(&temp->raw_data, handle->raw_data.length);
		memcpy(temp->raw_data.buffer, handle->raw_data.buffer, temp->raw_data.length);
	}

	*result = (net_nfc_target_info_h)temp;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_release_tag_info(net_nfc_target_info_s *info)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_tag_info_s *list = NULL;

	if (info == NULL)
		return NET_NFC_NULL_PARAMETER;

	list = info->tag_info_list;
	if (list != NULL)
	{
		int i = 0;
		for (i = 0; i < info->number_of_keys; i++, list++)
		{
			if (list->key != NULL)
				_net_nfc_util_free_mem(list->key);

			if (list->value != NULL)
				net_nfc_free_data(list->value);
		}

		_net_nfc_util_free_mem(info->tag_info_list);
	}

	if (info->keylist != NULL)
	{
		_net_nfc_util_free_mem(info->keylist);
	}

	net_nfc_util_free_data(&info->raw_data);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_release_tag_info(net_nfc_target_info_h target_info)
{
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_target_info_s *info = (net_nfc_target_info_s *)target_info;

	if (info == NULL)
		return NET_NFC_NULL_PARAMETER;

	net_nfc_util_release_tag_info(info);

	_net_nfc_util_free_mem(info);

	return result;
}
