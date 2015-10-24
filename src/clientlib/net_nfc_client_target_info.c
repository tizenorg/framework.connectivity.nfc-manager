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

#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_data.h"
#include "net_nfc_target_info.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_ndef_message.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_tag_type(net_nfc_target_info_h target_info,
	net_nfc_target_type_e *type)
{
	net_nfc_target_info_s *target_info_private =
		(net_nfc_target_info_s *)target_info;

	if (type == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*type = NET_NFC_UNKNOWN_TARGET;

	if (target_info == NULL)
	{
		return NET_NFC_INVALID_HANDLE;
	}

	*type = target_info_private->devType;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_tag_handle(net_nfc_target_info_h target_info,
	net_nfc_target_handle_h *handle)
{
	net_nfc_target_info_s *target_info_private =
		(net_nfc_target_info_s *)target_info;

	if (handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*handle = NULL;

	if (target_info == NULL)
	{
		return NET_NFC_INVALID_HANDLE;
	}

	*handle = (net_nfc_target_handle_h)target_info_private->handle;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_tag_ndef_support(net_nfc_target_info_h target_info,
	bool *is_support)
{
	net_nfc_target_info_s *target_info_private =
		(net_nfc_target_info_s *)target_info;

	if (target_info == NULL || is_support == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*is_support = (bool)target_info_private->is_ndef_supported;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_tag_ndef_state(net_nfc_target_info_h target_info,
	net_nfc_ndef_card_state_e *state)
{
	net_nfc_target_info_s *target_info_private =
		(net_nfc_target_info_s *)target_info;

	if (target_info == NULL || state == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*state = (net_nfc_ndef_card_state_e)target_info_private->ndefCardState;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_tag_max_data_size(net_nfc_target_info_h target_info,
	uint32_t *max_size)
{
	net_nfc_target_info_s *target_info_private =
		(net_nfc_target_info_s *)target_info;

	if (target_info == NULL || max_size == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*max_size = target_info_private->maxDataSize;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_tag_actual_data_size(
	net_nfc_target_info_h target_info, uint32_t * actual_data)
{
	net_nfc_target_info_s *target_info_private =
		(net_nfc_target_info_s *)target_info;

	if (target_info == NULL || actual_data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	*actual_data = target_info_private->actualDataSize;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_tag_info_keys(net_nfc_target_info_h target_info,
	char ***keys, int * number_of_keys)
{
	net_nfc_target_info_s *handle = (net_nfc_target_info_s *)target_info;
	int i = 0;

	if (keys == NULL || number_of_keys == NULL || target_info == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (handle->tag_info_list == NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	if (handle->number_of_keys <= 0)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	DEBUG_CLIENT_MSG("number of keys = [%d]", handle->number_of_keys);

	if (handle->keylist != NULL)
	{
		*number_of_keys = handle->number_of_keys;
		*keys = handle->keylist;

		return NET_NFC_OK;
	}

	i = handle->number_of_keys * sizeof(char *);

	_net_nfc_util_alloc_mem(*keys, i);
	if (*keys == NULL)
		return NET_NFC_ALLOC_FAIL;

	net_nfc_tag_info_s *tag_info = handle->tag_info_list;

	for (; i < handle->number_of_keys; i++, tag_info++)
	{
		(*keys)[i] = tag_info->key;
	}

	*number_of_keys = handle->number_of_keys;

	/* store local context */
	handle->keylist = *keys;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_tag_info_value(net_nfc_target_info_h target_info,
	const char *key, data_h *value)
{
	net_nfc_target_info_s *handle = (net_nfc_target_info_s *)target_info;
	net_nfc_tag_info_s *tag_info;

	if (target_info == NULL || key == NULL || value == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (handle->tag_info_list == NULL)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	int i = 0;

	tag_info = handle->tag_info_list;

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
		return NET_NFC_NO_DATA_FOUND;

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_get_tag_ndef_message(net_nfc_target_info_h target_info,
	ndef_message_h *msg)
{
	net_nfc_target_info_s *target_info_private =
		(net_nfc_target_info_s *)target_info;
	net_nfc_error_e result;

	if (target_info == NULL || msg == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	result = net_nfc_create_ndef_message_from_rawdata(msg,
		(data_h)&target_info_private->raw_data);

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_duplicate_target_info(net_nfc_target_info_h origin,
	net_nfc_target_info_h *result)
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

	if (handle->raw_data.length > 0)
	{
		net_nfc_util_init_data(&temp->raw_data, handle->raw_data.length);
		memcpy(temp->raw_data.buffer, handle->raw_data.buffer, temp->raw_data.length);
	}

	*result = (net_nfc_target_info_h)temp;

	return NET_NFC_OK;
}

static net_nfc_error_e _release_tag_info(net_nfc_target_info_s *info)
{
	net_nfc_tag_info_s *list = NULL;

	if (info == NULL)
		return NET_NFC_NULL_PARAMETER;

	list = info->tag_info_list;
	if (list != NULL)
	{
		int i;

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

	net_nfc_util_clear_data(&info->raw_data);

	return NET_NFC_OK;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_release_tag_info(net_nfc_target_info_h target_info)
{
	net_nfc_target_info_s *info = (net_nfc_target_info_s *)target_info;
	net_nfc_error_e result;

	if (info == NULL)
		return NET_NFC_NULL_PARAMETER;

	result = _release_tag_info(info);

	_net_nfc_util_free_mem(info);

	return result;
}
