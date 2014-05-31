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

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>

#include "net_nfc_debug_private.h"

int net_nfc_util_get_va_list_length(va_list list)
{
	int length = 0;

	while (va_arg(list, void *) != 0)
	{
		length += (sizeof(int) + va_arg(list, int));
	}

	return length;
}

int net_nfc_util_fill_va_list(uint8_t *buffer, int length, va_list list)
{
	uint8_t *data = NULL;
	int len = 0;
	int current = 0;

	while (current < length && (data = va_arg(list, void *)) != NULL)
	{
		if ((len = va_arg(list, int)) > 0)
		{
			memcpy(buffer + current, &len, sizeof(len));
			current += sizeof(len);

			memcpy(buffer + current, data, len);
			current += len;
		}
	}

	return current;
}

void net_nfc_util_set_non_block_socket(int socket)
{
	DEBUG_SERVER_MSG("set non block socket");

	int flags = fcntl(socket, F_GETFL);
	flags |= O_NONBLOCK;

	if (fcntl(socket, F_SETFL, flags) < 0)
	{
		DEBUG_ERR_MSG("fcntl, executing nonblock error");
	}
}
