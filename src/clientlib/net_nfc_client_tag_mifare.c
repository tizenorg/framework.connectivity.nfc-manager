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
#include <glib.h>
#include <string.h>

#include "net_nfc_client_transceive.h"
#include "net_nfc_client_tag_internal.h"

#include "net_nfc_tag_mifare.h"

#include "net_nfc_data.h"
#include "net_nfc_typedef_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_target_info.h"
#include "net_nfc_util_internal.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

#define MIFARE_CMD_RAW			0x00U
#define MIFARE_CMD_AUTH_A		0x60U /**< authenticate with key A */
#define MIFARE_CMD_AUTH_B		0x61U /**< authenticate with key B */
#define MIFARE_CMD_READ			0x30U /**< read 16 bytes */
#define MIFARE_CMD_WRITE_BLOCK		0xA0U /**< write 16 bytes */
#define MIFARE_CMD_WRITE_PAGE		0xA2U /**< write 4 bytes */
#define MIFARE_CMD_INCREMENT		0xC1U /**< Increment. */
#define MIFARE_CMD_DECREMENT		0xC0U /**< Decrement. */
#define MIFARE_CMD_TRANSFER		0xB0U /**< Tranfer.   */
#define MIFARE_CMD_RESTORE		0xC2U /**< Restore.   */
#define MIFARE_TAG_KEY	"UID"

#define MIFARE_CMD_READ_SECTOR	0x38U /* read sector */
#define MIFARE_CMD_WRITE_SECTOR	0xA8U /* write sector */

static uint8_t default_key[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static uint8_t mad_key[6] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
static uint8_t net_nfc_forum_key[6] = { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 };

#define MIFARE_BLOCK_4 4
#define MIFARE_BLOCK_16 16

#define MIFARE_MINI_SECTORS 5
#define MIFARE_1K_SECTORS 16
#define MIFARE_4K_SECTORS 40

#define MIFARE_BLOCK_SIZE 16	/* 1 block is 16 byte */
#define MIFARE_PAGE_SIZE 4	/* 1 page is 4 byte */


NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_authenticate_with_keyA(
						net_nfc_target_handle_h handle,
						uint8_t sector,
						data_h auth_key,
						void *callback,
						void *user_data)
{
	net_nfc_target_info_s* target_info = NULL;

	data_s *key;
	data_s rawdata;

	data_h UID = NULL;

	uint8_t* send_buffer = NULL;
	uint8_t* temp = NULL;

	int send_buffer_length = 0;

	uint8_t sector_to_block = 0;


	if (handle == NULL || auth_key == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_client_tag_is_connected() == FALSE)
		return NET_NFC_OPERATION_FAIL;

	key = (data_s *)auth_key;

	if (key->length != 6)
		return NET_NFC_OUT_OF_BOUND;

	target_info = net_nfc_client_tag_get_client_target_info();

	if (target_info)
	{
		if (target_info->devType < NET_NFC_MIFARE_MINI_PICC ||
				target_info->devType > NET_NFC_MIFARE_4K_PICC)
		{
			DEBUG_CLIENT_MSG("not a MIFARE Classic TAG");
			return NET_NFC_NOT_SUPPORTED;
		}
	}

	if (net_nfc_get_tag_info_value((net_nfc_target_info_h)target_info,
					MIFARE_TAG_KEY,
					&UID) != NET_NFC_OK)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	switch (target_info->devType)
	{
	case NET_NFC_MIFARE_MINI_PICC :
		{
			/* 0 ~ 4 : 5 sector and 4 block with 16 bytes */
			if (sector > MIFARE_MINI_SECTORS - 1)
				return NET_NFC_OUT_OF_BOUND;

			sector_to_block = sector * MIFARE_BLOCK_4 + 3;
		}
		break;
	case NET_NFC_MIFARE_1K_PICC :
		{
			/* 0 ~ 15 : 16 sector and 4 block with 16 bytes */
			if (sector > MIFARE_1K_SECTORS)
				return NET_NFC_OUT_OF_BOUND;

			sector_to_block = sector * MIFARE_BLOCK_4 + 3;
		}
		break;
	case NET_NFC_MIFARE_4K_PICC :
		{
			/* 0 ~ 31 : 32 sector and 4 block with 16 bytes
			 * 32 ~ 39 : 8 sector and 16 block with 16 bytes
			 */
			if (sector > MIFARE_4K_SECTORS)
				return NET_NFC_OUT_OF_BOUND;

			if (sector < 32)
				sector_to_block = sector * MIFARE_BLOCK_4 + 3;
			else
			{
				sector_to_block = (31 * MIFARE_BLOCK_4 + 3)
						+ (sector - 32)
						* MIFARE_BLOCK_16 + 15;
			}
		}
		break;
	default :
		break;
	}


	/* cmd + addr + UID + AUTH_KEY + CRC_A */
	send_buffer_length = 1 + 1 + ((data_s*)UID)->length
			+ key->length + 2;

	_net_nfc_util_alloc_mem(send_buffer,
			send_buffer_length * sizeof(uint8_t));
	if (send_buffer == NULL)
	{
		net_nfc_free_data(UID);
		return NET_NFC_ALLOC_FAIL;
	}

	temp = send_buffer;

	*temp = MIFARE_CMD_AUTH_A;
	temp++;

	*temp = sector_to_block;
	temp++;

	memcpy(temp, ((data_s*)UID)->buffer, ((data_s*)UID)->length);
	temp = temp + ((data_s*)UID)->length;

	memcpy(temp, key->buffer, key->length);

	net_nfc_util_compute_CRC(CRC_A, send_buffer, send_buffer_length);


	rawdata.buffer = send_buffer;
	rawdata.length = send_buffer_length;

	net_nfc_error_e result = net_nfc_client_transceive(handle,
							(data_h)&rawdata,
							callback,
							user_data);

	if (send_buffer != NULL)
		_net_nfc_util_free_mem(send_buffer);

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_authenticate_with_keyB(
						net_nfc_target_handle_h handle,
						uint8_t sector,
						data_h auth_key,
						void *callback,
						void *user_data)
{
	net_nfc_target_info_s* target_info = NULL;

	data_s *key;
	data_s rawdata;

	data_h UID = NULL;

	uint8_t* send_buffer = NULL;
	uint8_t* temp = NULL;

	int send_buffer_length = 0;

	uint8_t sector_to_block = 0;


	if (handle == NULL || auth_key == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_client_tag_is_connected() == FALSE)
		return NET_NFC_OPERATION_FAIL;

	key = (data_s *)auth_key;

	if (key->length != 6)
		return NET_NFC_OUT_OF_BOUND;

	target_info = net_nfc_client_tag_get_client_target_info();

	if (target_info != NULL)
	{
		if (target_info->devType < NET_NFC_MIFARE_MINI_PICC ||
				target_info->devType > NET_NFC_MIFARE_4K_PICC)
		{
			DEBUG_CLIENT_MSG("not a MIFARE Classic TAG");
			return NET_NFC_NOT_SUPPORTED;
		}
	}

	if (net_nfc_get_tag_info_value((net_nfc_target_info_h)target_info,
					MIFARE_TAG_KEY,
					&UID) != NET_NFC_OK)
	{
		return NET_NFC_NO_DATA_FOUND;
	}

	switch (target_info->devType)
	{
	case NET_NFC_MIFARE_MINI_PICC :
		{
			/* 0 ~ 4 : 5 sector and 4 block with 16 bytes */
			if (sector > MIFARE_MINI_SECTORS)
				return NET_NFC_OUT_OF_BOUND;

			sector_to_block = sector * MIFARE_BLOCK_4 + 3;
		}
		break;
	case NET_NFC_MIFARE_1K_PICC :
		{
			/* 0 ~ 15 : 16 sector and 4 block with 16 bytes */
			if (sector > MIFARE_1K_SECTORS)
				return NET_NFC_OUT_OF_BOUND;

			sector_to_block = sector * MIFARE_BLOCK_4 + 3;
		}
		break;
	case NET_NFC_MIFARE_4K_PICC :
		{
			/* 0 ~ 31 : 32 sector and 4 block with 16 bytes
			 * 32 ~ 39 : 8 sector and 16 block with 16 bytes
			 */
			if (sector > MIFARE_4K_SECTORS)
				return NET_NFC_OUT_OF_BOUND;

			if (sector < 32)
				sector_to_block = sector * MIFARE_BLOCK_4 + 3;
			else
			{
				sector_to_block = (31 * MIFARE_BLOCK_4 + 3)
						+ (sector - 32)
						* MIFARE_BLOCK_16 + 15;
			}
		}
		break;
	default :
		break;
	}

	send_buffer_length = 1 + 1 + ((data_s*)UID)->length
		+ key->length + 2; /* cmd + addr + UID + AUTH_KEY + CRC_A */

	_net_nfc_util_alloc_mem(send_buffer, send_buffer_length
				* sizeof(uint8_t));
	if (send_buffer == NULL)
	{
		net_nfc_free_data(UID);
		return NET_NFC_ALLOC_FAIL;
	}

	temp = send_buffer;

	*temp = MIFARE_CMD_AUTH_B;
	temp++;

	*temp = sector_to_block;
	temp++;

	memcpy(temp, ((data_s*)UID)->buffer, ((data_s*)UID)->length);
	temp = temp + ((data_s*)UID)->length;

	memcpy(temp, key->buffer, key->length);

	net_nfc_util_compute_CRC(CRC_A, send_buffer, send_buffer_length);

	rawdata.buffer = send_buffer;
	rawdata.length = send_buffer_length;

	net_nfc_error_e result = net_nfc_client_transceive(handle,
							(data_h)&rawdata,
							callback,
							user_data);

	if (send_buffer != NULL)
		_net_nfc_util_free_mem(send_buffer);

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_read(net_nfc_target_handle_h handle,
					uint8_t addr,
					void *callback,
					void *user_data)
{
	net_nfc_target_info_s* target_info = NULL;

	data_s rawdata;

	uint8_t send_buffer[2] = { 0 };


	if (handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_client_tag_is_connected() == FALSE)
		return NET_NFC_OPERATION_FAIL;

	target_info = net_nfc_client_tag_get_client_target_info();

	if (target_info != NULL)
	{
		if (target_info->devType < NET_NFC_MIFARE_MINI_PICC ||
			target_info->devType > NET_NFC_MIFARE_ULTRA_PICC)
		{
			DEBUG_CLIENT_MSG("not a MIFARE TAG = [%d]",
						target_info->devType);
			return NET_NFC_NOT_SUPPORTED;
		}

		if (target_info->devType == NET_NFC_MIFARE_ULTRA_PICC)
		{
			if (addr > 7)
				return NET_NFC_OUT_OF_BOUND;
		}
	}


	send_buffer[0] = MIFARE_CMD_READ;
	send_buffer[1] = addr;


	rawdata.buffer = send_buffer;
	rawdata.length = 2;

	return net_nfc_client_transceive_data(handle,
					(data_h)&rawdata,
					callback,
					user_data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_write_block(
						net_nfc_target_handle_h handle,
						uint8_t addr,
						data_h data,
						void *callback,
						void *user_data)
{
	net_nfc_target_info_s* target_info = NULL;

	data_s rawdata;

	uint8_t* send_buffer = NULL;

	uint32_t send_buffer_length = 0;


	if (handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_client_tag_is_connected() == FALSE)
		return NET_NFC_OPERATION_FAIL;


	target_info = net_nfc_client_tag_get_client_target_info();

	if (target_info == NULL)
		return NET_NFC_NOT_INITIALIZED;

	if (target_info->devType < NET_NFC_MIFARE_MINI_PICC ||
			target_info->devType > NET_NFC_MIFARE_ULTRA_PICC)
	{
		DEBUG_CLIENT_MSG("not a MIFARE TAG = [%d] \n",
					target_info->devType);
		return NET_NFC_NOT_SUPPORTED;
	}

	if (target_info->devType == NET_NFC_MIFARE_ULTRA_PICC)
	{
		if (addr > 7)
			return NET_NFC_OUT_OF_BOUND;
	}

	if (target_info->devType == NET_NFC_MIFARE_ULTRA_PICC)
	{
		if (((data_s *)data)->length > MIFARE_PAGE_SIZE)
		{
			uint8_t* temp = NULL;

			/* cmd + addr + page */
			send_buffer_length = 1 + 1 + MIFARE_PAGE_SIZE;

			_net_nfc_util_alloc_mem(send_buffer,
					send_buffer_length * sizeof(uint8_t));
			if (send_buffer == NULL)
				return NET_NFC_ALLOC_FAIL;

			temp = send_buffer;

			*temp = MIFARE_CMD_WRITE_PAGE;
			temp++;

			*temp = addr;
			temp++;

			memcpy(temp,
				((data_s*)data)->buffer,
				MIFARE_PAGE_SIZE);

		}
		else
		{
			uint8_t* temp = NULL;

			/* cmd + addr + page */
			send_buffer_length = 1 + 1 +
					((data_s*)data)->length;

			_net_nfc_util_alloc_mem(send_buffer,
					send_buffer_length * sizeof(uint8_t));
			if (send_buffer == NULL)
				return NET_NFC_ALLOC_FAIL;

			temp = send_buffer;

			*temp = MIFARE_CMD_WRITE_PAGE;
			temp++;

			*temp = addr;
			temp++;

			memcpy(temp,
				((data_s*)data)->buffer,
				((data_s*)data)->length);
		}

	}
	else
	{

		if (((data_s*)data)->length > MIFARE_BLOCK_SIZE)
		{
			uint8_t* temp = NULL;

			/* cmd + addr + page*/
			send_buffer_length = 1 + 1 + MIFARE_BLOCK_SIZE;

			_net_nfc_util_alloc_mem(send_buffer,
					send_buffer_length * sizeof(uint8_t));
			if (send_buffer == NULL)
				return NET_NFC_ALLOC_FAIL;

			temp = send_buffer;

			*temp = MIFARE_CMD_WRITE_BLOCK;
			temp++;

			*temp = addr;
			temp++;

			memcpy(temp,
				((data_s*)data)->buffer,
				MIFARE_BLOCK_SIZE);
		}
		else
		{
			uint8_t* temp = NULL;

			/* cmd + addr + page  */
			send_buffer_length = 1 + 1 + ((data_s*)data)->length;

			_net_nfc_util_alloc_mem(send_buffer,
					send_buffer_length * sizeof(uint8_t));
			if (send_buffer == NULL)
				return NET_NFC_ALLOC_FAIL;

			temp = send_buffer;

			*temp = MIFARE_CMD_WRITE_BLOCK;
			temp++;

			*temp = addr;
			temp++;

			memcpy(temp,
				((data_s*)data)->buffer,
				((data_s*)data)->length);
		}
	}


	rawdata.buffer = send_buffer;
	rawdata.length = send_buffer_length;

	net_nfc_error_e result = net_nfc_client_transceive(handle,
							(data_h)&rawdata,
							callback,
							user_data);

	if (send_buffer != NULL)
		_net_nfc_util_free_mem(send_buffer);

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_write_page(
						net_nfc_target_handle_h handle,
						uint8_t addr,
						data_h data,
						void *callback,
						void *user_data)
{
	net_nfc_target_info_s* target_info = NULL;

	uint8_t* send_buffer = NULL;

	uint32_t send_buffer_length = 0;

	if (handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_client_tag_is_connected() == FALSE)
		return NET_NFC_OPERATION_FAIL;

	target_info = net_nfc_client_tag_get_client_target_info();

	if (target_info == NULL)
		return NET_NFC_NOT_INITIALIZED;

	if (target_info->devType < NET_NFC_MIFARE_MINI_PICC ||
			target_info->devType > NET_NFC_MIFARE_ULTRA_PICC)
	{
		DEBUG_CLIENT_MSG("not a MIFARE TAG = [%d] \n",
				target_info->devType);
		return NET_NFC_NOT_SUPPORTED;
	}

	if (target_info->devType == NET_NFC_MIFARE_ULTRA_PICC)
	{
		if (addr > 7)
			return NET_NFC_OUT_OF_BOUND;
	}

	if (target_info->devType == NET_NFC_MIFARE_ULTRA_PICC)
	{
		if (((data_s*)data)->length > MIFARE_PAGE_SIZE)
		{
			uint8_t* temp = NULL;

			/* cmd + addr + page  */
			send_buffer_length = 1 + 1 + MIFARE_PAGE_SIZE;

			_net_nfc_util_alloc_mem(send_buffer,
					send_buffer_length * sizeof(uint8_t));
			if (send_buffer == NULL)
				return NET_NFC_ALLOC_FAIL;

			temp = send_buffer;

			*temp = MIFARE_CMD_WRITE_PAGE;
			temp++;

			*temp = addr;
			temp++;

			memcpy(temp,
				((data_s*)data)->buffer,
				MIFARE_PAGE_SIZE);
		}
		else
		{
			uint8_t* temp = NULL;

			/* cmd + addr + page */
			send_buffer_length = 1 + 1 + ((data_s*)data)->length;

			_net_nfc_util_alloc_mem(send_buffer,
					send_buffer_length * sizeof(uint8_t));
			if (send_buffer == NULL)
				return NET_NFC_ALLOC_FAIL;

			temp = send_buffer;

			*temp = MIFARE_CMD_WRITE_PAGE;
			temp++;

			*temp = addr;
			temp++;

			memcpy(temp,
				((data_s*)data)->buffer,
				((data_s*)data)->length);
		}

	}
	else
	{
		if (((data_s*)data)->length > MIFARE_PAGE_SIZE)
		{
			uint8_t* temp = NULL;

			/* cmd + addr + page */
			send_buffer_length = 1 + 1 + MIFARE_PAGE_SIZE;

			_net_nfc_util_alloc_mem(send_buffer,
					send_buffer_length * sizeof(uint8_t));
			if (send_buffer == NULL)
				return NET_NFC_ALLOC_FAIL;

			temp = send_buffer;

			*temp = MIFARE_CMD_WRITE_BLOCK;
			temp++;

			*temp = addr;
			temp++;

			memcpy(temp,
				((data_s*)data)->buffer,
				MIFARE_PAGE_SIZE);

		}
		else
		{
			uint8_t* temp = NULL;

			/* cmd + addr + page */
			send_buffer_length = 1 + 1 + ((data_s*)data)->length;

			_net_nfc_util_alloc_mem(send_buffer,
					send_buffer_length * sizeof(uint8_t));
			if (send_buffer == NULL)
				return NET_NFC_ALLOC_FAIL;

			temp = send_buffer;

			*temp = MIFARE_CMD_WRITE_BLOCK;
			temp++;

			*temp = addr;
			temp++;

			memcpy(temp,
				((data_s*)data)->buffer,
				((data_s*)data)->length);
		}

	}


	data_s rawdata;

	rawdata.buffer = send_buffer;
	rawdata.length = send_buffer_length;

	net_nfc_error_e result = net_nfc_client_transceive(handle,
							(data_h)&rawdata,
							callback,
							user_data);

	if (send_buffer != NULL)
		_net_nfc_util_free_mem(send_buffer);

	return result;
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_increment(net_nfc_target_handle_h handle,
						uint8_t addr,
						int value,
						void *callback,
						void *user_data)
{
	net_nfc_target_info_s* target_info = NULL;

	data_s rawdata;

	uint8_t send_buffer[8] = { 0 };


	if (handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_client_tag_is_connected() == FALSE)
		return NET_NFC_OPERATION_FAIL;

	target_info = net_nfc_client_tag_get_client_target_info();

	if (target_info)
	{
		if (target_info->devType < NET_NFC_MIFARE_MINI_PICC ||
				target_info->devType > NET_NFC_MIFARE_4K_PICC)
		{
			DEBUG_CLIENT_MSG(
					"not a MIFARE Classic TAG = [%d]",
					target_info->devType);
			return NET_NFC_NOT_SUPPORTED;
		}
	}


	send_buffer[0] = MIFARE_CMD_INCREMENT;
	send_buffer[1] = addr;

	/* little endian.
	   little value of byte array will be saved first in memory */
	send_buffer[5] = (value & 0xFF000000) >> 24;
	send_buffer[4] = (value & 0x00FF0000) >> 16;
	send_buffer[3] = (value & 0x0000FF00) >> 8;
	send_buffer[2] = (value & 0x000000FF);

	net_nfc_util_compute_CRC(CRC_A, send_buffer, 8);

	rawdata.buffer = send_buffer;
	rawdata.length = 8;

	return net_nfc_client_transceive(handle, (data_h)&rawdata, callback,
					user_data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_decrement(net_nfc_target_handle_h handle,
						uint8_t addr,
						int value,
						void *callback,
						void *user_data)
{
	net_nfc_target_info_s* target_info = NULL;

	data_s rawdata;

	uint8_t send_buffer[8] = { 0 };

	if (handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_client_tag_is_connected() == FALSE)
		return NET_NFC_OPERATION_FAIL;

	target_info = net_nfc_client_tag_get_client_target_info();

	if (target_info)
	{

		if (target_info->devType < NET_NFC_MIFARE_MINI_PICC ||
				target_info->devType > NET_NFC_MIFARE_4K_PICC)
		{
			DEBUG_CLIENT_MSG("not a MIFARE Classic TAG = [%d] \n",
					target_info->devType);
			return NET_NFC_NOT_SUPPORTED;
		}
	}

	send_buffer[0] = MIFARE_CMD_DECREMENT;
	send_buffer[1] = addr;

	/* little endian.
	   little value of byte array will be saved first in memory */
	send_buffer[5] = (value & 0xFF000000) >> 24;
	send_buffer[4] = (value & 0x00FF0000) >> 16;
	send_buffer[3] = (value & 0x0000FF00) >> 8;
	send_buffer[2] = (value & 0x000000FF);

	net_nfc_util_compute_CRC(CRC_A, send_buffer, 8);

	DEBUG_MSG_PRINT_BUFFER(send_buffer, 8);

	rawdata.buffer = send_buffer;
	rawdata.length = 8;

	return net_nfc_client_transceive(handle, (data_h)&rawdata, callback,
					user_data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_transfer(net_nfc_target_handle_h handle,
					uint8_t addr,
					void *callback,
					void *user_data)
{
	net_nfc_target_info_s* target_info = NULL;

	data_s rawdata;

	uint8_t send_buffer[4] = { 0 };

	if (handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_client_tag_is_connected() == FALSE)
		return NET_NFC_OPERATION_FAIL;

	target_info = net_nfc_client_tag_get_client_target_info();

	if (target_info)
	{
		if (target_info->devType < NET_NFC_MIFARE_MINI_PICC ||
				target_info->devType > NET_NFC_MIFARE_4K_PICC)
		{
			DEBUG_CLIENT_MSG("not a MIFARE Classic TAG = [%d]",
					target_info->devType);
			return NET_NFC_NOT_SUPPORTED;
		}
	}

	send_buffer[0] = MIFARE_CMD_TRANSFER;
	send_buffer[1] = addr;

	net_nfc_util_compute_CRC(CRC_A, send_buffer, 4);

	rawdata.buffer = send_buffer;
	rawdata.length = 4;

	return net_nfc_client_transceive(handle, (data_h)&rawdata, callback,
					user_data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_restore(net_nfc_target_handle_h handle,
					uint8_t addr,
					void *callback,
					void *user_data)
{
	net_nfc_target_info_s* target_info = NULL;

	data_s rawdata;

	uint8_t send_buffer[4] = { 0 };

	if (handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if (net_nfc_client_tag_is_connected() == FALSE)
		return NET_NFC_OPERATION_FAIL;

	target_info = net_nfc_client_tag_get_client_target_info();

	if (target_info)
	{
		if (target_info->devType < NET_NFC_MIFARE_MINI_PICC ||
				target_info->devType > NET_NFC_MIFARE_4K_PICC)
		{
			DEBUG_CLIENT_MSG("not a MIFARE Classic TAG = [%d]",
					target_info->devType);
			return NET_NFC_NOT_SUPPORTED;
		}
	}

	send_buffer[0] = MIFARE_CMD_RESTORE;
	send_buffer[1] = addr;

	net_nfc_util_compute_CRC(CRC_A, send_buffer, 4);

	rawdata.buffer = send_buffer;
	rawdata.length = 4;

	return net_nfc_client_transceive(handle, (data_h)&rawdata, callback,
					user_data);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_create_default_key(data_h* key)
{
	if (key == NULL)
		return NET_NFC_NULL_PARAMETER;

	return net_nfc_create_data(key, default_key, 6);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_create_application_directory_key(
								data_h* key)
{
	if (key == NULL)
		return NET_NFC_NULL_PARAMETER;

	return net_nfc_create_data(key, mad_key, 6);
}

NET_NFC_EXPORT_API
net_nfc_error_e net_nfc_client_mifare_create_net_nfc_forum_key(data_h* key)
{
	if (key == NULL)
		return NET_NFC_NULL_PARAMETER;

	return net_nfc_create_data(key, net_nfc_forum_key, 6);
}

