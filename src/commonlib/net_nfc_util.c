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

// libc header
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>

// platform header
#include <bluetooth-api.h>
#include <vconf.h>

// nfc-manager header
#include "net_nfc_util_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_oem_controller.h"
#include "net_nfc_util_defines.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

static const char *schema[] =
{
	"",
	"http://www.",
	"https://www.",
	"http://",
	"https://",
	"tel:",
	"mailto:",
	"ftp://anonymous:anonymous@",
	"ftp://ftp.",
	"ftps://",
	"sftp://",
	"smb://",
	"nfs://",
	"ftp://",
	"dav://",
	"news:",
	"telnet://",
	"imap:",
	"rtsp://",
	"urn:",
	"pop:",
	"sip:",
	"sips:",
	"tftp:",
	"btspp://",
	"btl2cap://",
	"btgoep://",
	"tcpobex://",
	"irdaobex://",
	"file://",
	"urn:epc:id:",
	"urn:epc:tag:",
	"urn:epc:pat:",
	"urn:epc:raw:",
	"urn:epc:",
	"urn:epc:nfc:",
};

// defines for bluetooth api
#define USE_BLUETOOTH_API
static uint8_t *bt_addr = NULL;

/* for log tag */
#define NET_NFC_MANAGER_NAME "nfc-manager-daemon"
static const char *log_tag = LOG_CLIENT_TAG;
extern char *__progname;
FILE *nfc_log_file = NULL;

const char *net_nfc_get_log_tag()
{
	return log_tag;
}

void __attribute__ ((constructor)) lib_init()
{
	if (__progname != NULL && strncmp(__progname, NET_NFC_MANAGER_NAME, strlen(NET_NFC_MANAGER_NAME)) == 0)
	{
		log_tag = LOG_SERVER_TAG;
	}
}

void __attribute__ ((destructor)) lib_fini()
{
}

void net_nfc_manager_init_log()
{
	nfc_log_file = fopen(NFC_DLOG_FILE, "a+");
	if (nfc_log_file != NULL)
	{
		char timeBuf[50];
		time_t rawtime;

		time (&rawtime);
		strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", localtime(&rawtime));
		fprintf(nfc_log_file, "\n%s",timeBuf);
		fprintf(nfc_log_file, "========== log begin, pid [%d] =========", getpid());
		fflush(nfc_log_file);
	}
	else
	{
		fprintf(stderr, "\n\nfopen error\n\n");
	}
}

void net_nfc_manager_fini_log()
{
	if (nfc_log_file != NULL)
	{
		char timeBuf[50];
		time_t rawtime;

		time (&rawtime);
		strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", localtime(&rawtime));
		fprintf(nfc_log_file, "\n%s",timeBuf);
		fprintf(nfc_log_file, "=========== log end, pid [%d] ==========", getpid());
		fflush(nfc_log_file);
		fclose(nfc_log_file);
		nfc_log_file = NULL;
	}
}

NET_NFC_EXPORT_API void __net_nfc_util_free_mem(void **mem, char *filename, unsigned int line)
{
	if (mem == NULL)
	{
		DEBUG_MSG("FILE: %s, LINE:%d, Invalid parameter in mem free util, mem is NULL", filename, line);
		return;
	}

	if (*mem == NULL)
	{
		DEBUG_MSG("FILE: %s, LINE:%d, Invalid Parameter in mem free util, *mem is NULL", filename, line);
		return;
	}

	free(*mem);
	*mem = NULL;
}

NET_NFC_EXPORT_API void __net_nfc_util_alloc_mem(void **mem, int size, char *filename, unsigned int line)
{
	if (mem == NULL || size <= 0)
	{
		DEBUG_MSG("FILE: %s, LINE:%d, Invalid parameter in mem alloc util, mem [%p], size [%d]", filename, line, mem, size);
		return;
	}

	if (*mem != NULL)
	{
		DEBUG_MSG("FILE: %s, LINE:%d, WARNING: Pointer is not NULL, mem [%p]", filename, line, *mem);
	}

	*mem = calloc(1, size);

	if (*mem == NULL)
	{
		DEBUG_ERR_MSG("FILE: %s, LINE:%d, Allocation is failed, size [%d]", filename, line, size);
	}
}

NET_NFC_EXPORT_API void __net_nfc_util_strdup(char **output, const char *origin, char *filename, unsigned int line)
{
	if (output == NULL || origin == NULL)
	{
		DEBUG_MSG("FILE: %s, LINE:%d, Invalid parameter in strdup, output [%p], origin [%p]", filename, line, output, origin);
		return;
	}

	if (*output != NULL)
	{
		DEBUG_MSG("FILE: %s, LINE:%d, WARNING: Pointer is not NULL, mem [%p]", filename, line, *output);
	}

	*output = strdup(origin);

	if (*output == NULL)
	{
		DEBUG_ERR_MSG("FILE: %s, LINE:%d, strdup failed", filename, line);
	}
}

NET_NFC_EXPORT_API bool net_nfc_util_alloc_data(data_s *data, uint32_t length)
{
	if (data == NULL || length == 0)
		return false;

	_net_nfc_util_alloc_mem(data->buffer, length);
	if (data->buffer == NULL)
		return false;

	data->length = length;

	return true;
}

NET_NFC_EXPORT_API bool net_nfc_util_duplicate_data(data_s *dest, net_nfc_data_s *src)
{
	if (dest == NULL || src == NULL || src->length == 0)
		return false;

	if (net_nfc_util_alloc_data(dest, src->length) == false)
		return false;

	memcpy(dest->buffer, src->buffer, dest->length);

	return true;
}

NET_NFC_EXPORT_API void net_nfc_util_free_data(data_s *data)
{
	if (data == NULL || data->buffer == NULL)
		return;

	_net_nfc_util_free_mem(data->buffer);
}

NET_NFC_EXPORT_API void net_nfc_util_mem_free_detail_msg(int msg_type, int message, void *data)
{
	if (data == NULL)
		return;

	if (msg_type == NET_NFC_UTIL_MSG_TYPE_REQUEST)
	{
		_net_nfc_util_free_mem(data);
	}
	else if (msg_type == NET_NFC_UTIL_MSG_TYPE_RESPONSE)
	{
		switch (message)
		{
		case NET_NFC_MESSAGE_READ_NDEF :
			{
				net_nfc_response_read_ndef_t *msg = (net_nfc_response_read_ndef_t *)data;
				_net_nfc_util_free_mem(msg->data.buffer);
			}
			break;
		case NET_NFC_MESSAGE_TRANSCEIVE :
			{
				net_nfc_response_transceive_t *msg = (net_nfc_response_transceive_t *)data;
				_net_nfc_util_free_mem(msg->data.buffer);
			}
			break;
		case NET_NFC_MESSAGE_TAG_DISCOVERED :
			{
				net_nfc_response_tag_discovered_t *msg = (net_nfc_response_tag_discovered_t *)data;
				_net_nfc_util_free_mem(msg->target_info_values.buffer);
				_net_nfc_util_free_mem(msg->raw_data.buffer);
			}
			break;

		case NET_NFC_MESSAGE_LLCP_RECEIVE :
			{
				net_nfc_response_receive_socket_t *msg = (net_nfc_response_receive_socket_t *)data;
				_net_nfc_util_free_mem(msg->data.buffer);
			}
			break;

		case NET_NFC_MESSAGE_P2P_RECEIVE :
			{
				net_nfc_response_p2p_receive_t *msg = (net_nfc_response_p2p_receive_t *)data;
				_net_nfc_util_free_mem(msg->data.buffer);
			}
			break;

		case NET_NFC_MESSAGE_SEND_APDU_SE :
			{
				net_nfc_response_send_apdu_t *msg = (net_nfc_response_send_apdu_t *)data;
				_net_nfc_util_free_mem(msg->data.buffer);
			}
			break;

		default :
			break;
		}

		_net_nfc_util_free_mem(data);
	}
	else
	{
		DEBUG_MSG("unknown message type");
	}
}

net_nfc_conn_handover_carrier_state_e net_nfc_util_get_cps(net_nfc_conn_handover_carrier_type_e carrier_type)
{
	net_nfc_conn_handover_carrier_state_e cps = NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE;

	if (carrier_type == NET_NFC_CONN_HANDOVER_CARRIER_BT)
	{
		int ret = bluetooth_check_adapter();

		switch (ret)
		{
		case BLUETOOTH_ADAPTER_ENABLED :
			cps = NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE;
			break;

		case BLUETOOTH_ADAPTER_CHANGING_ENABLE :
			cps = NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATING;
			break;

		case BLUETOOTH_ADAPTER_DISABLED :
		case BLUETOOTH_ADAPTER_CHANGING_DISABLE :
		case BLUETOOTH_ERROR_NO_RESOURCES :
		default :
			cps = NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE;
			break;
		}
	}
	else if (carrier_type == NET_NFC_CONN_HANDOVER_CARRIER_WIFI_BSS)
	{
		int wifi_state = 0;

		vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);

		switch (wifi_state)
		{
		case VCONFKEY_WIFI_UNCONNECTED :
		case VCONFKEY_WIFI_CONNECTED :
		case VCONFKEY_WIFI_TRANSFER :
			cps = NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE;
			break;

		case VCONFKEY_WIFI_OFF :
		default :
			cps = NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE;
			break;
		}
	}

	return cps;
}

uint8_t *net_nfc_util_get_local_bt_address()
{
	if (bt_addr != NULL)
	{
		return bt_addr;
	}

	_net_nfc_util_alloc_mem(bt_addr, BLUETOOTH_ADDRESS_LENGTH);
	if (bt_addr != NULL)
	{
		if (net_nfc_util_get_cps(NET_NFC_CONN_HANDOVER_CARRIER_BT) != NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE)
		{
			// bt power is off. so get bt address from configuration file.
			FILE *fp = NULL;

			if ((fp = fopen(HIDDEN_BT_ADDR_FILE, "r")) != NULL)
			{
				unsigned char temp[BLUETOOTH_ADDRESS_LENGTH * 2] = { 0, };

				int ch;
				int count = 0;
				int i = 0;

				while ((ch = fgetc(fp)) != EOF && count < BLUETOOTH_ADDRESS_LENGTH * 2)
				{
					if (((ch >= '0') && (ch <= '9')))
					{
						temp[count++] = ch - '0';
					}
					else if (((ch >= 'a') && (ch <= 'z')))
					{
						temp[count++] = ch - 'a' + 10;
					}
					else if (((ch >= 'A') && (ch <= 'Z')))
					{
						temp[count++] = ch - 'A' + 10;
					}
				}

				for (; i < BLUETOOTH_ADDRESS_LENGTH; i++)
				{
					bt_addr[i] = temp[i * 2] << 4 | temp[i * 2 + 1];
				}

				fclose(fp);
			}
		}
		else
		{
			bluetooth_device_address_t local_address;

			memset(&local_address, 0x00, sizeof(bluetooth_device_address_t));

			bluetooth_get_local_address(&local_address);

			memcpy(bt_addr, &local_address.addr, BLUETOOTH_ADDRESS_LENGTH);
		}
	}

	return bt_addr;
}

void net_nfc_util_enable_bluetooth(void)
{
	bluetooth_enable_adapter();
}

bool net_nfc_util_strip_string(char *buffer, int buffer_length)
{
	bool result = false;
	char *temp = NULL;
	int i = 0;

	_net_nfc_util_alloc_mem(temp, buffer_length);
	if (temp == NULL)
	{
		return result;
	}

	for (; i < buffer_length; i++)
	{
		if (buffer[i] != ' ' && buffer[i] != '\t')
			break;
	}

	if (i < buffer_length)
	{
		memcpy(temp, &buffer[i], buffer_length - i);
		memset(buffer, 0x00, buffer_length);

		memcpy(buffer, temp, buffer_length - i);

		result = true;
	}
	else
	{
		result = false;
	}

	_net_nfc_util_free_mem(temp);

	return true;
}

static uint16_t _net_nfc_util_update_CRC(uint8_t ch, uint16_t *lpwCrc)
{
	ch = (ch ^ (uint8_t)((*lpwCrc) & 0x00FF));
	ch = (ch ^ (ch << 4));
	*lpwCrc = (*lpwCrc >> 8) ^ ((uint16_t)ch << 8) ^ ((uint16_t)ch << 3) ^ ((uint16_t)ch >> 4);
	return (*lpwCrc);
}

void net_nfc_util_compute_CRC(CRC_type_e CRC_type, uint8_t *buffer, uint32_t length)
{
	uint8_t chBlock = 0;
	int msg_length = length - 2;
	uint8_t *temp = buffer;

	// default is CRC_B
	uint16_t wCrc = 0xFFFF; /* ISO/IEC 13239 (formerly ISO/IEC 3309) */

	switch (CRC_type)
	{
	case CRC_A :
		wCrc = 0x6363;
		break;

	case CRC_B :
		wCrc = 0xFFFF;
		break;
	}

	do
	{
		chBlock = *buffer++;
		_net_nfc_util_update_CRC(chBlock, &wCrc);
	}
	while (--msg_length > 0);

	if (CRC_type == CRC_B)
	{
		wCrc = ~wCrc; /* ISO/IEC 13239 (formerly ISO/IEC 3309) */
	}

	temp[length - 2] = (uint8_t)(wCrc & 0xFF);
	temp[length - 1] = (uint8_t)((wCrc >> 8) & 0xFF);
}

const char *net_nfc_util_get_schema_string(int index)
{
	if (index == 0 || index >= NET_NFC_SCHEMA_MAX)
		return NULL;
	else
		return schema[index];
}
