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
#include <glib.h>

// platform header
#include "aul.h"
#include "pkgmgr-info.h"
#include <bluetooth-api.h>
#include <vconf.h>

// nfc-manager header
#include "net_nfc_util_internal.h"
#include "net_nfc_debug_internal.h"
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
FILE *nfc_log_file;

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
	struct tm *local_tm;
	nfc_log_file = fopen(NFC_DLOG_FILE, "a+");
	if (nfc_log_file != NULL)
	{
		char timeBuf[50];
		time_t rawtime;

		time (&rawtime);
		local_tm = localtime(&rawtime);

		if(local_tm != NULL)
		{
			strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", local_tm);
			fprintf(nfc_log_file, "\n%s",timeBuf);
			fprintf(nfc_log_file, "========== log begin, pid [%d] =========", getpid());
			fflush(nfc_log_file);
		}
	}
	else
	{
		fprintf(stderr, "\n\nfopen error\n\n");
	}
}

void net_nfc_manager_fini_log()
{
	struct tm *local_tm;
	if (nfc_log_file != NULL)
	{
		char timeBuf[50];
		time_t rawtime;

		time (&rawtime);
		local_tm = localtime(&rawtime);

		if(local_tm != NULL)
		{
			strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", local_tm);
			fprintf(nfc_log_file, "\n%s",timeBuf);
			fprintf(nfc_log_file, "=========== log end, pid [%d] ==========", getpid());
			fflush(nfc_log_file);
			fclose(nfc_log_file);
			nfc_log_file = NULL;
		}
	}
}

NET_NFC_EXPORT_API void __net_nfc_util_free_mem(void **mem, char *filename, unsigned int line)
{
	if (mem == NULL)
	{
		SECURE_LOGD("FILE: %s, LINE:%d, Invalid parameter in mem free util, mem is NULL", filename, line);
		return;
	}

	if (*mem == NULL)
	{
		SECURE_LOGD("FILE: %s, LINE:%d, Invalid Parameter in mem free util, *mem is NULL", filename, line);
		return;
	}

	g_free(*mem);
	*mem = NULL;
}

NET_NFC_EXPORT_API void __net_nfc_util_alloc_mem(void **mem, int size, char *filename, unsigned int line)
{
	if (mem == NULL || size <= 0)
	{
		SECURE_LOGD("FILE: %s, LINE:%d, Invalid parameter in mem alloc util, mem [%p], size [%d]", filename, line, mem, size);
		return;
	}

	if (*mem != NULL)
	{
		SECURE_LOGD("FILE: %s, LINE:%d, WARNING: Pointer is not NULL, mem [%p]", filename, line, *mem);
	}

	*mem = g_malloc0(size);

	if (*mem == NULL)
	{
		SECURE_LOGD("FILE: %s, LINE:%d, Allocation is failed, size [%d]", filename, line, size);
	}
}

NET_NFC_EXPORT_API void __net_nfc_util_strdup(char **output, const char *origin, char *filename, unsigned int line)
{
	if (output == NULL || origin == NULL)
	{
		SECURE_LOGD("FILE: %s, LINE:%d, Invalid parameter in strdup, output [%p], origin [%p]", filename, line, output, origin);
		return;
	}

	if (*output != NULL)
	{
		SECURE_LOGD("FILE: %s, LINE:%d, WARNING: Pointer is not NULL, mem [%p]", filename, line, *output);
	}

	*output = g_strdup(origin);

	if (*output == NULL)
	{
		SECURE_LOGD("FILE: %s, LINE:%d, strdup failed", filename, line);
	}
}

NET_NFC_EXPORT_API data_s *net_nfc_util_create_data(uint32_t length)
{
	data_s *data;

	_net_nfc_util_alloc_mem(data, sizeof(*data));
	if (length > 0) {
		net_nfc_util_init_data(data, length);
	}

	return data;
}

NET_NFC_EXPORT_API bool net_nfc_util_init_data(data_s *data, uint32_t length)
{
	if (data == NULL || length == 0)
		return false;

	_net_nfc_util_alloc_mem(data->buffer, length);
	if (data->buffer == NULL)
		return false;

	data->length = length;

	return true;
}

NET_NFC_EXPORT_API data_s *net_nfc_util_duplicate_data(data_s *src)
{
	data_s *data;

	if (src == NULL || src->length == 0)
		return false;

	data = net_nfc_util_create_data(src->length);
	if (data != NULL) {
		memcpy(data->buffer, src->buffer, data->length);
	}

	return data;
}

NET_NFC_EXPORT_API bool net_nfc_util_append_data(data_s *dest, data_s *src)
{
	data_s *data;

	if (dest == NULL || src == NULL || src->length == 0)
		return false;

	data = net_nfc_util_create_data(dest->length + src->length);
	if (data != NULL) {
		if (dest->length > 0) {
			memcpy(data->buffer, dest->buffer, dest->length);
		}
		memcpy(data->buffer + dest->length, src->buffer, src->length);

		net_nfc_util_clear_data(dest);
		net_nfc_util_init_data(dest, data->length);
		memcpy(dest->buffer, data->buffer, data->length);

		net_nfc_util_free_data(data);
	}

	return true;
}

NET_NFC_EXPORT_API void net_nfc_util_clear_data(data_s *data)
{
	if (data == NULL)
		return;

	if (data->buffer != NULL) {
		_net_nfc_util_free_mem(data->buffer);
		data->buffer = NULL;
	}

	data->length = 0;
}

NET_NFC_EXPORT_API void net_nfc_util_free_data(data_s *data)
{
	if (data == NULL)
		return;

	net_nfc_util_clear_data(data);

	_net_nfc_util_free_mem(data);
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

#define BLUETOOTH_ADDRESS_LENGTH	6
#define HIDDEN_BT_ADDR_FILE		"/opt/etc/.bd_addr"

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

#define MAX_HANDLE	65535
#define NEXT_HANDLE(__x) ((__x) == MAX_HANDLE ? 1 : ((__x) + 1))

static uint32_t next_handle = 1;
static GHashTable *handle_table;

static void *_get_memory_address(uint32_t handle)
{
	return g_hash_table_lookup(handle_table,
		(gconstpointer)handle);
}

uint32_t net_nfc_util_create_memory_handle(void *address)
{
	uint32_t handle;

	if (handle_table == NULL) {
		handle_table = g_hash_table_new(g_int_hash, g_int_equal);
	}

	g_assert(g_hash_table_size(handle_table) < MAX_HANDLE);

	g_hash_table_insert(handle_table, (gpointer)next_handle,
		(gpointer)address);

	handle = next_handle;

	/* find next available handle */
	do {
		next_handle = NEXT_HANDLE(next_handle);
	} while (_get_memory_address(next_handle) != NULL);

	return handle;
}

void *net_nfc_util_get_memory_address(uint32_t handle)
{
	void *address;

	if (handle_table == NULL || handle == 0 || handle > MAX_HANDLE)
		return NULL;

	address = _get_memory_address(handle);

	return address;
}

void net_nfc_util_destroy_memory_handle(uint32_t handle)
{
	if (handle_table == NULL || handle == 0 || handle > MAX_HANDLE)
		return;

	g_hash_table_remove(handle_table, (gconstpointer)handle);
}

#define IS_HEX(c) (((c) >= '0' && (c) <= '9') || ((c) >= 'A' && (c) <= 'F') || \
	((c) >= 'a' && (c) <= 'f'))

bool net_nfc_util_aid_check_validity(const char *aid)
{
	const char *temp = aid;
	bool asterisk = false;

	if (aid == NULL || strlen(aid) == 0) {
		return false;
	}

	while (*temp != '\0') {
		if (asterisk == true) {
			/* asterisk sould be placed at last */
			return false;
		}

		if (IS_HEX(*temp) == false) {
			if (*temp == '*') {
				asterisk = true;
			} else {
				/* wrong character */
				return false;
			}
		}

		temp++;
	}

	return true;
}

bool net_nfc_util_aid_is_prefix(const char *aid)
{
	size_t len;

	if (net_nfc_util_aid_check_validity(aid) == false) {
		return false;
	}

	len = strlen(aid);

	return (aid[len - 1] == '*');
}

bool net_nfc_util_aid_is_matched(const char *aid_criteria,
	const char *aid_target)
{
	const char *criteria = aid_criteria;
	const char *target = aid_target;
	bool is_prefix;
	bool result;

	if (net_nfc_util_aid_check_validity(criteria) == false) {
		return false;
	}

	if (net_nfc_util_aid_check_validity(target) == false) {
		return false;
	}

	is_prefix = net_nfc_util_aid_is_prefix(target);

	while (true) {
		if (*criteria == *target) {
			if (*criteria == '\0') {
				result = true;
				break;
			}
		} else if (*criteria == '*') {
			if (is_prefix == true) {
				/* different prefix */
				result = false;
				break;
			} else {
				/* prefix matched */
				result = true;
				break;
			}
		} else {
			result = false;
			break;
		}

		criteria++;
		target++;
	}

	return result;
}

bool net_nfc_util_get_pkgid_by_pid(pid_t pid, char *pkgid, size_t len)
{
	pkgmgrinfo_appinfo_h appinfo = NULL;
	char *temp = NULL;
	char package[1024];
	int ret;
	bool result = false;

	/* get pkgid id from pid */
	ret = aul_app_get_pkgname_bypid(pid, package, sizeof(package));
	if (ret < 0) {
		DEBUG_ERR_MSG("aul_app_get_pkgname_bypid failed [%d]", ret);

		goto END;
	}

	ret = pkgmgrinfo_appinfo_get_appinfo(package, &appinfo);
	if (ret < 0) {
		DEBUG_ERR_MSG("pkgmgrinfo_appinfo_get_appinfo failed, [%d]", ret);

		goto END;
	}

	ret = pkgmgrinfo_appinfo_get_pkgid(appinfo, &temp);
	if (ret < 0) {
		DEBUG_ERR_MSG("pkgmgrinfo_appinfo_get_pkgid failed, [%d]", ret);

		goto END;
	}

	result = (snprintf(pkgid, len, "%s", temp) > 0);

END :
	if (appinfo != NULL) {
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
	}

	return result;
}

#define TO_BINARY(x) (((x) >= '0' && (x) <= '9') ? ((x) - '0') : (((x) >= 'A' && (x) <= 'F') ? ((x) - 'A' + 10) : (((x) >= 'a' && (x) <= 'f') ? ((x) - 'a' + 10) : 0)))

bool net_nfc_util_hex_string_to_binary(const char *str, data_s *result)
{
	size_t len, i;

	if (str == NULL || result == NULL) {
		return false;
	}

	len = strlen(str);
	if (len < 2) {
		return false;
	}

	for (i = 0; i < len; i++) {
		if (IS_HEX(str[i]) == false) {
			return false;
		}
	}

	len /= 2;

	if (net_nfc_util_init_data(result, len) == false) {
		return false;
	}

	for (i = 0; i < len; i++) {
		result->buffer[i] = TO_BINARY(str[i << 1]) << 4;
		result->buffer[i] |= TO_BINARY(str[(i << 1) + 1]);
	}

	return true;
}

bool net_nfc_util_binary_to_hex_string(data_s *data, char *out_buf, uint32_t max_len)
{
	int current = 0;
	uint8_t *buffer;
	size_t len;

	if (data == NULL || data->buffer == NULL || data->length == 0 ||
		out_buf == NULL || max_len == 0)
		return false;

	buffer = data->buffer;
	len = data->length;

	while (len > 0 && current < max_len) {
		current += snprintf(out_buf + current, max_len - current,
			"%02X", *(buffer++));
		len--;
	}

	return true;
}
