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


#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <glib.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "appsvc.h"
#include "aul.h"
#include "vconf.h"
#include "Ecore_X.h"

#include "net_nfc_typedef.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_ndef_record.h"
#include "net_nfc_manager_util_private.h"
#include "net_nfc_app_util_private.h"
#include "net_nfc_server_context_private.h"
//#include "syspopup_caller.h"

#define OSP_K_COND			"__OSP_COND_NAME__"
#define OSP_K_COND_TYPE			"nfc"
#define OSP_K_LAUNCH_TYPE		"__OSP_LAUNCH_TYPE__"

static bool _net_nfc_app_util_get_operation_from_record(ndef_record_s *record, char *operation, size_t length);
static bool _net_nfc_app_util_get_mime_from_record(ndef_record_s *record, char *mime, size_t length);
#ifdef USE_FULL_URI
static bool _net_nfc_app_util_get_uri_from_record(ndef_record_s *record, char *uri, size_t length);
#endif
static bool _net_nfc_app_util_get_data_from_record(ndef_record_s *record, char *data, size_t length);

static const char *sbeam_mime_type[] =
{
	"text/DirectShareGallery",
	"text/DirectShareMusic",
	"text/DirectShareVideos",
	"text/DirectShareFile",
	"text/DirectSharePolarisViewer",
	"text/DirectSharePolarisEditor",
	"text/DirectShareDefault",
	"text/DirectShareError",
	NULL
};

static const char osp_launch_type_condition[] = "condition";

net_nfc_error_e net_nfc_app_util_process_ndef(data_s *data)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	ndef_message_s *msg = NULL;
	char operation[2048] = { 0, };
	char mime[2048] = { 0, };
	char text[2048] = { 0, };
#ifdef USE_FULL_URI
	char uri[2048] = { 0, };
#endif
	int ret = 0;

	if (data == NULL || data->buffer == NULL || data->length == 0)
	{
		DEBUG_ERR_MSG("net_nfc_app_util_process_ndef NET_NFC_NULL_PARAMETER");
		return NET_NFC_NULL_PARAMETER;
	}

	/* create file */
	if ((result = net_nfc_app_util_store_ndef_message(data)) != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_app_util_store_ndef_message failed [%d]", result);
		return result;
	}

	/* check state of launch popup */
	if(net_nfc_app_util_check_launch_state() == TRUE)
	{
		DEBUG_SERVER_MSG("skip launch popup!!!");
		result = NET_NFC_OK;
		return result;
	}

	if (net_nfc_util_create_ndef_message(&msg) != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("memory alloc fail..");
		return NET_NFC_ALLOC_FAIL;
	}

	/* parse ndef message and fill appsvc data */
	if ((result = net_nfc_util_convert_rawdata_to_ndef_message(data, msg)) != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_app_util_store_ndef_message failed [%d]", result);
		goto ERROR;
	}

	if (_net_nfc_app_util_get_operation_from_record(msg->records, operation, sizeof(operation)) == FALSE)
	{
		DEBUG_ERR_MSG("_net_nfc_app_util_get_operation_from_record failed [%d]", result);
		result = NET_NFC_UNKNOWN_ERROR;
		goto ERROR;
	}

	if (_net_nfc_app_util_get_mime_from_record(msg->records, mime, sizeof(mime)) == FALSE)
	{
		DEBUG_ERR_MSG("_net_nfc_app_util_get_mime_from_record failed [%d]", result);
		result = NET_NFC_UNKNOWN_ERROR;
		goto ERROR;
	}
#ifdef USE_FULL_URI
	if (_net_nfc_app_util_get_uri_from_record(msg->records, uri, sizeof(uri)) == FALSE)
	{
		DEBUG_ERR_MSG("_net_nfc_app_util_get_uri_from_record failed [%d]", result);
		result = NET_NFC_UNKNOWN_ERROR;
		goto ERROR;
	}
#endif
	/* launch appsvc */
	if (_net_nfc_app_util_get_data_from_record(msg->records, text, sizeof(text)) == FALSE)
	{
		DEBUG_ERR_MSG("_net_nfc_app_util_get_data_from_record failed [%d]", result);
		result = NET_NFC_UNKNOWN_ERROR;
		goto ERROR;
	}

	ret = net_nfc_app_util_appsvc_launch(operation, uri, mime, text);
#if 0
	if (ret == APPSVC_RET_ENOMATCH)
	{
		/* TODO : check again */
		ret = net_nfc_app_util_appsvc_launch(operation, uri, mime, text);
	}
#endif

	DEBUG_SERVER_MSG("net_nfc_app_util_appsvc_launch return %d", ret);

	result = NET_NFC_OK;

ERROR :
	net_nfc_util_free_ndef_message(msg);

	return result;
}

bool _net_nfc_app_util_change_file_owner_permission(FILE *file)
{
	char *buffer = NULL;
	size_t buffer_len = 0;
	struct passwd pwd = { 0, };
	struct passwd *pw_inhouse = NULL;
	struct group grp = { 0, };
	struct group *gr_inhouse = NULL;

	if (file == NULL)
		return false;

	/* change permission */
	fchmod(fileno(file), 0777);

	/* change owner */
	/* get passwd id */
	buffer_len = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (buffer_len == -1)
	{
		buffer_len = 16384;
	}

	_net_nfc_util_alloc_mem(buffer, buffer_len);
	if (buffer == NULL)
		return false;

	getpwnam_r("inhouse", &pwd, buffer, buffer_len, &pw_inhouse);
	_net_nfc_util_free_mem(buffer);

	/* get group id */
	buffer_len = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (buffer_len == -1)
	{
		buffer_len = 16384;
	}

	_net_nfc_util_alloc_mem(buffer, buffer_len);
	if (buffer == NULL)
		return false;

	getgrnam_r("inhouse", &grp, buffer, buffer_len, &gr_inhouse);
	_net_nfc_util_free_mem(buffer);

	if ((pw_inhouse != NULL) && (gr_inhouse != NULL))
	{
		if (fchown(fileno(file), pw_inhouse->pw_uid, gr_inhouse->gr_gid) < 0)
		{
			DEBUG_ERR_MSG("failed to change owner");
		}
	}

	return true;
}

net_nfc_error_e net_nfc_app_util_store_ndef_message(data_s *data)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	char file_name[1024] = { 0, };
	struct stat st;
	FILE *fp = NULL;

	if (data == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	/* check and make directory */
	snprintf(file_name, sizeof(file_name), "%s/%s", NET_NFC_MANAGER_DATA_PATH,
		NET_NFC_MANAGER_DATA_PATH_MESSAGE);

	if (stat(file_name, &st) == -1)
	{
		int result;
		char command[1024];

		DEBUG_SERVER_MSG("path doesn't exist, do mkdir : %s", file_name);

		snprintf(command, sizeof(command), "mkdir -p -m 755 %s", file_name);

		result = system(command);

		if (stat(file_name, &st) == -1)
		{
			DEBUG_ERR_MSG("mkdir failed");
			return NET_NFC_UNKNOWN_ERROR;
		}
	}

	/* create file */
	snprintf(file_name, sizeof(file_name), "%s/%s/%s", NET_NFC_MANAGER_DATA_PATH,
		NET_NFC_MANAGER_DATA_PATH_MESSAGE, NET_NFC_MANAGER_NDEF_FILE_NAME);
	DEBUG_SERVER_MSG("file path : %s", file_name);

	unlink(file_name);

	if ((fp = fopen(file_name, "w")) != NULL)
	{
		int length = 0;

		if ((length = fwrite(data->buffer, 1, data->length, fp)) > 0)
		{
			DEBUG_SERVER_MSG("[%d] bytes is written", length);

			_net_nfc_app_util_change_file_owner_permission(fp);

			fflush(fp);
			fsync(fileno(fp));

			result = NET_NFC_OK;
		}
		else
		{
			DEBUG_ERR_MSG("write is failed = [%d]", data->length);
			result = NET_NFC_UNKNOWN_ERROR;
		}

		fclose(fp);
	}

	return result;
}

bool net_nfc_app_util_is_dir(const char* path_name)
{
	struct stat statbuf = { 0 };

	if (stat(path_name, &statbuf) == -1)
	{
		return false;
	}

	if (S_ISDIR(statbuf.st_mode) != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void net_nfc_app_util_clean_storage(char* src_path)
{
	struct dirent* ent = NULL;
	DIR* dir = NULL;

	char path[1024] = { 0 };

	if ((dir = opendir(src_path)) == NULL)
	{
		return;
	}

	while ((ent = readdir(dir)) != NULL)
	{
		if (strncmp(ent->d_name, ".", 1) == 0 || strncmp(ent->d_name, "..", 2) == 0)
		{
			continue;
		}
		else
		{
			snprintf(path, 1024, "%s/%s", src_path, ent->d_name);

			if (net_nfc_app_util_is_dir(path) != false)
			{
				net_nfc_app_util_clean_storage(path);
				rmdir(path);
			}
			else
			{
				unlink(path);
			}
		}
	}

	closedir(dir);

	rmdir(src_path);
}

static bool __check_is_sbeam_record(ndef_record_s *record)
{
	data_s *type_s = &record->type_s;
	int index = 0;

	if (type_s->buffer == NULL || type_s->length == 0)
	{
		return FALSE;
	}

	DEBUG_SERVER_MSG("mime : %s", type_s->buffer);

	while (sbeam_mime_type[index] != NULL)
	{
		if (strncasecmp((char *)type_s->buffer, sbeam_mime_type[index],
			MIN(type_s->length, strlen(sbeam_mime_type[index]))) == 0)
		{
			return TRUE;
		}
		index++;
	}

	return FALSE;
}

static void _to_lower_utf_8(char *str)
{
	while (*str != 0)
	{
		if (*str >= 'A' && *str <= 'Z')
			*str += ('a' - 'A');

		str++;
	}
}

static void _to_lower(int type, char *str)
{
	_to_lower_utf_8(str);
}

static bool _net_nfc_app_util_get_operation_from_record(ndef_record_s *record, char *operation, size_t length)
{
	bool result = false;
	char *op_text = NULL;

	if (record == NULL || operation == NULL || length == 0)
	{
		return result;
	}

	switch (record->TNF)
	{
	case NET_NFC_RECORD_WELL_KNOWN_TYPE :
		op_text = "http://tizen.org/appcontrol/operation/nfc/wellknown";
		break;

	case NET_NFC_RECORD_MIME_TYPE :
		{
			if (__check_is_sbeam_record(record))
				op_text = "http://tizen.org/appcontrol/operation/nfc_sbeam_receive";
			else
				op_text = "http://tizen.org/appcontrol/operation/nfc/mime";
		}
		break;

	case NET_NFC_RECORD_URI : /* Absolute URI */
		op_text = "http://tizen.org/appcontrol/operation/nfc/uri";
		break;

	case NET_NFC_RECORD_EXTERNAL_RTD : /* external type */
		op_text = "http://tizen.org/appcontrol/operation/nfc/external";
		break;

	case NET_NFC_RECORD_EMPTY : /* empty_tag */
		op_text = "http://tizen.org/appcontrol/operation/nfc/empty";
		break;

	case NET_NFC_RECORD_UNKNOWN : /* unknown msg. discard it */
	case NET_NFC_RECORD_UNCHAGNED : /* RFU msg. discard it */
	default :
		break;
	}

	if (op_text != NULL)
	{
		snprintf(operation, length, "%s", op_text);
		result = TRUE;
	}

	return result;
}

static bool _net_nfc_app_util_get_mime_from_record(ndef_record_s *record, char *mime, size_t length)
{
	bool result = false;

	if (record == NULL || mime == NULL || length == 0)
	{
		return result;
	}

	switch (record->TNF)
	{
	case NET_NFC_RECORD_WELL_KNOWN_TYPE :
		{
			if (record->type_s.buffer == NULL || record->type_s.length == 0 ||
				record->payload_s.buffer == NULL || record->payload_s.length == 0)
			{
				DEBUG_ERR_MSG("Broken NDEF Message [NET_NFC_RECORD_WELL_KNOWN_TYPE]");
				break;
			}

			if (record->type_s.length == 1 && record->type_s.buffer[0] == 'U')
			{
				snprintf(mime, length, "U/0x%02x", record->payload_s.buffer[0]);
			}
			else
			{
				memcpy(mime, record->type_s.buffer, record->type_s.length);
				mime[record->type_s.length] = '\0';

				strncat(mime, "/*", 2);
				mime[record->type_s.length + 2] = '\0';
			}

			//DEBUG_SERVER_MSG("mime [%s]", mime);

			result = true;
		}
		break;

	case NET_NFC_RECORD_MIME_TYPE :
		{
			char *token = NULL;
			char *buffer = NULL;
			int len = 0;

			if (record->type_s.buffer == NULL || record->type_s.length == 0)
			{
				DEBUG_ERR_MSG("Broken NDEF Message [NET_NFC_RECORD_MIME_TYPE]");
				break;
			}

			/* get mime type */
			_net_nfc_util_alloc_mem(buffer, record->type_s.length + 1);
			if (buffer == NULL)
			{
				DEBUG_ERR_MSG("_net_nfc_manager_util_alloc_mem return NULL");
				break;
			}
			memcpy(buffer, record->type_s.buffer, record->type_s.length);

			//DEBUG_SERVER_MSG("NET_NFC_RECORD_MIME_TYPE type [%s]", buffer);

			token = strchr(buffer, ';');
			if (token != NULL)
			{
				//DEBUG_SERVER_MSG("token = strchr(buffer, ';') != NULL, len [%d]", token - buffer);
				len = MIN(token - buffer, length - 1);
			}
			else
			{
				len = MIN(strlen(buffer), length - 1);
			}

			//DEBUG_SERVER_MSG("len [%d]", len);

			strncpy(mime, buffer, len);
			mime[len] = '\0';

			_to_lower(0, mime);

			//DEBUG_SERVER_MSG("mime [%s]", mime);

			_net_nfc_util_free_mem(buffer);

			result = true;
		}
		break;

	case NET_NFC_RECORD_URI : /* Absolute URI */
	case NET_NFC_RECORD_EXTERNAL_RTD : /* external type */
	case NET_NFC_RECORD_EMPTY :  /* empty_tag */
		result = true;
		break;

	case NET_NFC_RECORD_UNKNOWN : /* unknown msg. discard it */
	case NET_NFC_RECORD_UNCHAGNED : /* RFU msg. discard it */
	default :
		break;
	}

	return result;
}

#ifdef USE_FULL_URI
static bool _net_nfc_app_util_get_uri_from_record(ndef_record_s *record, char *data, size_t length)
{
	bool result = false;

	if (record == NULL || data == NULL || length == 0)
	{
		return result;
	}

	switch (record->TNF)
	{
	case NET_NFC_RECORD_WELL_KNOWN_TYPE :
	case NET_NFC_RECORD_URI : /* Absolute URI */
		{
			char *uri = NULL;

			if (net_nfc_util_create_uri_string_from_uri_record(record, &uri) == NET_NFC_OK &&
				uri != NULL)
			{
				//DEBUG_SERVER_MSG("uri record : %s", uri);
				snprintf(data, length, "%s", uri);

				_net_nfc_util_free_mem(uri);
			}
			result = true;
		}
		break;

	case NET_NFC_RECORD_EXTERNAL_RTD : /* external type */
		{
			data_s *type = &record->type_s;

			if (type->length > 0)
			{
#if 0
				char *buffer = NULL;
				int len = strlen(NET_NFC_UTIL_EXTERNAL_TYPE_SCHEME);

				_net_nfc_util_alloc_mem(buffer, type->length + len + 1);
				if (buffer != NULL)
				{
					memcpy(buffer, NET_NFC_UTIL_EXTERNAL_TYPE_SCHEME, len);
					memcpy(buffer + len, type->buffer, type->length);

					/* to lower case!! */
					strlwr(buffer);

					DEBUG_SERVER_MSG("uri record : %s", buffer);
					snprintf(data, length, "%s", buffer);

					_net_nfc_util_free_mem(buffer);
				}
#else
				int len = MIN(type->length, length - 1);
				memcpy(data, type->buffer, len);
				data[len] = 0;

				/* to lower case!! */
				_to_lower(0, data);

				//DEBUG_SERVER_MSG("uri record : %s", data);
				result = true;
#endif
			}
		}
		break;

	case NET_NFC_RECORD_MIME_TYPE :
	case NET_NFC_RECORD_EMPTY : /* empy msg. discard it */
		result = true;
		break;

	case NET_NFC_RECORD_UNKNOWN : /* unknown msg. discard it */
	case NET_NFC_RECORD_UNCHAGNED : /* RFU msg. discard it */
	default :
		break;
	}

	return result;
}
#endif

static bool _net_nfc_app_util_get_data_from_record(ndef_record_s *record, char *data, size_t length)
{
	bool result = false;

	if (record == NULL || data == NULL || length == 0)
	{
		return result;
	}

	switch (record->TNF)
	{
	case NET_NFC_RECORD_WELL_KNOWN_TYPE :
		{
			if (record->type_s.buffer == NULL || record->type_s.length == 0
				|| record->payload_s.buffer == NULL || record->payload_s.length == 0)
			{
				DEBUG_ERR_MSG("Broken NDEF Message [NET_NFC_RECORD_WELL_KNOWN_TYPE]");
				break;
			}

			if (record->type_s.length == 1 && record->type_s.buffer[0] == 'T')
			{
				uint8_t *buffer_temp = record->payload_s.buffer;
				uint32_t buffer_length = record->payload_s.length;

				int index = (buffer_temp[0] & 0x3F) + 1;
				int text_length = buffer_length - index;

				memcpy(data, &(buffer_temp[index]), MIN(text_length, length));
			}

			//DEBUG_SERVER_MSG("data [%s]", data);

			result = true;
		}
		break;

	case NET_NFC_RECORD_MIME_TYPE :
	case NET_NFC_RECORD_URI : /* Absolute URI */
	case NET_NFC_RECORD_EXTERNAL_RTD : /* external type */
	case NET_NFC_RECORD_EMPTY : /* empy msg. discard it */
		result = true;
		break;

	case NET_NFC_RECORD_UNKNOWN : /* unknown msg. discard it */
	case NET_NFC_RECORD_UNCHAGNED : /* RFU msg. discard it */
	default :
		break;
	}

	return result;
}

void net_nfc_app_util_aul_launch_app(char* package_name, bundle* kb)
{
	int result = 0;
	if((result = aul_launch_app(package_name, kb)) < 0)
	{
		switch(result)
		{
		case AUL_R_EINVAL:
			DEBUG_SERVER_MSG("aul launch error : AUL_R_EINVAL");
			break;
		case AUL_R_ECOMM:
			DEBUG_SERVER_MSG("aul launch error : AUL_R_ECOM");
			break;
		case AUL_R_ERROR:
			DEBUG_SERVER_MSG("aul launch error : AUL_R_ERROR");
			break;
		default:
			DEBUG_SERVER_MSG("aul launch error : unknown ERROR");
			break;
		}
	}
	else
	{
		DEBUG_SERVER_MSG("success to launch [%s]", package_name);
	}
}

int net_nfc_app_util_appsvc_launch(const char *operation, const char *uri, const char *mime, const char *data)
{
	int result = -1;

	bundle *bd = NULL;

	bd = bundle_create();
	if (bd == NULL)
		return result;

	if (operation != NULL && strlen(operation) > 0)
	{
		DEBUG_SERVER_MSG("operation : %s", operation);
		appsvc_set_operation(bd, operation);
	}

	if (uri != NULL && strlen(uri) > 0)
	{
		DEBUG_SERVER_MSG("uri : %s", uri);
		appsvc_set_uri(bd, uri);
	}

	if (mime != NULL && strlen(mime) > 0)
	{
		DEBUG_SERVER_MSG("mime : %s", mime);
		appsvc_set_mime(bd, mime);
	}

	if (data != NULL && strlen(data) > 0)
	{
		DEBUG_SERVER_MSG("data : %s", data);
		appsvc_add_data(bd, "data", data);
	}

	bundle_add(bd, OSP_K_COND, OSP_K_COND_TYPE);
	bundle_add(bd, OSP_K_LAUNCH_TYPE, osp_launch_type_condition);

	result = appsvc_run_service(bd, 0, NULL, NULL);

	bundle_free(bd);

	return result;
}

void _binary_to_string(uint8_t *buffer, uint32_t len, char *out_buf, uint32_t max_len)
{
	int current = 0;

	if (buffer == NULL || len == 0 || out_buf == NULL || max_len == 0)
		return;

	while (len > 0 && current < max_len)
	{
		current += snprintf(out_buf + current, max_len - current, "%02X", *(buffer++));
		len--;
	}
}

void _string_to_binary(const char *input, uint8_t *output, uint32_t *length)
{
	int current = 0;
	int temp;

	if (input == NULL || *length == 0 || output == NULL)
		return;

	DEBUG_SERVER_MSG("_string_to_binary ");

	/* strlen("nfc://secure/aid/") = 17 */

	input += 17;

	while (*input && (current < *length))
	{
		temp = (*input++) - '0';

		if(temp > 9)
			temp -= 7;

		if(current % 2)
		{
			output[current / 2] += temp;
		}
		else
		{
			output[current / 2] = temp << 4;
		}

		current++;
	}

	*length = current / 2;
}

int net_nfc_app_util_launch_se_transaction_app(net_nfc_secure_element_type_e se_type,
		uint8_t *aid, uint32_t aid_len, uint8_t *param, uint32_t param_len)
{
	int result;
	bundle *bd = NULL;

	/* launch */
	bd = bundle_create();

	appsvc_set_operation(bd, "http://tizen.org/appcontrol/operation/nfc/transaction");

	/* convert aid to aid string */
	if (aid != NULL && aid_len > 0)
	{
		char temp_string[1024] = { 0, };
		char aid_string[1024] = { 0, };

		_binary_to_string(aid, aid_len, temp_string, sizeof(temp_string));
		switch(se_type)
		{
			case SECURE_ELEMENT_TYPE_UICC:
				snprintf(aid_string, sizeof(aid_string), "nfc://secure/SIM1/aid/%s", temp_string);
				break;
			case SECURE_ELEMENT_TYPE_ESE:
				snprintf(aid_string, sizeof(aid_string), "nfc://secure/eSE/aid/%s", temp_string);
				break;
			default:
				snprintf(aid_string, sizeof(aid_string), "nfc://secure/aid/%s", temp_string);
				break;
		}
		DEBUG_SERVER_MSG("aid_string : %s", aid_string);
		appsvc_set_uri(bd, aid_string);
	}

	if (param != NULL && param_len > 0)
	{
		char param_string[1024] = { 0, };

		_binary_to_string(param, param_len, param_string, sizeof(param_string));
		DEBUG_SERVER_MSG("param_string : %s", param_string);
		appsvc_add_data(bd, "data", param_string);
	}

	result = appsvc_run_service(bd, 0, NULL, NULL);

	bundle_free(bd);

	return result;
}

int net_nfc_app_util_encode_base64(uint8_t *buffer, uint32_t buf_len, char *result, uint32_t max_result)
{
	int ret = -1;
	BUF_MEM *bptr;
	BIO *b64, *bmem;

	if (buffer == NULL || buf_len == 0 || result == NULL || max_result == 0)
		return ret;

	/* base 64 */
	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);

	BIO_write(b64, buffer, buf_len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	memset(result, 0, max_result);
	memcpy(result, bptr->data, MIN(bptr->length, max_result - 1));

	BIO_free_all(b64);

	ret = 0;

	return ret;
}

int net_nfc_app_util_decode_base64(const char *buffer, uint32_t buf_len, uint8_t *result, uint32_t *res_len)
{
	int ret = -1;
	char *temp = NULL;

	if (buffer == NULL || buf_len == 0 || result == NULL || res_len == NULL || *res_len == 0)
		return ret;

	_net_nfc_util_alloc_mem(temp, buf_len);
	if (temp != NULL)
	{
		BIO *b64, *bmem;
		uint32_t temp_len;

		b64 = BIO_new(BIO_f_base64());
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		bmem = BIO_new_mem_buf((void *)buffer, buf_len);
		bmem = BIO_push(b64, bmem);

		temp_len = BIO_read(bmem, temp, buf_len);

		BIO_free_all(bmem);

		memset(result, 0, *res_len);
		memcpy(result, temp, MIN(temp_len, *res_len));

		*res_len = MIN(temp_len, *res_len);

		_net_nfc_util_free_mem(temp);

		ret = 0;
	}
	else
	{
		DEBUG_ERR_MSG("alloc failed");
	}

	return ret;
}

pid_t net_nfc_app_util_get_focus_app_pid()
{
	Ecore_X_Window focus;
	pid_t pid;

	ecore_x_init(":0");

	focus = ecore_x_window_focus_get();
	if (ecore_x_netwm_pid_get(focus, &pid))
		return pid;

	return -1;
}

bool net_nfc_app_util_check_launch_state()
{
	pid_t focus_app_pid;
	net_nfc_launch_popup_state_e popup_state;
	bool result = false;

	focus_app_pid = net_nfc_app_util_get_focus_app_pid();

	popup_state = net_nfc_server_get_client_popup_state(focus_app_pid);

	if(popup_state == NET_NFC_NO_LAUNCH_APP_SELECT)
		result = true;

	return result;
}

