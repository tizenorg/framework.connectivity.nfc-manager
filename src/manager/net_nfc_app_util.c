/*
  * Copyright 2012  Samsung Electronics Co., Ltd
  *
  * Licensed under the Flora License, Version 1.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://www.tizenopensource.org/license
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

#include "net_nfc_typedef.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_manager_util_private.h"
#include "net_nfc_app_util_private.h"
#include "net_nfc_util_access_control_private.h"
//#include "syspopup_caller.h"

#include "appsvc.h"
#include "aul.h"
#include "vconf.h"

#define NET_NFC_DEFAULT_APP "com.samsung.nfc-app"
#define NET_NFC_SYSPOPUP "nfc-syspopup"

#define BT_CARRIER_MIME_NAME "application/vnd.bluetooth.ep.oob"
#define WIFI_CARRIER_MIME_NAME "application/vnd.wfa.wsc"

static bool _net_nfc_app_util_get_operation_from_record(ndef_record_s *record, char *operation, size_t length);
static bool _net_nfc_app_util_get_mime_from_record(ndef_record_s *record, char *mime, size_t length);
static bool _net_nfc_app_util_get_data_from_record(ndef_record_s *record, char *data, size_t length);

static char *uri_scheme[] =
{
	"http:",
	"https:",
	"ftp:",
	"sftp:",
	"smb:",
	"nfs:",
	"telnet:",
	"file:",
	"ssh:",
	"market:",
	"tel:",
	"mailto",
	"news:",
	"sip:",
	"sips:",
	"tftp:",
	"imap:",
	"pop:",
	"",
};

static const char *sbeam_mime_type[] =
{
	"text/DirectShareGallery",
	"text/DirectShareMusic",
	"text/DirectShareVideos",
	"text/DirectShareFile",
	"text/DirectSharePolarisViewer",
	"text/DirectSharePolarisEditor",
	"text/DirectShareDefault"
};

net_nfc_error_e net_nfc_app_util_process_ndef(data_s *data)
{
	net_nfc_error_e result = NET_NFC_UNKNOWN_ERROR;
	ndef_message_s *msg = NULL;
	char operation[2048] = {0, };
	char mime[2048] = {0, };
	char text[2048] = {0, };
	int ret = 0;
	int disable = 0;

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
	if (vconf_get_bool(NET_NFC_DISABLE_LAUNCH_POPUP_KEY, &disable) == 0 && disable == FALSE)
	{
		DEBUG_MSG("skip launch popup");
		result = NET_NFC_OK;
		return result;
	}

	if(net_nfc_util_create_ndef_message (&msg) != NET_NFC_OK)
	{
		DEBUG_ERR_MSG ("memory alloc fail..");
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

	DEBUG_MSG("operation : %s", operation);

	if (_net_nfc_app_util_get_mime_from_record(msg->records, mime, sizeof(mime)) == FALSE)
	{
		DEBUG_ERR_MSG("_net_nfc_app_util_get_mime_from_record failed [%d]", result);
		result = NET_NFC_UNKNOWN_ERROR;
		goto ERROR;
	}

	DEBUG_MSG("mime : %s", mime);

	/* launch appsvc */
	if (_net_nfc_app_util_get_data_from_record(msg->records, text, sizeof(text)) == TRUE)
	{
		ret = net_nfc_app_util_appsvc_launch(operation, NULL, mime, text);
	}
	else
	{
		ret = net_nfc_app_util_appsvc_launch(operation, NULL, mime, NULL);
	}

	DEBUG_MSG("net_nfc_app_util_appsvc_launch return %d", ret);

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
	snprintf(file_name, sizeof(file_name), "%s/%s", NET_NFC_MANAGER_DATA_PATH, NET_NFC_MANAGER_DATA_PATH_MESSAGE);
	DEBUG_MSG("path : %s", file_name);

	if (stat(file_name, &st) == -1)
	{
		char command[1024];

		DEBUG_MSG("path doesn't exist : %s", file_name);

		snprintf(command, sizeof(command), "mkdir -p -m 755 %s", file_name);
		DEBUG_MSG("command : %s", command);

		system(command);

		if (stat(file_name, &st) == -1)
		{
			DEBUG_ERR_MSG("mkdir failed");
			return NET_NFC_UNKNOWN_ERROR;
		}
	}

	/* create file */
	snprintf(file_name, sizeof(file_name), "%s/%s/%s", NET_NFC_MANAGER_DATA_PATH, NET_NFC_MANAGER_DATA_PATH_MESSAGE, NET_NFC_MANAGER_NDEF_FILE_NAME);
	DEBUG_MSG("file path : %s", file_name);

	unlink(file_name);

	DEBUG_MSG("file name is = [%s]", file_name);

	if ((fp = fopen(file_name, "w")) != NULL)
	{
		int length = 0;

		if ((length = fwrite(data->buffer, 1, data->length, fp)) > 0)
		{
			DEBUG_MSG("[%d] bytes is written", length);
		}
		else
		{
			DEBUG_MSG("write is failed = [%d]", data->length);
		}

		_net_nfc_app_util_change_file_owner_permission(fp);

		fflush(fp);
		fsync(fileno(fp));
		fclose(fp);

		result = NET_NFC_OK;
	}

	return result;
}

bool net_nfc_app_util_is_dir(const char* path_name)
{
	struct stat statbuf = {0};

	if (stat(path_name, &statbuf) == -1)
	{
		return false;
	}

	if(S_ISDIR(statbuf.st_mode) != 0)
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

	char path[1024] = {0};

	if ((dir = opendir(src_path)) == NULL )
	{
		return;
	}

	while((ent = readdir(dir)) != NULL)
	{
		if( strncmp(ent->d_name, "." , 1 ) == 0 || strncmp(ent->d_name, ".." , 2) == 0)
		{
			continue;
		}
		else
		{
			snprintf(path,1024, "%s/%s", src_path, ent->d_name);

			if(net_nfc_app_util_is_dir(path) != false)
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
	bool result = FALSE;
	data_s type_s = record->type_s;
	int index = 0;

	if (type_s.buffer == NULL || type_s.length == 0)
	{
		return result;
	}

	DEBUG_MSG("type_s.buffer [%s]", type_s.buffer);

	while (strlen(sbeam_mime_type[index]) > 0)
	{
		if (strncasecmp(type_s.buffer, sbeam_mime_type[index], strlen(sbeam_mime_type[index])) == 0)
		{
			return TRUE;
		}
		index++;
	}

	return result;
}

static bool _net_nfc_app_util_get_operation_from_record(ndef_record_s *record, char *operation, size_t length)
{
	bool result = FALSE;
	char *op_text = NULL;

	if (record == NULL || operation == NULL || length == 0)
	{
		return result;
	}

	switch (record->TNF)
	{
	case NET_NFC_RECORD_WELL_KNOWN_TYPE :
		op_text = "http://tizen.org/appcontrol/operation/nfc_well_known_type";
		break;
	case NET_NFC_RECORD_MIME_TYPE :
	{
		if (__check_is_sbeam_record(record))
			op_text = "http://tizen.org/appcontrol/operation/nfc_sbeam_receive";
		else
			op_text = "http://tizen.org/appcontrol/operation/nfc_mime_type";
	}
		break;
	case NET_NFC_RECORD_URI : /* Absolute URI */
		op_text = "http://tizen.org/appcontrol/operation/nfc_uri_type";
		break;
	case NET_NFC_RECORD_EXTERNAL_RTD : /* external type */
		op_text = "http://tizen.org/appcontrol/operation/nfc_external_type";
		break;
	case NET_NFC_RECORD_EMPTY : /* empty_tag */
		op_text = "http://tizen.org/appcontrol/operation/nfc_empty_type";
		break;
	case NET_NFC_RECORD_UNKNOWN : /* unknown msg. discard it */
	case NET_NFC_RECORD_UNCHAGNED : /* RFU msg. discard it */
	default :
		break;
	}

	if (op_text != NULL)
	{
		size_t op_length = 0;

		op_length = MIN(strlen(op_text) + 1, length);

		strncpy(operation, op_text, op_length - 1);
		operation[op_length - 1] = '\0';
		result = TRUE;
	}

	return result;
}

static bool _net_nfc_app_util_get_mime_from_record(ndef_record_s *record, char *mime, size_t length)
{
	bool result = FALSE;

	if (record == NULL || mime == NULL || length == 0)
	{
		return result;
	}

	switch (record->TNF)
	{
	case NET_NFC_RECORD_WELL_KNOWN_TYPE :
		{
			if (record->type_s.buffer == NULL || record->type_s.length == 0 || record->payload_s.buffer == NULL || record->payload_s.length == 0)
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

			DEBUG_MSG("mime [%s]", mime);

			result = TRUE;
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
			_net_nfc_manager_util_alloc_mem(buffer, record->type_s.length + 1);
			if (buffer == NULL)
			{
				DEBUG_ERR_MSG("_net_nfc_manager_util_alloc_mem return NULL");
				break;
			}
			memcpy(buffer, record->type_s.buffer, record->type_s.length);

			DEBUG_MSG("NET_NFC_RECORD_MIME_TYPE type [%s]", buffer);

			token = strchr(buffer, ';');
			if (token != NULL)
			{
				DEBUG_MSG("token = strchr(buffer, ';') != NULL, len [%d]", token - buffer);
				len = MIN(token - buffer, length - 1);
			}
			else
			{
				len = MIN(strlen(buffer), length - 1);
			}

			DEBUG_MSG("len [%d]", len);

			strncpy(mime, buffer, len);
			mime[len] = '\0';

			DEBUG_MSG("mime [%s]", mime);

			_net_nfc_manager_util_free_mem(buffer);

			result = TRUE;
		}
		break;

	case NET_NFC_RECORD_URI : /* Absolute URI */
		{
			CURL *curl_handle = NULL;
			char *buffer = NULL;
			uint32_t scheme_len = 0;
			int index = 0;
			char scheme[100] = {0, };

			DEBUG_MSG("record->type_s.length [%d]" , record->type_s.length);
			DEBUG_MSG("record->type_s.buffer [%s]" , record->type_s.buffer);

			if (record->type_s.buffer == NULL || record->type_s.length == 0)
			{
				DEBUG_ERR_MSG("Broken NDEF Message [NET_NFC_RECORD_URI]");
				break;
			}

			_net_nfc_manager_util_alloc_mem(buffer, record->type_s.length + 1);
			if (buffer == NULL)
			{
				DEBUG_ERR_MSG("_net_nfc_manager_util_alloc_mem return NULL");
				break;
			}
			memcpy(buffer, record->type_s.buffer, record->type_s.length);

			while (strlen(uri_scheme[index]) > 0)
			{
				if (strncasecmp(buffer, uri_scheme[index], strlen(uri_scheme[index])) == 0)
				{
					scheme_len = MIN(sizeof(scheme) - 1, strlen(uri_scheme[index]) - 1);

					memcpy(scheme, uri_scheme[index], scheme_len);
					scheme[scheme_len] = '\0';
					DEBUG_MSG("uri scheme = [%s]" ,buffer );
					break;
				}
				index++;
			}

			if (scheme_len == 0)
			{
				scheme_len = MIN(sizeof(scheme) - 1, strlen("unknown"));

				memcpy(scheme, "unknown", scheme_len);
				scheme[scheme_len] = '\0';
			}

			snprintf(mime, length, "%s/%s", scheme, buffer);
			DEBUG_MSG("mime [%s]", mime);

			DEBUG_MSG("mime not end [%s]", mime);
			_net_nfc_manager_util_free_mem(buffer);

			result = TRUE;
		}
		break;

	case NET_NFC_RECORD_EXTERNAL_RTD : /* external type */
		{
			CURL *curl_handle = NULL;
			char *token = NULL;
			char *buffer = NULL;
			int token_len = 0;
			int len = 0;

			if (record->type_s.buffer == NULL || record->type_s.length == 0)
			{
				DEBUG_ERR_MSG("Broken NDEF Message [NET_NFC_RECORD_EXTERNAL_RTD]");
				break;
			}

			/* get mime type */
			_net_nfc_manager_util_alloc_mem(buffer, record->type_s.length + 1);
			if (buffer == NULL)
			{
				DEBUG_ERR_MSG("_net_nfc_manager_util_alloc_mem return NULL");
				break;
			}
			memcpy(buffer, record->type_s.buffer, record->type_s.length);

			DEBUG_MSG("NET_NFC_RECORD_EXTERNAL_RTD type [%s]", buffer);

			token = strchr(buffer, ':');
			if (token != NULL)
			{
				DEBUG_MSG("token = strchr(buffer, ':') != NULL");
				*token = '/';
				token_len = token - buffer;

				memcpy(mime, buffer, token_len);
				mime[token_len] = '/';
				mime[token_len + 1] = '\0';
			}
			else
			{
				strncpy(mime, "unknown/", 8);
				mime[8] = '\0';
			}

			DEBUG_MSG("mime not end [%s]", mime);
			_net_nfc_manager_util_free_mem(buffer);

			/* percent encode uri */
			curl_handle = curl_easy_init();
			if (curl_handle == NULL)
			{
				DEBUG_ERR_MSG("curl_easy_init return NULL");
				break;
			}

			buffer = curl_easy_escape(curl_handle, (char *)record->type_s.buffer, record->type_s.length);
			if (buffer == NULL)
			{
				DEBUG_ERR_MSG("curl_easy_escape return NULL");
				curl_easy_cleanup(curl_handle);
				break;
			}
			DEBUG_MSG("curl_easy_escape result [%s]", buffer);

			token_len = strlen(mime);
			len = MIN(length - token_len - 1, strlen(buffer));

			memcpy(mime + token_len, buffer, len);
			mime[len + token_len] = '\0';

			DEBUG_MSG("mime [%s]", mime);

			/* release curl */
			curl_free(buffer);
			curl_easy_cleanup(curl_handle);

			result = TRUE;
		}
		break;

	case NET_NFC_RECORD_EMPTY :  /* empty_tag */
		result = TRUE;
		mime = NULL;
		break;


	case NET_NFC_RECORD_UNKNOWN : /* unknown msg. discard it */
	case NET_NFC_RECORD_UNCHAGNED : /* RFU msg. discard it */
	default :
		break;
	}

	return result;
}

static bool _net_nfc_app_util_get_data_from_record(ndef_record_s *record, char *data, size_t length)
{
	bool result = FALSE;

	if (record == NULL || data == NULL || length == 0)
	{
		return result;
	}

	switch (record->TNF)
	{
	case NET_NFC_RECORD_WELL_KNOWN_TYPE :
		{
			if (record->type_s.buffer == NULL || record->type_s.length == 0 || record->payload_s.buffer == NULL || record->payload_s.length == 0)
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

			DEBUG_MSG("data [%s]", data);

			result = TRUE;
		}
		break;

	case NET_NFC_RECORD_MIME_TYPE :
	case NET_NFC_RECORD_URI : /* Absolute URI */
	case NET_NFC_RECORD_EXTERNAL_RTD : /* external type */
	case NET_NFC_RECORD_EMPTY : /* empy msg. discard it */
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
				DEBUG_MSG("aul launch error : AUL_R_EINVAL");
				break;
			case AUL_R_ECOMM:
				DEBUG_MSG("aul launch error : AUL_R_ECOM");
				break;
			case AUL_R_ERROR:
				DEBUG_MSG("aul launch error : AUL_R_ERROR");
				break;
			default:
				DEBUG_MSG("aul launch error : unknown ERROR");
				break;
		}
	}
	else
	{
		DEBUG_MSG("success to launch [%s]", package_name);
	}
}

int net_nfc_app_util_appsvc_launch(const char *operation, const char *uri, const char *mime, const char *data)
{
	int result = -1;

	bundle *bd = NULL;

	bd = bundle_create();
	if (bd == NULL)
		return result;

	if (operation != NULL)
	{
		appsvc_set_operation(bd, operation);
	}

	if (uri != NULL)
	{
		appsvc_set_uri(bd, uri);
	}

	if (mime != NULL)
	{
		appsvc_set_mime(bd, mime);
	}

	if (data != NULL)
	{
		appsvc_add_data(bd, "data", data);
	}

	result = appsvc_run_service(bd, 0, NULL, NULL);

	bundle_free(bd);

	return result;
}

static int _pkglist_iter_fn(const char* pkg_name, void *data)
{
	int result = 0;
	const char *aid_string = NULL;
	uint8_t aid[1024] = { 0, };
	uint32_t length = sizeof(aid);

	aid_string = appsvc_get_uri((bundle *)data);
	DEBUG_MSG("package name : %s, aid_string : %s", pkg_name, aid_string);

	/* convert aid string to aid */
	net_nfc_app_util_decode_base64(aid_string, strlen(aid_string), aid, &length);

	if (net_nfc_util_access_control_is_authorized_package(pkg_name, aid, length) == true)
	{
		DEBUG_MSG("allowed package : %s", pkg_name);

		/* launch */
		aul_launch_app(pkg_name, (bundle *)data);

		result = 1; /* break iterator */
	}
	else
	{
		DEBUG_MSG("not allowed package : %s", pkg_name);
	}

 	return result;
}

gboolean _invoke_get_list(gpointer data)
{
	bundle *bd = (bundle *)data;

	appsvc_get_list(bd, _pkglist_iter_fn, (bundle *)bd);

	bundle_free(bd);

	return 0;
}

int net_nfc_app_util_launch_se_transaction_app(uint8_t *aid, uint32_t aid_len, uint8_t *param, uint32_t param_len)
{
	char aid_string[1024] = { 0, };
	char param_string[1024] = { 0, };
	bundle *bd = NULL;

	/* initialize and make list */
	if (net_nfc_util_access_control_is_initialized() == false)
	{
		net_nfc_util_access_control_initialize();
	}

	net_nfc_util_access_control_update_list();

	/* convert aid to aid string */
	net_nfc_app_util_encode_base64(aid, aid_len, aid_string, sizeof(aid_string));
	DEBUG_MSG("aid_string : %s", aid_string);

	net_nfc_app_util_encode_base64(param, param_len, param_string, sizeof(param_string));
	DEBUG_MSG("param_string : %s", param_string);

	/* launch */
	bd = bundle_create();

	appsvc_set_operation(bd, "http://tizen.org/appcontrol/operation/nfc_se_transaction");
	appsvc_set_uri(bd, aid_string);
	appsvc_add_data(bd, "data", param_string);

	g_idle_add((GSourceFunc)_invoke_get_list, (gpointer)bd);

	return 0;
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

	_net_nfc_manager_util_alloc_mem(temp, buf_len);
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

		_net_nfc_manager_util_free_mem(temp);

		ret = 0;
	}
	else
	{
		DEBUG_ERR_MSG("alloc failed");
	}

	return ret;
}
