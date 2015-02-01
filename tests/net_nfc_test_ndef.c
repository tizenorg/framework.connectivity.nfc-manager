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

#include "net_nfc_client_ndef.h"

#include "net_nfc_test_tag.h"
#include "net_nfc_test_ndef.h"
#include "net_nfc_test_util.h"
#include "net_nfc_ndef_message.h"
#include "net_nfc_target_info.h"
#include "net_nfc_ndef_record.h"
#include "net_nfc_test_util.c"


static void run_next_callback(gpointer user_data);

static void print_record_well_known_type(ndef_record_h record);

static void print_record(ndef_record_h record);

static void print_ndef_message(ndef_message_h message);

static net_nfc_target_handle_h ndef_get_handle(void);

static ndef_message_h create_ndef_message_text(const gchar *str,
					const gchar *lang,
					net_nfc_encode_type_e encode);

static void set_string(const gchar *str);

static gchar *get_write_string(void);


static void ndef_read_cb(net_nfc_error_e result,
		ndef_message_h message,
		void *user_data);

static void ndef_write_cb(net_nfc_error_e result,
		void *user_data);

static void ndef_make_read_only_cb(net_nfc_error_e result,
				void *user_data);

static void ndef_format_cb(net_nfc_error_e result,
		void *user_data);

static gchar *ndef_str = NULL;
static gint ndef_count = 0;

static void run_next_callback(gpointer user_data)
{
	if (user_data)
	{
		GCallback callback;

		callback = (GCallback)(user_data);

		callback();
	}
}

static void print_record_well_known_type(ndef_record_h record)
{
	gchar *uri = NULL;
	gchar *lang = NULL;
	gchar *text = NULL;

	net_nfc_encode_type_e enc;

	net_nfc_create_uri_string_from_uri_record(record, &uri);
	if (uri)
	{
		g_print("URI: %s\n", uri);
		g_free(uri);
	}

	net_nfc_create_text_string_from_text_record(record, &text);
	if(text)
	{
		g_print("Text:\n%s\n", text);
		set_string(text);
		g_free(text);

	}

	net_nfc_get_languange_code_string_from_text_record(record, &lang);
	if(lang)
	{
		g_print("Language: %s\n", lang);
		g_free(lang);
	}

	net_nfc_get_encoding_type_from_text_record(record, &enc);
	switch (enc)
	{
		case NET_NFC_ENCODE_UTF_8:
			g_print("Encoding: UTF-8\n");
			break;
		case NET_NFC_ENCODE_UTF_16:
			g_print("Encoding: UTF-16\n");
			break;
		default:
			g_print("Encoding: Unknown\n");
	}
}

static void print_record(ndef_record_h record)
{
	guint8 flag;
	gchar *str = NULL;

	gchar *tnf_str[] = {
		"Empty",
		"Well-known type",
		"Media-type",
		"Absolute URI",
		"External type",
		"Unknown",
		"Unchanged"
	};

	net_nfc_record_tnf_e tnf;

	data_h type = NULL;
	data_h id = NULL;
	data_h payload = NULL;

	net_nfc_get_record_flags(record, &flag);
	net_nfc_get_record_tnf(record, &tnf);

	g_print("MB: %d ME: %d CF: %d SR: %d IL: %d TNF: %s\n",
			net_nfc_get_record_mb(flag),
			net_nfc_get_record_me(flag),
			net_nfc_get_record_cf(flag),
			net_nfc_get_record_sr(flag),
			net_nfc_get_record_il(flag),
			tnf_str[tnf]);

	if (net_nfc_get_record_type(record, &type) == NET_NFC_OK)
	{
		str = g_strndup((gchar *)net_nfc_get_data_buffer(type),
				net_nfc_get_data_length(type));
		g_print("Type : %s\n", str);
		g_free(str);
	}

	net_nfc_get_record_id(record, &id);

	str = g_strndup((gchar *)net_nfc_get_data_buffer(id),
			net_nfc_get_data_length(id));
	g_print("ID : %s\n", str);
	g_free(str);

	if (net_nfc_get_record_payload(record, &payload) == NET_NFC_OK)
	{
		print_received_data(payload);
	}

	switch(tnf)
	{
		case NET_NFC_RECORD_EMPTY:
			break;
		case NET_NFC_RECORD_WELL_KNOWN_TYPE:
			print_record_well_known_type(record);
			break;
		case NET_NFC_RECORD_MIME_TYPE:
			break;
		case NET_NFC_RECORD_URI:
			break;
		case NET_NFC_RECORD_EXTERNAL_RTD:
			break;
		case NET_NFC_RECORD_UNKNOWN:
			break;
		case NET_NFC_RECORD_UNCHAGNED:
			break;
		default:
			g_print("TNF: unknown error\n");
			break;
	}
}

static void print_ndef_message(ndef_message_h message)
{
	gint count = 0;
	gint i;

	if (message == NULL)
	{
		g_print("Empty ndef message\n");
		return;
	}

	if (net_nfc_get_ndef_message_record_count(message,
						&count) != NET_NFC_OK)
	{
		g_print("can not get count of record\n");
		return;
	}

	for (i = 0; i < count; i++)
	{
		ndef_record_h record = NULL;

		g_print("Record count : %d\n", i+1);

		if (net_nfc_get_record_by_index(message,
						i,
						&record) != NET_NFC_OK)
		{
			g_print("can not get record from index %d\n", i);
			continue;
		}

		print_record(record);
	}

	g_print("\n");
}

static net_nfc_target_handle_h ndef_get_handle(void)
{
	net_nfc_target_info_h info;
	net_nfc_target_handle_h handle;

	bool is_ndef = false;

	info = net_nfc_test_tag_get_target_info();
	if (info == NULL)
	{
		g_print("net_nfc_target_info_h is NULL\n");
		return NULL;
	}

	net_nfc_get_tag_ndef_support(info, &is_ndef);

	if (is_ndef == false)
	{
		g_print("Tag does not support NDEF\n");
		return NULL;
	}

	net_nfc_get_tag_handle(info, &handle);

	return handle;
}

static ndef_message_h create_ndef_message_text(const gchar *str,
					const gchar *lang,
					net_nfc_encode_type_e encode)
{
	ndef_record_h record = NULL;
	ndef_message_h message = NULL;

	if (net_nfc_create_ndef_message(&message) != NET_NFC_OK)
	{
		g_printerr("Can not create ndef message\n");
		return NULL;
	}

	if (net_nfc_create_text_type_record(&record,
					str,
					lang,
					encode) != NET_NFC_OK)
	{
		g_printerr("Can not create text record(%s, %d): %s\n",
				lang, encode, str);

		net_nfc_free_ndef_message(message);
		return NULL;
	}

	if (net_nfc_append_record_to_ndef_message(message,
					record) != NET_NFC_OK)
	{
		g_printerr("Can not append record to message\n");
		net_nfc_free_ndef_message(message);
		return NULL;
	}

	return message;
}

static void set_string(const gchar *str)
{
	gint count = 0;

	if (str == NULL)
		return;

	sscanf(str, "Count: %d", &count);

	if (count == 0)
		ndef_str = g_strdup(str);
	else
	{
		gchar *tmp;
		gchar *pos;

		pos = (gchar *)str;
		tmp = g_strdup_printf("Count: %d", count);
		if (strncmp(pos, tmp, strlen(tmp)) == 0)
		{
			if (*pos == ' ')
				pos++;

			ndef_str = g_strdup(pos + strlen(tmp));
		}

		g_free(tmp);
	}

	ndef_count = count;
}

static gchar *get_write_string(void)
{
	gchar *str = NULL;

	ndef_count++;

	if (ndef_str == NULL)
		str = g_strdup_printf("Count: %d", ndef_count);
	else
		str = g_strdup_printf("Count: %d %s", ndef_count, ndef_str);

	return str;
}

static void ndef_read_cb(net_nfc_error_e result,
		ndef_message_h message,
		void *user_data)
{
	g_print("Read NDEF Completed %d\n", result);

	print_ndef_message(message);

	run_next_callback(user_data);
}

static void ndef_write_cb(net_nfc_error_e result,
		void *user_data)
{
	g_print("Write NDEF Completed %d\n", result);

	run_next_callback(user_data);
}


static void ndef_make_read_only_cb(net_nfc_error_e result,
				void *user_data)
{
	g_print("Make Read only Completed %d\n", result);

	run_next_callback(user_data);
}

static void ndef_format_cb(net_nfc_error_e result,
		void *user_data)

{
	g_print("NDEF Format Completed: %d\n", result);

	run_next_callback(user_data);
}



void net_nfc_test_ndef_read(gpointer data,
			gpointer user_data)
{
	net_nfc_target_handle_h handle;

	handle = ndef_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);

		return;
	}

	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	net_nfc_client_ndef_read(handle,
				ndef_read_cb,
				user_data);
}

void net_nfc_test_ndef_write(gpointer data,
			gpointer user_data)
{
	net_nfc_target_handle_h handle;
	ndef_message_h message;

	gchar *str = NULL;

	handle = ndef_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}

	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	str = get_write_string();
	if(str == NULL)
	{
		g_printerr("Can not get write string\n");

		run_next_callback(user_data);
		return;
	}

	message = create_ndef_message_text(str,
					"en-US",
					NET_NFC_ENCODE_UTF_8);

	g_free(str);

	if (message == NULL)
	{
		g_printerr("message is NULL\n");

		run_next_callback(user_data);
		return;
	}

	net_nfc_client_ndef_write(handle,
				message,
				ndef_write_cb,
				user_data);

}

void net_nfc_test_ndef_make_read_only(gpointer data,
				gpointer user_data)
{
	net_nfc_target_handle_h handle;

	handle = ndef_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}

	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	net_nfc_client_ndef_make_read_only(handle,
					ndef_make_read_only_cb,
					user_data);
}

void net_nfc_test_ndef_format(gpointer data,
			gpointer user_data)
{
	net_nfc_target_handle_h handle;
	data_h key;
	guint8 format_data[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	handle = ndef_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}

	net_nfc_create_data(&key, format_data, 6);

	net_nfc_client_ndef_format(handle,
				key,
				ndef_format_cb,
				user_data);

	net_nfc_free_data(key);

	return;
}

void net_nfc_test_ndef_read_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_target_handle_h handle;
	ndef_message_h message = NULL;
	net_nfc_error_e result;

	handle = ndef_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}

	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	result = net_nfc_client_ndef_read_sync(handle,
					&message);

	g_print("Read Ndef: %d\n", result);

	print_ndef_message(message);

	net_nfc_free_ndef_message(message);

	run_next_callback(user_data);
}

void net_nfc_test_ndef_write_sync(gpointer data,
				gpointer user_data)
{
	gchar *str = NULL;

	net_nfc_target_handle_h handle;
	ndef_message_h message;
	net_nfc_error_e result;

	handle = ndef_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);
		return;
	}

	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	str = get_write_string();
	if(str == NULL)
	{
		g_printerr("Can not get write string\n");

		run_next_callback(user_data);
		return;
	}

	message = create_ndef_message_text(str,
					"en-US",
					NET_NFC_ENCODE_UTF_8);

	g_free(str);

	if (message == NULL)
	{
		g_printerr("message is NULL\n");

		run_next_callback(user_data);

		return;
	}

	result = net_nfc_client_ndef_write_sync(handle, message);

	g_print("Write Ndef: %d\n", result);

	run_next_callback(user_data);
}

void net_nfc_test_ndef_make_read_only_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_target_handle_h handle;
	net_nfc_error_e result;

	handle = ndef_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);

		return;
	}

	g_print("Handle is %#x\n", GPOINTER_TO_UINT(handle));

	result = net_nfc_client_ndef_make_read_only_sync(handle);

	g_print("Make Read Only: %d\n", result);

	run_next_callback(user_data);
}

void net_nfc_test_ndef_format_sync(gpointer data,
				gpointer user_data)
{
	net_nfc_target_handle_h handle;
	net_nfc_error_e result;
	data_h key;
	guint8 format_data[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	handle = ndef_get_handle();
	if (handle == NULL)
	{
		g_printerr("Handle is NULL\n");

		run_next_callback(user_data);

		return;
	}

	net_nfc_create_data(&key, format_data, 6);

	result = net_nfc_client_ndef_format_sync(handle, key);

	net_nfc_free_data(key);

	g_print("NDEF Format %d\n", result);

	run_next_callback(user_data);
}
