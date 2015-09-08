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


#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include "net_nfc.h"
#include "ndef-tool.h"

static GMainLoop *main_loop = NULL;

#if 0
typedef struct _response_context_t
{
	int type;
	void *user_param;
} response_context_t;



static void _handover_completed_cb(net_nfc_error_e result,
	data_h data, void *user_data)
{
//	response_context_t *context = (response_context_t *)user_data;
//	data_h rawdata;

	if (result == NET_NFC_OK)
		fprintf(stdout, "handover success!!!\n\n");
	else
		fprintf(stdout, "handover failed.\n\n");

//	net_nfc_create_rawdata_from_ndef_message((ndef_message_h)context->user_param, &rawdata);
//
//	net_nfc_ex
	g_main_loop_quit(main_loop);
}

static void _handover_cb(net_nfc_target_handle_h handle, void *user_data)
{
	fprintf(stdout, "\ntry to handover...\n\n");

	net_nfc_exchanger_request_connection_handover(handle,
		NET_NFC_CONN_HANDOVER_CARRIER_BT);
}

void _nfc_response_cb(net_nfc_message_e message, net_nfc_error_e result,
	void *data, void *user_param, void *trans_data)
{
	response_context_t *context = (response_context_t *)user_param;

	switch (message)
	{
	case NET_NFC_MESSAGE_TAG_DISCOVERED :
		{
			net_nfc_target_handle_h handle = NULL;
			bool is_ndef = false;

			net_nfc_get_tag_handle((net_nfc_target_info_h)data, &handle);
			net_nfc_get_tag_ndef_support((net_nfc_target_info_h)data, &is_ndef);

			ndef_tool_display_discovered_tag(data);

			if (is_ndef == true)
			{
				if (context->type == 0) /* read */
				{
					_tag_read_cb(handle, user_param);
				}
				else
				{
					_tag_write_cb(handle, user_param);
				}
			}
			else
			{
				fprintf(stdout, "No NDEF tag.. read failed.\n\n");
				g_main_loop_quit(main_loop);
			}
		}
		break;

	case NET_NFC_MESSAGE_READ_NDEF :
		_tag_read_completed_cb((ndef_message_h)data, user_param);
		break;

	case NET_NFC_MESSAGE_WRITE_NDEF :
		_tag_write_completed_cb(result, user_param);
		break;

	case NET_NFC_MESSAGE_P2P_DISCOVERED :

		ndef_tool_display_discovered_target(data);

		if (context->type == 1) /* receive */
		{
			_p2p_send_cb((net_nfc_target_handle_h)data, user_param);
		}
		else if (context->type == 2) /* handover */
		{
			_handover_cb((net_nfc_target_handle_h)data, user_param);
		}
		break;

	case NET_NFC_MESSAGE_P2P_SEND :
		_p2p_send_completed_cb(result, user_param);
		break;

	case NET_NFC_MESSAGE_P2P_RECEIVE :
		_p2p_receive_completed_cb(data, user_param);
		break;

	case NET_NFC_MESSAGE_CONNECTION_HANDOVER :
		_handover_completed_cb(result, data, user_param);
		break;

	case NET_NFC_MESSAGE_OPEN_INTERNAL_SE :
		_open_se_cb(result, data, user_param);
		break;

	case NET_NFC_MESSAGE_SEND_APDU_SE :
		_send_apdu_se_cb(result, data, trans_data, user_param);
		break;

	case NET_NFC_MESSAGE_GET_ATR_SE :
		_get_atr_cb(result, data, trans_data, user_param);
		break;

	case NET_NFC_MESSAGE_CLOSE_INTERNAL_SE :
		_close_se_cb(result, user_param);
		break;

	default :
		break;
	}
}
#endif
static void _initialize_tag_context()
{
	int ret = 0;

	if (!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	ret = net_nfc_client_initialize();
	if (ret == NET_NFC_OK)
	{
	}
}

static void _run_tag_action()
{
	main_loop = g_main_new(TRUE);
	g_main_loop_run(main_loop);
}

static void _release_tag_context(void)
{
	net_nfc_client_deinitialize();
}

static void __device_detached(void *user_data)
{
	g_main_loop_quit(main_loop);
}

static void __ndef_read_completed(net_nfc_error_e result,
	ndef_message_h message, void *user_data)
{
	if (message != NULL)
	{
		ndef_tool_write_ndef_message_to_file((char *)user_data, message);
		ndef_tool_display_ndef_message_from_file((char *)user_data);
	} else {
		fprintf(stdout, "read complete!!! but message is null [%d]\n", result);
	}
}

static void __tag_discovered_read(net_nfc_target_info_h info, void *user_data)
{
	int result;
	bool ndef = false;

	ndef_tool_display_discovered_tag(info);

	net_nfc_get_tag_ndef_support(info, &ndef);
	if (ndef == true) {
		net_nfc_target_handle_h handle = NULL;

		result = net_nfc_get_tag_handle(info, &handle);
		if (result == NET_NFC_OK && handle != NULL) {
			net_nfc_client_ndef_read(handle, __ndef_read_completed,
				user_data);
		} else {
			fprintf(stdout, "failed to get tag handle [%d]\n", result);
		}
	} else {
		fprintf(stdout, "tag is not supported NDEF\n");
	}
}

int ndef_tool_read_ndef_from_tag(const char *file)
{
	int result = 0;

	_initialize_tag_context();

	fprintf(stdout, "Contact a tag to device.....\n");

	net_nfc_client_sys_handler_set_launch_popup_state_force(false);

	net_nfc_client_tag_set_tag_discovered(__tag_discovered_read, (void *)file);
	net_nfc_client_tag_set_tag_detached(__device_detached, NULL);

	_run_tag_action();

	net_nfc_client_tag_unset_tag_detached();
	net_nfc_client_tag_unset_tag_discovered();

	net_nfc_client_sys_handler_set_launch_popup_state_force(true);

	return result;
}

static void __ndef_write_completed(net_nfc_error_e result, void *user_data)
{
	if (result == NET_NFC_OK)
		fprintf(stdout, "write success!!!\n\n");
	else
		fprintf(stdout, "write failed [%d]\n\n", result);
}

static void __tag_discovered_write(net_nfc_target_info_h info, void *user_data)
{
	int result;
	bool ndef = false;

	ndef_tool_display_discovered_tag(info);

	net_nfc_get_tag_ndef_support(info, &ndef);
	if (ndef == true) {
		net_nfc_target_handle_h handle = NULL;

		result = net_nfc_get_tag_handle(info, &handle);
		if (result == NET_NFC_OK && handle != NULL) {
			ndef_message_h message = NULL;

			result = ndef_tool_read_ndef_message_from_file((char *)user_data, &message);
			if (result > 0) {
				net_nfc_client_ndef_write(handle, message, __ndef_write_completed,
					user_data);
				net_nfc_free_ndef_message(message);
			} else {
				fprintf(stdout, "failed to get message from file [%d]\n", result);
			}
		} else {
			fprintf(stdout, "failed to get tag handle [%d]\n", result);
		}
	} else {
		fprintf(stdout, "tag is not supported NDEF\n");
	}
}

int ndef_tool_write_ndef_to_tag(const char *file)
{
	int result = 0;

	_initialize_tag_context();

	fprintf(stdout, "Contact a tag to device.....\n");

	net_nfc_client_sys_handler_set_launch_popup_state_force(false);

	net_nfc_client_tag_set_tag_discovered(__tag_discovered_write, (void *)file);
	net_nfc_client_tag_set_tag_detached(__device_detached, NULL);

	_run_tag_action();

	net_nfc_client_tag_unset_tag_detached();
	net_nfc_client_tag_unset_tag_discovered();

	net_nfc_client_sys_handler_set_launch_popup_state_force(true);

	return result;
}

static void __p2p_discovered_receive(net_nfc_target_handle_h handle_info,
	void *user_data)
{
	ndef_tool_display_discovered_target(handle_info);
}

static void __p2p_data_received(data_h data, void *user_data)
{
	fprintf(stdout, "\np2p receive complete!!!\n\n");
	if (data != NULL)
	{
		ndef_message_h msg;

		net_nfc_create_ndef_message_from_rawdata(&msg, data);

		ndef_tool_write_ndef_message_to_file((char *)user_data, msg);

		net_nfc_free_ndef_message(msg);

		ndef_tool_display_ndef_message_from_file((char *)user_data);
	}
}

int ndef_tool_receive_ndef_via_p2p(const char *file)
{
	int result = 0;

	_initialize_tag_context();

	fprintf(stdout, "Contact a target to device.....\n");

	net_nfc_client_sys_handler_set_launch_popup_state_force(false);

	net_nfc_client_p2p_set_device_discovered(__p2p_discovered_receive, NULL);
	net_nfc_client_p2p_set_device_detached(__device_detached, NULL);
	net_nfc_client_p2p_set_data_received(__p2p_data_received, (void *)file);

	_run_tag_action();

	net_nfc_client_p2p_unset_data_received();
	net_nfc_client_p2p_unset_device_detached();
	net_nfc_client_p2p_unset_device_discovered();

	net_nfc_client_sys_handler_set_launch_popup_state_force(true);

	return result;
}

static void __p2p_send_completed(net_nfc_error_e result, void *user_data)
{
	if (result == NET_NFC_OK)
		fprintf(stdout, "send success!!!\n\n");
	else
		fprintf(stdout, "send failed.\n\n");
}

static void __p2p_discovered_send(net_nfc_target_handle_h handle, void *user_data)
{
	int result;
	data_h rawdata;
	ndef_message_h message;

	ndef_tool_display_discovered_target(handle);

	fprintf(stdout, "\nsending...\n\n");

	result = ndef_tool_read_ndef_message_from_file((char *)user_data, &message);
	if (result > 0) {
		net_nfc_create_rawdata_from_ndef_message(message, &rawdata);
		net_nfc_client_p2p_send(handle, rawdata, __p2p_send_completed,
			user_data);
		net_nfc_free_data(rawdata);
		net_nfc_free_ndef_message(message);
	} else {
		fprintf(stdout, "failed to get message from file [%d]\n", result);
	}
}

int ndef_tool_send_ndef_via_p2p(const char *file)
{

	int result = 0;

	_initialize_tag_context();

	fprintf(stdout, "Contact a target to device.....\n");

	net_nfc_client_sys_handler_set_launch_popup_state_force(false);

	net_nfc_client_p2p_set_device_discovered(__p2p_discovered_send, (void *)file);
	net_nfc_client_p2p_set_device_detached(__device_detached, NULL);

	_run_tag_action();

	net_nfc_client_p2p_unset_device_detached();
	net_nfc_client_p2p_unset_device_discovered();

	net_nfc_client_sys_handler_set_launch_popup_state_force(true);

	return result;
}

static void __p2p_connection_handover_completed_cb(
	net_nfc_error_e result,
	net_nfc_conn_handover_carrier_type_e carrier,
	data_h ac_data,
	void *user_data)
{
	fprintf(stdout, "\nhandover finished [%d]\n\n", result);
}

static void __p2p_discovered_connection_handover(net_nfc_target_handle_h handle, void *user_data)
{
	int result;

	ndef_tool_display_discovered_target(handle);

	fprintf(stdout, "\ntry to connection handover...\n\n");

	result = net_nfc_client_p2p_connection_handover(handle,
		NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN,
		__p2p_connection_handover_completed_cb, user_data);
	if (result < 0) {
		fprintf(stdout, "net_nfc_client_p2p_connection_handover [%d]\n", result);
	}
}

int ndef_tool_connection_handover(const char *file)
{
	int result = 0;

	_initialize_tag_context();

	fprintf(stdout, "Contact a target to device.....\n");

	net_nfc_client_sys_handler_set_launch_popup_state_force(false);

	net_nfc_client_p2p_set_device_discovered(__p2p_discovered_connection_handover, (void *)file);
	net_nfc_client_p2p_set_device_detached(__device_detached, NULL);

	_run_tag_action();

	net_nfc_client_p2p_unset_device_detached();
	net_nfc_client_p2p_unset_device_discovered();

	net_nfc_client_sys_handler_set_launch_popup_state_force(true);

	return result;
}

#if 0
static int _make_file_to_ndef_message(ndef_message_h *msg, const char *file_name)
{
	int result = 0;
	FILE *file = NULL;

	file = fopen(file_name, "rb");
	if (file != NULL)
	{
		long int file_size = 0;
		size_t read = 0;

		fseek(file, 0, SEEK_END);
		file_size = ftell(file);
		fseek(file, 0, SEEK_SET);

		if (file_size > 0)
		{
			data_h data;

			net_nfc_create_data(&data, NULL, file_size);
			if (data != NULL)
			{
				ndef_record_h record;
				data_h type;

				read = fread((void *)net_nfc_get_data_buffer(data), 1, file_size, file);

				net_nfc_create_ndef_message(msg);

				net_nfc_create_data(&type, (uint8_t *)"image/jpeg", 10);

				net_nfc_create_record(&record, NET_NFC_RECORD_MIME_TYPE, type, NULL, data);

				net_nfc_append_record_to_ndef_message(*msg, record);

				net_nfc_free_data(type);
				net_nfc_free_data(data);

				result = file_size;
			}
		}

		fclose(file);
	}

	return result;
}


gboolean __connection_handover(gpointer data)
{
	net_nfc_target_handle_h handle = NULL;
	net_nfc_error_e result;

	fprintf(stdout, "try to open eSE.....\n");

	result = net_nfc_client_p2p_connection_handover()se_open_internal_secure_element_sync(NET_NFC_SE_TYPE_ESE, &handle);
	if (result == NET_NFC_OK) {
		data_h atr = NULL;

		fprintf(stdout, "Open success, getting ATR.....\n");

		result = net_nfc_client_se_get_atr_sync(handle, &atr);
		if (result == NET_NFC_OK) {
			fprintf(stdout, "ATR\n");

			net_nfc_free_data(atr);
		}

		result = net_nfc_client_se_close_internal_secure_element_sync(handle);
	}

	return FALSE;
}

int ndef_tool_connection_handover(const char *file)
{
	int result = 0;
	ndef_message_h msg = NULL;

	if (_make_file_to_ndef_message(&msg, file) > 0)
	{
		response_context.type = 2;
		response_context.user_param = (void *)msg;

		_initialize_tag_context();

		fprintf(stdout, "Contact a target to device.....\n");

		_run_tag_action();

		net_nfc_free_ndef_message(msg);

		_release_tag_context();
	}

	return result;
}

#endif
static unsigned char char_to_num[] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

static int _convert_string_to_hex(const char *str, unsigned char *buffer, size_t length)
{
	size_t i, j, len = strlen(str);

	for (i = 0, j = 0; i < len; j++)
	{
		buffer[j] = (char_to_num[(unsigned char)str[i++]] << 4);
		if (i < len)
		{
			buffer[j] |= char_to_num[(unsigned char)str[i++]];
		}
	}

	return (int)j;
}

static gboolean __send_apdu(gpointer data)
{
	net_nfc_target_handle_h handle = NULL;
	net_nfc_error_e result;

	fprintf(stdout, "try to open eSE.....\n");

	result = net_nfc_client_se_open_internal_secure_element_sync(NET_NFC_SE_TYPE_ESE, &handle);
	if (result == NET_NFC_OK) {
		data_h response = NULL;

		fprintf(stdout, "Open success, send apdu.....\n");

		ndef_tool_display_buffer("APDU", net_nfc_get_data_buffer(data),
			net_nfc_get_data_length(data));

		result = net_nfc_client_se_send_apdu_sync(handle, data, &response);
		if (result == NET_NFC_OK) {
			ndef_tool_display_buffer("Response", net_nfc_get_data_buffer(response),
				net_nfc_get_data_length(response));
		} else {
			fprintf(stdout, "failed to send apdu [%d]\n", result);
		}

		net_nfc_free_data(response);

		result = net_nfc_client_se_close_internal_secure_element_sync(handle);
	} else {
		fprintf(stdout, "failed to open eSE [%d]\n", result);
	}

	net_nfc_free_data(data);

	g_main_loop_quit(main_loop);

	return FALSE;
}

int ndef_tool_send_apdu(const char *apdu)
{
	int result = 0;
	unsigned char *buffer;
	unsigned int length = (strlen(apdu) >> 1) + 1;

	buffer = calloc(1, length);
	if (buffer != NULL)
	{
		length = _convert_string_to_hex(apdu, buffer, length);
		if (length > 0)
		{
			data_h data;

			_initialize_tag_context();

			net_nfc_create_data(&data, buffer, length);

			g_idle_add(__send_apdu, data);

			_run_tag_action();

			_release_tag_context();
		}

		free(buffer);
	}

	return result;
}

static gboolean __get_atr(gpointer data)
{
	net_nfc_target_handle_h handle = NULL;
	net_nfc_error_e result;

	fprintf(stdout, "try to open eSE.....\n");

	result = net_nfc_client_se_open_internal_secure_element_sync(NET_NFC_SE_TYPE_ESE, &handle);
	if (result == NET_NFC_OK) {
		data_h atr = NULL;

		fprintf(stdout, "Open success, getting ATR.....\n");

		result = net_nfc_client_se_get_atr_sync(handle, &atr);
		if (result == NET_NFC_OK) {
			ndef_tool_display_buffer("ATR", net_nfc_get_data_buffer(data),
				net_nfc_get_data_length(data));
		} else {
			fprintf(stdout, "failed to get atr [%d]\n", result);
		}

		net_nfc_free_data(atr);

		result = net_nfc_client_se_close_internal_secure_element_sync(handle);
	} else {
		fprintf(stdout, "failed to open eSE [%d]\n", result);
	}

	return FALSE;
}

int ndef_tool_get_atr()
{
	int result = 0;

	_initialize_tag_context();

	g_idle_add(__get_atr, NULL);

	_run_tag_action();

	return result;
}
