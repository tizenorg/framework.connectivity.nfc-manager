/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <glib.h>
#include "net_nfc_server_p2p.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_server_llcp.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_server_tag.h"
#include "net_nfc_server_snep.h"
#include "net_nfc_server_process_snep.h"
#include "net_nfc_app_util_internal.h"
#include "net_nfc_util_gdbus_internal.h"


typedef struct _net_nfc_server_snep_msg_t
{
	uint8_t version;
	uint8_t op;
	uint32_t length;
	uint8_t data[0];
}
__attribute__ ((packed)) net_nfc_server_snep_msg_t;

typedef struct _net_nfc_server_snep_get_msg_t
{
	uint32_t length;
	uint8_t data[0];
}
__attribute__ ((packed)) net_nfc_server_snep_get_msg_t;

typedef struct _net_nfc_server_cb_data_t
{
	net_nfc_server_snep_listen_cb cb;
	void *user_param;
}
net_nfc_server_cb_data_t;

typedef struct _net_nfc_server_snep_context_t
{
	net_nfc_target_handle_s *handle;
	net_nfc_error_e result;
	net_nfc_llcp_socket_t socket;
	uint32_t state;
	uint32_t type;
	data_s data;
	net_nfc_server_snep_cb cb;
	void *user_param;
	GQueue queue;
}
net_nfc_server_snep_context_t;

typedef struct _net_nfc_server_snep_job_t
{
	net_nfc_server_snep_context_t *context;
	net_nfc_target_handle_s *handle;
	net_nfc_error_e result;
	net_nfc_llcp_socket_t socket;
	uint32_t state;
	uint32_t type;
	data_s data;
	net_nfc_server_snep_cb cb;
	void *user_param;
}
net_nfc_server_snep_job_t;


typedef struct __net_nfc_server_snep_server_context_t
{
	net_nfc_target_handle_s *handle;
	int client;
	void *user_param;
}
_net_nfc_server_snep_server_context_t;

typedef struct __net_nfc_server_snep_service_context_t
{
	net_nfc_target_handle_s *handle;
	int client;
	uint32_t type;
	data_s data;
	void *user_param;
}
_net_nfc_server_snep_service_context_t;

typedef void (*_net_nfc_server_snep_operation_cb)(
				net_nfc_error_e result,
				uint32_t type,
				data_s *data,
				void *user_param);

typedef struct _net_nfc_server_snep_op_context_t
{
	net_nfc_target_handle_s *handle;
	net_nfc_error_e result;
	int socket;
	uint32_t state;
	uint32_t type;
	uint32_t current;
	uint16_t miu;
	data_s data;
	uint32_t offset;
	_net_nfc_server_snep_operation_cb cb;
	void *user_param;
}

net_nfc_server_snep_op_context_t;

#define SNEP_MAJOR_VER			1
#define SNEP_MINOR_VER			0
#define SNEP_VERSION			((SNEP_MAJOR_VER << 4) | SNEP_MINOR_VER)

#define SNEP_HEADER_LEN			(sizeof(net_nfc_server_snep_msg_t))
#define SNEP_MAX_LEN			(SNEP_HEADER_LEN + 1024 * 100)

#define SNEP_REQUEST			(0)
#define SNEP_RESPONSE			(0x80)

#define SNEP_PAIR_OP(__x)		((__x) ^ SNEP_RESPONSE)
#define SNEP_MAKE_PAIR_OP(__x, __y)	((SNEP_PAIR_OP(__x) & SNEP_RESPONSE) | (__y))

#define IS_SNEP_REQ(__x)		(((__x) & SNEP_RESPONSE) == SNEP_REQUEST)
#define IS_SNEP_RES(__x)		(((__x) & SNEP_RESPONSE) == SNEP_RESPONSE)

static GList *list_listen_cb = NULL;

static void _net_nfc_server_snep_recv(
				net_nfc_server_snep_op_context_t *context);

static void _net_nfc_server_snep_send(
				net_nfc_server_snep_op_context_t *context);

static net_nfc_error_e net_nfc_server_snep_recv(
				net_nfc_target_handle_s *handle,
				net_nfc_llcp_socket_t socket,
				_net_nfc_server_snep_operation_cb cb,
				void *user_param);

static net_nfc_error_e net_nfc_server_snep_send(
				net_nfc_target_handle_s *handle,
				net_nfc_llcp_socket_t socket,
				uint32_t type,
				data_s *data,
				_net_nfc_server_snep_operation_cb cb,
				void *user_param);


static void _net_nfc_server_snep_client_process(
				net_nfc_server_snep_job_t *job);

static void _net_nfc_server_snep_server_process(
				net_nfc_server_snep_context_t *context);

/**********************************************************************/
static bool _net_nfc_server_snep_add_get_response_cb(
					net_nfc_server_snep_listen_cb cb,
					void *user_param)
{
	net_nfc_server_cb_data_t *data = NULL;
	bool result = false;

	_net_nfc_util_alloc_mem(data, sizeof(*data));
	if (data != NULL)
	{
		data->cb = cb;
		data->user_param = user_param;

		list_listen_cb = g_list_append(list_listen_cb, data);
		if (list_listen_cb != NULL)
		{
			result = true;
		}
		else
		{
			DEBUG_ERR_MSG("g_list_append failed");
		}
	}
	else
	{
		DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
	}

	return result;
}

static gint _net_nfc_server_snep_compare_func_cb(
					gconstpointer a,
					gconstpointer b)
{
	net_nfc_server_cb_data_t *data = (net_nfc_server_cb_data_t *)a;

	if (data->cb == (void *)b)
		return 0;
	else
		return 1;
}

static void _net_nfc_server_snep_del_get_response_cb(
					net_nfc_server_snep_listen_cb cb)
{
	GList *list;

	list = g_list_find_custom(list_listen_cb,
				cb,
				_net_nfc_server_snep_compare_func_cb);

	if (list != NULL)
		list_listen_cb = g_list_delete_link(list_listen_cb, list);
}

static bool _net_nfc_server_snep_process_get_response_cb(
				net_nfc_target_handle_s *handle,
				data_s *data,
				uint32_t max_len)
{
	GList *list = list_listen_cb;

	for(list = g_list_first(list); list != NULL; list = g_list_next(list))
	{
		net_nfc_server_cb_data_t *cb_data =
			(net_nfc_server_cb_data_t *)list->data;

		if(list->data == NULL)
			continue;

		if (cb_data->cb != NULL)
		{
			DEBUG_SERVER_MSG("invoke callback [%p]", cb_data->cb);
			if (cb_data->cb(handle,
				SNEP_REQ_GET,
				max_len,
				data,
				cb_data->user_param) == true)
			return true;
		}
	}

	return false;
}

static net_nfc_server_snep_op_context_t *
_net_nfc_server_snep_create_send_context(uint32_t type,
			net_nfc_target_handle_s *handle,
			net_nfc_llcp_socket_t socket,
			data_s *data,
			void *cb,
			void *user_param)
{
	net_nfc_server_snep_op_context_t *context = NULL;
	uint32_t data_len = 0;
	net_nfc_server_snep_msg_t *msg;
	net_nfc_llcp_config_info_s config;
	net_nfc_error_e result;

	if (net_nfc_controller_llcp_get_remote_config(handle,
			&config, &result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_get_remote_config failed, [%d]",
					result);

		return NULL;
	}

	_net_nfc_util_alloc_mem(context, sizeof(*context));
	if (context == NULL)
	{
		return NULL;
	}

	if (type == SNEP_REQ_GET)
	{
		data_len = sizeof(net_nfc_server_snep_msg_t);
	}

	if (data != NULL)
	{
		data_len += data->length;
	}

	net_nfc_util_init_data(&context->data, SNEP_HEADER_LEN + data_len);
	if (context->data.buffer == NULL)
	{
		_net_nfc_util_free_mem(context);
		return NULL;
	}

	msg = (net_nfc_server_snep_msg_t *)context->data.buffer;

	msg->version = SNEP_VERSION;
	msg->op = type;

	if (data_len > 0)
	{
		uint8_t *buffer;

		msg->length = htonl(data_len);

		if (type == SNEP_REQ_GET)
		{
			net_nfc_server_snep_msg_t *get_msg =
				(net_nfc_server_snep_msg_t *)msg->data;

			get_msg->length = htonl(SNEP_MAX_LEN);
			buffer = get_msg->data;
		}
		else
		{
			buffer = msg->data;
		}

		if (data != NULL && data->buffer != NULL)
		{
			DEBUG_SERVER_MSG("data->length [%d]", data->length);

			/* copy ndef information to response msg */
			memcpy(buffer, data->buffer, data->length);
		}
	}

	context->handle = handle;
	context->type = type;
	context->state = NET_NFC_LLCP_STEP_01;
	context->socket = socket;
	context->cb = cb;
	context->user_param = user_param;
	context->miu = MIN(config.miu, net_nfc_server_llcp_get_miu());

	return context;
}

static net_nfc_server_snep_op_context_t *
_net_nfc_server_snep_create_recv_context(
			net_nfc_target_handle_s *handle,
			net_nfc_llcp_socket_t socket,
			void *cb,
			void *user_param)
{
	net_nfc_server_snep_op_context_t *context = NULL;
	net_nfc_llcp_config_info_s config;
	net_nfc_error_e result;

	if (net_nfc_controller_llcp_get_remote_config(handle,
					&config,
					&result) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_get_remote_config failed, [%d]",
					result);
		return NULL;
	}

	_net_nfc_util_alloc_mem(context, sizeof(*context));

	if (context == NULL)
		return NULL;

	context->handle = handle;
	context->state = NET_NFC_LLCP_STEP_01;
	context->socket = socket;
	context->cb = cb;
	context->user_param = user_param;
	context->miu = MIN(config.miu, net_nfc_server_llcp_get_miu());

	return context;
}

static void _net_nfc_server_snep_destory_context(
				net_nfc_server_snep_op_context_t *context)
{
	if (context != NULL)
	{
		if (context->data.buffer != NULL)
			net_nfc_util_clear_data(&context->data);

		_net_nfc_util_free_mem(context);
	}
}

static void _net_nfc_server_recv_fragment_cb(
				net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param)
{
	net_nfc_server_snep_op_context_t *context =
		(net_nfc_server_snep_op_context_t *)user_param;
	uint8_t *buffer;
	uint32_t length;

	DEBUG_SERVER_MSG("_net_nfc_server_recv_fragment_cb,"
				" socket [%x], result [%d]",socket, result);

	if (context == NULL)
		return;

	context->result = result;

	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("error [%d]", result);
		context->state = NET_NFC_STATE_ERROR;
		goto END;
	}

	if (data == NULL || data->buffer == NULL || data->length == 0)
	{
		DEBUG_ERR_MSG("invalid response");
		context->state = NET_NFC_STATE_ERROR;
		goto END;
	}

	if (context->state == NET_NFC_LLCP_STEP_01)
	{
		net_nfc_server_snep_msg_t *msg =
			(net_nfc_server_snep_msg_t *)data->buffer;

		if (data->length < SNEP_HEADER_LEN)
		{
			DEBUG_ERR_MSG("too short data, length [%d]",
						data->length);
			/* FIXME!!! what should I do. */
			context->type = SNEP_RESP_BAD_REQ;
			context->state = NET_NFC_STATE_ERROR;
			context->result = NET_NFC_BUFFER_TOO_SMALL;
			goto END;
		}

		length = htonl(msg->length);
#if 0 /* snep unlimited */
		if (length > SNEP_MAX_LEN)
		{
			DEBUG_ERR_MSG("too long snep message, length [%d]",
						length);
			if (IS_SNEP_REQ(msg->op))
			{
				context->type = SNEP_RESP_EXCESS_DATA;
			}
			else
			{
				context->type = SNEP_REQ_REJECT;
			}
			context->state = NET_NFC_LLCP_STEP_04;
			context->result = NET_NFC_INSUFFICIENT_STORAGE;
			goto END;
		}
#endif
		if (IS_SNEP_REQ(msg->op) &&
			GET_MAJOR_VER(msg->version) > SNEP_MAJOR_VER)
		{
			DEBUG_ERR_MSG("not supported version, version [0x%02x]",
						msg->version);
			context->type = SNEP_RESP_UNSUPPORTED_VER;
			context->state = NET_NFC_LLCP_STEP_04;
			context->result = NET_NFC_NOT_SUPPORTED;
			goto END;
		}

		if (length > 0)
		{
			/* buffer create */
			net_nfc_util_init_data(&context->data, length);
			if (context->data.buffer == NULL)
			{
				DEBUG_ERR_MSG("net_nfc_util_alloc_data failed");
				if (IS_SNEP_REQ(msg->op))
				{
					context->type = SNEP_RESP_REJECT;
				}
				else
				{
					context->type = SNEP_REQ_REJECT;
				}
				context->state = NET_NFC_LLCP_STEP_04;
				context->result = NET_NFC_ALLOC_FAIL;
				goto END;
			}
		}

		DEBUG_SERVER_MSG("incoming message, type [0x%02x], length [%d]",
					msg->op, length);

		context->type = msg->op;
		buffer = msg->data;
		length = data->length - SNEP_HEADER_LEN;
		context->state = NET_NFC_LLCP_STEP_02;
	}
	else
	{
		buffer = data->buffer;
		length = data->length;
		context->state = NET_NFC_LLCP_STEP_03;
	}

	if (context->data.length > 0)
	{
		/* copy data */
		memcpy(context->data.buffer + context->offset,
					buffer, length);
		context->offset += length;

		DEBUG_SERVER_MSG("receive progress... [%d|%d]",
					context->offset, context->data.length);

		if (context->offset >= context->data.length)
			context->state = NET_NFC_LLCP_STEP_RETURN;

	}
	else
	{
		DEBUG_SERVER_MSG("receive complete... [no ndef message]");
		context->state = NET_NFC_LLCP_STEP_RETURN;
	}

END :
	_net_nfc_server_snep_recv(context);
}


static void _net_nfc_server_recv_fragment(
				net_nfc_server_snep_op_context_t *context)
{
	net_nfc_error_e result;

	DEBUG_SERVER_MSG("socket [%x] waiting data.....", context->socket);

	if (net_nfc_controller_llcp_recv(
				context->handle,
				context->socket,
				context->miu,
				&result,
				_net_nfc_server_recv_fragment_cb,
				context) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_recv failed, [%d]", result);
		context->state = NET_NFC_STATE_ERROR;
		context->result = result;
		_net_nfc_server_snep_recv(context);
	}
}


void _net_nfc_server_snep_recv_send_cb(
				net_nfc_error_e result,
				uint32_t type,
				data_s *data,
				void *user_param)
{
	net_nfc_server_snep_op_context_t *context =
			(net_nfc_server_snep_op_context_t *)user_param;

	DEBUG_SERVER_MSG("_net_nfc_server_snep_recv_send_cb, result [%d]", result);

	if (context == NULL)/* TODO */
		return;

	if (result == NET_NFC_OK)
		context->state = NET_NFC_LLCP_STEP_03;
	else
	{
		DEBUG_ERR_MSG("net_nfc_server_snep_send failed, [0x%x][%d]",
					type, result);
		context->state = NET_NFC_STATE_ERROR;
		context->result = result;
	}

	_net_nfc_server_snep_recv(context);
}

void _net_nfc_server_snep_recv_send_reject_cb(
				net_nfc_error_e result,
				uint32_t type,
				data_s *data,
				void *user_param)
{
	net_nfc_server_snep_op_context_t *context =
			(net_nfc_server_snep_op_context_t *)user_param;

	DEBUG_SERVER_MSG("_net_nfc_server_snep_recv_send_reject_cb,"
			" result [%d]", result);

	if (context == NULL)/* TODO */
		return;

	context->state = NET_NFC_LLCP_STEP_RETURN;

	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_server_snep_send failed, [0x%x][%d]",
				type, result);
	}

	_net_nfc_server_snep_recv(context);
}

static void _net_nfc_server_snep_recv(
			net_nfc_server_snep_op_context_t *context)
{
	if (context == NULL)
		return;

	switch (context->state)
	{
	case NET_NFC_LLCP_STEP_01 :
	case NET_NFC_LLCP_STEP_03 :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_%02d",
			context->state - NET_NFC_LLCP_STEP_01 + 1);

		/* receive fragment */
		_net_nfc_server_recv_fragment(context);
		break;

	case NET_NFC_LLCP_STEP_02 :
		{
			uint8_t op = context->type;

			DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_02");

			/* make correct request/response code */
			op = SNEP_MAKE_PAIR_OP(op, SNEP_REQ_CONTINUE);

			/* send response */
			net_nfc_server_snep_send(
				context->handle,
				context->socket,
				op,
				NULL,
				_net_nfc_server_snep_recv_send_cb,
				context);
		}
		break;

	case NET_NFC_LLCP_STEP_04 :
		{
			DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_04");

			/* send response */
			net_nfc_server_snep_send(
				context->handle,
				context->socket,
				context->type,
				NULL,
				_net_nfc_server_snep_recv_send_reject_cb,
				context);
		}
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		{
			DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_RETURN");

			/* complete and invoke callback */
			context->cb(
				context->result,
				context->type,
				&context->data,
				context->user_param);

			_net_nfc_server_snep_destory_context(context);
		}
		break;

	case NET_NFC_STATE_ERROR :
	default :
		DEBUG_ERR_MSG("NET_NFC_STATE_ERROR");

		/* error, invoke callback */
		DEBUG_ERR_MSG("net_nfc_server_snep_recv failed, [%d]",
				context->result);

		context->cb(
			context->result,
			context->type,
			NULL,
			context->user_param);

		_net_nfc_server_snep_destory_context(context);

		break;
	}
}

static net_nfc_error_e
net_nfc_server_snep_recv(
			net_nfc_target_handle_s *handle,
			net_nfc_llcp_socket_t socket,
			_net_nfc_server_snep_operation_cb cb,
			void *user_param)
{
	net_nfc_server_snep_op_context_t *context;
	net_nfc_error_e result;

	/* create context */
	context = _net_nfc_server_snep_create_recv_context(
						handle,
						socket,
						cb,
						user_param);
	if (context != NULL) {
		/* send response */
		_net_nfc_server_snep_recv(context);
		result = NET_NFC_OK;
	} else {
		result = NET_NFC_ALLOC_FAIL;

		if (cb != NULL) {
			cb(result, -1, NULL, user_param);
		}
	}

	return result;
}

static void _net_nfc_server_send_fragment_cb(
				net_nfc_llcp_socket_t socket,
				net_nfc_error_e result,
				data_s *data,
				void *extra,
				void *user_param)
{
	net_nfc_server_snep_op_context_t *context =
		(net_nfc_server_snep_op_context_t *)user_param;

	DEBUG_SERVER_MSG("_net_nfc_server_send_fragment_cb,"
			" socket [%x], result [%d]",socket, result);

	if (context == NULL)
		return;

	context->result = result;

	if (result == NET_NFC_OK)
	{
		DEBUG_SERVER_MSG("send progress... [%d|%d]",
				context->offset, context->data.length);
		if (context->offset < context->data.length)
		{
			if (context->state == NET_NFC_LLCP_STEP_01)
			{
				/* first fragment */
				context->state = NET_NFC_LLCP_STEP_02;
			}
			else
			{
				context->state = NET_NFC_LLCP_STEP_03;
			}
		}
		else
		{
			context->state = NET_NFC_LLCP_STEP_RETURN;
		}
	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_send failed, [%d]",
					result);
		context->state = NET_NFC_STATE_ERROR;
	}

	_net_nfc_server_snep_send(context);
}

static void _net_nfc_server_send_fragment(
				net_nfc_server_snep_op_context_t *context)
{
	data_s req_msg;
	uint32_t remain_len;
	net_nfc_error_e result;

	if (context == NULL)
		return;

	/* calc remain buffer length */
	remain_len = context->data.length - context->offset;

	req_msg.length = (remain_len < context->miu) ? remain_len : context->miu;
	req_msg.buffer = context->data.buffer + context->offset;

	DEBUG_SERVER_MSG("try to send data, socket [%x], offset [%d],"
			" current [%d], remain [%d]",context->socket, context->offset,
			req_msg.length, remain_len - req_msg.length);

	context->offset += req_msg.length;

	if (net_nfc_controller_llcp_send(context->handle,
					context->socket,
					&req_msg,
					&result,
					_net_nfc_server_send_fragment_cb,
					context) == false)
	{
		DEBUG_ERR_MSG("net_nfc_controller_llcp_send failed, [%d]",
					result);
		context->state = NET_NFC_STATE_ERROR;
		context->result = result;
		_net_nfc_server_snep_send(context);
	}
}

void _net_nfc_server_snep_send_recv_cb(
				net_nfc_error_e result,
				uint32_t type,
				data_s *data,
				void *user_param)
{
	net_nfc_server_snep_op_context_t *context =
		(net_nfc_server_snep_op_context_t *)user_param;

	DEBUG_SERVER_MSG("_net_nfc_server_snep_send_recv_cb,"
				" result [%d]", result);

	if (context == NULL)/* TODO */
		return;

	DEBUG_SERVER_MSG("received message, type [%d]", type);

	context->result = result;
	context->type = type;

	switch (type)
	{
	case SNEP_REQ_CONTINUE :
	case SNEP_RESP_CONT :
		context->state = NET_NFC_LLCP_STEP_03;
		break;

	case SNEP_REQ_REJECT :
	case SNEP_RESP_REJECT :
		context->state = NET_NFC_STATE_ERROR;
		context->result = NET_NFC_LLCP_SOCKET_FRAME_REJECTED;
		break;

	case SNEP_RESP_NOT_FOUND :
		context->state = NET_NFC_STATE_ERROR;
		context->result = NET_NFC_NO_DATA_FOUND;
		break;

	case SNEP_RESP_EXCESS_DATA :
		context->state = NET_NFC_STATE_ERROR;
		context->result = NET_NFC_INSUFFICIENT_STORAGE;
		break;

	case SNEP_RESP_BAD_REQ :
		context->state = NET_NFC_STATE_ERROR;
		context->result = NET_NFC_INVALID_FORMAT;
		break;

	case SNEP_RESP_NOT_IMPLEMENT :
	case SNEP_RESP_UNSUPPORTED_VER :
		context->state = NET_NFC_STATE_ERROR;
		context->result = NET_NFC_NOT_ALLOWED_OPERATION;
		break;

	default :
		context->state = NET_NFC_STATE_ERROR;
		context->result = NET_NFC_OPERATION_FAIL;
		break;
	}

	_net_nfc_server_snep_send(context);
}

static void _net_nfc_server_snep_send(
			net_nfc_server_snep_op_context_t *context)
{
	if (context == NULL)
	{
		return;
	}

	switch (context->state)
	{
	case NET_NFC_LLCP_STEP_01 :
	case NET_NFC_LLCP_STEP_03 :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_%02d",
				context->state - NET_NFC_LLCP_STEP_01 + 1);

		/* send fragment */
		_net_nfc_server_send_fragment(context);
		break;

	case NET_NFC_LLCP_STEP_02 :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_02");

		/* receive response */
		net_nfc_server_snep_recv(
			context->handle,
			context->socket,
			_net_nfc_server_snep_send_recv_cb,
			context);
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_RETURN");

		/* complete and invoke callback */
		context->cb(
			context->result,
			context->type,
			NULL,
			context->user_param);

		_net_nfc_server_snep_destory_context(context);
		break;

	case NET_NFC_STATE_ERROR :
		DEBUG_ERR_MSG("NET_NFC_STATE_ERROR");

		/* error, invoke callback */
		DEBUG_ERR_MSG("net_nfc_server_snep_send failed, [%d]",
				context->result);

		context->cb(
			context->result,
			context->type,
			NULL,
			context->user_param);

		_net_nfc_server_snep_destory_context(context);
		break;

	default :
		DEBUG_ERR_MSG("NET_NFC_LLCP_STEP_??");

		context->cb(NET_NFC_OPERATION_FAIL,
			context->type,
			NULL,
			context->user_param);

		_net_nfc_server_snep_destory_context(context);
		break;
	}
}

net_nfc_error_e net_nfc_server_snep_send(
				net_nfc_target_handle_s *handle,
				net_nfc_llcp_socket_t socket,
				uint32_t type,
				data_s *data,
				_net_nfc_server_snep_operation_cb cb,
				void *user_param)
{
	net_nfc_server_snep_op_context_t *context;
	net_nfc_error_e result;

	/* create context */
	context = _net_nfc_server_snep_create_send_context(
							type,
							handle,
							socket,
							data,
							cb,
							user_param);
	if (context != NULL)
	{
		/* send response */
		_net_nfc_server_snep_send(context);
		result = NET_NFC_OK;
	}
	else
	{
		DEBUG_ERR_MSG("_net_nfc_server_snep_create_send_context failed");

		result = NET_NFC_ALLOC_FAIL;

		if (cb != NULL) {
			cb(result, type, NULL, user_param);
		}
	}

	return result;
}

static void _net_nfc_server_snep_server_recv_cb(
				net_nfc_error_e result,
				uint32_t type,
				data_s *data,
				void *user_param)
{
	net_nfc_server_snep_context_t *context =
			(net_nfc_server_snep_context_t *)user_param;

	DEBUG_SERVER_MSG("_net_nfc_server_snep_server_recv_cb"
				"result [%d]", result);

	if (context == NULL)
	{
		/* TODO */
		return;
	}

	context->result = result;
	context->type = type;

	if (result == NET_NFC_OK && data != NULL && data->buffer != NULL)
	{
		DEBUG_SERVER_MSG("received message, type [%d], length [%d]",
				type, data->length);

		net_nfc_util_init_data(&context->data, data->length);
		if (context->data.buffer != NULL)
		{
			memcpy(context->data.buffer,
					data->buffer, data->length);

			switch (type)
			{
			case SNEP_REQ_GET :
					context->state = NET_NFC_LLCP_STEP_02;
					break;

			case SNEP_REQ_PUT :
					context->state = NET_NFC_LLCP_STEP_04;
					break;

			default :
					DEBUG_ERR_MSG("invalid request, [%d]", type);
					context->state = NET_NFC_STATE_ERROR;
					context->result = NET_NFC_NOT_ALLOWED_OPERATION;
					break;
			}
		}
		else
		{
			DEBUG_ERR_MSG("net_nfc_util_alloc_data failed");
			/* TODO */
			context->state = NET_NFC_STATE_ERROR;
			context->result = NET_NFC_ALLOC_FAIL;
		}
	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_server_snep_recv failed, [%d]", result);
		context->type = type;
		context->state = NET_NFC_STATE_ERROR;
	}

	_net_nfc_server_snep_server_process(context);
}


static void _net_nfc_server_snep_server_send_cb(net_nfc_error_e result,
						uint32_t type,
						data_s *data,
						void *user_param)
{
	net_nfc_server_snep_context_t *context =
			(net_nfc_server_snep_context_t *)user_param;

	DEBUG_SERVER_MSG("_net_nfc_server_snep_server_send_cb"
		", result [%d]", result);

	if (context == NULL)/* TODO */
		return;

	context->result = result;

	if (result == NET_NFC_OK)
	{
		DEBUG_SERVER_MSG("server process success. and restart....");

		/* restart */
		net_nfc_util_clear_data(&context->data);
		context->state = NET_NFC_LLCP_STEP_01;
	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_server_snep_send failed, [%d]", result);
		context->state = NET_NFC_STATE_ERROR;
	}

	_net_nfc_server_snep_server_process(context);
}


static void _net_nfc_server_snep_server_process(
			net_nfc_server_snep_context_t *context)
{
	if (context == NULL)
		return;

	switch (context->state)
	{
	case NET_NFC_LLCP_STEP_01 :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_01");

		/* receive request */
		net_nfc_server_snep_recv(
				context->handle,
				context->socket,
				_net_nfc_server_snep_server_recv_cb,
				context);
		break;

	case NET_NFC_LLCP_STEP_02 :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_02");

		context->state = NET_NFC_LLCP_STEP_03;

		if (context->cb == NULL ||
				context->cb((net_nfc_snep_handle_h)context,
						context->result,
						context->type,
						&context->data,
						context->user_param) != NET_NFC_OK)
		{
			/* there is no response for GET request */
			DEBUG_ERR_MSG("there is no response for GET request");

			/* receive request */
			net_nfc_server_snep_send(context->handle,
						context->socket,
						SNEP_RESP_NOT_FOUND,
						NULL,
						_net_nfc_server_snep_server_send_cb,
						context);
		}
		break;

	case NET_NFC_LLCP_STEP_03 :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_03");

		/* receive request */
		net_nfc_server_snep_send(context->handle,
					context->socket,
					SNEP_RESP_SUCCESS,
					&context->data,
					_net_nfc_server_snep_server_send_cb,
					context);
		break;

	case NET_NFC_LLCP_STEP_04 :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_04");

		if (context->cb != NULL)
		{
			/* complete and invoke callback */
			context->cb(
				(net_nfc_snep_handle_h)context,
				NET_NFC_OK,
				context->type,
				&context->data,
				context->user_param);
		}

		/* receive request */
		net_nfc_server_snep_send(context->handle,
					context->socket,
					SNEP_RESP_SUCCESS,
					NULL,
					_net_nfc_server_snep_server_send_cb,
					context);
		break;

	case NET_NFC_LLCP_STEP_10 : /* server error, and need to send error code to client */
		{
			/* FIXME : */
		}
		break;

	case NET_NFC_STATE_ERROR :
		DEBUG_SERVER_MSG("NET_NFC_STATE_ERROR");

		/* error, invoke callback */
		DEBUG_ERR_MSG("_snep_server_recv failed, [%d]",
				context->result);
#if 0 /* temp code */
		if (context->cb != NULL)
		{
			context->cb((net_nfc_snep_handle_h)context,
						context->result,
						context->type,
						NULL,
						context->user_param);
		}
#endif
		/* restart?? */
		break;

	default :
		DEBUG_ERR_MSG("NET_NFC_LLCP_STEP_??");
		/* TODO */
		break;
	}
}


static void _net_nfc_server_snep_clear_queue(
			gpointer data,
			gpointer user_data)
{
	net_nfc_server_snep_job_t *job = (net_nfc_server_snep_job_t *)data;

	if (job != NULL)
	{
		if (job->cb != NULL)
		{
			job->cb((net_nfc_snep_handle_h)job->context,
				NET_NFC_OPERATION_FAIL, job->type,
				NULL, job->user_param);
		}

		if (job->data.buffer != NULL)
		{
			net_nfc_util_clear_data(&job->data);
		}

		_net_nfc_util_free_mem(job);
	}
}


static void _net_nfc_server_snep_incomming_socket_error_cb(
			net_nfc_error_e result,
			net_nfc_target_handle_s *handle,
			net_nfc_llcp_socket_t socket,
			data_s *data,
			void *user_param)
{
	net_nfc_server_snep_context_t *context =
		(net_nfc_server_snep_context_t *)user_param;

	DEBUG_SERVER_MSG("_net_nfc_server_snep_incomming_socket_error_cb,"
		" socket [%x], result [%d]",socket, result);

	if (context == NULL)
	{
		return;
	}

	if (context->data.buffer != NULL)
	{
		net_nfc_util_clear_data(&context->data);
	}

	g_queue_foreach(&context->queue,
		_net_nfc_server_snep_clear_queue,
		NULL);

	_net_nfc_util_free_mem(context);
}


static void _net_nfc_server_snep_socket_error_cb(
				net_nfc_error_e result,
				net_nfc_target_handle_s *handle,
				net_nfc_llcp_socket_t socket,
				data_s *data,
				void *user_param)
{
	net_nfc_server_snep_context_t *context =
			(net_nfc_server_snep_context_t *)user_param;

	DEBUG_SERVER_MSG("_net_nfc_server_snep_socket_error_cb"
			" socket [%x], result [%d]",socket, result);

	if (context == NULL)
	{
		return;
	}

	if (context->cb != NULL)
	{
		context->cb((net_nfc_snep_handle_h)context,
					result,
					NET_NFC_LLCP_STOP,
					NULL,
					context->user_param);
	}

	/*net_nfc_controller_llcp_socket_close(socket, &result);*/

	if (context->data.buffer != NULL)
	{
		net_nfc_util_clear_data(&context->data);
	}

	g_queue_foreach(&context->queue,
		_net_nfc_server_snep_clear_queue,
		NULL);

	_net_nfc_util_free_mem(context);
}


static void _net_nfc_server_snep_incoming_cb(
				net_nfc_error_e result,
				net_nfc_target_handle_s *handle,
				net_nfc_llcp_socket_t socket,
				data_s *data,
				void *user_param)
{
	net_nfc_server_snep_context_t *context =
		(net_nfc_server_snep_context_t *)user_param;
	net_nfc_server_snep_context_t *accept_context = NULL;

	if (context == NULL)
	{
		return;
	}

	DEBUG_SERVER_MSG("snep incoming socket [%x], result [%d]", socket, result);

	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("listen socket failed, [%d]", result);

		goto ERROR;
	}

	/* start snep server */
	_net_nfc_util_alloc_mem(accept_context, sizeof(*accept_context));

	if (accept_context == NULL)
	{
		DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}

	accept_context->handle = context->handle;
	accept_context->socket = socket;
	accept_context->cb = context->cb;
	accept_context->user_param = context->user_param;
	accept_context->state = NET_NFC_LLCP_STEP_01;

	result = net_nfc_server_llcp_simple_accept(handle,
		socket,
		_net_nfc_server_snep_incomming_socket_error_cb,
		accept_context);
	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_server_llcp_simple_accept failed, [%d]", result);
		goto ERROR;
	}

	DEBUG_SERVER_MSG("socket [%x] accepted.. waiting for request message", socket);

	_net_nfc_server_snep_server_process(accept_context);

	return;

ERROR :
	if (accept_context != NULL)
	{
		_net_nfc_util_free_mem(accept_context);
	}
}

net_nfc_error_e net_nfc_server_snep_server(
				net_nfc_target_handle_s *handle,
				const char *san,
				sap_t sap,
				net_nfc_server_snep_cb cb,
				void *user_param)
{
	net_nfc_error_e result;
	net_nfc_server_snep_context_t *context = NULL;

	if (handle == NULL || san == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (net_nfc_server_target_connected(handle) == false) {
		return NET_NFC_NOT_CONNECTED;
	}

	_net_nfc_util_alloc_mem(context, sizeof(*context));
	if (context == NULL)
	{
		DEBUG_ERR_MSG("_create_snep_context failed");
		result = NET_NFC_ALLOC_FAIL;
		goto ERROR;
	}

	context->handle = handle;
	context->cb = cb;
	context->user_param = user_param;
	context->state = NET_NFC_LLCP_STEP_01;

	result = net_nfc_server_llcp_simple_server(handle,
				san,
				sap,
				_net_nfc_server_snep_incoming_cb,
				_net_nfc_server_snep_socket_error_cb,
				context);

	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_server_llcp_simple_server failed, [%d]",
				result);
		goto ERROR;
	}

	DEBUG_SERVER_MSG("start snep server, san [%s], sap [%d]",
			san, sap);
	return result;

ERROR :
	if (context != NULL)
		_net_nfc_util_free_mem(context);

	return result;
}

net_nfc_error_e net_nfc_server_snep_server_send_get_response(
					net_nfc_snep_handle_h snep_handle,
					data_s *data)
{
	net_nfc_server_snep_context_t *context =
			(net_nfc_server_snep_context_t *)snep_handle;
	net_nfc_error_e result = NET_NFC_OK;

	if (context == NULL/* && check valid handle */)
	{
		DEBUG_ERR_MSG("invalid handle");
		return NET_NFC_INVALID_PARAM;
	}

	if (net_nfc_server_target_connected(context->handle) == false) {
		return NET_NFC_NOT_CONNECTED;
	}

	DEBUG_SERVER_MSG("send get response, socket [%x]", context->socket);

	/* check correct status */
	if (context->type == SNEP_REQ_GET)
	{
		if (context->data.buffer != NULL)
			net_nfc_util_clear_data(&context->data);

		if (data != NULL)
		{
			context->type = SNEP_RESP_SUCCESS;

			if (net_nfc_util_init_data(&context->data, data->length) == true)
			{
				memcpy(context->data.buffer, data->buffer,
						data->length);
			}
			else
			{
				DEBUG_ERR_MSG("net_nfc_util_alloc_data failed");
				result = NET_NFC_ALLOC_FAIL;
			}
		}
		else
		{
			/* not found */
			context->type = SNEP_RESP_NOT_FOUND;
		}

		_net_nfc_server_snep_server_process(context);
	}
	else
	{
		DEBUG_ERR_MSG("incorrect handle state");
		result = NET_NFC_INVALID_STATE;
	}

	return result;
}

static void _net_nfc_server_snep_client_send_cb(
				net_nfc_error_e result,
				uint32_t type,
				data_s *data,
				void *user_param)
{
	net_nfc_server_snep_job_t *job =
			(net_nfc_server_snep_job_t *)user_param;

	if (job == NULL)
	{
		/* TODO */
		return;
	}

	job->type = type;
	job->result = result;

	if (result == NET_NFC_OK)
	{
		job->state = NET_NFC_LLCP_STEP_02;

		net_nfc_util_clear_data(&job->data);
	}
	else
	{
		DEBUG_ERR_MSG("net_nfc_server_snep_send failed, [%d]", result);
		job->state = NET_NFC_STATE_ERROR;
	}

	_net_nfc_server_snep_client_process(job);
}

static void _net_nfc_server_snep_client_recv_cb(
				net_nfc_error_e result,
				uint32_t type,
				data_s *data,
				void *user_param)
{
	net_nfc_server_snep_job_t *job =
			(net_nfc_server_snep_job_t *)user_param;

	if (job == NULL)
	{
		/* TODO */
		return;
	}

	job->type = type;
	job->result = result;

	if (result == NET_NFC_OK)
	{
		if (type == SNEP_RESP_SUCCESS)
		{
			job->state = NET_NFC_LLCP_STEP_RETURN;
			if (data != NULL && data->buffer != NULL)
			{
				net_nfc_util_init_data(&job->data, data->length);
				if (job->data.buffer != NULL)
				{
					memcpy(job->data.buffer, data->buffer,
						data->length);
				}
				else
				{
					DEBUG_ERR_MSG("net_nfc_util_alloc_data failed");
					job->state = NET_NFC_STATE_ERROR;
					job->result = NET_NFC_ALLOC_FAIL;
				}
			}
		}
		else
		{
			/* TODO */
			DEBUG_ERR_MSG("invalid request, [0x%x]", type);
			job->state = NET_NFC_STATE_ERROR;
			job->result = NET_NFC_NOT_ALLOWED_OPERATION;
		}
	}
	else
	{

		DEBUG_ERR_MSG("net_nfc_server_snep_recv failed, [%d]", result);
		job->state = NET_NFC_STATE_ERROR;
	}

	_net_nfc_server_snep_client_process(job);
}


static void _net_nfc_server_snep_client_do_job(net_nfc_server_snep_context_t *context)
{
	if (context->state == NET_NFC_LLCP_IDLE &&
		g_queue_is_empty(&context->queue) == false) {
		net_nfc_server_snep_job_t *job;

		job = g_queue_pop_head(&context->queue);
		if (job != NULL) {
			context->state = NET_NFC_LLCP_STEP_01;
			job->state = NET_NFC_LLCP_STEP_01;
			_net_nfc_server_snep_client_process(job);
		}
	}
}

static void _net_nfc_server_snep_client_process(
			net_nfc_server_snep_job_t *job)
{
	bool finish = false;

	if (job == NULL)
	{
		return;
	}

	switch (job->state)
	{
	case NET_NFC_LLCP_STEP_01 :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_01");

		/* send request */
		net_nfc_server_snep_send(job->handle,
			job->socket,
			job->type,
			&job->data,
			_net_nfc_server_snep_client_send_cb,
			job);
		break;

	case NET_NFC_LLCP_STEP_02 :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_02");

		/* receive response */
		net_nfc_server_snep_recv(job->handle,
			job->socket,
			_net_nfc_server_snep_client_recv_cb,
			job);
		break;

	case NET_NFC_LLCP_STEP_RETURN :
		DEBUG_SERVER_MSG("NET_NFC_LLCP_STEP_RETURN");

		/* complete and invoke callback */
		if (job->cb != NULL)
		{
			job->cb((net_nfc_snep_handle_h)job->context,
				NET_NFC_OK,
				job->type,
				&job->data,
				job->user_param);
		}

		/* finish job */
		finish = true;
		break;

	case NET_NFC_STATE_ERROR :
	default :
		DEBUG_ERR_MSG("NET_NFC_STATE_ERROR");

		/* error, invoke callback */
		DEBUG_ERR_MSG("_snep_client_send failed, [%d]",
			job->result);
		if (job->cb != NULL)
		{
			job->cb((net_nfc_snep_handle_h)job->context,
				job->result,
				job->type,
				&job->data,
				job->user_param);
		}

		/* finish job */
		finish = true;
		break;
	}

	if (finish == true)
	{
		net_nfc_server_snep_context_t *context = job->context;

		if (job->data.buffer != NULL)
		{
			net_nfc_util_clear_data(&job->data);
		}

		_net_nfc_util_free_mem(job);

		context->state = NET_NFC_LLCP_IDLE;

		_net_nfc_server_snep_client_do_job(context);
	}
}

static void _net_nfc_server_snep_connected_cb(
				net_nfc_error_e result,
				net_nfc_target_handle_s *handle,
				net_nfc_llcp_socket_t socket,
				data_s *data,
				void *user_param)
{
	net_nfc_server_snep_context_t *context =
			(net_nfc_server_snep_context_t *)user_param;

	if (context == NULL)
	{
		return;
	}

	context->socket = socket;

	if (result == NET_NFC_OK)
	{
		/* start snep client */
		DEBUG_SERVER_MSG("socket [%x] connected. send message",
				socket);
	}
	else
	{
		DEBUG_ERR_MSG("connect socket failed, [%d]", result);
	}

	if (context->cb != NULL)
	{
		context->cb((net_nfc_snep_handle_h)context,
					result,
					NET_NFC_LLCP_START,
					NULL,
					context->user_param);
	}
}

net_nfc_error_e net_nfc_server_snep_client(
				net_nfc_target_handle_s *handle,
				const char *san,
				sap_t sap,
				net_nfc_server_snep_cb cb,
				void *user_param)
{
	net_nfc_error_e result;
	net_nfc_server_snep_context_t *context = NULL;

	if (handle == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (net_nfc_server_target_connected(handle) == false) {
		return NET_NFC_NOT_CONNECTED;
	}

	_net_nfc_util_alloc_mem(context, sizeof(*context));
	if (context == NULL)
	{
		DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
		result = NET_NFC_ALLOC_FAIL;

		goto ERROR;
	}
	context->handle = handle;
	context->cb = cb;
	context->user_param = user_param;

	result = net_nfc_server_llcp_simple_client(handle,
					san,
					sap,
					_net_nfc_server_snep_connected_cb,
					_net_nfc_server_snep_socket_error_cb,
					context);

	if (result != NET_NFC_OK)
	{
		DEBUG_ERR_MSG("net_nfc_server_llcp_simple_client failed, [%d]",
				result);

		goto ERROR;
	}

	if (san != NULL)
		DEBUG_SERVER_MSG("start snep client, san [%s]", san);
	else
		DEBUG_SERVER_MSG("start snep client, sap [%d]", sap);

	return result;

ERROR :
	if (context != NULL)
	{
		if (context->data.buffer != NULL)
		{
			net_nfc_util_clear_data(&context->data);
		}
		_net_nfc_util_free_mem(context);
	}

	return result;
}


net_nfc_error_e net_nfc_server_snep_client_request(
			net_nfc_snep_handle_h snep,
			uint8_t type,
			data_s *data,
			net_nfc_server_snep_cb cb,
			void *user_param)
{
	net_nfc_server_snep_context_t *context = (net_nfc_server_snep_context_t *)snep;
	net_nfc_error_e result = NET_NFC_OK;
	net_nfc_server_snep_job_t *job;

	if (context == NULL || data == NULL || data->buffer == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (net_nfc_server_target_connected(context->handle) == false) {
		return NET_NFC_NOT_CONNECTED;
	}

	/* check type */
	_net_nfc_util_alloc_mem(job, sizeof(*job));
	if (job != NULL)
	{
		net_nfc_util_init_data(&job->data, data->length);
		if (job->data.buffer != NULL)
		{
			memcpy(job->data.buffer, data->buffer, data->length);
		}
		job->type = type;
		job->cb = cb;
		job->user_param = user_param;

		job->context = context;
		job->handle = context->handle;
		job->socket = context->socket;

		g_queue_push_tail(&context->queue, job);
	}
	else
	{
		return NET_NFC_ALLOC_FAIL;
	}

	INFO_MSG("enqueued jobs [%d]", g_queue_get_length(&context->queue));

	/* if client is idle, starts sending request */
	if (context->state == NET_NFC_LLCP_IDLE)
	{
		_net_nfc_server_snep_client_do_job(context);
	} else {
		INFO_MSG("client is working. this job will be enqueued");
	}

	return result;
}

static net_nfc_error_e _net_nfc_server_default_server_cb_(
						net_nfc_snep_handle_h handle,
						net_nfc_error_e result,
						uint32_t type,
						data_s *data,
						void *user_param)
{
	DEBUG_SERVER_MSG("type [%d], result [%d], data [%p], user_param [%p]",
			type, result, data, user_param);

	if (result != NET_NFC_OK || data == NULL || data->buffer == NULL)
	{
		/* restart */
		return NET_NFC_NULL_PARAMETER;
	}

	switch (type)
	{
	case SNEP_REQ_GET:
		{
			net_nfc_server_snep_get_msg_t *msg =
					(net_nfc_server_snep_get_msg_t *)data->buffer;


			uint32_t max_len = htonl(msg->length);
			data_s get_msg = { msg->data,data->length - sizeof(msg->length)};

			DEBUG_SERVER_MSG("GET : acceptable max_len [%d], message [%d]",
					max_len, data->length - sizeof(msg->length));

			if (_net_nfc_server_snep_process_get_response_cb(handle, &get_msg, max_len))
			{
				result = NET_NFC_OK;
			}
			else
			{
				result = NET_NFC_NOT_SUPPORTED;
			}
		}
		break;

	case SNEP_REQ_PUT :
		{
			net_nfc_server_p2p_received(data);
			net_nfc_app_util_process_ndef(data);

			result = NET_NFC_OK;
		}
		break;

	default :
		DEBUG_ERR_MSG("error [%d]", result);
		break;
	}

	return result;
}


static net_nfc_error_e _net_nfc_server_default_client_cb_(
						net_nfc_snep_handle_h handle,
						net_nfc_error_e result,
						uint32_t type,
						data_s *data,
						void *user_param)
{
	_net_nfc_server_snep_service_context_t *context =
		(_net_nfc_server_snep_service_context_t*)user_param;

	DEBUG_SERVER_MSG("type [%d], result [%d], data [%p]",
			type, result, data);

	if (user_param == NULL)
		return NET_NFC_NULL_PARAMETER;;

	switch (type)
	{
	case SNEP_RESP_SUCCESS :
	case SNEP_RESP_BAD_REQ :
	case SNEP_RESP_EXCESS_DATA :
	case SNEP_RESP_NOT_FOUND :
	case SNEP_RESP_NOT_IMPLEMENT :
	case SNEP_RESP_REJECT :
	case SNEP_RESP_UNSUPPORTED_VER :
		context = (_net_nfc_server_snep_service_context_t *)user_param;

		net_nfc_server_p2p_data_sent(result, context->user_param);
		break;

	default :
		DEBUG_ERR_MSG("error [%d]", result);
		break;
	}

	return result;
}


static net_nfc_error_e _net_nfc_server_default_client_connected_cb_(
	net_nfc_snep_handle_h handle,
	net_nfc_error_e result,
	uint32_t type,
	data_s *data,
	void *user_param)
{
	_net_nfc_server_snep_service_context_t *context =
		(_net_nfc_server_snep_service_context_t *)user_param;

	DEBUG_SERVER_MSG("type [%d], result [%d], data [%p], user_param [%p]",
	type, result, data, user_param);

	if (context == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (result == NET_NFC_OK)
	{
		result = net_nfc_server_snep_client_request(handle,
			context->type,
			&context->data,
			_net_nfc_server_default_client_cb_,
			context);
	}
	else
	{
		if (context->data.buffer != NULL)
		{
			net_nfc_util_clear_data(&context->data);
		}
		_net_nfc_util_free_mem(context);
	}

	return result;
}


net_nfc_error_e net_nfc_server_snep_default_server_start(
						net_nfc_target_handle_s *handle)
{
	/* start default snep server, register your callback */
	return net_nfc_server_snep_server(handle,
				SNEP_SAN,
				SNEP_SAP,
				_net_nfc_server_default_server_cb_,
				(void *)1234);
}


net_nfc_error_e net_nfc_server_snep_default_client_start(
				net_nfc_target_handle_s *handle,
				int type,
				data_s *data,
				int client,
				void *user_param)
{
	_net_nfc_server_snep_service_context_t *context = NULL;
	net_nfc_error_e result;

	_net_nfc_util_alloc_mem(context, sizeof(*context));
	if (context != NULL)
	{
		context->handle = handle;
		context->client = client;
		context->user_param = user_param;
		context->type = type;
		net_nfc_util_init_data(&context->data, data->length);
		if (context->data.buffer != NULL)
		{
			memcpy(context->data.buffer, data->buffer,
				data->length);
		}
		/* start default snep client, register your callback */
		result = net_nfc_server_snep_client(handle,
					SNEP_SAN,
					SNEP_SAP,
					_net_nfc_server_default_client_connected_cb_,
					context);

		if (result != NET_NFC_OK)
		{
			DEBUG_ERR_MSG("net_nfc_server_snep_client failed, [%d]",
					result);
			if (context->data.buffer != NULL)
			{
				net_nfc_util_clear_data(&context->data);
			}
			_net_nfc_util_free_mem(context);
		}
		return result;
	}
	else
	{
		return NET_NFC_ALLOC_FAIL;
	}
}

net_nfc_error_e
net_nfc_server_snep_default_server_register_get_response_cb(
			net_nfc_server_snep_listen_cb cb,
			void *user_param)
{
	net_nfc_error_e result;

	if (_net_nfc_server_snep_add_get_response_cb(cb, user_param) == true)
	{
		result = NET_NFC_OK;
	}
	else
	{
		result = NET_NFC_ALREADY_REGISTERED;
	}

	return result;
}

net_nfc_error_e
net_nfc_server_snep_default_server_unregister_get_response_cb(
			net_nfc_server_snep_listen_cb cb)
{
	_net_nfc_server_snep_del_get_response_cb(cb);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_server_snep_default_server_send_get_response(
				net_nfc_snep_handle_h snep_handle, data_s *data)
{
	net_nfc_server_snep_context_t *context =
			(net_nfc_server_snep_context_t *)snep_handle;
	net_nfc_error_e result = NET_NFC_OK;

	if (context == NULL/* && check valid handle */)
	{
		DEBUG_ERR_MSG("invalid handle");
		return NET_NFC_INVALID_PARAM;
	}

	/* check correct status */
	if (context->type == SNEP_REQ_GET &&
			context->state == NET_NFC_LLCP_STEP_03)
	{
		net_nfc_server_snep_server_send_get_response(snep_handle, data);
	}
	else
	{
		DEBUG_ERR_MSG("incorrect handle state");
		result = NET_NFC_INVALID_STATE;
	}

	return result;
}

static void _snep_default_activate_cb(int event,
	net_nfc_target_handle_s *handle,
	uint32_t sap, const char *san, void *user_param)
{
	net_nfc_error_e result;

	DEBUG_SERVER_MSG("event [%d], handle [%p], sap [%d], san [%s]",
		event, handle, sap, san);

	if (event == NET_NFC_LLCP_START) {
		/* start snep server */
		result = net_nfc_server_snep_server(handle, (char *)san, sap,
			_net_nfc_server_default_server_cb_, user_param);
		if (result != NET_NFC_OK) {
			DEBUG_ERR_MSG("net_nfc_service_snep_server failed, [%d]",
				result);
		}
	} else if (event == NET_NFC_LLCP_UNREGISTERED) {
		/* unregister server, do nothing */
	}
}

net_nfc_error_e net_nfc_server_snep_default_server_register()
{
	char id[20];

	/* TODO : make id, */
	snprintf(id, sizeof(id), "%d", getpid());

	/* start default snep server */
	return net_nfc_server_llcp_register_service(id,
		SNEP_SAP,
		SNEP_SAN,
		_snep_default_activate_cb,
		NULL);
}

net_nfc_error_e net_nfc_server_snep_default_server_unregister()
{
	char id[20];

	/* TODO : make id, */
	snprintf(id, sizeof(id), "%d", getpid());

	/* start default snep server */
	return net_nfc_server_llcp_unregister_service(id,
		SNEP_SAP,
		SNEP_SAN);
}

net_nfc_error_e net_nfc_server_snep_parse_get_request(data_s *request,
	size_t *max_len, data_s *message)
{
	net_nfc_server_snep_msg_t *msg = NULL;

	if (request == NULL || request->buffer == NULL ||
		request->length == 0 || max_len == NULL || message == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	msg = (net_nfc_server_snep_msg_t *)request->buffer;

	*max_len = htonl(msg->length);

	message->buffer = msg->data;
	message->length = request->length - sizeof(msg->length);

	DEBUG_SERVER_MSG("GET : acceptable max_len [%d], message [%d]",
			*max_len, request->length - sizeof(msg->length));

	return NET_NFC_OK;
}
