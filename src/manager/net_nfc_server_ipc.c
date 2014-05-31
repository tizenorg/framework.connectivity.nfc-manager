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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib-object.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include "vconf.h"
#include "security-server.h"

#include "net_nfc_typedef_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_ipc.h"
#include "net_nfc_server_ipc_private.h"
#include "net_nfc_server_dispatcher_private.h"
#include "net_nfc_controller_private.h"
#include "net_nfc_manager_util_private.h"
#include "net_nfc_server_context_private.h"

/////////////////////////////

/* static variable */
#ifdef SECURITY_SERVER
static char *cookies = NULL;
static int cookies_size = 0;
static gid_t gid = 0;
#endif

static pthread_mutex_t g_server_socket_lock = PTHREAD_MUTEX_INITIALIZER;
static net_nfc_server_info_t g_server_info = { 0, };

/////////////////

/*define static function*/

static gboolean net_nfc_server_ipc_callback_func(GIOChannel* channel, GIOCondition condition, gpointer data);
static bool net_nfc_server_read_client_request(int client_sock_fd, net_nfc_error_e* result);
static bool net_nfc_server_process_client_connect_request();

/////////////////////////

bool net_nfc_server_set_server_state(uint32_t state)
{
	pthread_mutex_lock(&g_server_socket_lock);

	if (state == NET_NFC_SERVER_IDLE)
		g_server_info.state &= NET_NFC_SERVER_IDLE;
	else
		g_server_info.state |= state;

	pthread_mutex_unlock(&g_server_socket_lock);

	return true;
}

bool net_nfc_server_unset_server_state(uint32_t state)
{
	pthread_mutex_lock(&g_server_socket_lock);

	g_server_info.state &= ~state;

	pthread_mutex_unlock(&g_server_socket_lock);

	return true;
}

uint32_t net_nfc_server_get_server_state()
{
	return g_server_info.state;
}



bool net_nfc_server_ipc_initialize()
{
	int result = 0;

	pthread_mutex_lock(&g_server_socket_lock);

	/* initialize server context */
	g_server_info.server_src_id = 0;
	g_server_info.server_channel = (GIOChannel *)NULL;
	g_server_info.server_sock_fd = -1;
	g_server_info.state = NET_NFC_SERVER_IDLE;
	g_server_info.target_info = NULL;
	///////////////////////////////

#ifdef USE_UNIX_DOMAIN
	struct sockaddr_un saddrun_rv;

	g_server_info.server_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (g_server_info.server_sock_fd == -1)
	{
		DEBUG_SERVER_MSG("get socket is failed");
		goto ERROR;
	}

	net_nfc_util_set_non_block_socket(g_server_info.server_sock_fd);

	result = remove(NET_NFC_SERVER_DOMAIN);

	memset(&saddrun_rv, 0, sizeof(struct sockaddr_un));
	saddrun_rv.sun_family = AF_UNIX;
	strncpy(saddrun_rv.sun_path, NET_NFC_SERVER_DOMAIN, sizeof(saddrun_rv.sun_path) - 1);

	if ((result = bind(g_server_info.server_sock_fd, (struct sockaddr *)&saddrun_rv, sizeof(saddrun_rv))) < 0)
	{
		DEBUG_ERR_MSG("bind is failed");
		goto ERROR;
	}

	if ((result = chmod(NET_NFC_SERVER_DOMAIN, 0777)) < 0)
	{
		DEBUG_ERR_MSG("can not change permission of UNIX DOMAIN file");
		goto ERROR;
	}

#else
	struct sockaddr_in serv_addr;

	g_server_info.server_sock_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (g_server_info.server_sock_fd == -1)
	{
		DEBUG_SERVER_MSG("get socket is failed");
		goto ERROR;
	}

	net_nfc_util_set_non_block_socket(g_server_info.server_sock_fd);

	memset(&serv_addr, 0x00, sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(NET_NFC_SERVER_PORT);

	int val = 1;

	if (setsockopt(g_server_info.server_sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&val, sizeof(val)) == 0)
	{
		DEBUG_SERVER_MSG("reuse address");
	}

	if (bind(g_server_info.server_sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		DEBUG_ERR_MSG("bind is failed");
		goto ERROR;
	}
#endif

	if ((result = listen(g_server_info.server_sock_fd, NET_NFC_CLIENT_MAX)) < 0)
	{
		DEBUG_ERR_MSG("listen is failed");
		goto ERROR;
	}

	GIOCondition condition = (GIOCondition)(G_IO_ERR | G_IO_HUP | G_IO_IN);

	if ((g_server_info.server_channel = g_io_channel_unix_new(g_server_info.server_sock_fd)) != NULL)
	{
		if ((g_server_info.server_src_id = g_io_add_watch(g_server_info.server_channel, condition, net_nfc_server_ipc_callback_func, NULL)) < 1)
		{
			DEBUG_ERR_MSG(" g_io_add_watch is failed");
			goto ERROR;
		}
	}
	else
	{
		DEBUG_ERR_MSG(" g_io_channel_unix_new is failed");
		goto ERROR;
	}

#ifdef SECURITY_SERVER
	gid = security_server_get_gid(NET_NFC_MANAGER_OBJECT);
	if (gid == 0)
	{
		DEBUG_ERR_MSG("get gid from security server is failed. this object is not allowed by security server");
		goto ERROR;
	}

	if ((cookies_size = security_server_get_cookie_size()) > 0)
	{
		_net_nfc_util_alloc_mem(cookies, cookies_size);
		if (cookies == NULL)
		{
			DEBUG_ERR_MSG("alloc failed");
			goto ERROR;
		}
	}
	else
	{
		DEBUG_ERR_MSG("security_server_get_cookie_size failed");
		goto ERROR;
	}
#endif

	net_nfc_dispatcher_start_thread();
	DEBUG_SERVER_MSG("server ipc is initialized");

	if (vconf_set_bool(NET_NFC_DISABLE_LAUNCH_POPUP_KEY, TRUE) != 0)
		DEBUG_ERR_MSG("SERVER : launch state set vconf fail");

	pthread_mutex_unlock(&g_server_socket_lock);
	return true;

ERROR :
#ifdef SECURITY_SERVER
	if (cookies == NULL)
	{
		_net_nfc_util_free_mem(cookies);
	}
#endif

	if (g_server_info.server_src_id > 0)
	{
		g_source_remove(g_server_info.server_src_id);
		g_server_info.server_src_id = 0;
	}

	if (g_server_info.server_channel != NULL)
	{
		g_io_channel_unref(g_server_info.server_channel);
		g_server_info.server_channel = NULL;
	}

	if (g_server_info.server_sock_fd != -1)
	{
		shutdown(g_server_info.server_sock_fd, SHUT_RDWR);
		close(g_server_info.server_sock_fd);
		g_server_info.server_sock_fd = -1;
	}

	pthread_mutex_unlock(&g_server_socket_lock);
	return false;
}

void net_nfc_server_ipc_finalize()
{
	/* cleanup client */
	net_nfc_server_deinit_client_context();

#ifdef SECURITY_SERVER
	if (cookies == NULL)
	{
		_net_nfc_util_free_mem(cookies);
	}
#endif

	if (g_server_info.server_src_id > 0)
	{
		g_source_remove(g_server_info.server_src_id);
		g_server_info.server_src_id = 0;
	}

	if (g_server_info.server_channel != NULL)
	{
		g_io_channel_unref(g_server_info.server_channel);
		g_server_info.server_channel = NULL;
	}

	if (g_server_info.server_sock_fd != -1)
	{
		shutdown(g_server_info.server_sock_fd, SHUT_RDWR);
		close(g_server_info.server_sock_fd);
		g_server_info.server_sock_fd = -1;
	}
}

gboolean net_nfc_server_ipc_callback_func(GIOChannel *channel, GIOCondition condition, gpointer data)
{
	gboolean result = TRUE;
	int sock_fd = g_io_channel_unix_get_fd(channel);

	if ((G_IO_ERR & condition) || (G_IO_HUP & condition))
	{
		DEBUG_ERR_MSG("G_IO_ERR");
		if (sock_fd > 0)
		{
			if (sock_fd == g_server_info.server_sock_fd)
			{
				DEBUG_SERVER_MSG("server socket is closed");

				net_nfc_dispatcher_cleanup_queue();
				net_nfc_server_ipc_finalize();
			}
			else
			{
				DEBUG_SERVER_MSG("client socket is closed, socket [%d]", sock_fd);

				net_nfc_server_cleanup_client_context(sock_fd);
			}
		}

		result = FALSE;
	}
	else if (G_IO_NVAL & condition)
	{
		DEBUG_ERR_MSG("INVALID socket");
		result = FALSE;
	}
	else if (G_IO_IN & condition)
	{
		if (sock_fd > 0)
		{
			if (sock_fd == g_server_info.server_sock_fd)
			{
				/* client connect request */
				net_nfc_server_process_client_connect_request();
			}
			else
			{
				net_nfc_error_e result = NET_NFC_OK;

				if (net_nfc_server_read_client_request(sock_fd, &result) == false)
				{
					switch (result)
					{
					case NET_NFC_OPERATION_FAIL :
						DEBUG_SERVER_MSG("clear context and shutdown socket");
						net_nfc_server_cleanup_client_context(sock_fd);
						result = FALSE;
						break;

					default :
						DEBUG_ERR_MSG("read client request is failed = [0x%x]", result);
						net_nfc_server_cleanup_client_context(sock_fd);
						result = FALSE;
						break;
					}
				}
			}
		}
	}

	return result;
}

bool net_nfc_server_process_client_connect_request()
{
	socklen_t addrlen = 0;
	int client_sock_fd = 0;
	GIOChannel *client_channel = NULL;
	uint32_t client_src_id = 0;
	pid_t client_pid = -1;
#ifdef USE_UNIX_DOMAIN
	struct ucred uc;
	socklen_t uc_len = sizeof(uc);
#endif
	DEBUG_SERVER_MSG("client is trying to connect to server");

	if (net_nfc_server_get_client_count() >= NET_NFC_CLIENT_MAX)
	{
		DEBUG_SERVER_MSG("client is fully served. no more capa is remained.");
		return false;
	}

	if ((client_sock_fd = accept(g_server_info.server_sock_fd, NULL, &addrlen)) < 0)
	{
		DEBUG_ERR_MSG("can not accept client");
		return false;
	}

#ifdef USE_UNIX_DOMAIN
	if (!getsockopt(client_sock_fd, SOL_SOCKET, SO_PEERCRED, &uc, &uc_len))
	{
		client_pid = uc.pid;
	}
#endif
	DEBUG_SERVER_MSG("client [%d] is accepted by server, socket[%d]",
		client_pid, client_sock_fd);

	GIOCondition condition = (GIOCondition)(G_IO_ERR | G_IO_HUP | G_IO_IN);

	if ((client_channel = g_io_channel_unix_new(client_sock_fd)) != NULL)
	{
		if ((client_src_id = g_io_add_watch(client_channel, condition,
			net_nfc_server_ipc_callback_func, NULL)) < 1)
		{
			DEBUG_ERR_MSG("add io callback is failed");
			goto ERROR;
		}
	}
	else
	{
		DEBUG_ERR_MSG("create new g io channel is failed");
		goto ERROR;
	}

	DEBUG_SERVER_MSG("client socket is bond with g_io_channel");

	net_nfc_server_add_client_context(client_pid, client_sock_fd,
		client_channel, client_src_id, NET_NFC_CLIENT_ACTIVE_STATE);

	return true;

ERROR :
	if (client_channel != NULL)
	{
		g_io_channel_unref(client_channel);
		client_channel = NULL;
	}

	if (client_sock_fd != -1)
	{
		shutdown(client_sock_fd, SHUT_RDWR);
		close(client_sock_fd);
		client_sock_fd = -1;
	}

	return false;
}

int __net_nfc_server_read_util(int client_sock_fd, void **detail, size_t size)
{
	static uint8_t flushing[128];

	*detail = NULL;
	_net_nfc_util_alloc_mem(*detail, size);

	if (*detail == NULL)
	{
		size_t read_size;
		int readbyes = size;

		while (readbyes > 0)
		{
			read_size = readbyes > 128 ? 128 : readbyes;
			if (net_nfc_server_recv_message_from_client(client_sock_fd, flushing, read_size) < 0)
			{
				return false;
			}
			readbyes -= read_size;
		}
		return false;
	}

	if (net_nfc_server_recv_message_from_client(client_sock_fd, *detail, size) < 0)
	{
		_net_nfc_util_free_mem(*detail);
		return false;
	}
	return true;
}

bool net_nfc_server_read_client_request(int client_sock_fd, net_nfc_error_e *result)
{
	int read = 0;
	uint32_t offset = 0;
	uint32_t length = 0;
	uint8_t *buffer = NULL;
	net_nfc_request_msg_t *req_msg = NULL;

	if ((read = net_nfc_server_recv_message_from_client(client_sock_fd, (void *)&length, sizeof(length))) <= 0)
	{
		DEBUG_ERR_MSG("shutdown request from client");
		*result = NET_NFC_OPERATION_FAIL;
		return false;
	}

	if (read != sizeof(length))
	{
		DEBUG_ERR_MSG("failed to read message length [%d]", read);
		*result = NET_NFC_IPC_FAIL;
		return false;
	}

	if (length > NET_NFC_MAX_MESSAGE_LENGTH)
	{
		DEBUG_ERR_MSG("too long message [%d]", length);
		*result = NET_NFC_IPC_FAIL;
		return false;
	}

	_net_nfc_util_alloc_mem(buffer, length);
	if (buffer == NULL)
	{
		*result = NET_NFC_ALLOC_FAIL;
		return false;
	}

	memset(buffer, 0, length);

	if ((read = net_nfc_server_recv_message_from_client(client_sock_fd, (void *)buffer, length)) != length)
	{
		DEBUG_ERR_MSG("failed to read message [%d]", read);
		_net_nfc_util_free_mem(buffer);
		*result = NET_NFC_IPC_FAIL;
		return false;
	}

#ifdef SECURITY_SERVER
	uint32_t cookie_len = *(uint32_t *)(buffer + offset);
	offset += sizeof(cookie_len);

	if (cookie_len == cookies_size && (length - offset) > cookies_size)
	{
		int error = 0;

		/* copy cookie */
		memcpy(cookies, buffer + offset, cookies_size);
		offset += cookies_size;

		/* for debug */
#if 0
		DEBUG_SERVER_MSG("recevied cookies");
		DEBUG_MSG_PRINT_BUFFER(cookies, cookie_len);
#endif

		/* check cookie */
		if ((error = security_server_check_privilege(cookies, gid)) < 0)
		{
			DEBUG_ERR_MSG("failed to authentificate client [%d]", error);
			_net_nfc_util_free_mem(buffer);
			*result = NET_NFC_SECURITY_FAIL;
			return false;
		}
	}
	else
	{
		DEBUG_ERR_MSG("there is no cookie or invalid in message");
		_net_nfc_util_free_mem(buffer);
		*result = NET_NFC_SECURITY_FAIL;
		return false;
	}
#endif

	if (length > offset)
	{
		_net_nfc_util_alloc_mem(req_msg, length - offset);
		if (req_msg != NULL)
		{
			memcpy(req_msg, buffer + offset, length - offset);
		}
		else
		{
			_net_nfc_util_free_mem(buffer);
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}
	}
	else
	{
		_net_nfc_util_free_mem(buffer);
		*result = NET_NFC_IPC_FAIL;
		return false;
	}

	_net_nfc_util_free_mem(buffer);

	pid_t client_pid = -1;

	net_nfc_client_info_t *info;
	info = net_nfc_server_get_client_context(client_sock_fd);
	if (info != NULL)
	{
		client_pid = info->pid;
	}
	DEBUG_MSG(">>>>>>>>>>>>>>> [%d] >> SERVER (msg [%d], length [%d])", client_pid, req_msg->request_type, length);

#ifdef BROADCAST_MESSAGE
	/* set client socket descriptor */
	req_msg->client_fd = client_sock_fd;
#endif

	/* process exceptional case of request type */
	switch (req_msg->request_type)
	{
	case NET_NFC_MESSAGE_SERVICE_CHANGE_CLIENT_STATE :
		{
			net_nfc_request_change_client_state_t *detail = (net_nfc_request_change_client_state_t *)req_msg;

			net_nfc_server_set_client_state(client_sock_fd, detail->client_state);
			DEBUG_SERVER_MSG("net_nfc_server_read_client_request is finished");

			_net_nfc_util_free_mem(req_msg);

			return true;
		}
		break;

	case NET_NFC_MESSAGE_SERVICE_SET_LAUNCH_STATE :
		{
			DEBUG_SERVER_MSG("checking NET_NFC_MESSAGE_SERVICE_SET_LAUNCH_STATE...");
#if 1
			int ret = security_server_check_privilege_by_sockfd(req_msg->client_fd,"nfc-manager::common","w");

			if (ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED)
			{
				DEBUG_SERVER_MSG("checking faile and return...");
//				return false;
			}
#endif

			net_nfc_request_set_launch_state_t *detail = (net_nfc_request_set_launch_state_t *)req_msg;

			net_nfc_server_set_launch_state(client_sock_fd, detail->set_launch_popup);

			_net_nfc_util_free_mem(req_msg);

			return true;
		}
		break;

	default :
		break;
	}

#ifdef BROADCAST_MESSAGE
	net_nfc_dispatcher_queue_push(req_msg);
#else
	/* check current client context is activated. */
	if (net_nfc_server_get_client_state(client_sock_fd) == NET_NFC_CLIENT_ACTIVE_STATE)
	{
		DEBUG_SERVER_MSG("client is activated");
		net_nfc_dispatcher_queue_push(req_msg);
		DEBUG_SERVER_MSG("net_nfc_server_read_client_request is finished");
		break;
	}
	else
	{
		DEBUG_SERVER_MSG("client is deactivated");

		/* free req_msg */
		_net_nfc_util_free_mem(req_msg);

		DEBUG_SERVER_MSG("net_nfc_server_read_client_request is finished");
		return false;
	}
#endif

	return true;
}

#ifdef BROADCAST_MESSAGE
bool net_nfc_server_send_message_to_client(int socket, void *message, int length)
{
	int len = 0;
	bool result = true;

	pthread_mutex_lock(&g_server_socket_lock);
	len = send(socket, (void *)message, length, MSG_NOSIGNAL);
	pthread_mutex_unlock(&g_server_socket_lock);

	if (len <= 0)
	{
		uint8_t buf[1024] = { 0x00, };

		DEBUG_ERR_MSG("send failed : socket [%d], length [%d], [%s]", socket, length, strerror_r(errno, (char *)buf, sizeof(buf)));
		if (errno == EPIPE)
		{
			abort();
		}
		result = false;
	}

	return result;
}
#else
bool net_nfc_server_send_message_to_client(void* message, int length)
{
	pthread_mutex_lock(&g_server_socket_lock);
	int leng = send(g_server_info.client_sock_fd, (void *)message, length, 0);
	pthread_mutex_unlock(&g_server_socket_lock);

	if(leng > 0)
	{
		return true;
	}
	else
	{
		DEBUG_ERR_MSG("failed to send message, socket = [%d], msg_length = [%d]", g_server_info.client_sock_fd, length);
		return false;
	}
}
#endif

int net_nfc_server_recv_message_from_client(int client_sock_fd, void* message, int length)
{
	int leng = recv(client_sock_fd, message, length, 0);

	return leng;
}

static void _net_nfc_for_each_cb(net_nfc_client_info_t *client, void *user_param)
{
	if (user_param != NULL)
	{
		int length = *(int *)user_param;
		uint8_t *send_buffer = ((uint8_t *)user_param) + sizeof(int);

		if (net_nfc_server_send_message_to_client(client->socket, send_buffer, length) == true)
		{
//			DEBUG_MSG(">>>>> TO CLIENT [%d] >>>>> (msg [%d], length [%d])", client->socket, msg_type, length);
			DEBUG_MSG("<<<<<<<<<<<<<<< [%d] << SERVER (length [%d])", client->pid, length);
		}
	}
}

#ifdef BROADCAST_MESSAGE
bool net_nfc_broadcast_response_msg(int msg_type, ...)
{
	va_list list;
	int total_size = 0;
	int written_size = 0;
	uint8_t *send_buffer = NULL;

	va_start(list, msg_type);

	/* total length */
	total_size += sizeof(msg_type);
	total_size += net_nfc_util_get_va_list_length(list);

	_net_nfc_util_alloc_mem(send_buffer, total_size + sizeof(total_size));

	memcpy(send_buffer + written_size, &(total_size), sizeof(total_size));
	written_size += sizeof(total_size);

	memcpy(send_buffer + written_size, &(msg_type), sizeof(msg_type));
	written_size += sizeof(msg_type);

	written_size += net_nfc_util_fill_va_list(send_buffer + written_size, total_size + sizeof(total_size) - written_size, list);

	va_end(list);

	net_nfc_server_for_each_client_context(_net_nfc_for_each_cb, send_buffer);

	_net_nfc_util_free_mem(send_buffer);

	return true;
}

bool net_nfc_send_response_msg(int socket, int msg_type, ...)
#else
bool net_nfc_send_response_msg(int msg_type, ...)
#endif
{
	va_list list;
	int total_size = 0;
	int written_size = 0;
	uint8_t *send_buffer = NULL;
	net_nfc_client_info_t *info;

	va_start(list, msg_type);

	total_size += sizeof(msg_type);
	total_size += net_nfc_util_get_va_list_length(list);

	_net_nfc_util_alloc_mem(send_buffer, total_size + sizeof(total_size));

//	memcpy(send_buffer + written_size, &(total_size), sizeof(total_size));
//	written_size += sizeof(total_size);

	memcpy(send_buffer + written_size, &(msg_type), sizeof(msg_type));
	written_size += sizeof(msg_type);

//	written_size += net_nfc_util_fill_va_list(send_buffer + written_size, total_size + sizeof(total_size) - written_size, list);
	written_size += net_nfc_util_fill_va_list(send_buffer + written_size, total_size - written_size, list);

	va_end(list);

	if ((info = net_nfc_server_get_client_context(socket)) != NULL)
	{
#ifdef BROADCAST_MESSAGE
		if (net_nfc_server_send_message_to_client(socket, (void *)send_buffer, total_size) == true)
#else
		if (net_nfc_server_send_message_to_client((void *)send_buffer, total_size) == true)
#endif
		{
			DEBUG_MSG("<<<<<<<<<<<<<<< [%d] << SERVER (msg [%d], length [%d])", info->pid, msg_type, total_size - sizeof(total_size));
		}
	}
	else
	{
		DEBUG_ERR_MSG("Client not found : socket [%d], length [%d]", socket, total_size + sizeof(total_size));
	}

	_net_nfc_util_free_mem(send_buffer);

	return true;
}

void net_nfc_server_set_tag_info(void *info)
{
	net_nfc_request_target_detected_t *detail = (net_nfc_request_target_detected_t *)info;
	net_nfc_current_target_info_s *target_info = NULL;

	pthread_mutex_lock(&g_server_socket_lock);

	if (g_server_info.target_info != NULL)
		_net_nfc_util_free_mem(g_server_info.target_info);

	_net_nfc_util_alloc_mem(target_info, sizeof(net_nfc_current_target_info_s) + detail->target_info_values.length);
	if (target_info != NULL)
	{
		target_info->handle = detail->handle;
		target_info->devType = detail->devType;

		if (target_info->devType != NET_NFC_NFCIP1_INITIATOR && target_info->devType != NET_NFC_NFCIP1_TARGET)
		{
			target_info->number_of_keys = detail->number_of_keys;
			target_info->target_info_values.length = detail->target_info_values.length;
			memcpy(&target_info->target_info_values, &detail->target_info_values, target_info->target_info_values.length);
		}

		g_server_info.target_info = target_info;
	}

	pthread_mutex_unlock(&g_server_socket_lock);
}

bool net_nfc_server_is_target_connected(void *handle)
{
	bool result = false;

	if (g_server_info.target_info != NULL && g_server_info.target_info->handle == handle)
		result = true;

	return result;
}

net_nfc_current_target_info_s *net_nfc_server_get_tag_info()
{
	return g_server_info.target_info;
}

void net_nfc_server_free_current_tag_info()
{
	pthread_mutex_lock(&g_server_socket_lock);

	_net_nfc_util_free_mem(g_server_info.target_info);

	pthread_mutex_unlock(&g_server_socket_lock);
}
