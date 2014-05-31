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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <stdarg.h>
#include <signal.h>
#include <glib-object.h>

#include "net_nfc_typedef_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_private.h"
#include "net_nfc_client_ipc_private.h"
#include "net_nfc_client_dispatcher_private.h"

/* static variable */
static pid_t g_client_pid;
static int g_client_sock_fd = -1;
static pthread_mutex_t g_client_ipc_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_client_ipc_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t cb_lock = PTHREAD_MUTEX_INITIALIZER;
static net_nfc_response_cb client_cb = NULL;
static net_nfc_error_e sync_result;

#ifdef G_MAIN_LOOP
static GIOChannel *g_client_channel = NULL;
static uint32_t g_client_src_id = 0;
#else
#ifdef USE_IPC_EPOLL
#define EPOLL_SIZE 128
static int g_client_poll_fd = -1;
static struct epoll_event g_client_poll_event = { 0, };
#else
static fd_set fdset_read;
#endif
static pthread_t g_poll_thread = (pthread_t)0;
#endif

/* static function */
static net_nfc_response_msg_t *net_nfc_client_read_response_msg(net_nfc_error_e *result);
#ifdef G_MAIN_LOOP
gboolean net_nfc_client_ipc_callback_func(GIOChannel *channel, GIOCondition condition, gpointer data);
#else
static bool net_nfc_client_ipc_polling(net_nfc_error_e *result);
static void *net_nfc_client_ipc_thread(void *data);
#endif

/////////////////////

inline void net_nfc_client_ipc_lock()
{
	pthread_mutex_lock(&g_client_ipc_mutex);
}

inline void net_nfc_client_ipc_unlock()
{
	pthread_mutex_unlock(&g_client_ipc_mutex);
}

static void net_nfc_client_prepare_sync_call(net_nfc_request_msg_t *msg)
{
	net_nfc_client_ipc_lock();

	NET_NFC_FLAGS_SET_SYNC_CALL(msg->flags);
}

static net_nfc_error_e net_nfc_client_wait_sync_call(int timeout)
{
	net_nfc_error_e result = NET_NFC_OPERATION_FAIL;
	struct timeval now;
	struct timespec ts;

	gettimeofday(&now, NULL);
	ts.tv_sec = now.tv_sec + timeout;
	ts.tv_nsec = now.tv_usec * 1000;

	if (pthread_cond_timedwait(&g_client_ipc_cond, &g_client_ipc_mutex,
		&ts) == 0)
	{
		result = sync_result;
	}

	return result;
}

static void net_nfc_client_post_sync_call()
{
	net_nfc_client_ipc_unlock();
}

static void net_nfc_client_recv_sync_call()
{
	net_nfc_client_ipc_lock();
}

static void net_nfc_client_notify_sync_call(net_nfc_error_e result)
{
	sync_result = result;

	pthread_cond_signal(&g_client_ipc_cond);
	net_nfc_client_ipc_unlock();
}

bool net_nfc_client_is_connected()
{
#ifdef G_MAIN_LOOP
	if (g_client_sock_fd != -1 && g_client_channel != NULL && g_client_src_id != 0)
#else
#ifdef USE_IPC_EPOLL
	if (g_client_sock_fd != -1 && g_client_poll_fd != -1 && g_poll_thread != (pthread_t)NULL)
#else
	if (g_client_sock_fd != -1 && g_poll_thread != (pthread_t)NULL)
#endif
#endif
	{
		return true;
	}
	else
	{
		return false;
	}
}

static net_nfc_error_e _finalize_client_socket()
{
	net_nfc_error_e result = NET_NFC_OK;

	DEBUG_CLIENT_MSG("finalize client socket");

	net_nfc_client_ipc_lock();

	if (g_client_sock_fd != -1)
	{
#ifdef G_MAIN_LOOP
		g_io_channel_unref(g_client_channel);
		g_client_channel = NULL;

		g_source_remove(g_client_src_id);
		g_client_src_id = 0;
#else
#if 0
		if (g_poll_thread != (pthread_t)NULL)
		{
#ifdef NET_NFC_USE_SIGTERM
			/* This is dangerous because of the lock inside of the thread it creates dead lock!
			 * it may damage the application data or lockup, sigterm can be recieved while the application codes is executed in callback function
			 */
			pthread_kill(g_poll_thread, SIGTERM);
#else
			DEBUG_CLIENT_MSG("join epoll_thread start");
			pthread_join(g_poll_thread, NULL);
			DEBUG_CLIENT_MSG("join epoll_thread end");
#endif
		}
		g_poll_thread = (pthread_t)NULL;
#endif
#ifdef USE_IPC_EPOLL
		if (g_client_poll_fd != -1)
		{
			struct epoll_event ev;

			ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLERR;
			ev.data.fd = g_client_sock_fd;

			int ret = epoll_ctl(g_client_poll_fd, EPOLL_CTL_DEL, g_client_sock_fd, &ev);

			ret = close(g_client_poll_fd);
			g_client_poll_fd = -1;
			DEBUG_CLIENT_MSG("epoll close, %d", ret);
		}
#else
		FD_CLR(g_client_sock_fd, &fdset_read);
#endif
#endif // #ifdef G_MAIN_LOOP
		close(g_client_sock_fd);
		g_client_sock_fd = -1;
		DEBUG_CLIENT_MSG("close socket");
	}

	net_nfc_client_ipc_unlock();

	return result;
}

net_nfc_error_e net_nfc_client_socket_initialize()
{
	int ret;
	net_nfc_error_e result = NET_NFC_OK;

	if (net_nfc_client_is_connected() == true)
	{
		DEBUG_CLIENT_MSG("client is already initialized");
		return NET_NFC_ALREADY_INITIALIZED;
	}

	g_client_pid = getpid();

	pthread_mutexattr_t attr;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
	pthread_mutex_init(&cb_lock, &attr);

#ifdef USE_UNIX_DOMAIN
	struct sockaddr_un saddrun_rv;
	socklen_t len_saddr = 0;

	memset(&saddrun_rv, 0, sizeof(struct sockaddr_un));

	net_nfc_client_ipc_lock();

	g_client_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (g_client_sock_fd == -1)
	{
		DEBUG_ERR_MSG("get socket is failed");
		net_nfc_client_ipc_unlock();
		return NET_NFC_IPC_FAIL;
	}

	DEBUG_CLIENT_MSG("socket is created");

	net_nfc_util_set_non_block_socket(g_client_sock_fd);

	saddrun_rv.sun_family = AF_UNIX;
	strncpy(saddrun_rv.sun_path, NET_NFC_SERVER_DOMAIN, sizeof(saddrun_rv.sun_path) - 1);

	len_saddr = sizeof(saddrun_rv.sun_family) + strlen(NET_NFC_SERVER_DOMAIN);

	if (connect(g_client_sock_fd, (struct sockaddr *)&saddrun_rv, len_saddr) < 0)
	{
		DEBUG_ERR_MSG("error is occured");
		result = NET_NFC_IPC_FAIL;
		goto ERROR;
	}
#else
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0x00, sizeof(struct sockaddr_in));

	g_client_sock_fd = socket(PF_INET, SOCK_STREAM, 0);

	if (g_client_sock_fd == -1)
	{
		DEBUG_ERR_MSG("get socket is failed ");
		net_nfc_client_ipc_unlock();
		return NET_NFC_IPC_FAIL;
	}

	DEBUG_CLIENT_MSG("socket is created");

	net_nfc_util_set_non_block_socket(g_client_sock_fd);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(NET_NFC_SERVER_PORT);

	if ((connect(g_client_sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0)
	{
		DEBUG_ERR_MSG("error is occured");
		result = NET_NFC_IPC_FAIL;
		goto ERROR;
	}

#endif

#ifdef G_MAIN_LOOP

	GIOCondition condition = (GIOCondition)(G_IO_ERR | G_IO_HUP | G_IO_IN);

	if ((g_client_channel = g_io_channel_unix_new(g_client_sock_fd)) != NULL)
	{
		if ((g_client_src_id = g_io_add_watch(g_client_channel, condition, net_nfc_client_ipc_callback_func, NULL)) < 1)
		{
			DEBUG_ERR_MSG(" g_io_add_watch is failed ");
			result = NET_NFC_IPC_FAIL;
			goto ERROR;
		}
	}
	else
	{
		DEBUG_ERR_MSG(" g_io_channel_unix_new is failed ");
		result = NET_NFC_IPC_FAIL;
		goto ERROR;
	}

	DEBUG_CLIENT_MSG("socket and g io channel is binded");

#else

#ifdef USE_IPC_EPOLL
	if ((g_client_poll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1)
	{
		DEBUG_ERR_MSG("error is occured");
		result = NET_NFC_IPC_FAIL;
		goto ERROR;
	}

	memset(&g_client_poll_event, 0, sizeof(g_client_poll_event));

	struct epoll_event ev;

	ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
	ev.data.fd = g_client_sock_fd;

	ret = epoll_ctl(g_client_poll_fd, EPOLL_CTL_ADD, g_client_sock_fd, &ev);
#else
	FD_ZERO(&fdset_read);
	FD_SET(g_client_sock_fd, &fdset_read);
#endif

	/* create polling thread and go */
	pthread_attr_t thread_attr;
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

	pthread_cond_t pcond = PTHREAD_COND_INITIALIZER;

	if (pthread_create(&g_poll_thread, NULL, net_nfc_client_ipc_thread, &pcond) != 0)
	{
		DEBUG_ERR_MSG("error is occured");
		pthread_attr_destroy(&thread_attr);
		result = NET_NFC_THREAD_CREATE_FAIL;
		goto ERROR;
	}

	usleep(0);

#ifdef NET_NFC_USE_SIGTERM
	pthread_cond_wait(&pcond, &g_client_ipc_mutex);
#endif

	DEBUG_CLIENT_MSG("start ipc thread = [%x]", (uint32_t)g_poll_thread);

	//////////////////////////////////

	pthread_attr_destroy(&thread_attr);

#endif // #ifdef G_MAIN_LOOP
	net_nfc_client_ipc_unlock();

	return NET_NFC_OK;

ERROR :
	DEBUG_ERR_MSG("error while initializing client ipc");

	net_nfc_client_ipc_unlock();

	_finalize_client_socket();

	return result;
}

#ifdef NET_NFC_USE_SIGTERM
static void thread_sig_handler(int signo)
{
	/* do nothing */
}
#endif

#ifndef G_MAIN_LOOP
static void *net_nfc_client_ipc_thread(void *data)
{
	DEBUG_CLIENT_MSG("net_nfc_client_ipc_thread is started = [0x%lx]", pthread_self());

#ifdef NET_NFC_USE_SIGTERM

	struct sigaction act;
	act.sa_handler = thread_sig_handler;
	sigaction(SIGTERM, &act, NULL);

	sigset_t newmask;
	sigemptyset(&newmask);
	sigaddset(&newmask, SIGTERM);
	pthread_sigmask(SIG_UNBLOCK, &newmask, NULL);
	DEBUG_CLIENT_MSG("sighandler is registered");

#endif

#ifdef NET_NFC_USE_SIGTERM
	net_nfc_client_ipc_lock();
	pthread_cond_signal((pthread_cond_t *)data);
	net_nfc_client_ipc_unlock();
#endif

	bool condition = true;

	while (condition == true)
	{
		net_nfc_error_e result = 0;

		if (net_nfc_client_ipc_polling(&result) != true)
		{
			switch (result)
			{
			case NET_NFC_OPERATION_FAIL :
				DEBUG_CLIENT_MSG("shutdown request from server, stop ipc polling thread");
				_finalize_client_socket();
				condition = false;
				break;

			case NET_NFC_IPC_FAIL :
				DEBUG_ERR_MSG("abnormal socket close.");
				_finalize_client_socket();
				condition = false;
				break;

			default :
				DEBUG_ERR_MSG("???");
				break;
			}
		}
		else
		{
			net_nfc_response_msg_t *msg = NULL;

			DEBUG_CLIENT_MSG("message is coming from server to client");

			msg = net_nfc_client_read_response_msg(&result);

			if (msg != NULL && msg->detail_message != NULL)
			{
				/* TODO : need to remove */
				net_nfc_response_msg_t *temp = (net_nfc_response_msg_t *)(msg->detail_message);
;
				if (NET_NFC_FLAGS_IS_SYNC_CALL(temp->flags))
				{
					net_nfc_error_e result;

					net_nfc_client_recv_sync_call();

					/* call a callback in IPC thread */
					result = net_nfc_client_dispatch_sync_response(msg);

					/* unset sync call flag */
					net_nfc_client_notify_sync_call(result);
				}
				else
				{
					pthread_mutex_lock(&cb_lock);
#ifdef USE_GLIB_MAIN_LOOP
					net_nfc_client_call_dispatcher_in_g_main_loop(client_cb, msg);
#elif USE_ECORE_MAIN_LOOP
					net_nfc_client_call_dispatcher_in_ecore_main_loop(client_cb, msg);
#else
					net_nfc_client_call_dispatcher_in_current_context(client_cb, msg);
#endif
					pthread_mutex_unlock(&cb_lock);
				}
			}
			else
			{
				/* if client is waiting for unlock signal, then unlock it.
				 * and send error message
				 * or make error response message and pass to client callback
				 */
				if (net_nfc_client_is_connected() == false)
				{
					condition = false;
				}
				DEBUG_ERR_MSG("cannot read response msg");
			}
		}
	}

	DEBUG_CLIENT_MSG("net_nfc_client_ipc_thread is terminated");

	return (void *)NULL;
}
#endif

#ifdef G_MAIN_LOOP
gboolean net_nfc_client_ipc_callback_func(GIOChannel *channel, GIOCondition condition, gpointer data)
{
	DEBUG_CLIENT_MSG("event is detected on client socket");

	if(G_IO_IN & condition)
	{

		int client_sock_fd = 0;

		if(channel == g_client_channel)
		{

			DEBUG_CLIENT_MSG("message from server to client socket");

			net_nfc_error_e result = NET_NFC_OK;
			net_nfc_response_msg_t *msg = net_nfc_client_read_response_msg(&result);

			if(msg != NULL)
			{

				net_nfc_client_call_dispatcher_in_current_context(client_cb, msg);
			}
			else
			{
				DEBUG_CLIENT_MSG("can not read response msg or callback is NULL");
			}

		}
		else
		{
			DEBUG_CLIENT_MSG("unknown channel ");
			return FALSE;
		}
	}
	else
	{

		DEBUG_CLIENT_MSG("IO ERROR. socket is closed ");

		/* clean up client context */
		net_nfc_client_socket_finalize();

		return FALSE;
	}

	return TRUE;
}
#else
bool net_nfc_client_ipc_polling(net_nfc_error_e *result)
{
	int num_of_sockets = 0;

	if (result == NULL)
	{
		return false;
	}

	*result = NET_NFC_OK;

#ifdef USE_IPC_EPOLL
	DEBUG_CLIENT_MSG("wait event from epoll");

	if (g_client_poll_fd == -1 || g_client_sock_fd == -1)
	{
		DEBUG_ERR_MSG("client is deinitialized. ");
		*result = NET_NFC_IPC_FAIL;
		return false;
	}

	/* 0.5sec */
#ifndef USE_EPOLL_TIMEOUT
	while ((num_of_sockets = epoll_wait(g_client_poll_fd, &g_client_poll_event, 1, 300)) == 0)
	{
		if (g_client_poll_fd == -1)
		{
			DEBUG_CLIENT_MSG("client ipc thread is terminated");
			return false;
		}
	}
#else
	num_of_sockets = epoll_wait(g_client_poll_fd, &g_client_poll_event, 1, -1);
#endif
	if (num_of_sockets == 1)
	{
		if (g_client_poll_event.events & EPOLLRDHUP)
		{
			DEBUG_CLIENT_MSG("EPOLLRDHUP");
			*result = NET_NFC_OPERATION_FAIL;
			return false;
		}
		else if (g_client_poll_event.events & EPOLLHUP)
		{
			DEBUG_CLIENT_MSG("EPOLLHUP");
			*result = NET_NFC_IPC_FAIL;
			return false;
		}
		else if (g_client_poll_event.events & EPOLLERR)
		{
			DEBUG_CLIENT_MSG("EPOLLERR");
			*result = NET_NFC_IPC_FAIL;
			return false;
		}
		else if (g_client_poll_event.events & EPOLLIN)
		{
			if (g_client_poll_event.data.fd == g_client_sock_fd)
			{
				return true;
			}
			else
			{
				DEBUG_ERR_MSG("unexpected socket connection");
				return false;
			}
		}
	}
	else
	{
		DEBUG_ERR_MSG("epoll_wait returns error");
		return false;
	}
#else
	DEBUG_CLIENT_MSG("wait event from select");

	int temp = select(g_client_sock_fd + 1, &fdset_read, NULL, NULL, NULL);

	if(temp > 0)
	{
		if(FD_ISSET(g_client_sock_fd, &fdset_read) == true)
		{
			int val = 0;
			int size = 0;

			if(getsockopt(g_client_sock_fd, SOL_SOCKET, SO_ERROR, &val, &size) == 0)
			{
				if(val != 0)
				{
					DEBUG_CLIENT_MSG("socket is on error");
					return false;
				}
				else
				{
					DEBUG_CLIENT_MSG("socket is readable");
					return true;
				}
			}
		}
		else
		{
			DEBUG_ERR_MSG("unknown error");
			*result = NET_NFC_IPC_FAIL;
			return false;
		}
	}
#endif

	DEBUG_CLIENT_MSG("polling error");
	*result = NET_NFC_IPC_FAIL;
	return false;
}
#endif

void net_nfc_client_socket_finalize()
{
	net_nfc_client_ipc_lock();

	if (g_client_sock_fd != -1)
	{
		DEBUG_CLIENT_MSG("shutdown socket, and wait EPOLLRDHUP");
		shutdown(g_client_sock_fd, SHUT_WR);
	}

	net_nfc_client_ipc_unlock();
}

int __net_nfc_client_read_util(void **detail, size_t size)
{
	int length;
	static uint8_t flushing[128];

	if (recv(g_client_sock_fd, &length, sizeof(length), 0) != sizeof(length))
	{
		return 0;
	}

	*detail = NULL;
	_net_nfc_util_alloc_mem(*detail, size);

	/* if the allocation is failed, this codes flush out all the buffered data */
	if (*detail == NULL)
	{
		size_t read_size;
		int readbytes = size;
		while (readbytes > 0)
		{
			read_size = readbytes > 128 ? 128 : readbytes;
			if (recv(g_client_sock_fd, flushing, read_size, 0) <= 0)
			{
				return 0;
			}
			readbytes -= read_size;
		}
		return 0;
	}
	/* read */
	if (recv(g_client_sock_fd, *detail, size, 0) <= 0)
	{
		_net_nfc_util_free_mem(*detail);
		return 0;
	}
	return 1;
}

net_nfc_response_msg_t *net_nfc_client_read_response_msg(net_nfc_error_e *result)
{
	net_nfc_response_msg_t *resp_msg = NULL;

	_net_nfc_util_alloc_mem(resp_msg, sizeof(net_nfc_response_msg_t));
	if (resp_msg == NULL)
	{
		DEBUG_ERR_MSG("malloc fail");
		*result = NET_NFC_ALLOC_FAIL;
		return NULL;
	}

	if (recv(g_client_sock_fd, (void *)&(resp_msg->response_type), sizeof(int), 0) != sizeof(int))
	{
		DEBUG_ERR_MSG("reading message is failed");
		_net_nfc_util_free_mem(resp_msg);

		return NULL;
	}

//	DEBUG_MSG("<<<<< FROM SERVER <<<<< (msg [%d], length [%d])", resp_msg->response_type, length);
	DEBUG_MSG("[%d] <<<<<<<<<<<<<<< (msg [%d])", g_client_pid, resp_msg->response_type);

	switch (resp_msg->response_type)
	{
	case NET_NFC_MESSAGE_SET_SE :
		{
			net_nfc_response_set_se_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_set_se_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_GET_SE :
		{
			net_nfc_response_get_se_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_get_se_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_SE_TYPE_CHANGED :
		{
			net_nfc_response_notify_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_notify_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_OPEN_INTERNAL_SE :
		{
			net_nfc_response_open_internal_se_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_open_internal_se_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			DEBUG_CLIENT_MSG("handle = [0x%p]", resp_detail->handle);
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_CLOSE_INTERNAL_SE :
		{
			net_nfc_response_close_internal_se_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_close_internal_se_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_SEND_APDU_SE :
		{

			net_nfc_response_send_apdu_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_send_apdu_t));
			if (res == 1)
			{
				if (resp_detail->data.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->data.buffer), resp_detail->data.length);
					if (res == 2)
					{
						resp_msg->detail_message = resp_detail;
					}
					else
					{
						_net_nfc_util_free_mem(resp_detail);
						res--;
					}
				}
				else
				{
					resp_msg->detail_message = resp_detail;
					resp_detail->data.buffer = NULL;
				}
			}
			if (res == 0)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_TAG_DISCOVERED :
		{
			net_nfc_response_tag_discovered_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_tag_discovered_t));
			if (res == 1)
			{
				if (resp_detail->target_info_values.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->target_info_values.buffer), resp_detail->target_info_values.length);
					if (res == 2)
					{
						if (resp_detail->raw_data.length > 0)
						{
							res += __net_nfc_client_read_util((void **)&(resp_detail->raw_data.buffer), resp_detail->raw_data.length);
							if (res == 3)
							{
								resp_msg->detail_message = resp_detail;
							}
							else
							{
								_net_nfc_util_free_mem(resp_detail);
								res--;
							}
						}
						else
						{
							resp_msg->detail_message = resp_detail;
							resp_detail->raw_data.buffer = NULL;
						}
					}
					else
					{
						_net_nfc_util_free_mem(resp_detail);
						res--;
					}
				}
				else
				{
					resp_msg->detail_message = resp_detail;
					resp_detail->target_info_values.buffer = NULL;
				}
			}
			if (res == 0)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_GET_CURRENT_TAG_INFO :
		{
			net_nfc_response_get_current_tag_info_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_get_current_tag_info_t));
			if (res == 1)
			{
				if (resp_detail->target_info_values.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->target_info_values.buffer), resp_detail->target_info_values.length);
					if (res == 2)
					{
						if (resp_detail->raw_data.length > 0)
						{
							res += __net_nfc_client_read_util((void **)&(resp_detail->raw_data.buffer), resp_detail->raw_data.length);
							if (res == 3)
							{
								resp_msg->detail_message = resp_detail;
							}
							else
							{
								_net_nfc_util_free_mem(resp_detail);
								res--;
							}
						}
						else
						{
							resp_msg->detail_message = resp_detail;
							resp_detail->raw_data.buffer = NULL;
						}
					}
					else
					{
						_net_nfc_util_free_mem(resp_detail);
						res--;
					}
				}
				else
				{
					resp_msg->detail_message = resp_detail;
					resp_detail->target_info_values.buffer = NULL;
				}
			}
			if (res == 0)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_SE_START_TRANSACTION :
	case NET_NFC_MESSAGE_SE_END_TRANSACTION :
	case NET_NFC_MESSAGE_SE_TYPE_TRANSACTION :
	case NET_NFC_MESSAGE_SE_CONNECTIVITY :
	case NET_NFC_MESSAGE_SE_FIELD_ON :
	case NET_NFC_MESSAGE_SE_FIELD_OFF :
		{
			net_nfc_response_se_event_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_se_event_t));
			if (res == 1)
			{
				if (resp_detail->aid.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->aid.buffer), resp_detail->aid.length);
					if (res == 2)
					{
						if (resp_detail->param.length > 0)
						{
							res += __net_nfc_client_read_util((void **)&(resp_detail->param.buffer), resp_detail->param.length);
							if (res == 3)
							{
								resp_msg->detail_message = resp_detail;
							}
							else
							{
								_net_nfc_util_free_mem(resp_detail);
								res--;
							}
						}
						else
						{
							resp_msg->detail_message = resp_detail;
							resp_detail->param.buffer = NULL;
						}
					}
					else
					{
						_net_nfc_util_free_mem(resp_detail);
						res--;
					}
				}
				else
				{
					resp_msg->detail_message = resp_detail;
					resp_detail->aid.buffer = NULL;
				}
			}
			if (res == 0)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_CARD_EMULATION_CHANGE_SE :
		{
			net_nfc_response_se_change_card_emulation_t *resp_detail = NULL;
			int res = 0;

			DEBUG_CLIENT_MSG("Client Receive the NET_NFC_MESSAGE_CARD_EMULATION_CHANGE_SE");

			res = __net_nfc_client_read_util((void **)&resp_detail,
							sizeof(net_nfc_response_se_change_card_emulation_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;

		}
		break;

	case NET_NFC_MESSAGE_SE_CARD_EMULATION_CHANGED :
		{
			net_nfc_response_notify_t *resp_detail = NULL;
			int res = 0;

			DEBUG_CLIENT_MSG("Client Receive the NET_NFC_MESSAGE_SE_CARD_EMULATION_CHANGED");

			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_notify_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_TRANSCEIVE :
		{
			net_nfc_response_transceive_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_transceive_t));
			if (res == 1)
			{
				if (resp_detail->data.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->data.buffer), resp_detail->data.length);
					if (res == 2)
					{
						resp_msg->detail_message = resp_detail;
					}
					else
					{
						_net_nfc_util_free_mem(resp_detail);
						res--;
					}
				}
				else
				{
					resp_msg->detail_message = resp_detail;
					resp_detail->data.buffer = NULL;
				}
			}
			if (res == 0)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_READ_NDEF :
		{

			net_nfc_response_read_ndef_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_read_ndef_t));
			if (res == 1)
			{
				if (resp_detail->data.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->data.buffer), resp_detail->data.length);
					if (res == 2)
					{
						resp_msg->detail_message = resp_detail;
					}
					else
					{
						_net_nfc_util_free_mem(resp_detail);
						res--;
					}
				}
				else
				{
					resp_msg->detail_message = resp_detail;
					resp_detail->data.buffer = NULL;
				}
			}
			if (res == 0)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_WRITE_NDEF :
		{
			net_nfc_response_write_ndef_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_write_ndef_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_SIM_TEST :
		{
			net_nfc_response_test_t *resp_detail = NULL;
			int res = 0;

			DEBUG_CLIENT_MSG("message from server NET_NFC_MESSAGE_SIM_TEST");

			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_test_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_PRBS_TEST :
		{
			net_nfc_response_test_t *resp_detail = NULL;
			int res = 0;

			DEBUG_CLIENT_MSG("message from server NET_NFC_MESSAGE_PRBS_TEST");

			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_test_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_SET_EEDATA :
		{
			net_nfc_response_test_t *resp_detail = NULL;
			int res = 0;

			DEBUG_CLIENT_MSG("message from server NET_NFC_MESSAGE_SET_EEDATA");

			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_test_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_GET_FIRMWARE_VERSION :
		{
			net_nfc_response_firmware_version_t *resp_detail = NULL;

			DEBUG_CLIENT_MSG("message from server NET_NFC_MESSAGE_GET_FIRMWARE_VERSION");

			if (__net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_firmware_version_t)) > 0)
			{
				if (__net_nfc_client_read_util((void **)&(resp_detail->data.buffer), resp_detail->data.length) > 0)
				{
					resp_msg->detail_message = resp_detail;
				}
				else
				{
					_net_nfc_util_free_mem(resp_msg);
					_net_nfc_util_free_mem(resp_detail);
					return NULL;
				}
			}
			else
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_NOTIFY :
		{
			net_nfc_response_notify_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_notify_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;
	case NET_NFC_MESSAGE_TAG_DETACHED :
		{
			net_nfc_response_target_detached_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_target_detached_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_FORMAT_NDEF :
		{

			net_nfc_response_format_ndef_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_format_ndef_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;

		}
		break;

	case NET_NFC_MESSAGE_LLCP_DISCOVERED :
		{
			net_nfc_response_llcp_discovered_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_llcp_discovered_t));
			if (res == 1)
			{
				if (resp_detail->target_info_values.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->target_info_values.buffer), resp_detail->target_info_values.length);
					if (res == 2)
					{
						resp_msg->detail_message = resp_detail;
					}
					else
					{
						_net_nfc_util_free_mem(resp_detail);
						res--;
					}
				}
				else
				{
					resp_msg->detail_message = resp_detail;
					resp_detail->target_info_values.buffer = NULL;
				}
			}
			if (res == 0)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_P2P_DETACHED :
		{
			net_nfc_response_llcp_detached_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_llcp_detached_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_LLCP_LISTEN :
		{
			net_nfc_response_listen_socket_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_listen_socket_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;

		}
		break;
	case NET_NFC_MESSAGE_LLCP_CONNECT :
		{
			net_nfc_response_connect_socket_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_connect_socket_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;

		}
		break;
	case NET_NFC_MESSAGE_LLCP_CONNECT_SAP :
		{
			net_nfc_response_connect_sap_socket_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_connect_sap_socket_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;

		}
		break;
	case NET_NFC_MESSAGE_LLCP_SEND :
		{
			net_nfc_response_send_socket_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_send_socket_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_LLCP_RECEIVE :
		{
			net_nfc_response_receive_socket_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_receive_socket_t));
			if (res == 1)
			{

				if (resp_detail->data.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->data.buffer), resp_detail->data.length);
				}
				if (res == 2)
				{
					resp_msg->detail_message = resp_detail;
				}
				else
				{
					_net_nfc_util_free_mem(resp_detail);
					res--;
				}
			}
			else
			{
				resp_msg->detail_message = resp_detail;
				resp_detail->data.buffer = NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_P2P_RECEIVE :
		{
			net_nfc_response_p2p_receive_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_p2p_receive_t));
			if (res == 1)
			{

				if (resp_detail->data.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->data.buffer), resp_detail->data.length);
				}
				if (res == 2)
				{
					resp_msg->detail_message = resp_detail;
				}
				else
				{
					_net_nfc_util_free_mem(resp_detail);
					res--;
				}
			}
			else
			{
				resp_msg->detail_message = resp_detail;
				resp_detail->data.buffer = NULL;
			}
		}
		break;

	case NET_NFC_MESSAGE_SERVICE_LLCP_CLOSE :
		{
			net_nfc_response_close_socket_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_close_socket_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;
	case NET_NFC_MESSAGE_LLCP_DISCONNECT :
		{
			net_nfc_response_disconnect_socket_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_disconnect_socket_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_LLCP_CONFIG :
		{
			net_nfc_response_config_llcp_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_config_llcp_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_LLCP_ERROR :
		{
			net_nfc_response_llcp_socket_error_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_llcp_socket_error_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_LLCP_ACCEPTED :
		{
			net_nfc_response_incomming_llcp_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_incomming_llcp_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_P2P_DISCOVERED :
		{
			net_nfc_response_p2p_discovered_t *resp_detail = NULL;
			int res = 0;

			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_p2p_discovered_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_P2P_SEND :
		{
			net_nfc_response_p2p_send_t *resp_detail = NULL;
			int res = 0;

			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_p2p_send_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_CONNECTION_HANDOVER :
		{
			net_nfc_response_connection_handover_t *resp_detail = NULL;
			int res = 0;

			DEBUG_CLIENT_MSG("NET_NFC_MESSAGE_CONNECTION_HANDOVER");
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_connection_handover_t));

			if (res == 1)
			{
				if (resp_detail->data.length > 0)
				{
					res += __net_nfc_client_read_util((void **)&(resp_detail->data.buffer), resp_detail->data.length);
					if (res < 2)
					{
						DEBUG_ERR_MSG("__net_nfc_client_read_util failed. res [%d]", res);
						_net_nfc_util_free_mem(resp_detail);
						_net_nfc_util_free_mem(resp_msg);
						return NULL;
					}
				}
			}
			else
			{
				DEBUG_ERR_MSG("__net_nfc_client_read_util failed. res [%d]", res);
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}

			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_IS_TAG_CONNECTED :
		{
			net_nfc_response_is_tag_connected_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_is_tag_connected_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;
		}
		break;

	case NET_NFC_MESSAGE_GET_CURRENT_TARGET_HANDLE :
		{
			net_nfc_response_get_current_target_handle_t *resp_detail = NULL;
			int res = 0;
			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_get_current_target_handle_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;

		}
		break;

	case NET_NFC_MESSAGE_SERVICE_INIT :
		{
			net_nfc_response_test_t *resp_detail = NULL;
			int res = 0;

			DEBUG_CLIENT_MSG("Client Receive the NET_NFC_MESSAGE_SERVICE_INIT");

			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_test_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;

		}
		break;

	case NET_NFC_MESSAGE_SERVICE_DEINIT :
		{
			net_nfc_response_test_t *resp_detail = NULL;
			int res = 0;

			DEBUG_CLIENT_MSG("Client Receive the NET_NFC_MESSAGE_SERVICE_DEINIT");

			res = __net_nfc_client_read_util((void **)&resp_detail, sizeof(net_nfc_response_test_t));
			if (res != 1)
			{
				_net_nfc_util_free_mem(resp_msg);
				return NULL;
			}
			resp_msg->detail_message = resp_detail;

		}
		break;

	default :
		{
			DEBUG_CLIENT_MSG("Currently NOT supported RESP TYPE = [%d]", resp_msg->response_type);
			_net_nfc_util_free_mem(resp_msg);
			return NULL;
		}

	}

	return resp_msg;
}

bool __net_nfc_client_send_msg(void *message, int length)
{
	bool result = (send(g_client_sock_fd, (void *)message, length, MSG_NOSIGNAL) > 0);

	if (result == false)
	{
		uint8_t buf[1024] = { 0x00, };
		DEBUG_ERR_MSG("send failed : %s", strerror_r(errno, (char *)buf, sizeof(buf)));
	}

	return result;
}

static char *cookies = NULL;
static int cookies_size = 0;

void _net_nfc_client_set_cookies(const char *cookie, size_t size)
{
	if (cookie != NULL && size > 0)
	{
		_net_nfc_util_alloc_mem(cookies, size);

		memcpy(cookies, cookie, size);
		cookies_size = size;
	}
}

void _net_nfc_client_free_cookies(void)
{
	_net_nfc_util_free_mem(cookies);
	cookies_size = 0;
}

static net_nfc_error_e _send_request(net_nfc_request_msg_t *msg, va_list list)
{
	uint8_t *send_buffer = NULL;
	int total_size = 0;
	int written_size = 0;

	/* calc message length */
#ifdef SECURITY_SERVER
	total_size += (sizeof(cookies_size) + cookies_size);
#endif
	total_size += msg->length;
	total_size += net_nfc_util_get_va_list_length(list);

	_net_nfc_util_alloc_mem(send_buffer, total_size + sizeof(total_size));
	if (send_buffer == NULL)
	{
		return NET_NFC_ALLOC_FAIL;
	}

	/* fill message */
	/*  - total length */
	memcpy(send_buffer + written_size, &total_size, sizeof(total_size));
	written_size += sizeof(total_size);

#ifdef SECURITY_SERVER
	/*  -- security server cookie */
	memcpy(send_buffer + written_size, &cookies_size, sizeof(cookies_size));
	written_size += sizeof(cookies_size);

	memcpy(send_buffer + written_size, cookies, cookies_size);
	written_size += cookies_size;
#endif

	/*  -- request message struct */
	memcpy(send_buffer + written_size, msg, msg->length);
	written_size += msg->length;

	/*  -- varient arguemts */
	written_size += net_nfc_util_fill_va_list(send_buffer + written_size, total_size + sizeof(total_size) - written_size, list);

	bool msg_result = __net_nfc_client_send_msg((void *)send_buffer, total_size + sizeof(total_size));

	_net_nfc_util_free_mem(send_buffer);
	sleep(0);

	if (msg_result)
	{
		DEBUG_MSG("[%d] >>>>>>>>>>>>>>> (msg [%d], length [%d])", g_client_pid, msg->request_type, total_size);
		return NET_NFC_OK;
	}
	else
	{
		return NET_NFC_IPC_FAIL;
	}
}

net_nfc_error_e net_nfc_client_send_request(net_nfc_request_msg_t *msg, ...)
{
	va_list list;
	net_nfc_error_e result = NET_NFC_OK;

	va_start(list, msg);

	net_nfc_client_ipc_lock();

	result = _send_request(msg, list);

	net_nfc_client_ipc_unlock();

	va_end(list);

	return result;
}

net_nfc_error_e net_nfc_client_send_request_sync(net_nfc_request_msg_t *msg, ...)
{
	va_list list;
	net_nfc_error_e result = NET_NFC_OK;

	net_nfc_client_prepare_sync_call(msg);

	va_start(list, msg);

	result = _send_request(msg, list);

	va_end(list);

	if (result == NET_NFC_OK)
	{
		result = net_nfc_client_wait_sync_call(3);
	}
	net_nfc_client_post_sync_call();

	return result;
}

net_nfc_error_e _net_nfc_client_register_cb(net_nfc_response_cb cb)
{
	if (cb == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	pthread_mutex_lock(&cb_lock);
	client_cb = cb;
	pthread_mutex_unlock(&cb_lock);

	return NET_NFC_OK;
}

net_nfc_error_e _net_nfc_client_unregister_cb(void)
{
	if (client_cb == NULL)
	{
		return NET_NFC_NOT_REGISTERED;
	}

	pthread_mutex_lock(&cb_lock);
	client_cb = NULL;
	pthread_mutex_unlock(&cb_lock);

	return NET_NFC_OK;
}
