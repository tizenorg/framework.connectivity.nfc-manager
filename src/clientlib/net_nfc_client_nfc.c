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

#include <unistd.h>
#include <pthread.h>
#include <glib.h>
#include <dbus/dbus-glib.h>

#include "vconf.h"
#ifdef SECURITY_SERVER
#include <security-server.h>
#endif

#include "net_nfc.h"
#include "net_nfc_typedef.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_client_ipc_private.h"
#include "net_nfc_exchanger_private.h"
#include "net_nfc_client_nfc_private.h"
#include "net_nfc_manager_dbus.h"
#include "nfc-service-glue.h"

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif

#define BUFFER_LENGTH_MAX 1024

static client_context_t g_client_context = { NULL, NET_NFC_OK, PTHREAD_MUTEX_INITIALIZER, NET_NFC_ALL_ENABLE, NULL, false };

static void _net_nfc_reset_client_context()
{
	g_client_context.register_user_param = NULL;
	g_client_context.result = NET_NFC_OK;
	g_client_context.filter = NET_NFC_ALL_ENABLE;
	g_client_context.initialized = false;
}

static net_nfc_error_e _net_nfc_launch_daemon()
{
	net_nfc_error_e result = NET_NFC_OPERATION_FAIL;
	DBusGConnection *connection = NULL;
	GError *error = NULL;

	dbus_g_thread_init();

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error == NULL)
	{
		DBusGProxy *proxy = NULL;

		proxy = dbus_g_proxy_new_for_name(connection, "org.tizen.nfc_service", "/org/tizen/nfc_service", "org.tizen.nfc_service");
		if (proxy != NULL)
		{
			guint dbus_result = 0;

			if (org_tizen_nfc_service_launch(proxy, getpid(), &dbus_result, &error) == true)
			{
				DEBUG_CLIENT_MSG("org_tizen_nfc_service_launch success");
				result = NET_NFC_OK;
			}
			else
			{
				DEBUG_ERR_MSG("org_tizen_nfc_service_launch failed");
				if (error != NULL)
				{
					DEBUG_ERR_MSG("message : [%s]", error->message);
					g_error_free(error);
				}
			}

			g_object_unref(proxy);
		}
		else
		{
			DEBUG_ERR_MSG("dbus_g_proxy_new_for_name failed");
		}
	}
	else
	{
		DEBUG_ERR_MSG("dbus_g_bus_get failed");
		if (error != NULL)
		{
			DEBUG_ERR_MSG("message : [%s]", error->message);
			g_error_free(error);
		}
	}

	return result;
}

#if 0
static net_nfc_error_e _net_nfc_terminate_daemon()
{
	net_nfc_error_e result = NET_NFC_OPERATION_FAIL;
	DBusGConnection *connection = NULL;
	GError *error = NULL;

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error == NULL)
	{
		DBusGProxy *proxy = NULL;

		proxy = dbus_g_proxy_new_for_name(connection, "org.tizen.nfc_service", "/org/tizen/nfc_service", "org.tizen.nfc_service");
		if (proxy != NULL)
		{
			guint dbus_result = 0;

			if (org_tizen_nfc_service_terminate(proxy, &dbus_result, &error) == true)
			{
				DEBUG_CLIENT_MSG("org_tizen_nfc_service_terminate success");
				result = NET_NFC_OK;
			}
			else
			{
				DEBUG_ERR_MSG("org_tizen_nfc_service_terminate failed");
				if (error != NULL)
				{
					DEBUG_ERR_MSG("message : [%s]", error->message);
					g_error_free(error);
				}
			}

			g_object_unref (proxy);
		}
		else
		{
			DEBUG_ERR_MSG("dbus_g_proxy_new_for_name failed");
		}
	}
	else
	{
		DEBUG_ERR_MSG("dbus_g_bus_get failed, message : [%s]", error->message);
		g_error_free(error);
	}

	return result;
}
#endif

#ifdef SECURITY_SERVER
static net_nfc_error_e _net_nfc_load_cookies()
{
	net_nfc_error_e result = NET_NFC_OK;
	int cookies_size;
	char cookies[512] = { 0, };

	if ((cookies_size = security_server_get_cookie_size()) > 0)
	{
		int error = 0;

		if ((error = security_server_request_cookie(cookies, cookies_size)) == SECURITY_SERVER_API_SUCCESS)
		{
#if 0
			DEBUG_SERVER_MSG("load cookies");
			DEBUG_MSG_PRINT_BUFFER(cookies, cookies_size);
#endif

			_net_nfc_client_set_cookies(cookies, cookies_size);

			result = NET_NFC_OK;
		}
		else
		{
			DEBUG_ERR_MSG("security server request cookies error = [%d]", error);

			result = NET_NFC_SECURITY_FAIL;
		}
	}
	else
	{
		DEBUG_ERR_MSG("wrong cookie length");

		result = NET_NFC_SECURITY_FAIL;
	}

	return result;
}
#endif

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_initialize()
{
	net_nfc_error_e result = NET_NFC_OK;

	if (!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	g_type_init();

	pthread_mutex_lock(&g_client_context.g_client_lock);

	if (g_client_context.initialized == true)
	{
		pthread_mutex_unlock(&g_client_context.g_client_lock);
		return result;
	}

	result = _net_nfc_launch_daemon();
	if (result != NET_NFC_OK)
	{
		pthread_mutex_unlock(&g_client_context.g_client_lock);
		return result;
	}

	_net_nfc_reset_client_context();

#ifdef SECURITY_SERVER
	result = _net_nfc_load_cookies();
	if (result != NET_NFC_OK)
	{
		pthread_mutex_unlock(&g_client_context.g_client_lock);
		return result;
	}
#endif

	result = net_nfc_client_socket_initialize();
	if (result == NET_NFC_OK || result == NET_NFC_ALREADY_INITIALIZED)
	{
		DEBUG_CLIENT_MSG("socket is initialized");
		g_client_context.initialized = true;
	}
	else
	{
		DEBUG_ERR_MSG("socket init is failed = [%d]", result);
		_net_nfc_client_free_cookies();
	}

	pthread_mutex_unlock(&g_client_context.g_client_lock);

	return result;
}

/* this is sync call */
NET_NFC_EXPORT_API net_nfc_error_e net_nfc_deinitialize()
{
	net_nfc_error_e result = NET_NFC_OK;

	pthread_mutex_lock(&g_client_context.g_client_lock);

	net_nfc_client_socket_finalize();
	_net_nfc_client_free_cookies();
	_net_nfc_reset_client_context();

#if 0
	result = _net_nfc_terminate_daemon();
#endif

	pthread_mutex_unlock(&g_client_context.g_client_lock);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_response_callback(net_nfc_response_cb cb, void *user_param)
{
	net_nfc_error_e result = NET_NFC_OK;

	if (cb == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	pthread_mutex_lock(&g_client_context.g_client_lock);

	g_client_context.register_user_param = user_param;
	result = _net_nfc_client_register_cb(cb);

	pthread_mutex_unlock(&g_client_context.g_client_lock);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_unset_response_callback(void)
{
	net_nfc_error_e result = NET_NFC_OK;

	pthread_mutex_lock(&g_client_context.g_client_lock);

	g_client_context.register_user_param = NULL;
	result = _net_nfc_client_unregister_cb();

	pthread_mutex_unlock(&g_client_context.g_client_lock);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_launch_popup_state(int enable)
{
	net_nfc_error_e ret;
	net_nfc_request_set_launch_state_t request = { 0, };

	request.length = sizeof(net_nfc_request_set_launch_state_t);
	request.request_type = NET_NFC_MESSAGE_SERVICE_SET_LAUNCH_STATE;

	pthread_mutex_lock(&g_client_context.g_client_lock);
	g_client_context.set_launch_popup = enable;

	if(enable)
		request.set_launch_popup = NET_NFC_LAUNCH_APP_SELECT;
	else
		request.set_launch_popup = NET_NFC_NO_LAUNCH_APP_SELECT;

	pthread_mutex_unlock(&g_client_context.g_client_lock);

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_launch_popup_state(int *state)
{
	net_nfc_error_e result = NET_NFC_OK;

	if (state == NULL)
		return NET_NFC_NULL_PARAMETER;

	pthread_mutex_lock(&g_client_context.g_client_lock);
	*state = g_client_context.set_launch_popup;
	pthread_mutex_unlock(&g_client_context.g_client_lock);

	return result;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_set_state(int state, net_nfc_set_activation_completed_cb callback)
{
	net_nfc_error_e ret = NET_NFC_UNKNOWN_ERROR;

	DEBUG_CLIENT_MSG("net_nfc_set_state[Enter]");

#if 0
	if (!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	g_type_init();
#endif

	if (state == FALSE)/*Deinit*/
	{
		ret = net_nfc_send_deinit(NULL);

		DEBUG_CLIENT_MSG("Send the deinit msg!!, result [%d]", ret);
	}
	else/*INIT*/
	{
		ret = net_nfc_send_init(NULL);

		DEBUG_CLIENT_MSG("Send the init msg!!, result [%d]", ret);
	}

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_is_supported(int *state)
{
	net_nfc_error_e ret;

	if (state != NULL)
	{
		if (vconf_get_bool(VCONFKEY_NFC_FEATURE, state) == 0)
		{
			ret = NET_NFC_OK;
		}
		else
		{
			ret = NET_NFC_INVALID_STATE;
		}
	}
	else
	{
		ret = NET_NFC_NULL_PARAMETER;
	}

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_get_state(int *state)
{
	net_nfc_error_e ret;

	if (state != NULL)
	{
		if (vconf_get_bool(VCONFKEY_NFC_STATE, state) == 0)
		{
			ret = NET_NFC_OK;
		}
		else
		{
			ret = NET_NFC_INVALID_STATE;
		}
	}
	else
	{
		ret = NET_NFC_NULL_PARAMETER;
	}

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_state_activate(void)
{
	net_nfc_error_e ret;
	net_nfc_request_change_client_state_t request = { 0, };

	request.length = sizeof(net_nfc_request_change_client_state_t);
	request.request_type = NET_NFC_MESSAGE_SERVICE_CHANGE_CLIENT_STATE;
	request.client_state = NET_NFC_CLIENT_ACTIVE_STATE;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_state_deactivate(void)
{
	net_nfc_error_e ret;
	net_nfc_request_change_client_state_t request = { 0, };

	request.length = sizeof(net_nfc_request_change_client_state_t);
	request.request_type = NET_NFC_MESSAGE_SERVICE_CHANGE_CLIENT_STATE;
	request.client_state = NET_NFC_CLIENT_INACTIVE_STATE;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&request, NULL);

	return ret;
}

client_context_t *net_nfc_get_client_context()
{
	return &g_client_context;
}

bool net_nfc_tag_is_connected()
{
	bool result = false;

	pthread_mutex_lock(&g_client_context.g_client_lock);

	result = (g_client_context.target_info != NULL && g_client_context.target_info->handle != NULL);

	pthread_mutex_unlock(&g_client_context.g_client_lock);

	return result;
}

net_nfc_error_e net_nfc_send_init(void *context)
{
	net_nfc_error_e ret;
	net_nfc_request_msg_t req_msg = { 0, };

	req_msg.length = sizeof(net_nfc_request_msg_t);
	req_msg.request_type = NET_NFC_MESSAGE_SERVICE_INIT;
	req_msg.user_param = (uint32_t)context;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&req_msg, NULL);

	return ret;
}

net_nfc_error_e net_nfc_send_deinit(void *context)
{
	net_nfc_error_e ret;
	net_nfc_request_msg_t req_msg = { 0, };

	req_msg.length = sizeof(net_nfc_request_msg_t);
	req_msg.request_type = NET_NFC_MESSAGE_SERVICE_DEINIT;
	req_msg.user_param = (uint32_t)context;

	ret = net_nfc_client_send_request((net_nfc_request_msg_t *)&req_msg, NULL);

	return ret;
}

