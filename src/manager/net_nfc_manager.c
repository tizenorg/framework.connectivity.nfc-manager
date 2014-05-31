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
#include <unistd.h>
#include <glib.h>
#include <pthread.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-bindings.h>
#include <sys/utsname.h>

#include "heynoti.h"
#include "vconf.h"

#include "net_nfc_server_ipc_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_service_private.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_service_vconf_private.h"
#include "net_nfc_app_util_private.h"
#include "net_nfc_controller_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_server_dispatcher_private.h"
#include "net_nfc_server_context_private.h"
#include "net_nfc_manager_dbus.h"
#include "nfc-service-binding.h"

static GMainLoop *loop = NULL;
static GObject *object = NULL;
static DBusGConnection *connection = NULL;
static pid_t launch_by_client = 0;

static void __net_nfc_discovery_polling_cb(keynode_t *node, void *user_data);

G_DEFINE_TYPE(Nfc_Service, nfc_service, G_TYPE_OBJECT)

/* Just Check the assert  and set the error message */
#define __G_ASSERT(test, return_val, error, domain, error_code)\
	G_STMT_START\
	{\
		if G_LIKELY (!(test)) { \
			g_set_error (error, domain, error_code, #test); \
			return (return_val); \
		}\
	}\
	G_STMT_END

GQuark nfc_service_error_quark(void)
{
	DEBUG_MSG("nfc_service_error_quark entered");

	return g_quark_from_static_string("nfc_service_error");
}

static void nfc_service_init(Nfc_Service *nfc_service)
{
	DEBUG_MSG("nfc_service_init entered");
}

static void nfc_service_class_init(Nfc_ServiceClass *nfc_service_class)
{
	DEBUG_MSG("nfc_service_class_init entered");

	dbus_g_object_type_install_info(NFC_SERVICE_TYPE, &dbus_glib_nfc_service_object_info);
}

gboolean nfc_service_launch(Nfc_Service *nfc_service, const pid_t pid, guint *result_val, GError **error)
{
	DEBUG_MSG("nfc_service_launch entered");

	DEBUG_SERVER_MSG("nfc_service_launch NFC MANAGER PID=[%d]", getpid());
	DEBUG_SERVER_MSG("nfc_service_launch NFC MANAGER TID=[%lx]", pthread_self());
	DEBUG_SERVER_MSG("requested client pid [%d]", pid);

	launch_by_client = getpid();

	return TRUE;
}

gboolean nfc_service_terminate(Nfc_Service *nfc_service, guint *result_val, GError **error)
{
	int result, state;

	DEBUG_MSG("nfc_service_terminate entered, remain client [%d]", net_nfc_server_get_client_count());

	result = vconf_get_bool(VCONFKEY_NFC_STATE, &state);
	if (result != 0)
	{
		DEBUG_MSG("VCONFKEY_NFC_STATE is not exist: %d ", result);
		return false;
	}

	/*TEMP CODE*/
	//if ((g_server_info.connected_client_count <=1) && (state == false))
	if (state == false)
	{
		g_main_loop_quit(loop);

		if (vconf_set_bool(VCONFKEY_NFC_STATE, FALSE) != 0)
		{
			DEBUG_ERR_MSG("vconf_set_bool failed");
		}

		DEBUG_MSG("Real nfc_service_terminate end");
	}
	else
	{
		DEBUG_MSG("Fake nfc_service_terminate end");
	}

	return TRUE;
}

static void _net_nfc_intialize_dbus_connection()
{
	GError *error = NULL;
	DBusGProxy *proxy = NULL;
	guint ret = 0;

	g_type_init();

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error == NULL)
	{
		object = (GObject *)g_object_new(NFC_SERVICE_TYPE, NULL);
		dbus_g_connection_register_g_object(connection, NFC_SERVICE_PATH, object);

		/* register service */
		proxy = dbus_g_proxy_new_for_name(connection, DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS);
		if (proxy != NULL)
		{
			if (!org_freedesktop_DBus_request_name(proxy, NFC_SERVICE_NAME, 0, &ret, &error))
			{
				DEBUG_MSG("Unable to register service: %s", error->message);
				g_error_free(error);
			}

			g_object_unref(proxy);
		}
		else
		{
			DEBUG_MSG("dbus_g_proxy_new_for_name failed");
		}
	}
	else
	{
		DEBUG_MSG("ERROR: Can't get on system bus [%s]", error->message);
		g_error_free(error);
	}
}

static void _net_nfc_deintialize_dbus_connection()
{
	if (connection != NULL && object != NULL)
	{
		dbus_g_connection_unregister_g_object(connection, object);
		g_object_unref(object);
	}
}

int main(int check, char* argv[])
{
	int result = 0;
	void *handle = NULL;
	int state = 0;

	if (!g_thread_supported())
	{
		g_thread_init(NULL);
	}

	g_type_init();

	net_nfc_manager_init_log();

	DEBUG_SERVER_MSG("start nfc manager");
	DEBUG_SERVER_MSG("argv0 = %s", argv[0]);
	DEBUG_SERVER_MSG("argv1 = %s", argv[1]);

	net_nfc_app_util_clean_storage(MESSAGE_STORAGE);

	handle = net_nfc_controller_onload();
	if (handle == NULL)
	{
		DEBUG_ERR_MSG("load plugin library is failed");
		return 0;
	}

	if (net_nfc_controller_support_nfc(&result) == true)
	{
		DEBUG_SERVER_MSG("NFC Support");
		if (vconf_set_bool(VCONFKEY_NFC_FEATURE, VCONFKEY_NFC_FEATURE_ON) != 0)
		{
			DEBUG_SERVER_MSG("VCONFKEY_NFC_FEATURE ON failed");
		}
	}
	else
	{
		DEBUG_ERR_MSG("NFC doesn't support");

		if (vconf_set_bool(VCONFKEY_NFC_FEATURE, VCONFKEY_NFC_FEATURE_OFF) != 0)
		{
			DEBUG_SERVER_MSG("VCONFKEY_NFC_FEATURE OFF failed");
		}

		if (vconf_set_bool(VCONFKEY_NFC_STATE, FALSE) != 0)
		{
			DEBUG_SERVER_MSG("VCONFKEY_NFC_STATE failed");
		}

		net_nfc_controller_unload(handle);
	}

	result = vconf_get_bool(VCONFKEY_NFC_STATE, &state);
	if (result != 0)
	{
		DEBUG_MSG("VCONFKEY_NFC_STATE is not exist: %d ", result);

		goto EXIT;
	}

	DEBUG_MSG("vconf state value [%d]", state);

	if (argv[1] != NULL)
	{
		if (state == FALSE && !(strncmp(argv[1], "script", 6)))
		{
			DEBUG_ERR_MSG("Init Script execute nfc manager. But State is false.");

			goto EXIT;
		}
	}

	if (net_nfc_server_ipc_initialize() != true)
	{
		DEBUG_ERR_MSG("nfc server ipc initialization is failed");

		goto EXIT;
	}

	DEBUG_SERVER_MSG("nfc server ipc init is ok");

	_net_nfc_intialize_dbus_connection();

#if 0
	int fd = 0;

	fd = heynoti_init();
	DEBUG_MSG("Noti init: %d", fd);
	if (fd == -1)
		return 0;

	/*Power Manager send the system_wakeup noti to subscriber*/
	result = heynoti_subscribe(fd, "system_wakeup", __net_nfc_discovery_polling_cb, (void *)fd);
	DEBUG_MSG("noti add: %d", result);

	if (result == -1)
		return 0;

	result = heynoti_attach_handler(fd);
	DEBUG_MSG("attach handler : %d", result);

	if (result == -1)
		return 0;
#endif
	vconf_notify_key_changed("memory/pm/state", __net_nfc_discovery_polling_cb, NULL);

	net_nfc_service_vconf_register_notify_listener();

	loop = g_main_new(TRUE);
	g_main_loop_run(loop);

EXIT :
	_net_nfc_deintialize_dbus_connection();
	net_nfc_service_vconf_unregister_notify_listener();
	net_nfc_server_ipc_finalize();
	net_nfc_controller_unload(handle);

	net_nfc_manager_fini_log();

	return 0;
}

static void __net_nfc_discovery_polling_cb(keynode_t *node, void *user_data)
{
	int state;
	int pm_state = 0;
	net_nfc_error_e result;

	result = vconf_get_bool(VCONFKEY_NFC_STATE, &state);
	if (result != 0)
	{
		DEBUG_MSG("VCONFKEY_NFC_STATE is not exist: %d ", result);
	}

	result = vconf_get_int("memory/pm/state", &pm_state);
	DEBUG_MSG("PM STATE : %d ", pm_state);

	DEBUG_MSG("__net_nfc_discovery_polling_cb[Enter]");
#if 0
	if(state == TRUE)
	{
		net_nfc_request_msg_t *req_msg = NULL;

		_net_nfc_util_alloc_mem(req_msg, sizeof(net_nfc_request_msg_t));

		if (req_msg == NULL)
		{
			DEBUG_MSG("_net_nfc_util_alloc_mem[NULL]");
			return;
		}

		req_msg->length = sizeof(net_nfc_request_msg_t);
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_RESTART_POLLING_LOOP;

		net_nfc_dispatcher_queue_push(req_msg);
	}
	else
	{
		DEBUG_SERVER_MSG("Don't need to wake up. NFC is OFF!!");
	}
#endif

	if ((pm_state == 1) || (pm_state == 3))/*Screen On*/
	{
		net_nfc_request_msg_t *req_msg = NULL;

		_net_nfc_util_alloc_mem(req_msg, sizeof(net_nfc_request_msg_t));

		if (req_msg == NULL)
		{
			DEBUG_MSG("_net_nfc_util_alloc_mem[NULL]");
			return;
		}

		req_msg->length = sizeof(net_nfc_request_msg_t);
		req_msg->user_param = pm_state;
		req_msg->request_type = NET_NFC_MESSAGE_SERVICE_RESTART_POLLING_LOOP;

		net_nfc_dispatcher_queue_push(req_msg);
	}
	else
	{
		DEBUG_MSG("Do not anything!!");
	}

	DEBUG_MSG("__net_nfc_discovery_polling_cb[Out]");
}

