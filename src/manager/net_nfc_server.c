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

#include <gio/gio.h>

#include "net_nfc_debug_internal.h"
#include "net_nfc_gdbus.h"
#include "net_nfc_server_common.h"
#include "net_nfc_server.h"
#include "net_nfc_server_manager.h"
#include "net_nfc_server_tag.h"
#include "net_nfc_server_ndef.h"
#include "net_nfc_server_llcp.h"
#include "net_nfc_server_p2p.h"
#include "net_nfc_server_transceive.h"
#include "net_nfc_server_test.h"
#include "net_nfc_server_handover.h"
#include "net_nfc_server_se.h"
#include "net_nfc_server_snep.h"
#include "net_nfc_server_system_handler.h"
#include "net_nfc_server_context_internal.h"
#include "net_nfc_server_hce.h"


static GDBusConnection *connection = NULL;
static guint subscribe_id;

pid_t net_nfc_server_gdbus_get_pid(const char *name)
{
	guint pid = 0;
	GError *error = NULL;
	GVariant *_ret;

	_ret = g_dbus_connection_call_sync(connection,
		"org.freedesktop.DBus",
		"/org/freedesktop/DBus",
		"org.freedesktop.DBus",
		"GetConnectionUnixProcessID",
		g_variant_new("(s)", name),
		NULL,
		G_DBUS_CALL_FLAGS_NONE,
		-1,
		NULL,
		&error);
	if (_ret != NULL) {
		g_variant_get(_ret, "(u)", &pid);
		g_variant_unref(_ret);
	}

	return pid;
}

static void _name_owner_changed(GDBusProxy *proxy,
	const gchar *name, const gchar *old_owner,
	const gchar *new_owner, void *user_data)
{
	if (name == NULL || old_owner == NULL || new_owner == NULL) {
		DEBUG_ERR_MSG("invalid parameter");

		return;
	}

	if (strlen(new_owner) == 0) {
		if (net_nfc_server_gdbus_check_client_is_running(old_owner)) {
			/* remove client context */
			net_nfc_server_gdbus_cleanup_client_context(old_owner);
		}
	}
}

static void _on_name_owner_changed(GDBusConnection *connection,
	const gchar *sender_name, const gchar *object_path,
	const gchar *interface_name, const gchar *signal_name,
	GVariant *parameters, gpointer user_data)
{
	gchar *name;
	gchar *old_owner;
	gchar *new_owner;

	g_variant_get(parameters,
		"(sss)",
		&name,
		&old_owner,
		&new_owner);

	_name_owner_changed((GDBusProxy *)connection,
		name, old_owner, new_owner, user_data);
}

static void _subscribe_name_owner_changed_event()
{
	if (connection == NULL)
		return;

	/* subscribe signal */
	subscribe_id = g_dbus_connection_signal_subscribe(connection,
		"org.freedesktop.DBus", /* bus name */
		"org.freedesktop.DBus", /* interface */
		"NameOwnerChanged", /* member */
		"/org/freedesktop/DBus", /* path */
		NULL, /* arg0 */
		G_DBUS_SIGNAL_FLAGS_NONE,
		_on_name_owner_changed,
		NULL, NULL);
}

static void _unsubscribe_name_owner_changed_event()
{
	if (connection == NULL)
		return;

	/* subscribe signal */
	if (subscribe_id > 0) {
		g_dbus_connection_signal_unsubscribe(connection, subscribe_id);
	}
}

void net_nfc_server_gdbus_init(void)
{
	GError *error = NULL;

	if (connection)
		g_object_unref(connection);

	connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (connection == NULL)
	{
		DEBUG_ERR_MSG("Can not get connection %s", error->message);
		g_error_free (error);
		return;
	}

	net_nfc_server_gdbus_init_client_context();

	if (net_nfc_server_controller_thread_init() == FALSE)
	{
		DEBUG_ERR_MSG("Can not init controller thread");
		return;
	}

	_subscribe_name_owner_changed_event();

	if (net_nfc_server_manager_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init manager");
		return;
	}

	if (net_nfc_server_tag_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init tag");
		return;
	}

	if (net_nfc_server_ndef_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init ndef");
		return;
	}

	if (net_nfc_server_llcp_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init llcp");
		return;
	}

	if (net_nfc_server_p2p_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init tag");
		return;
	}

	if (net_nfc_server_transceive_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not initialize transceive");
		return;
	}

	if (net_nfc_server_test_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init Test");
		return;
	}

	if (net_nfc_server_handover_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not initialize transceive");
		return;
	}

	if (net_nfc_server_se_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init Test");
		return;
	}

	if (net_nfc_server_snep_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init controller thread");
		return;
	}

	if (net_nfc_server_system_handler_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init controller thread");
		return;
	}

	if (net_nfc_server_hce_init(connection) == FALSE)
	{
		DEBUG_ERR_MSG("Can not init Test");
		return;
	}
}

void net_nfc_server_gdbus_deinit(void)
{
	_unsubscribe_name_owner_changed_event();

	net_nfc_server_manager_deinit();
	net_nfc_server_tag_deinit();
	net_nfc_server_ndef_deinit();
	net_nfc_server_llcp_deinit();
	net_nfc_server_transceive_deinit();
	net_nfc_server_test_deinit();
	net_nfc_server_handover_deinit();
	net_nfc_server_se_deinit();
	net_nfc_server_snep_deinit();
	net_nfc_server_system_handler_deinit();

	net_nfc_server_controller_thread_deinit();

	net_nfc_server_gdbus_deinit_client_context();

	if (connection)
	{
		g_object_unref(connection);
		connection = NULL;
	}
}
