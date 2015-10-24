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
#ifndef __NET_NFC_SERVER_CONTEXT_INTERNAL_H__
#define __NET_NFC_SERVER_CONTEXT_INTERNAL_H__

#include <unistd.h>
#include <glib.h>
#include <gio/gio.h>

#include "net_nfc_typedef_internal.h"

typedef struct _net_nfc_client_context_info_t
{
	/* Permanent property */
	char *id;
	pid_t pid;
	pid_t pgid;

	/* changed by client state */
	int ref_se;
	client_state_e state;
	net_nfc_launch_popup_state_e launch_popup_state;
	net_nfc_launch_popup_state_e launch_popup_state_no_check;
	bool isTransactionFgDispatch;
} net_nfc_client_context_info_t;

typedef void (*net_nfc_server_gdbus_on_client_detached_cb)(
	net_nfc_client_context_info_t *client);

typedef void (*net_nfc_server_gdbus_for_each_client_cb)(
	net_nfc_client_context_info_t *client, void *user_param);

void net_nfc_server_gdbus_init_client_context();

void net_nfc_server_gdbus_deinit_client_context();

void net_nfc_server_gdbus_register_on_client_detached_cb(
	net_nfc_server_gdbus_on_client_detached_cb cb);

void net_nfc_server_gdbus_unregister_on_client_detached_cb(
	net_nfc_server_gdbus_on_client_detached_cb cb);

bool net_nfc_server_gdbus_check_privilege(GDBusMethodInvocation *invocation,
	GVariant *privilege,
	const char *object,
	const char *right);

void net_nfc_server_gdbus_add_client_context(const char *id,
	client_state_e state);

void net_nfc_server_gdbus_cleanup_client_context(const char *id);

net_nfc_client_context_info_t *net_nfc_server_gdbus_get_client_context(
	const char *id);

size_t net_nfc_server_gdbus_get_client_count();

void net_nfc_server_gdbus_for_each_client_context(
	net_nfc_server_gdbus_for_each_client_cb cb,
	void *user_param);

bool net_nfc_server_gdbus_check_client_is_running(const char *id);

client_state_e net_nfc_server_gdbus_get_client_state(
	const char *id);

void net_nfc_server_gdbus_set_client_state(const char *id,
	client_state_e state);

void net_nfc_server_gdbus_set_launch_state(const char *id,
	net_nfc_launch_popup_state_e popup_state,
	net_nfc_launch_popup_check_e check_foreground);

net_nfc_launch_popup_state_e net_nfc_server_gdbus_get_launch_state(
	const char *id);

net_nfc_launch_popup_state_e net_nfc_server_gdbus_get_client_popup_state(
	pid_t pid);
bool net_nfc_server_gdbus_get_client_transaction_fg_dispatch_state(pid_t pid);
bool net_nfc_app_util_check_transaction_fg_dispatch();

void net_nfc_server_gdbus_increase_se_count(const char *id);
void net_nfc_server_gdbus_decrease_se_count(const char *id);

bool net_nfc_server_gdbus_is_server_busy();

net_nfc_error_e net_nfc_server_gdbus_set_transaction_fg_dispatch(
	const char *id,
	int fgDispatch);

#endif //__NET_NFC_SERVER_CONTEXT_INTERNAL_H__
