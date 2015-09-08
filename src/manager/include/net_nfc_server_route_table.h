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

#ifndef __NET_NFC_SERVER_ROUTE_TABLE_H__
#define __NET_NFC_SERVER_ROUTE_TABLE_H__

#include <gio/gio.h>

#include "net_nfc_typedef_internal.h"

typedef struct _aid_info_t
{
	net_nfc_se_type_e se_type;
	net_nfc_card_emulation_category_t category;
	bool manifest;
	char *aid;
}
aid_info_t;

typedef struct _route_table_handler_t
{
	char *package;
	char *id;
	bool activated;
	GPtrArray *aids;
}
route_table_handler_t;

typedef bool (*net_nfc_server_route_table_handler_iter_cb)(
	const char *package, route_table_handler_t *handler, void *user_data);

typedef bool (*net_nfc_server_route_table_aid_iter_cb)(
	const char *package, route_table_handler_t *handler,
	aid_info_t *aid, void *user_data);

void net_nfc_server_route_table_init();
void net_nfc_server_route_table_load_db();
void net_nfc_server_route_table_deinit();

void net_nfc_server_route_table_iterate_handler(
	net_nfc_server_route_table_handler_iter_cb cb, void *user_data);

route_table_handler_t *net_nfc_server_route_table_find_handler(
	const char *package);

net_nfc_error_e net_nfc_server_route_table_add_handler(const char *id,
	const char *package);

net_nfc_error_e net_nfc_server_route_table_del_handler(const char *id,
	const char *package);

net_nfc_error_e net_nfc_server_set_handler_activation(const char *package);


route_table_handler_t *net_nfc_server_route_table_find_handler_by_id(
	const char *id);

net_nfc_error_e net_nfc_server_route_table_add_handler_by_id(const char *id);

net_nfc_error_e net_nfc_server_route_table_del_handler_by_id(const char *id);

net_nfc_error_e net_nfc_server_route_table_set_handler_by_id(const char *id);

net_nfc_error_e net_nfc_server_set_handler_activation_by_id(const char *id);



route_table_handler_t *net_nfc_server_route_table_find_handler_by_aid(
	const char *aid);

aid_info_t *net_nfc_server_route_table_find_aid(const char *package,
	const char *aid);

net_nfc_error_e net_nfc_server_route_table_add_aid(const char *id,
	const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	bool manifest, const char *aid);

void net_nfc_server_route_table_del_aid(const char *id, const char *package,
	const char *aid, bool force);

void net_nfc_server_route_table_del_aids(const char *id, const char *package,
	bool force);

void net_nfc_server_route_table_iterate_aid(const char *package,
	net_nfc_server_route_table_aid_iter_cb cb, void *user_data);

aid_info_t *net_nfc_server_route_table_find_aid_by_id(const char *package,
	const char *aid);

net_nfc_error_e net_nfc_server_route_table_add_aid_by_id(const char *id,
	net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	bool manifest, const char *aid);

void net_nfc_server_route_table_del_aid_by_id(const char *id, const char *aid,
	bool force);

void net_nfc_server_route_table_iterate_aid_by_id(const char *id,
	net_nfc_server_route_table_aid_iter_cb cb, void *user_data);


net_nfc_error_e net_nfc_server_route_table_insert_aid_into_db(
	const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	const char *aid, bool unlock, int power);

net_nfc_error_e net_nfc_server_route_table_delete_aid_from_db(
	const char *package, const char *aid);

net_nfc_error_e net_nfc_server_route_table_delete_aids_from_db(
	const char *package);

#endif //__NET_NFC_SERVER_ROUTE_TABLE_H__
