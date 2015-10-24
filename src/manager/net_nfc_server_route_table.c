/*
 * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sqlite3.h>

#include "vconf.h"

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_server.h"
#include "net_nfc_server_se.h"
#include "net_nfc_server_vconf.h"
#include "net_nfc_server_route_table.h"

#define PRINT_TABLE

/* route table database */
#define NFC_ROUTE_TABLE_DB_FILE "/opt/usr/data/nfc-manager-daemon/.route_table.db"
#define NFC_ROUTE_TABLE_DB_TABLE "route_table"

typedef void (*_iterate_db_cb)(const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, const char *aid,
	bool unlock, int power, bool manifest, void *user_data);

static sqlite3 *db;
static sqlite3_stmt *current_stmt;

static net_nfc_error_e __route_table_add_aid(const char *id,
	const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	const char *aid, bool unlock, int power, bool manifest);

static net_nfc_error_e __route_table_del_aid(const char *id,
	const char *package, const char *aid, bool force);

static bool __is_table_existing(const char *table)
{
	bool result;
	char *sql;
	int ret;

	sql = sqlite3_mprintf("SELECT count(*) FROM sqlite_master WHERE type='table' AND name ='%s';", table);
	if (sql != NULL) {
		sqlite3_stmt *stmt = NULL;

		ret = sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
		if (ret == SQLITE_OK) {
			ret = sqlite3_step(stmt);
			if (ret == SQLITE_ROW) {
				int count;

				count = sqlite3_column_int(stmt, 0);
				if (count > 0) {
					result = true;
				} else {
					result = false;
				}
			} else {
				DEBUG_ERR_MSG("sqlite3_step failed, [%d:%s]", ret, sqlite3_errmsg(db));

				result = false;
			}

			sqlite3_finalize(stmt);
		} else {
			DEBUG_ERR_MSG("sqlite3_prepare_v2 failed, [%d:%s]", ret, sqlite3_errmsg(db));

			result = false;
		}

		sqlite3_free(sql);
	} else {
		DEBUG_ERR_MSG("sqlite3_mprintf failed");

		result = false;
	}

	return result;
}

static void __create_table()
{
	int ret;
	char *sql;

	sql = sqlite3_mprintf("CREATE TABLE %s(idx INTEGER PRIMARY KEY, package TEXT NOT NULL, se_type INTEGER, category INTEGER, aid TEXT NOT NULL COLLATE NOCASE, unlock INTEGER, power INTEGER, manifest INTEGER);", NFC_ROUTE_TABLE_DB_TABLE);
	if (sql != NULL) {
		char *error = NULL;

		ret = sqlite3_exec(db, sql, NULL, NULL, &error);
		if (ret != SQLITE_OK) {
			DEBUG_ERR_MSG("sqlite3_exec() failed, [%d:%s]", ret, error);

			sqlite3_free(error);
		}

		sqlite3_free(sql);
	} else {
		DEBUG_ERR_MSG("sqlite3_mprintf failed");
	}
}

static void __prepare_table()
{
	if (__is_table_existing(NFC_ROUTE_TABLE_DB_TABLE) == false) {
		__create_table();
	}
}

static void __initialize_db()
{
	int result;
	char *error = NULL;

	if (db == NULL) {
		result = sqlite3_open_v2(NFC_ROUTE_TABLE_DB_FILE, &db,
			SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
			NULL);
		if (result != SQLITE_OK) {
			DEBUG_ERR_MSG("sqlite3_open_v2 failed, [%d]", result);

			goto ERR;
		}

		/* Enable persist journal mode */
		result = sqlite3_exec(db, "PRAGMA journal_mode = PERSIST",
			NULL, NULL, &error);
		if (result != SQLITE_OK) {
			DEBUG_ERR_MSG("Fail to change journal mode: %s", error);
			sqlite3_free(error);

			goto ERR;
		}

		__prepare_table();
	}

	return;

ERR :
	if (db != NULL) {
		result = sqlite3_close(db);
		if (result == SQLITE_OK) {
			db = NULL;
		} else {
			DEBUG_ERR_MSG("sqlite3_close failed, [%d]", result);
		}
	}
}

static void __finalize_db()
{
	int result;

	if (db != NULL) {
		if (current_stmt != NULL) {
			result = sqlite3_finalize(current_stmt);
			if (result != SQLITE_OK) {
				DEBUG_ERR_MSG("sqlite3_finalize failed, [%d]", result);
			}
		}

		result = sqlite3_close(db);
		if (result == SQLITE_OK) {
			db = NULL;
		} else {
			DEBUG_ERR_MSG("sqlite3_close failed, [%d]", result);
		}
	}
}

static void __iterate_db(_iterate_db_cb cb, void *user_data)
{
	char *sql;

	if (cb == NULL) {
		return;
	}

	sql = sqlite3_mprintf("SELECT * FROM %s;", NFC_ROUTE_TABLE_DB_TABLE);
	if (sql != NULL) {
		sqlite3_stmt *stmt = NULL;
		int ret;

		ret = sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
		if (ret == SQLITE_OK) {
			const char *package;
			net_nfc_se_type_e se_type;
			net_nfc_card_emulation_category_t category;
			const char *aid;
			bool unlock;
			int power;
			bool manifest;

			while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
				package = (const char *)sqlite3_column_text(stmt, 1);
				se_type = (net_nfc_se_type_e)sqlite3_column_int(stmt, 2);
				category = (net_nfc_card_emulation_category_t)sqlite3_column_int(stmt, 3);
				aid = (const char *)sqlite3_column_text(stmt, 4);
				unlock = (bool)sqlite3_column_int(stmt, 5);
				power = sqlite3_column_int(stmt, 6);
				manifest = (bool)sqlite3_column_int(stmt, 7);

				cb(package, se_type, category, aid, unlock, power, manifest, user_data);
			}

			sqlite3_finalize(stmt);
		} else {
			DEBUG_ERR_MSG("sqlite3_prepare_v2 failed, [%d:%s]", ret, sqlite3_errmsg(db));
		}

		sqlite3_free(sql);
	} else {
		DEBUG_ERR_MSG("sqlite3_mprintf failed");
	}
}

static net_nfc_error_e __insert_into_db(const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, const char *aid,
	bool unlock, int power, bool manifest)
{
	net_nfc_error_e result;
	char *sql;

	sql = sqlite3_mprintf("INSERT INTO %s (package, se_type, category, aid, unlock, power, manifest) values(?, %d, %d, ?, %d, %d, %d);",
		NFC_ROUTE_TABLE_DB_TABLE, se_type, category, (int)unlock, power, (int)manifest);
	if (sql != NULL) {
		sqlite3_stmt *stmt = NULL;
		int ret;

		ret = sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
		if (ret == SQLITE_OK) {
			ret = sqlite3_bind_text(stmt, 1, package,
				strlen(package), SQLITE_STATIC);
			if (ret != SQLITE_OK) {
				DEBUG_ERR_MSG("sqlite3_bind_text failed, [%d]", ret);

				result = NET_NFC_OPERATION_FAIL;
				goto END;
			}

			ret = sqlite3_bind_text(stmt, 2, aid,
				strlen(aid), SQLITE_STATIC);
			if (ret != SQLITE_OK) {
				DEBUG_ERR_MSG("sqlite3_bind_text failed, [%d]", ret);

				result = NET_NFC_OPERATION_FAIL;
				goto END;
			}

			ret = sqlite3_step(stmt);
			if (ret != SQLITE_DONE) {
				DEBUG_ERR_MSG("sqlite3_step failed, [%d:%s]", ret, sqlite3_errmsg(db));

				result = NET_NFC_OPERATION_FAIL;
				goto END;
			}

			result = NET_NFC_OK;
END :
			sqlite3_finalize(stmt);
		} else {
			DEBUG_ERR_MSG("sqlite3_prepare_v2 failed, [%d:%s]", ret, sqlite3_errmsg(db));

			result = NET_NFC_OPERATION_FAIL;
		}

		sqlite3_free(sql);
	} else {
		DEBUG_ERR_MSG("sqlite3_mprintf failed");

		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}

static net_nfc_error_e __delete_from_db(const char *package, const char *aid)
{
	net_nfc_error_e result;
	char *sql;
	char *error = NULL;

	sql = sqlite3_mprintf("DELETE FROM %s WHERE package=%Q AND aid=%Q;",
		NFC_ROUTE_TABLE_DB_TABLE, package, aid);
	if (sql != NULL) {
		int ret;

		ret = sqlite3_exec(db, sql, NULL, NULL, &error);
		if (ret == SQLITE_OK) {
			result = NET_NFC_OK;
		} else {
			DEBUG_ERR_MSG("sqlite3_exec failed, [%d:%s]", ret, error);

			result = NET_NFC_OPERATION_FAIL;
			sqlite3_free(error);
		}

		sqlite3_free(sql);
	} else {
		DEBUG_ERR_MSG("sqlite3_mprintf failed");

		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}
#if 0
static net_nfc_error_e __delete_aids_from_db(const char *package)
{
	net_nfc_error_e result;
	char *sql;
	char *error = NULL;

	sql = sqlite3_mprintf("DELETE FROM %s WHERE package=%Q;",
		NFC_ROUTE_TABLE_DB_TABLE, package);
	if (sql != NULL) {
		int ret;

		ret = sqlite3_exec(db, sql, NULL, NULL, &error);
		if (ret == SQLITE_OK) {
			result = NET_NFC_OK;
		} else {
			DEBUG_ERR_MSG("sqlite3_exec failed, [%d:%s]", ret, error);

			result = NET_NFC_OPERATION_FAIL;
			sqlite3_free(error);
		}

		sqlite3_free(sql);
	} else {
		DEBUG_ERR_MSG("sqlite3_mprintf failed");

		result = NET_NFC_ALLOC_FAIL;
	}

	return result;
}
#endif
////////////////////////////////////////////////////////////////////////////////

static char *activated_payment;
static GPtrArray *activated_other;

static void __update_payment_handler(const char *package)
{
	if (activated_payment != NULL) {
		g_free(activated_payment);
	}

	if (package != NULL) {
		activated_payment = g_strdup(package);
	}
}

static bool __is_payment_handler(const char *package)
{
	return (activated_payment != NULL &&
		g_strcmp0(package, activated_payment) == 0);
}

static void __set_payment_handler(const char *package)
{
	int result;

	result = vconf_set_str(VCONFKEY_NFC_PAYMENT_HANDLERS,
		package != NULL ? package : "");
	if (result < 0) {
		DEBUG_ERR_MSG("vconf_set_str(VCONFKEY_NFC_PAYMENT_HANDLER) failed, [%d]", result);
	}
}

static void __on_destroy_other_cb(gpointer data)
{
	g_free(data);
}

static void __update_other_handler(const char *packages)
{
	if (activated_other != NULL) {
		g_ptr_array_free(activated_other, true);
	}

	if (packages != NULL) {
		gchar **tokens;
		gchar **ptr;

		activated_other = g_ptr_array_new_full(10,
			__on_destroy_other_cb);

		tokens = g_strsplit(packages, "|", -1);

		for (ptr = tokens; *ptr != NULL; ptr++) {
			g_ptr_array_add(activated_other, g_strdup(*ptr));
		}

		g_strfreev(tokens);
	}
}

void net_nfc_server_route_table_update_other_handler(const char *packages)
{
	__update_other_handler(packages);

	net_nfc_server_route_table_do_update();
}

static bool __is_other_handler(const char *package)
{
	bool result = false;
	int i;

	for (i = 0; i < activated_other->len; i++) {
		if (g_strcmp0(package, activated_other->pdata[i]) == 0) {
			result = true;
			break;
		}
	}

	return result;
}

static void __remove_other_handler(const char *package)
{
	int i, found = -1, offset = 0;
	char built[4096] = { 0, };

	for (i = 0; i < activated_other->len; i++) {
		if (g_strcmp0(package, (char *)activated_other->pdata[i]) == 0) {
			found = i;
		} else {
			if (i != activated_other->len - 1) {
				offset += snprintf(built + offset,
					sizeof(built) - offset, "%s|",
					(char *)activated_other->pdata[i]);
			} else {
				offset += snprintf(built + offset,
					sizeof(built) - offset, "%s",
					(char *)activated_other->pdata[i]);
			}
		}
	}

	if (found >= 0) {
		/* vconf update */
		i = vconf_set_str(VCONFKEY_NFC_OTHER_HANDLERS, built);
		if (i < 0) {
			DEBUG_ERR_MSG("vconf_set_str(VCONFKEY_NFC_OTHERS_HANDLER) failed, [%d]", i);
		}
	}
}

static void __append_other_handler(const char *package)
{
	int result;
	char *others;
	char built[4096] = { 0, };

	if (__is_other_handler(package) == true) {
		return;
	}

	others = vconf_get_str(VCONFKEY_NFC_OTHER_HANDLERS);
	if (others != NULL) {
		if (strlen(others) > 0) {
			snprintf(built, sizeof(built), "%s|%s", others, package);
		} else {
			snprintf(built, sizeof(built), "%s", package);
		}

		g_free(others);
	} else {
		snprintf(built, sizeof(built), "%s", package);
	}

	/* vconf update */
	result = vconf_set_str(VCONFKEY_NFC_OTHER_HANDLERS, built);
	if (result < 0) {
		DEBUG_ERR_MSG("vconf_set_str(VCONFKEY_NFC_OTHERS_HANDLER) failed, [%d]", result);
	}
}

static bool __is_activated_handler(net_nfc_card_emulation_category_t category,
	const char *package)
{
	/* set nfc-manager to default handler */
	if (g_strcmp0(package, "nfc-manager") == 0) {
		return true;
	}

	switch (category) {
	case NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT :
		return __is_payment_handler(package);
	case NET_NFC_CARD_EMULATION_CATEGORY_OTHER :
		return __is_other_handler(package);
	default :
		return false;
	}
}

static void __activate_handler(const char *package,
	net_nfc_card_emulation_category_t category)
{
	switch (category) {
	case NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT :
		if (__is_payment_handler(package) == false) {
			__set_payment_handler(package);
		}
		break;

	case NET_NFC_CARD_EMULATION_CATEGORY_OTHER :
		if (__is_other_handler(package) == false) {
			__append_other_handler(package);
		}
		break;

	default :
		break;
	}
}

static void __deactivate_handler(const char *package,
	net_nfc_card_emulation_category_t category)
{
	switch (category) {
	case NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT :
		if (__is_payment_handler(package) == true) {
			__set_payment_handler(NULL);
		}
		break;

	case NET_NFC_CARD_EMULATION_CATEGORY_OTHER :
		if (__is_other_handler(package) == true) {
			__remove_other_handler(package);
		}
		break;

	default :
		break;
	}
}

void net_nfc_server_route_table_update_category_handler(const char *package,
	net_nfc_card_emulation_category_t category)
{
	switch (category) {
	case NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT :
		__update_payment_handler(package);
		net_nfc_server_route_table_do_update();
		break;

	case NET_NFC_CARD_EMULATION_CATEGORY_OTHER :
		__update_other_handler(package);
		net_nfc_server_route_table_do_update();
		break;

	default :
		break;
	}
}


////////////////////////////////////////////////////////////////////////////////

/*Routing Table base on AID*/
static GHashTable *routing_handlers;

static bool __get_package_name(const char *id, char *package, size_t len)
{
	pid_t pid;
	bool result;

	pid = net_nfc_server_gdbus_get_pid(id);
	if (pid > 0) {
		if (net_nfc_util_get_pkgid_by_pid(pid,
			package, len) == true) {
			result = true;
		} else {
			result = false;
		}
	} else {
		result = false;
	}

	return result;
}

static void __on_key_destroy(gpointer data)
{
	if (data != NULL) {
		g_free(data);
	}
}

static void __on_value_destroy(gpointer data)
{
	route_table_handler_t *listener = (route_table_handler_t *)data;

	if (data != NULL) {
		int i;

		for (i = NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT;
			i < NET_NFC_CARD_EMULATION_CATEGORY_MAX;
			i++) {
			if (listener->aids[i] != NULL) {
				g_ptr_array_free(listener->aids[i], true);
			}
		}

		if (listener->id != NULL) {
			g_free(listener->id);
		}

		g_free(data);
	}
}

static void __on_aid_info_destroy(gpointer data)
{
	aid_info_t *info = (aid_info_t *)data;

	if (info->aid != NULL) {
		g_free(info->aid);
	}

	g_free(info);
}

static void __on_iterate_db_aid_cb(const char *package,
	net_nfc_se_type_e se_type, net_nfc_card_emulation_category_t category,
	const char *aid, bool unlock, int power, bool manifest, void *user_data)
{
	net_nfc_server_route_table_add_handler(NULL, package);

	DEBUG_SERVER_MSG("package [%s], se_type [%d], category [%d], manifest [%d], aid [%s]", package, se_type, category, manifest, aid);

	__route_table_add_aid(NULL, package, se_type, category, aid, unlock, power, manifest);
}

void net_nfc_server_route_table_init()
{
	if (routing_handlers == NULL) {
		char *package;

		__initialize_db();

		package = vconf_get_str(VCONFKEY_NFC_PAYMENT_HANDLERS);
		__update_payment_handler(package);
		if (package != NULL) {
			g_free(package);
		}

		package = vconf_get_str(VCONFKEY_NFC_OTHER_HANDLERS);
		__update_other_handler(package);
		if (package != NULL) {
			g_free(package);
		}

		routing_handlers = g_hash_table_new_full(g_str_hash,
			g_str_equal, __on_key_destroy, __on_value_destroy);
	}
}

void net_nfc_server_route_table_load_db()
{
	if (routing_handlers != NULL) {
		__iterate_db(__on_iterate_db_aid_cb, NULL);
	}
}

void net_nfc_server_route_table_deinit()
{
	if (routing_handlers != NULL) {
		g_hash_table_destroy(routing_handlers);
		routing_handlers = NULL;

		__finalize_db();
	}

}

route_table_handler_t *net_nfc_server_route_table_find_handler(
	const char *package)
{
	return (route_table_handler_t *)g_hash_table_lookup(routing_handlers,
		(gconstpointer)package);
}

net_nfc_error_e net_nfc_server_route_table_add_handler(const char *id,
	const char *package)
{
	route_table_handler_t *data;
	net_nfc_error_e result;

	data = net_nfc_server_route_table_find_handler(package);
	if (data == NULL) {
		int i;

		DEBUG_SERVER_MSG("new package, [%s]", package);

		data = g_new0(route_table_handler_t, 1);

		data->package = g_strdup(package);
		if (id != NULL) {
			data->id = g_strdup(id);
		}

		/* full aid list in array index 0 */
		data->aids[NET_NFC_CARD_EMULATION_CATEGORY_UNKNOWN] =
			g_ptr_array_new_full(0, __on_aid_info_destroy);

		/* partial aid list for each category in array index > 1 */
		for (i = NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT;
			i < NET_NFC_CARD_EMULATION_CATEGORY_MAX;
			i++) {
			data->aids[i] = g_ptr_array_new();
		}

		g_hash_table_insert(routing_handlers, (gpointer)g_strdup(package),
			(gpointer)data);

		result = NET_NFC_OK;
	} else {
		if (id != NULL && data->id == NULL) {
			DEBUG_SERVER_MSG("update client id, [%s]", id);
			data->id = g_strdup(id);
		}

		result = NET_NFC_OK;
	}

	return result;
}

static net_nfc_error_e __do_routing_aid(aid_info_t *info, bool commit)
{
	net_nfc_error_e result;

	if (info->is_routed == false) {
		data_s temp = { 0, };

		INFO_MSG("route aid, aid [%s]", info->aid);

		if (net_nfc_util_aid_is_prefix(info->aid) == true) {
			DEBUG_SERVER_MSG("prefix...");
		}

		if (net_nfc_util_hex_string_to_binary(info->aid, &temp) == true) {
			net_nfc_controller_secure_element_route_aid(&temp, info->se_type, info->power, &result);
			if (result == NET_NFC_OK) {
				info->is_routed = true;

				if (commit == true) {
					net_nfc_controller_secure_element_commit_routing(&result);
				}
			} else {
				DEBUG_ERR_MSG("net_nfc_controller_secure_element_route_aid failed, [%d]", result);
			}

			net_nfc_util_clear_data(&temp);
		} else {
			DEBUG_ERR_MSG("net_nfc_util_hex_string_to_binary failed");

			result = NET_NFC_ALLOC_FAIL;
		}
	} else {
		DEBUG_ERR_MSG("already routed, aid [%s]", info->aid);

		result = NET_NFC_ALREADY_REGISTERED;
	}

	return result;
}

static net_nfc_error_e __do_unrouting_aid(aid_info_t *info, bool commit)
{
	net_nfc_error_e result;

	if (info->is_routed == true) {
		data_s temp = { 0, };

		INFO_MSG("unroute aid, aid [%s]", info->aid);

		if (net_nfc_util_aid_is_prefix(info->aid) == true) {
			DEBUG_SERVER_MSG("prefix...");
		}

		if (net_nfc_util_hex_string_to_binary(info->aid, &temp) == true) {
			net_nfc_controller_secure_element_unroute_aid(&temp, &result);
			if (result == NET_NFC_OK) {
				info->is_routed = false;

				if (commit == true) {
					net_nfc_controller_secure_element_commit_routing(&result);
				}
			} else {
				DEBUG_ERR_MSG("net_nfc_controller_secure_element_unroute_aid failed, [%d]", result);
			}

			net_nfc_util_clear_data(&temp);
		} else {
			DEBUG_ERR_MSG("net_nfc_util_hex_string_to_binary failed");

			result = NET_NFC_ALLOC_FAIL;
		}
	} else {
		DEBUG_ERR_MSG("didn't routed, aid [%s]", info->aid);

		result = NET_NFC_NOT_REGISTERED;
	}

	return result;
}

#if 0
net_nfc_error_e net_nfc_server_route_table_del_handler(const char *id,
	const char *package, bool force)
{
	route_table_handler_t *data;
	net_nfc_error_e result;
	bool need_commit = false;

	data = net_nfc_server_route_table_find_handler(package);
	if (data != NULL) {
		int i;
		aid_info_t *info;

		DEBUG_SERVER_MSG("deleting package, [%s]", package);

		for (i = NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT;
			i < NET_NFC_CARD_EMULATION_CATEGORY_MAX;
			i++) {
			/* deactivate for each category */
			if (data->activated[i] == true) {
				/* TODO */
			}
		}

		for (i = (int)data->aids[0]->len - 1; i >= 0; i--) {
			info = data->aids[0]->pdata[i];

			if (force == true || info->manifest == false) {
				if (__do_unrouting_aid(info, false) == NET_NFC_OK) {
					need_commit = true;
				}

				g_ptr_array_remove(data->aids[info->category], info);
				g_ptr_array_remove_index(data->aids[0], i);
			} else {
				DEBUG_SERVER_MSG("manifest aid, skip deleting, [%s]", info->aid);
			}
		}

		if (need_commit == true) {
			net_nfc_controller_secure_element_commit_routing(&result);
		}

		if (data->aids[0]->len == 0) {
			g_hash_table_remove(routing_handlers, package);
		} else {
			DEBUG_SERVER_MSG("remain some aids, [%d]", data->aids[0]->len);
		}

		result = NET_NFC_OK;
	} else {
		DEBUG_ERR_MSG("package not found");

		result = NET_NFC_OPERATION_FAIL;
	}

	return result;
}
#else
net_nfc_error_e net_nfc_server_route_table_del_handler(const char *id,
	const char *package, bool force)
{
	route_table_handler_t *data;
	net_nfc_error_e result;

	data = net_nfc_server_route_table_find_handler(package);
	if (data != NULL) {
		net_nfc_card_emulation_category_t category;

		if (data->id != NULL) {
			g_free(data->id);
			data->id = NULL;
		}

		if (data->aids[0]->len > 0) {
			net_nfc_server_route_table_del_aids(id, package, force);
		}

		for (category = NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT;
			category < NET_NFC_CARD_EMULATION_CATEGORY_MAX;
			category++) {
			if (data->aids[category]->len == 0 &&
				data->activated[category] == true) {
			/* deactivate for each category */
				DEBUG_SERVER_MSG("deactivate handler, [%d][%s]", category, package);

				/* TODO */
				__deactivate_handler(package, category);
			}
		}

		if (data->aids[0]->len == 0) {
			DEBUG_SERVER_MSG("deleting package, [%s]", package);

			g_hash_table_remove(routing_handlers, package);

			result = NET_NFC_OK;
		} else {
			DEBUG_ERR_MSG("remain some aids, [%d]", data->aids[0]->len);

			result = NET_NFC_OPERATION_FAIL;
		}
	} else {
		DEBUG_ERR_MSG("package not found");

		result = NET_NFC_OPERATION_FAIL;
	}

	return result;
}
#endif
void net_nfc_server_route_table_iterate_handler(
	net_nfc_server_route_table_handler_iter_cb cb, void *user_data)
{
	GHashTableIter iter;
	gpointer key;
	route_table_handler_t *data;

	if (routing_handlers == NULL)
		return;

	g_hash_table_iter_init(&iter, routing_handlers);

	while (g_hash_table_iter_next(&iter, &key, (gpointer)&data)) {
		if (cb((const char *)key, data, user_data) == false) {
			break;
		}
	}
}
#ifdef PRINT_TABLE
static const char *__get_se_name(net_nfc_se_type_e se_type)
{
	switch (se_type) {
	case NET_NFC_SE_TYPE_ESE :
		return "eSE";
	case NET_NFC_SE_TYPE_UICC :
		return "UICC";
	case NET_NFC_SE_TYPE_SDCARD :
		return "SD";
	case NET_NFC_SE_TYPE_HCE :
		return "HCE";
	default :
		return "Unknown";
	}
}

static bool _display_route_table_cb(const char *package,
	route_table_handler_t *handler, void *user_data)
{
	int i;

	DEBUG_SERVER_MSG(" + PACKAGE [%s|%s]", handler->package, handler->id);

	for (i = 0; i < handler->aids[0]->len; i++) {
		aid_info_t *info = (aid_info_t *)handler->aids[0]->pdata[i];

		DEBUG_SERVER_MSG(" +-- AID [%s], SE [%s], CATEGORY [%s%s], MANIFEST [%s]%s",
			info->aid,
			__get_se_name(info->se_type),
			info->category == NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT ? "payment" : "other",
			handler->activated[info->category] ? " (A)" : "",
			info->manifest ? "manifest" : "dynamic",
			info->is_routed ? ", (ROUTED)" : "");
	}

	return true;
}

static void __display_route_table()
{
	DEBUG_SERVER_MSG(" +------------------------------------------------+");
	net_nfc_server_route_table_iterate_handler(_display_route_table_cb, NULL);
	DEBUG_SERVER_MSG(" +------------------------------------------------+");
}
#endif
static bool __activation_iter_cb(const char *package,
	route_table_handler_t *handler, void *user_data)
{
	int i;
	bool ret = true;
	aid_info_t *info;
	gpointer *params = (gpointer *)user_data;
	net_nfc_se_type_e se_type;
	net_nfc_card_emulation_category_t category;

	category = (net_nfc_card_emulation_category_t)params[1];
	se_type = (net_nfc_se_type_e)params[2];

	if (params[0] != NULL &&
		g_ascii_strcasecmp(package, (const char *)params[0]) == 0) {
		handler->activated[category] = true;

		(*(int *)params[3])++;

		for (i = 0; i < handler->aids[category]->len; i++) {
			info = (aid_info_t *)handler->aids[category]->pdata[i];

			if (info->se_type == se_type) {
				if (info->is_routed == true) {
					__do_unrouting_aid(info, false);
				}
				continue;
			}

			if (info->is_routed == false) {
				__do_routing_aid(info, false);
			}

			/* FIXME : need commit?? check and return */
		}

		/* stop iterating */
		if (category == NET_NFC_CARD_EMULATION_CATEGORY_OTHER) {
			ret = false;
		}
	} else {
		if (category == NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT &&
			handler->activated[category] == true) {
			handler->activated[category] = false;

			for (i = 0; i < handler->aids[category]->len; i++) {
				info = (aid_info_t *)handler->aids[category]->pdata[i];

				if (info->is_routed == true) {
					__do_unrouting_aid(info, false);
				}

				/* FIXME : need commit?? check and return */
			}
		}
	}

	return ret;
}

net_nfc_error_e net_nfc_server_route_table_set_handler_activation(
	const char *package, net_nfc_card_emulation_category_t category)
{
	net_nfc_error_e result;
	gpointer params[4];
	int ret = 0;

	params[0] = (gpointer)package;
	params[1] = (gpointer)category;
	params[2] = (gpointer)net_nfc_server_se_get_se_type();
	params[3] = (gpointer)&ret;

	net_nfc_server_route_table_iterate_handler(__activation_iter_cb,
		(void *)params);

#ifdef PRINT_TABLE
	__display_route_table();
#endif

	if (ret == 1) {
		INFO_MSG("activated category [%d], package [%s]", category, package);

		net_nfc_controller_secure_element_commit_routing(&result);

		result = NET_NFC_OK;
	} else if (ret == 0) {
		DEBUG_ERR_MSG("package not found : [%s]", package);

		result = NET_NFC_NO_DATA_FOUND;
	} else {
		DEBUG_ERR_MSG("wrong result : [%s][%d]", package, ret);

		result = NET_NFC_OPERATION_FAIL;
	}

	return result;
}


route_table_handler_t *net_nfc_server_route_table_find_handler_by_id(
	const char *id)
{
	route_table_handler_t *result;
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		result = net_nfc_server_route_table_find_handler(package);
	} else {
		result = NULL;
	}

	return result;
}

net_nfc_error_e net_nfc_server_route_table_add_handler_by_id(const char *id)
{
	net_nfc_error_e result;
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		result = net_nfc_server_route_table_add_handler(id,
			package);
	} else {
		result = NET_NFC_INVALID_PARAM;
	}

	return result;
}

net_nfc_error_e net_nfc_server_route_table_del_handler_by_id(const char *id)
{
	net_nfc_error_e result;
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		result = net_nfc_server_route_table_del_handler(id, package, false);
	} else {
		result = NET_NFC_INVALID_PARAM;
	}

	return result;
}


net_nfc_error_e net_nfc_server_route_table_set_handler_activation_by_id(
	const char *id, net_nfc_card_emulation_category_t category)
{
	net_nfc_error_e result;
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		result = net_nfc_server_route_table_set_handler_activation(
			package, category);
	} else {
		result = NET_NFC_INVALID_PARAM;
	}

	return result;
}



aid_info_t *net_nfc_server_route_table_find_aid(const char *package,
	const char *aid)
{
	route_table_handler_t *handler;

	handler = net_nfc_server_route_table_find_handler(package);
	if (handler != NULL) {
		aid_info_t *info;
		int i;

		for (i = 0; i < handler->aids[0]->len; i++) {
			info = handler->aids[0]->pdata[i];

			if (g_ascii_strcasecmp(aid, info->aid) == 0) {
				return info;
			}
		}
	}

	return NULL;
}

static bool __find_handler_iter_cb(const char *package,
	route_table_handler_t *handler, void *user_data)
{
	bool result = true;
	gpointer *params = (gpointer *)user_data;
	aid_info_t *aid;

	aid = net_nfc_server_route_table_find_aid(package,
		(const char *)params[0]);
	if (aid != NULL) {
		if (aid->category != NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT ||
			handler->activated[aid->category] == true) {
			params[1] = handler;
			result = false;
		} else {
			DEBUG_SERVER_MSG("not activated payment aid, [%s]", aid->aid);
		}
	}

	return result;
}

route_table_handler_t *net_nfc_server_route_table_find_handler_by_aid(
	const char *aid)
{
	gpointer params[2];

	params[0] = g_strdup(aid);
	params[1] = NULL;

	net_nfc_server_route_table_iterate_handler(__find_handler_iter_cb, params);

	g_free(params[0]);

	return (route_table_handler_t *)params[1];
}

static bool __matched_aid_cb(const char *package,
	route_table_handler_t *handler, void *user_data)
{
	bool result = true;
	gpointer *params = (gpointer *)user_data;

	if (net_nfc_server_route_table_find_aid(package,
		(const char *)params[0]) != NULL) {
		params[1] = handler;
		result = false;
	}

	return result;
}

aid_info_t *net_nfc_server_route_table_find_first_matched_aid(const char *aid)
{
	__matched_aid_cb(NULL, NULL, NULL);

	return NULL;
}

static net_nfc_error_e __route_table_add_aid(const char *id,
	const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	const char *aid, bool unlock, int power, bool manifest)
{
	net_nfc_error_e result;
	route_table_handler_t *data;

	data = net_nfc_server_route_table_find_handler(package);
	if (data != NULL) {
		if (net_nfc_server_route_table_find_aid(package, aid) == NULL) {
			aid_info_t *info;

			DEBUG_SERVER_MSG("new aid, package [%s], se_type [%d], category [%d], aid [%s], ", package, se_type, category, aid);

			info = g_new0(aid_info_t, 1);

			info->aid = g_strdup(aid);
			info->se_type = se_type;
			info->category = category;
			info->unlock = unlock;
			info->power = power;
			info->manifest = manifest;

			g_ptr_array_add(data->aids[0], info);
			g_ptr_array_add(data->aids[category], info);

			if (se_type != net_nfc_server_se_get_se_type()) {
				if (data->activated[category] == true) {
					INFO_MSG("routing... package [%s], aid [%s], ", package, aid);

					result = __do_routing_aid(info, true);
				} else {
					INFO_MSG("not activated handler, aid [%s]", aid);

					result = NET_NFC_OK;
				}
			} else {
				INFO_MSG("route to default SE... skip, aid [%s]", aid);

				result = NET_NFC_OK;
			}
		} else {
			DEBUG_ERR_MSG("already exist, aid [%s]", aid);

			result = NET_NFC_ALREADY_REGISTERED;
		}
	} else {
		DEBUG_ERR_MSG("package not found");

		result = NET_NFC_OPERATION_FAIL;
	}

	return result;
}

static net_nfc_error_e __route_table_del_aid(const char *id,
	const char *package, const char *aid, bool force)
{
	net_nfc_error_e result = NET_NFC_NO_DATA_FOUND;
	route_table_handler_t *data;

	data = net_nfc_server_route_table_find_handler(package);
	if (data != NULL &&
		(id == NULL || data->id == NULL ||
			g_ascii_strcasecmp(id, data->id) == 0)) {
		int i;

		for (i = 0; i < data->aids[0]->len; i++) {
			aid_info_t *info = (aid_info_t *)data->aids[0]->pdata[i];

			if (g_ascii_strcasecmp(info->aid, aid) == 0) {
				if (force == true || info->manifest == false) {
					INFO_MSG("remove aid, package [%s], aid [%s]", package, aid);

					if (info->is_routed == true) {
						__do_unrouting_aid(info, true);
					}

					g_ptr_array_remove(data->aids[info->category], info);
					g_ptr_array_remove_index(data->aids[0], i);

					result = NET_NFC_OK;
				} else {
					DEBUG_SERVER_MSG("cannot remove aid because it stored in manifest, aid [%s]", info->aid);

					result = NET_NFC_OPERATION_FAIL;
				}

				break;
			}
		}
	}

	return result;
}

net_nfc_error_e net_nfc_server_route_table_add_aid(const char *id,
	const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	const char *aid)
{
	net_nfc_error_e result;

	result = net_nfc_server_route_table_add_handler(id, package);
	if (result == NET_NFC_OK) {
		result = __route_table_add_aid(id,
			package, se_type, category, aid, true, 1, false);
		if (result == NET_NFC_OK) {
			result = __insert_into_db(package, se_type, category, aid, true, 1, false);
			if (result != NET_NFC_OK) {
				DEBUG_ERR_MSG("__insert_into_db failed, [%d]", result);

				result = __route_table_del_aid(id, package, aid, false);
				if (result != NET_NFC_OK) {
					DEBUG_ERR_MSG("__route_table_del_aid failed, [%d]", result);
				}
			}
		} else {
			DEBUG_ERR_MSG("net_nfc_server_route_table_add_aid failed, [%d]", result);
		}
	} else {
		DEBUG_ERR_MSG("net_nfc_server_route_table_add_handler failed, [%d]", result);
	}

#ifdef PRINT_TABLE
	__display_route_table();
#endif
	return result;
}

net_nfc_error_e net_nfc_server_route_table_del_aid(const char *id,
	const char *package, const char *aid, bool force)
{
	net_nfc_error_e result = NET_NFC_OK;

	result = __route_table_del_aid(id, package, aid, false);
	if (result == NET_NFC_OK) {
	} else {
		DEBUG_ERR_MSG("__route_table_del_aid failed, [%d]", result);
	}

	result = __delete_from_db(package, aid);
	if (result != NET_NFC_OK) {
		DEBUG_ERR_MSG("__delete_from_db failed, [%d]", result);
	}

#ifdef PRINT_TABLE
	__display_route_table();
#endif
	return result;
}

net_nfc_error_e net_nfc_server_route_table_del_aids(const char *id,
	const char *package, bool force)
{
	net_nfc_error_e result = NET_NFC_NO_DATA_FOUND;
	route_table_handler_t *data;
	bool need_commit = false;

	data = net_nfc_server_route_table_find_handler(package);
	if (data != NULL &&
		(id == NULL || data->id == NULL ||
			g_ascii_strcasecmp(id, data->id) == 0)) {
		int i;

		for (i = (int)data->aids[0]->len - 1; i >= 0; i--) {
			aid_info_t *info = (aid_info_t *)data->aids[0]->pdata[i];

			if (force == true || info->manifest == false) {
				DEBUG_SERVER_MSG("remove aid, package [%s], aid [%s]", package, info->aid);

				if (info->is_routed == true &&
					__do_unrouting_aid(info, false) == NET_NFC_OK) {
					need_commit = true;
				}

				result = __delete_from_db(package, info->aid);
				if (result != NET_NFC_OK) {
					DEBUG_ERR_MSG("__delete_from_db failed, [%d]", result);
				}

				g_ptr_array_remove(data->aids[info->category], info);
				g_ptr_array_remove_index(data->aids[0], i);
			} else {
				DEBUG_SERVER_MSG("cannot remove aid because it stored in manifest, aid [%s]", info->aid);
			}
		}
	} else {
		DEBUG_SERVER_MSG("not found, package [%s]", package);
	}

	if (need_commit == true) {
		net_nfc_controller_secure_element_commit_routing(&result);
	}

#ifdef PRINT_TABLE
	__display_route_table();
#endif
	return result;
}

void net_nfc_server_route_table_iterate_aid(const char *package,
	net_nfc_server_route_table_aid_iter_cb cb, void *user_data)
{
	GHashTableIter iter;
	gpointer key;
	route_table_handler_t *data;
	int i;
	aid_info_t *info;

	if (routing_handlers == NULL)
		return;

	g_hash_table_iter_init(&iter, routing_handlers);

	while (g_hash_table_iter_next(&iter, &key, (gpointer)&data)) {
		for (i = 0; i < data->aids[0]->len; i++) {
			info = (aid_info_t *)data->aids[0]->pdata[i];

			cb((const char *)key, data, info, user_data);
		}
	}
}

aid_info_t *net_nfc_server_route_table_find_aid_by_id(const char *id,
	const char *aid)
{
	aid_info_t *result;
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		result = net_nfc_server_route_table_find_aid(package, aid);
	} else {
		result = NULL;
	}

	return result;

}

net_nfc_error_e net_nfc_server_route_table_add_aid_by_id(const char *id,
	net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	const char *aid)
{
	net_nfc_error_e result;
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		result = net_nfc_server_route_table_add_aid(id,
			package, se_type, category, aid);
	} else {
		result = NET_NFC_INVALID_PARAM;
	}

	return result;
}

net_nfc_error_e net_nfc_server_route_table_del_aid_by_id(const char *id,
	const char *aid, bool force)
{
	net_nfc_error_e result = NET_NFC_NO_DATA_FOUND;
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		result = net_nfc_server_route_table_del_aid(id,
			package, aid, force);
	}

	return result;
}


void net_nfc_server_route_table_iterate_aid_by_id(const char *id,
	net_nfc_server_route_table_aid_iter_cb cb, void *user_data)
{
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		net_nfc_server_route_table_iterate_aid(package, cb, user_data);
	}
}


net_nfc_error_e net_nfc_server_route_table_insert_aid_into_db(
	const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	const char *aid, bool unlock, int power)
{
	net_nfc_error_e result;

	result = __insert_into_db(package, se_type, category,
		aid, unlock, power, true);
	if (result == NET_NFC_OK) {
		result = net_nfc_server_route_table_add_handler(NULL, package);
		if (result == NET_NFC_OK) {
			result = __route_table_add_aid(NULL,
				package, se_type, category, aid,
				unlock, power, true);
			if (result == NET_NFC_OK) {
				if (category == NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT) {
					char *handler;

					handler = vconf_get_str(VCONFKEY_NFC_PAYMENT_HANDLERS);
					if (handler == NULL || strlen(handler) == 0) {
						DEBUG_SERVER_MSG("set to default payment handler, [%s]", package);

						__activate_handler(package, category);
					}

					if (handler != NULL) {
						g_free(handler);
					}
				} else {
					if (__is_activated_handler(category, package) == false) {
						__activate_handler(package, category);
					}
				}
			} else {
				DEBUG_ERR_MSG("net_nfc_server_route_table_add_aid failed, [%d]", result);
			}
		} else {
			DEBUG_ERR_MSG("net_nfc_server_route_table_add_handler failed, [%d]", result);
		}
	} else {
		DEBUG_ERR_MSG("__insert_into_db failed, [%d]", result);
	}

#ifdef PRINT_TABLE
	__display_route_table();
#endif
	return result;
}

net_nfc_error_e net_nfc_server_route_table_delete_aid_from_db(
	const char *package, const char *aid)
{
	net_nfc_error_e result;

	result = net_nfc_server_route_table_del_aid(NULL, package, aid, true);

	return result;
}

net_nfc_error_e net_nfc_server_route_table_delete_aids_from_db(
	const char *package)
{
	net_nfc_error_e result;

	result = net_nfc_server_route_table_del_aids(NULL, package, true);

	return result;
}

static bool __update_table_iter_cb(const char *package,
	route_table_handler_t *handler, void *user_data)
{
	gpointer *params = (gpointer *)user_data;
	int i;
	aid_info_t *info;
	net_nfc_se_type_e se_type;
	net_nfc_card_emulation_category_t category;
	int *ret;

	se_type = (net_nfc_se_type_e)params[0];
	ret = (int *)params[1];

	for (category = NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT;
		category < NET_NFC_CARD_EMULATION_CATEGORY_MAX;
		category++) {
		if (__is_activated_handler(category, package) == true) {
			for (i = 0; i < handler->aids[category]->len; i++) {
				info = (aid_info_t *)handler->aids[category]->pdata[i];

				if (info->se_type == se_type) {
					/* unroute aid when se type is same with default */
					if (info->is_routed == true) {
						__do_unrouting_aid(info, false);
					}

					continue;
				}

				if (info->is_routed == false) {
					__do_routing_aid(info, false);
				}
			}

			handler->activated[category] = true;
		} else {
			for (i = 0; i < handler->aids[category]->len; i++) {
				info = (aid_info_t *)handler->aids[category]->pdata[i];

				if (info->is_routed == true) {
					__do_unrouting_aid(info, false);
				}
			}

			handler->activated[category] = false;
		}
	}

	(*ret) = 0;

	return true;
}

net_nfc_error_e net_nfc_server_route_table_do_update(void)
{
	net_nfc_error_e result = NET_NFC_OK;
	gpointer params[3];
	net_nfc_se_type_e se_type;
	int ret = 0;

//	if (net_nfc_controller_secure_element_clear_aid_table(&result) == false) {
//		DEBUG_ERR_MSG("net_nfc_controller_secure_element_clear_aid_table failed, [%d]", result);
//	}

	se_type = net_nfc_server_se_get_se_type();

	params[0] = (gpointer)se_type;
	params[1] = (gpointer)&ret;

	net_nfc_server_route_table_iterate_handler(__update_table_iter_cb,
		(void *)params);

	if (ret == 0) {
		INFO_MSG("routing table update complete");

		result = NET_NFC_OK;
	} else if (ret > 1) {
		DEBUG_ERR_MSG("some packages are not updated, [%d]", ret);

		result = NET_NFC_OPERATION_FAIL;
	} else {
		DEBUG_ERR_MSG("wrong result, [%d]", ret);

		result = NET_NFC_OPERATION_FAIL;
	}

	net_nfc_controller_secure_element_commit_routing(&result);

#ifdef PRINT_TABLE
	__display_route_table();
#endif

	return result;
}
