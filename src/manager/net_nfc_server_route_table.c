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

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_server.h"
#include "net_nfc_server_se.h"
#include "net_nfc_server_route_table.h"


/* route table database */
#define NFC_ROUTE_TABLE_DB_FILE "/opt/usr/share/nfc-manager-daemon/.route_table.db"
#define NFC_ROUTE_TABLE_DB_TABLE "route_table"

typedef void (*_iterate_db_cb)(const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category, const char *aid,
	bool unlock, int power, void *user_data);

static sqlite3 *db;
static sqlite3_stmt *current_stmt;

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

	sql = sqlite3_mprintf("CREATE TABLE %s(idx INTEGER PRIMARY KEY, package TEXT NOT NULL, se_type INTEGER, category INTEGER, aid TEXT NOT NULL COLLATE NOCASE, unlock INTEGER, power INTEGER);", NFC_ROUTE_TABLE_DB_TABLE);
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

			while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
				package = (const char *)sqlite3_column_text(stmt, 1);
				se_type = (net_nfc_se_type_e)sqlite3_column_int(stmt, 2);
				category = (net_nfc_card_emulation_category_t)sqlite3_column_int(stmt, 3);
				aid = (const char *)sqlite3_column_text(stmt, 4);
				unlock = (bool)sqlite3_column_int(stmt, 5);
				power = sqlite3_column_int(stmt, 6);

				cb(package, se_type, category, aid, unlock, power, user_data);
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
	bool unlock, int power)
{
	net_nfc_error_e result;
	char *sql;

	sql = sqlite3_mprintf("INSERT INTO %s (package, se_type, category, aid, unlock, power) values(?, %d, %d, ?, %d, %d);",
		NFC_ROUTE_TABLE_DB_TABLE, se_type, category, (int)unlock, power);
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

////////////////////////////////////////////////////////////////////////////////

/*Routing Table base on AID*/
static GHashTable *routing_table_aid;


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
		if (listener->aids != NULL) {
			g_ptr_array_free(listener->aids, true);
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
	const char *aid, bool unlock, int power, void *user_data)
{
	net_nfc_server_route_table_add_handler(NULL, package);

	DEBUG_SERVER_MSG("package [%s], se_type [%d], category [%d], aid [%s]", package, se_type, category, aid);

	net_nfc_server_route_table_add_aid(NULL, package, se_type, category, true, aid);
}

void net_nfc_server_route_table_init()
{
	if (routing_table_aid == NULL) {
		__initialize_db();

		routing_table_aid = g_hash_table_new_full(g_str_hash,
			g_str_equal, __on_key_destroy, __on_value_destroy);

	}
}

void net_nfc_server_route_table_load_db()
{
	if (routing_table_aid != NULL) {
		__iterate_db(__on_iterate_db_aid_cb, NULL);
	}
}

void net_nfc_server_route_table_deinit()
{
	if (routing_table_aid != NULL) {
		g_hash_table_destroy(routing_table_aid);
		routing_table_aid = NULL;

		__finalize_db();
	}

}

route_table_handler_t *net_nfc_server_route_table_find_handler(
	const char *package)
{
	return (route_table_handler_t *)g_hash_table_lookup(routing_table_aid,
		(gconstpointer)package);
}

net_nfc_error_e net_nfc_server_route_table_add_handler(const char *id,
	const char *package)
{
	route_table_handler_t *data;
	net_nfc_error_e result;

	data = net_nfc_server_route_table_find_handler(package);
	if (data == NULL) {
		DEBUG_SERVER_MSG("new package, [%s]", package);

		data = g_new0(route_table_handler_t, 1);

		data->package = g_strdup(package);
		if (id != NULL) {
			data->id = g_strdup(id);
		}
		data->aids = g_ptr_array_new_full(0, __on_aid_info_destroy);

		g_hash_table_insert(routing_table_aid, (gpointer)g_strdup(package),
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

net_nfc_error_e net_nfc_server_route_table_del_handler(const char *id,
	const char *package)
{
	route_table_handler_t *data;
	net_nfc_error_e result;

	data = net_nfc_server_route_table_find_handler(package);
	if (data != NULL) {
		int i;
		aid_info_t *info;

		DEBUG_SERVER_MSG("deleting package, [%s]", package);

		for (i = (int)data->aids->len-1; i >= 0; i--) {
			info = data->aids->pdata[i];

			if (info->manifest == false) {
				g_ptr_array_remove_index(data->aids, i);
			} else {
				DEBUG_SERVER_MSG("manifest aid, [%s]", info->aid);
			}
		}

		if (data->aids->len == 0) {
			g_hash_table_remove(routing_table_aid, package);
		} else {
			DEBUG_SERVER_MSG("remain some aids, [%d]", data->aids->len);
		}

		result = NET_NFC_OK;
	} else {
		DEBUG_ERR_MSG("package not found");

		result = NET_NFC_OPERATION_FAIL;
	}

	return result;
}

void net_nfc_server_route_table_iterate_handler(
	net_nfc_server_route_table_handler_iter_cb cb, void *user_data)
{
	GHashTableIter iter;
	gpointer key;
	route_table_handler_t *data;

	if (routing_table_aid == NULL)
		return;

	g_hash_table_iter_init(&iter, routing_table_aid);

	while (g_hash_table_iter_next(&iter, &key, (gpointer)&data)) {
		if (cb((const char *)key, data, user_data) == false) {
			break;
		}
	}
}

static bool __activation_iter_cb(const char *package,
	route_table_handler_t *handler, void *user_data)
{
	int i;
	net_nfc_error_e result = NET_NFC_OK;
	aid_info_t *info;
	data_s temp;
	gpointer *params = (gpointer *)user_data;

	if (g_ascii_strcasecmp(package, (const char *)params[0]) == 0) {
		handler->activated = true;
		params[1] = (gpointer)((int)params[1] + 1);

		for (i = 0; i < handler->aids->len; i++) {

			info = (aid_info_t *)handler->aids->pdata[i];

			if (net_nfc_util_hex_string_to_binary(info->aid, &temp) == true) {
				net_nfc_controller_secure_element_route_aid(&temp, info->se_type, true, &result);

				net_nfc_util_clear_data(&temp);
			} else {
				DEBUG_ERR_MSG("net_nfc_util_hex_string_to_binary failed");
			}
		}
	} else {
		if (handler->activated == true) {
			handler->activated = false;

			for (i = 0; i < handler->aids->len; i++) {
				info = (aid_info_t *)handler->aids->pdata[i];

				if (info->category != NET_NFC_CARD_EMULATION_CATEGORY_PAYMENT) {
					continue;
				}

				if (net_nfc_util_hex_string_to_binary(info->aid, &temp) == true) {
					net_nfc_controller_secure_element_unroute_aid(&temp, &result);

					net_nfc_util_clear_data(&temp);
				} else {
					DEBUG_ERR_MSG("net_nfc_util_hex_string_to_binary failed");
				}
			}
		}
	}

	return true;
}

net_nfc_error_e net_nfc_server_set_handler_activation(const char *package)
{
	net_nfc_error_e result;
	gpointer params[2];

	params[0] = (gpointer)package;
	params[1] = (gpointer)0;

	net_nfc_server_route_table_iterate_handler(__activation_iter_cb,
		(void *)params);

	if ((int)params[1] == 1) {
		INFO_MSG("activated package : [%s]", package);

		net_nfc_controller_secure_element_commit_routing(&result);

		result = NET_NFC_OK;
	} else if ((int)params[1] == 0) {
		DEBUG_ERR_MSG("package not found : [%s]", package);
		result = NET_NFC_NO_DATA_FOUND;
	} else {
		DEBUG_ERR_MSG("wrong result : [%s][%d]", package, (int)params[1]);
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
		result = net_nfc_server_route_table_del_handler(id, package);
	} else {
		result = NET_NFC_INVALID_PARAM;
	}

	return result;
}


net_nfc_error_e net_nfc_server_set_handler_activation_by_id(const char *id)
{
	net_nfc_error_e result;
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		result = net_nfc_server_set_handler_activation(package);
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

		for (i = 0; i < handler->aids->len; i++) {
			info = handler->aids->pdata[i];

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
			handler->activated == true) {
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
	return NULL;
}

net_nfc_error_e net_nfc_server_route_table_add_aid(const char *id,
	const char *package, net_nfc_se_type_e se_type,
	net_nfc_card_emulation_category_t category,
	bool manifest, const char *aid)
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
			info->manifest = manifest;

			g_ptr_array_add(data->aids, info);

			if (se_type != net_nfc_server_se_get_se_type()) {
				if (data->activated == true ||
					category == NET_NFC_CARD_EMULATION_CATEGORY_OTHER) {
					data_s temp = { 0, };

					INFO_MSG("routing... package [%s], aid [%s], ", package, aid);

					if (net_nfc_util_aid_is_prefix(aid) == true) {
						DEBUG_SERVER_MSG("prefix...");
					}

					if (net_nfc_util_hex_string_to_binary(aid, &temp) == true) {
						net_nfc_controller_secure_element_route_aid(&temp, se_type, true, &result);

						net_nfc_controller_secure_element_commit_routing(&result);

						net_nfc_util_clear_data(&temp);
					} else {
						DEBUG_ERR_MSG("net_nfc_util_hex_string_to_binary failed");

						result = NET_NFC_INVALID_PARAM;
					}
				} else {
					DEBUG_SERVER_MSG("not activated handler, aid [%s]", aid);

					result = NET_NFC_OK;
				}
			} else {
				DEBUG_SERVER_MSG("route to default SE... skip, aid [%s]", aid);

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

void net_nfc_server_route_table_del_aid(const char *id, const char *package,
	const char *aid, bool force)
{
	net_nfc_error_e result = NET_NFC_OK;
	route_table_handler_t *data;

	data = net_nfc_server_route_table_find_handler(package);
	if (data != NULL &&
		(id == NULL || data->id == NULL ||
			g_ascii_strcasecmp(id, data->id) == 0)) {
		int i;

		for (i = 0; i < data->aids->len; i++) {
			aid_info_t *info = (aid_info_t *)data->aids->pdata[i];

			if (g_ascii_strcasecmp(info->aid, aid) == 0) {
				if (force == true || info->manifest == false) {
					DEBUG_SERVER_MSG("remove aid, package [%s], aid [%s]", package, aid);

					if (info->se_type != net_nfc_server_se_get_se_type() &&
						(data->activated == true ||
						info->category == NET_NFC_CARD_EMULATION_CATEGORY_OTHER)) {
						data_s temp = { 0, };

						INFO_MSG("unroute aid, package [%s], aid [%s]", package, aid);

						if (net_nfc_util_aid_is_prefix(aid) == true) {
							DEBUG_SERVER_MSG("prefix...");
						}

						if (net_nfc_util_hex_string_to_binary(aid, &temp) == true) {
							net_nfc_controller_secure_element_unroute_aid(&temp, &result);

							net_nfc_controller_secure_element_commit_routing(&result);

							net_nfc_util_clear_data(&temp);
						} else {
							DEBUG_ERR_MSG("net_nfc_util_hex_string_to_binary failed");
						}
					} else {
						DEBUG_SERVER_MSG("not activated aid... skip unrouting, aid [%s]", aid);
					}

					g_ptr_array_remove_index(data->aids, i);
				} else {
					DEBUG_SERVER_MSG("cannot remove aid because it stored in manifest, aid [%s]", info->aid);
				}

				break;
			}
		}
	}
}

void net_nfc_server_route_table_del_aids(const char *id, const char *package,
	bool force)
{
	net_nfc_error_e result = NET_NFC_OK;
	route_table_handler_t *data;
	bool need_commit = false;

	data = net_nfc_server_route_table_find_handler(package);
	if (data != NULL &&
		(id == NULL || data->id == NULL ||
			g_ascii_strcasecmp(id, data->id) == 0)) {
		int i;

		for (i = (int)data->aids->len - 1; i >= 0; i--) {
			aid_info_t *info = (aid_info_t *)data->aids->pdata[i];

			if (force == true || info->manifest == false) {
				DEBUG_SERVER_MSG("remove aid, package [%s], aid [%s]", package, info->aid);

				if (info->se_type != net_nfc_server_se_get_se_type() &&
					(data->activated == true ||
					info->category == NET_NFC_CARD_EMULATION_CATEGORY_OTHER)) {
					data_s temp = { 0, };

					INFO_MSG("unroute aid, package [%s], aid [%s]", package, info->aid);

					if (net_nfc_util_aid_is_prefix(info->aid) == true) {
						DEBUG_SERVER_MSG("prefix...");
					}

					if (net_nfc_util_hex_string_to_binary(info->aid, &temp) == true) {
						net_nfc_controller_secure_element_unroute_aid(&temp, &result);

						net_nfc_util_clear_data(&temp);

						need_commit = true;
					} else {
						DEBUG_ERR_MSG("net_nfc_util_hex_string_to_binary failed");
					}
				} else {
					DEBUG_SERVER_MSG("not activated aid... skip unrouting, aid [%s]", info->aid);
				}

				g_ptr_array_remove_index(data->aids, i);
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
}

void net_nfc_server_route_table_iterate_aid(const char *package,
	net_nfc_server_route_table_aid_iter_cb cb, void *user_data)
{
	GHashTableIter iter;
	gpointer key;
	route_table_handler_t *data;
	int i;
	aid_info_t *info;

	if (routing_table_aid == NULL)
		return;

	g_hash_table_iter_init(&iter, routing_table_aid);

	while (g_hash_table_iter_next(&iter, &key, (gpointer)&data)) {
		for (i = 0; i < data->aids->len; i++) {
			info = (aid_info_t *)data->aids->pdata[i];

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
	bool manifest, const char *aid)
{
	net_nfc_error_e result;
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		result = net_nfc_server_route_table_add_aid(id,
			package, se_type, category, manifest, aid);
	} else {
		result = NET_NFC_INVALID_PARAM;
	}

	return result;
}

void net_nfc_server_route_table_del_aid_by_id(const char *id, const char *aid,
	bool force)
{
	char package[1024];

	if (__get_package_name(id, package, sizeof(package)) == true) {
		net_nfc_server_route_table_del_aid(id,
			package, aid, force);
	}
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
		aid, unlock, power);
	if (result == NET_NFC_OK) {
		result = net_nfc_server_route_table_add_handler(NULL, package);
		if (result == NET_NFC_OK) {
			result = net_nfc_server_route_table_add_aid(NULL,
				package, se_type, category, true, aid);
			if (result != NET_NFC_OK) {
				DEBUG_ERR_MSG("net_nfc_server_route_table_add_aid failed, [%d]", result);
			}
		} else {
			DEBUG_ERR_MSG("net_nfc_server_route_table_add_handler failed, [%d]", result);
		}
	} else {
		DEBUG_ERR_MSG("__insert_into_db failed, [%d]", result);
	}

	return result;
}

net_nfc_error_e net_nfc_server_route_table_delete_aid_from_db(
	const char *package, const char *aid)
{
	net_nfc_error_e result;

	result = __delete_from_db(package, aid);
	if (result == NET_NFC_OK) {
		net_nfc_server_route_table_del_aid(NULL, package, aid, true);
	} else {
		DEBUG_ERR_MSG("__delete_from_db failed, [%d]", result);
	}

	return result;
}

net_nfc_error_e net_nfc_server_route_table_delete_aids_from_db(
	const char *package)
{
	net_nfc_error_e result;

	result = __delete_aids_from_db(package);
	if (result == NET_NFC_OK) {
		net_nfc_server_route_table_del_aids(NULL, package, true);
	}

	return result;
}
