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
#include <linux/limits.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>

#include <dd-display.h>/*for pm lock*/

#include "net_nfc_oem_controller.h"
#include "net_nfc_controller_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_debug_internal.h"
#include "net_nfc_server_tag.h"

#define NET_NFC_OEM_LIBRARY_PATH "/usr/lib/libnfc-plugin.so"
#define NET_NFC_DEFAULT_PLUGIN	"libnfc-plugin.so"


static net_nfc_oem_interface_s g_interface;

static void *net_nfc_controller_load_file(const char *dir_path,
					const char *filename)
{
	void *handle = NULL;
	char path[PATH_MAX] = { '\0' };
	struct stat st;

	net_nfc_error_e result;

	bool (*onload)(net_nfc_oem_interface_s *interfaces);

	snprintf(path, PATH_MAX, "%s/%s", dir_path, filename);
	DEBUG_SERVER_MSG("path : %s", path);

	if (stat(path, &st) == -1) {
		DEBUG_ERR_MSG("stat failed : file not found");
		goto ERROR;
	}

	if (S_ISREG(st.st_mode) == 0) {
		DEBUG_ERR_MSG("S_ISREG(st.st_mode) == 0");
		goto ERROR;
	}

	handle = dlopen(path, RTLD_LAZY);
	if (handle == NULL) {
		char buffer[1024];
		DEBUG_ERR_MSG("dlopen failed, [%d] : %s",
			errno, strerror_r(errno, buffer, sizeof(buffer)));
		goto ERROR;
	}

	onload = dlsym(handle, "onload");
	if (onload == NULL) {
		char buffer[1024];
		DEBUG_ERR_MSG("dlsym failed, [%d] : %s",
			errno, strerror_r(errno, buffer, sizeof(buffer)));
		goto ERROR;
	}

	memset(&g_interface, 0, sizeof(g_interface));
	if (onload(&g_interface) == false) {
		DEBUG_ERR_MSG("onload failed");
		goto ERROR;
	}

	if (net_nfc_controller_support_nfc(&result) == false) {
		DEBUG_ERR_MSG("net_nfc_controller_support_nfc failed, [%d]",
			result);
		goto ERROR;
	}

	return handle;

ERROR :
	if (handle != NULL) {
		dlclose(handle);
	}

	return NULL;
}

void *net_nfc_controller_onload()
{
	DIR *dirp;
	struct dirent *dir;

	void *handle = NULL;

	dirp = opendir(NFC_MANAGER_MODULEDIR);
	if (dirp == NULL)
	{
		DEBUG_ERR_MSG("Can not open directory %s",
				NFC_MANAGER_MODULEDIR);
		return NULL;
	}

	while ((dir = readdir(dirp)))
	{
		if ((strcmp(dir->d_name, ".") == 0) ||
				(strcmp(dir->d_name, "..") == 0))
		{
			continue;
		}

		/* check ".so" suffix */
		if (strcmp(dir->d_name + (strlen(dir->d_name) - strlen(".so")),
					".so") != 0)
			continue;

		/* check default plugin later */
		if (strcmp(dir->d_name, NET_NFC_DEFAULT_PLUGIN) == 0)
			continue;

		handle = net_nfc_controller_load_file(NFC_MANAGER_MODULEDIR,
						dir->d_name);
		if (handle)
		{
			SECURE_LOGD("Successfully loaded : %s",
					dir->d_name);
			closedir(dirp);
			return handle;
		}
	}

	closedir(dirp);

	/* load default plugin */
	handle = net_nfc_controller_load_file(NFC_MANAGER_MODULEDIR,
					NET_NFC_DEFAULT_PLUGIN);

	if (handle)
	{
		DEBUG_SERVER_MSG("loaded default plugin : %s",
				NET_NFC_DEFAULT_PLUGIN);
		return handle;
	}
	else
	{
		DEBUG_ERR_MSG("can not load default plugin : %s",
				NET_NFC_DEFAULT_PLUGIN);
		return NULL;
	}
}

bool net_nfc_controller_unload(void *handle)
{
	memset(&g_interface, 0x00, sizeof(net_nfc_oem_interface_s));

	if (handle != NULL)
	{
		dlclose(handle);
		handle = NULL;
	}
	return true;
}

bool net_nfc_controller_init(net_nfc_error_e *result)
{
	if (g_interface.init != NULL)
	{
		return g_interface.init(result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_deinit(void)
{
	if (g_interface.deinit != NULL)
	{
		return g_interface.deinit();
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_register_listener(target_detection_listener_cb target_detection_listener,
	se_transaction_listener_cb se_transaction_listener, llcp_event_listener_cb llcp_event_listener,
	hce_apdu_listener_cb hce_apdu_listener, net_nfc_error_e *result)
{
	if (g_interface.register_listener != NULL)
	{
		return g_interface.register_listener(target_detection_listener, se_transaction_listener,
			llcp_event_listener, hce_apdu_listener, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_unregister_listener()
{
	if (g_interface.unregister_listener != NULL)
	{
		return g_interface.unregister_listener();
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_get_firmware_version(data_s **data, net_nfc_error_e *result)
{
	if (g_interface.get_firmware_version != NULL)
	{
		return g_interface.get_firmware_version(data, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_check_firmware_version(net_nfc_error_e *result)
{
	if (g_interface.check_firmware_version != NULL)
	{
		return g_interface.check_firmware_version(result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_update_firmware(net_nfc_error_e *result)
{
	if (g_interface.update_firmeware != NULL)
	{
		return g_interface.update_firmeware(result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_get_stack_information(net_nfc_stack_information_s *stack_info, net_nfc_error_e *result)
{
	if (g_interface.get_stack_information != NULL)
	{
		return g_interface.get_stack_information(stack_info, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_configure_discovery(net_nfc_discovery_mode_e mode, net_nfc_event_filter_e config, net_nfc_error_e *result)
{
	if (g_interface.configure_discovery != NULL)
	{
		return g_interface.configure_discovery(mode, config, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_get_secure_element_list(net_nfc_secure_element_info_s *list, int *count, net_nfc_error_e *result)
{
	if (g_interface.get_secure_element_list != NULL)
	{
		return g_interface.get_secure_element_list(list, count, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_set_secure_element_mode(net_nfc_secure_element_type_e element_type, net_nfc_secure_element_mode_e mode, net_nfc_error_e *result)
{
	if (g_interface.set_secure_element_mode != NULL)
	{
		return g_interface.set_secure_element_mode(element_type, mode, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_open(net_nfc_secure_element_type_e element_type, net_nfc_target_handle_s **handle, net_nfc_error_e *result)
{
	int ret_val = 0;

	ret_val = display_lock_state(LCD_NORMAL, GOTO_STATE_NOW, 0);
	if (ret_val < 0) {
		DEBUG_ERR_MSG("display_lock_state failed, [%d]", ret_val);
	}

	if (g_interface.secure_element_open != NULL)
	{
		return g_interface.secure_element_open(element_type, handle, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_get_atr(net_nfc_target_handle_s *handle, data_s **atr, net_nfc_error_e *result)
{
	if (g_interface.secure_element_get_atr != NULL)
	{
		return g_interface.secure_element_get_atr(handle, atr, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_send_apdu(net_nfc_target_handle_s *handle, data_s *command, data_s **response, net_nfc_error_e *result)
{
	if (g_interface.secure_element_send_apdu != NULL)
	{
		return g_interface.secure_element_send_apdu(handle, command, response, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_close(net_nfc_target_handle_s *handle, net_nfc_error_e *result)
{
	int ret_val = 0;

	ret_val = display_unlock_state(LCD_NORMAL, PM_RESET_TIMER);
	if (ret_val < 0) {
		DEBUG_ERR_MSG("display_unlock_state failed, [%d]", ret_val);
	}

	if (g_interface.secure_element_close != NULL)
	{
		return g_interface.secure_element_close(handle, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_check_target_presence(net_nfc_target_handle_s *handle, net_nfc_error_e *result)
{
	if (g_interface.check_presence != NULL)
	{
		return g_interface.check_presence(handle, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_connect(net_nfc_target_handle_s *handle, net_nfc_error_e *result)
{
	int ret_val = 0;

	ret_val = display_lock_state(LCD_NORMAL, GOTO_STATE_NOW, 0);

	DEBUG_SERVER_MSG("net_nfc_controller_connect display_lock_state [%d]!!", ret_val);

	if (g_interface.connect != NULL)
	{
		return g_interface.connect(handle, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_disconnect(net_nfc_target_handle_s *handle, net_nfc_error_e *result)
{
	int ret_val = 0;

	ret_val = display_unlock_state(LCD_NORMAL, PM_RESET_TIMER);

	DEBUG_ERR_MSG("net_nfc_controller_disconnect display_lock_state [%d]!!", ret_val);

	if (g_interface.disconnect != NULL)
	{
		net_nfc_server_free_target_info();

		return g_interface.disconnect(handle, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_check_ndef(net_nfc_target_handle_s *handle, uint8_t *ndef_card_state, int *max_data_size, int *real_data_size, net_nfc_error_e *result)
{
	if (g_interface.check_ndef != NULL)
	{
		return g_interface.check_ndef(handle, ndef_card_state, max_data_size, real_data_size, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_read_ndef(net_nfc_target_handle_s *handle, data_s **data, net_nfc_error_e *result)
{
	if (g_interface.read_ndef != NULL)
	{
		return g_interface.read_ndef(handle, data, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_write_ndef(net_nfc_target_handle_s *handle, data_s *data, net_nfc_error_e *result)
{
	if (g_interface.write_ndef != NULL)
	{
		return g_interface.write_ndef(handle, data, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_make_read_only_ndef(net_nfc_target_handle_s *handle, net_nfc_error_e *result)
{
	if (g_interface.make_read_only_ndef != NULL)
	{
		return g_interface.make_read_only_ndef(handle, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_format_ndef(net_nfc_target_handle_s *handle, data_s *secure_key, net_nfc_error_e *result)
{
	if (g_interface.format_ndef != NULL)
	{
		return g_interface.format_ndef(handle, secure_key, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_transceive(net_nfc_target_handle_s *handle, net_nfc_transceive_info_s *info, data_s **data, net_nfc_error_e *result)
{
	if (g_interface.transceive != NULL)
	{
		return g_interface.transceive(handle, info, data, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_exception_handler()
{
	if (g_interface.exception_handler != NULL)
	{
		return g_interface.exception_handler();
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_is_ready(net_nfc_error_e *result)
{
	if (g_interface.is_ready != NULL)
	{
		return g_interface.is_ready(result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_config(net_nfc_llcp_config_info_s *config, net_nfc_error_e *result)
{
	if (g_interface.config_llcp != NULL)
	{
		return g_interface.config_llcp(config, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_check_llcp(net_nfc_target_handle_s *handle, net_nfc_error_e *result)
{
	if (g_interface.check_llcp_status != NULL)
	{
		return g_interface.check_llcp_status(handle, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_activate_llcp(net_nfc_target_handle_s *handle, net_nfc_error_e *result)
{
	if (g_interface.activate_llcp != NULL)
	{
		return g_interface.activate_llcp(handle, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

static GSList *llcp_sockets;

static gint _compare_socket_info(gconstpointer a, gconstpointer b)
{
	int result;
	socket_info_t *info = (socket_info_t *)a;

	if (info->socket == (net_nfc_llcp_socket_t)b)
		result = 0;
	else
		result = -1;

	return result;
}

static socket_info_t *_get_socket_info(net_nfc_llcp_socket_t socket)
{
	socket_info_t *result;
	GSList *item;

	item = g_slist_find_custom(llcp_sockets, GUINT_TO_POINTER(socket),
		_compare_socket_info);
	if (item != NULL) {
		result = (socket_info_t *)item->data;
	} else {
		result = NULL;
	}

	return result;
}

static socket_info_t *_add_socket_info(net_nfc_llcp_socket_t socket)
{
	socket_info_t *result;

	_net_nfc_util_alloc_mem(result, sizeof(*result));
	if (result != NULL) {
		result->socket = socket;

		llcp_sockets = g_slist_append(llcp_sockets, result);
	}

	return result;
}

static void _remove_socket_info(net_nfc_llcp_socket_t socket)
{
	GSList *item;

	item = g_slist_find_custom(llcp_sockets, GUINT_TO_POINTER(socket),
		_compare_socket_info);
	if (item != NULL) {
		llcp_sockets = g_slist_remove_link(llcp_sockets, item);
		free(item->data);
	}
}

static void _destroy_function(gpointer data)
{
	free(data);
}

static void _clear_socket_info()
{
	g_slist_free_full(llcp_sockets, _destroy_function);
	llcp_sockets = NULL;
}

void net_nfc_controller_llcp_socket_error_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result, void *data, void *user_param)
{
	socket_info_t *info;

	info = _get_socket_info(socket);
	if (info != NULL) {
		if (info->err_cb != NULL) {
			info->err_cb(socket, result, NULL, NULL, info->err_param);
		}

		_remove_socket_info(socket);
	}
}

bool net_nfc_controller_llcp_create_socket(net_nfc_llcp_socket_t *socket, net_nfc_socket_type_e socketType, uint16_t miu, uint8_t rw, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	if (g_interface.create_llcp_socket != NULL)
	{
		bool ret;
		socket_info_t *info;

		info = _add_socket_info(-1);
		if (info == NULL) {
			DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		ret = g_interface.create_llcp_socket(socket, socketType, miu, rw, result, NULL);
		if (ret == true) {
			info->socket = *socket;
			info->err_cb = cb;
			info->err_param = user_param;
		} else {
			_remove_socket_info(-1);
		}

		return ret;
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_bind(net_nfc_llcp_socket_t socket, uint8_t service_access_point, net_nfc_error_e *result)
{
	if (g_interface.bind_llcp_socket != NULL)
	{
		return g_interface.bind_llcp_socket(socket, service_access_point, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

void net_nfc_controller_llcp_incoming_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result, void *data, void *user_param)
{
	socket_info_t *info = (socket_info_t *)user_param;

	info = _get_socket_info(info->socket);
	if (info != NULL) {
		if (_add_socket_info(socket) != NULL) {
			if (info->work_cb != NULL) {
				info->work_cb(socket, result, NULL, NULL,
					info->work_param);
			}
		} else {
			DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
		}
	}
}

bool net_nfc_controller_llcp_listen(net_nfc_target_handle_s* handle, uint8_t *service_access_name, net_nfc_llcp_socket_t socket, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	if (g_interface.listen_llcp_socket != NULL)
	{
		socket_info_t *info;

		info = _get_socket_info(socket);
		if (info == NULL) {
			DEBUG_ERR_MSG("_get_socket_info failed");
			*result = NET_NFC_INVALID_HANDLE;
			return false;
		}

		info->work_cb = cb;
		info->work_param = user_param;

		return g_interface.listen_llcp_socket(handle, service_access_name, socket, result, info);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_accept(net_nfc_llcp_socket_t socket, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	if (g_interface.accept_llcp_socket != NULL)
	{
		socket_info_t *info;

		info = _get_socket_info(socket);
		if (info == NULL) {
			DEBUG_ERR_MSG("_get_socket_info failed");
			*result = NET_NFC_INVALID_HANDLE;
			return false;
		}

		info->err_cb = cb;
		info->err_param = user_param;

		return g_interface.accept_llcp_socket(socket, result, NULL);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_reject(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, net_nfc_error_e *result)
{
	if (g_interface.reject_llcp != NULL)
	{
		bool ret;

		ret = g_interface.reject_llcp(handle, socket, result);
		if (ret == true) {
			_remove_socket_info(socket);
		}

		return ret;
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

void net_nfc_controller_llcp_connected_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result, void *data, void *user_param)
{
	net_nfc_llcp_param_t *param = (net_nfc_llcp_param_t *)user_param;

	if (param == NULL)
		return;

	if (param->cb != NULL) {
		param->cb(param->socket, result, NULL, NULL, param->user_param);
	}

	_net_nfc_util_free_mem(param);
}

bool net_nfc_controller_llcp_connect_by_url(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, uint8_t *service_access_name, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	int ret_val = 0;
	bool ret;

	ret_val = display_lock_state(LCD_NORMAL, GOTO_STATE_NOW, 0);

	DEBUG_SERVER_MSG("net_nfc_controller_llcp_connect_by_url display_lock_state [%d]!!", ret_val);

	if (g_interface.connect_llcp_by_url != NULL)
	{
		net_nfc_llcp_param_t *param = NULL;

		_net_nfc_util_alloc_mem(param, sizeof(*param));
		if (param == NULL) {
			DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		param->socket = socket;
		param->cb = cb;
		param->user_param = user_param;

		ret = g_interface.connect_llcp_by_url(handle, socket, service_access_name, result, param);
		if (ret != true) {
			_remove_socket_info(socket);
		}
		return ret;
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_connect(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, uint8_t service_access_point, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	int ret_val = 0;

	ret_val = display_lock_state(LCD_NORMAL, GOTO_STATE_NOW, 0);

	DEBUG_SERVER_MSG("net_nfc_controller_llcp_connect display_lock_state [%d]!!", ret_val);

	if (g_interface.connect_llcp != NULL)
	{
		net_nfc_llcp_param_t *param = NULL;

		_net_nfc_util_alloc_mem(param, sizeof(*param));
		if (param == NULL) {
			DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		param->socket = socket;
		param->cb = cb;
		param->user_param = user_param;

		return g_interface.connect_llcp(handle, socket, service_access_point, result, param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

void net_nfc_controller_llcp_disconnected_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result, void *data, void *user_param)
{
	net_nfc_llcp_param_t *param = (net_nfc_llcp_param_t *)user_param;

	if (param == NULL)
		return;

	if (param->cb != NULL) {
		param->cb(param->socket, result, NULL, NULL, param->user_param);
	}

	_net_nfc_util_free_mem(param);
}

bool net_nfc_controller_llcp_disconnect(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	int ret_val = 0;

	ret_val = display_unlock_state(LCD_NORMAL, PM_RESET_TIMER);

	DEBUG_SERVER_MSG("net_nfc_controller_llcp_disconnect display_unlock_state [%d]!!", ret_val);

	if (g_interface.disconnect_llcp != NULL)
	{
		net_nfc_llcp_param_t *param = NULL;

		_net_nfc_util_alloc_mem(param, sizeof(*param));
		if (param == NULL) {
			DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		param->socket = socket;
		param->cb = cb;
		param->user_param = user_param;

		return g_interface.disconnect_llcp(handle, socket, result, param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_socket_close(net_nfc_llcp_socket_t socket, net_nfc_error_e *result)
{
	if (g_interface.close_llcp_socket != NULL)
	{
		return g_interface.close_llcp_socket(socket, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

void net_nfc_controller_llcp_received_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result, void *data, void *user_param)
{
	net_nfc_llcp_param_t *param = (net_nfc_llcp_param_t *)user_param;

	if (param == NULL)
		return;

	if (param->cb != NULL) {
		param->cb(param->socket, result, &param->data, data, param->user_param);
	}

	_net_nfc_util_free_mem(param);
}

bool net_nfc_controller_llcp_recv(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, uint32_t max_len, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	if (g_interface.recv_llcp != NULL)
	{
		net_nfc_llcp_param_t *param = NULL;

		_net_nfc_util_alloc_mem(param, sizeof(*param));
		if (param == NULL) {
			DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		param->socket = socket;
		param->cb = cb;
		if (max_len > 0) {
			if (net_nfc_util_init_data(&param->data, max_len) == false) {
				DEBUG_ERR_MSG("net_nfc_util_init_data failed");
				_net_nfc_util_free_mem(param);
				*result = NET_NFC_ALLOC_FAIL;
				return false;
			}
			param->data.length = max_len;
		}
		param->user_param = user_param;

		return g_interface.recv_llcp(handle, socket, &param->data, result, param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

void net_nfc_controller_llcp_sent_cb(net_nfc_llcp_socket_t socket,
	net_nfc_error_e result, void *data, void *user_param)
{
	net_nfc_llcp_param_t *param = (net_nfc_llcp_param_t *)user_param;

	if (param == NULL)
		return;

	if (param->cb != NULL) {
		param->cb(param->socket, result, NULL, NULL, param->user_param);
	}

	_net_nfc_util_free_mem(param);
}

bool net_nfc_controller_llcp_send(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, data_s *data, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	if (g_interface.send_llcp != NULL)
	{
		net_nfc_llcp_param_t *param = NULL;

		_net_nfc_util_alloc_mem(param, sizeof(*param));
		if (param == NULL) {
			DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		param->socket = socket;
		param->cb = cb;
		param->user_param = user_param;

		return g_interface.send_llcp(handle, socket, data, result, param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_recv_from(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, uint32_t max_len, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	if (g_interface.recv_from_llcp != NULL)
	{
		net_nfc_llcp_param_t *param = NULL;

		_net_nfc_util_alloc_mem(param, sizeof(*param));
		if (param == NULL) {
			DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		param->socket = socket;
		param->cb = cb;
		if (max_len > 0) {
			if (net_nfc_util_init_data(&param->data, max_len) == false) {
				DEBUG_ERR_MSG("net_nfc_util_init_data failed");
				_net_nfc_util_free_mem(param);
				*result = NET_NFC_ALLOC_FAIL;
				return false;
			}
			param->data.length = max_len;
		}
		param->user_param = user_param;

		return g_interface.recv_from_llcp(handle, socket, &param->data, result, param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_send_to(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, data_s *data, uint8_t service_access_point, net_nfc_error_e *result, net_nfc_service_llcp_cb cb, void *user_param)
{
	if (g_interface.send_to_llcp != NULL)
	{
		net_nfc_llcp_param_t *param = NULL;

		_net_nfc_util_alloc_mem(param, sizeof(*param));
		if (param == NULL) {
			DEBUG_ERR_MSG("_net_nfc_util_alloc_mem failed");
			*result = NET_NFC_ALLOC_FAIL;
			return false;
		}

		param->socket = socket;
		param->cb = cb;
		param->user_param = user_param;

		return g_interface.send_to_llcp(handle, socket, data, service_access_point, result, param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_get_remote_config(net_nfc_target_handle_s *handle, net_nfc_llcp_config_info_s *config, net_nfc_error_e *result)
{
	if (g_interface.get_remote_config != NULL)
	{
		return g_interface.get_remote_config(handle, config, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_get_remote_socket_info(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_option_s *option, net_nfc_error_e *result)
{
	if (g_interface.get_remote_socket_info != NULL)
	{
		return g_interface.get_remote_socket_info(handle, socket, option, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}

}

bool net_nfc_controller_sim_test(net_nfc_error_e *result)
{
	if (g_interface.sim_test != NULL)
	{
		return g_interface.sim_test(result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_prbs_test(net_nfc_error_e *result, uint32_t tech, uint32_t rate)
{
	if (g_interface.prbs_test != NULL)
	{
		return g_interface.prbs_test(result, tech, rate);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_test_mode_on(net_nfc_error_e *result)
{
	if (g_interface.test_mode_on != NULL)
	{
		return g_interface.test_mode_on(result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_test_mode_off(net_nfc_error_e *result)
{
	if (g_interface.test_mode_off != NULL)
	{
		return g_interface.test_mode_off(result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_support_nfc(net_nfc_error_e *result)
{
	if (g_interface.support_nfc != NULL)
	{
		return g_interface.support_nfc(result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_eedata_register_set(net_nfc_error_e *result, uint32_t mode, uint32_t reg_id, data_s *data)
{
	if (g_interface.eedata_register_set != NULL)
	{
		return g_interface.eedata_register_set(result, mode, reg_id, data);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_ese_test(net_nfc_error_e *result)
{
	if (g_interface.ese_test != NULL)
	{
		return g_interface.ese_test(result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("NFC ESE TEST interface is null");
		return false;
	}
}

bool net_nfc_controller_test_set_se_tech_type(net_nfc_error_e *result, net_nfc_se_type_e type, uint32_t tech)
{
	if (g_interface.test_set_se_tech_type != NULL)
	{
		return g_interface.test_set_se_tech_type(result, type, tech);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_ERR_MSG("interface is null");

		return false;
	}
}
#if 0
bool net_nfc_controller_hce_listener(hce_active_listener_cb hce_active_listener, hce_deactive_listener_cb hce_deactive_listener, hce_apdu_listener_cb hce_apdu_listener, net_nfc_error_e *result)
{
	if (g_interface.register_hce_listener != NULL)
	{
		return g_interface.register_hce_listener(hce_active_listener, hce_deactive_listener, hce_apdu_listener, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
#endif
bool net_nfc_controller_hce_response_apdu(net_nfc_target_handle_s *handle, data_s *response, net_nfc_error_e *result)
{
	if (g_interface.hce_response_apdu != NULL)
	{
		return g_interface.hce_response_apdu(handle, response, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_route_aid(data_s *aid, net_nfc_se_type_e se_type, int power, net_nfc_error_e *result)
{
	if (g_interface.route_aid != NULL)
	{
		return g_interface.route_aid(aid, se_type, power, result);
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_unroute_aid(data_s *aid, net_nfc_error_e *result)
{
	if (g_interface.unroute_aid != NULL)
	{
		return g_interface.unroute_aid(aid, result);
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_commit_routing(net_nfc_error_e *result)
{
	if (g_interface.commit_routing != NULL)
	{
		return g_interface.commit_routing(result);
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_set_default_route(
	net_nfc_se_type_e switch_on,
	net_nfc_se_type_e switch_off,
	net_nfc_se_type_e battery_off, net_nfc_error_e *result)
{
	if (g_interface.set_default_route != NULL)
	{
		return g_interface.set_default_route(switch_on, switch_off, battery_off, result);
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_clear_aid_table(net_nfc_error_e *result)
{
	if (g_interface.clear_aid_table != NULL)
	{
		return g_interface.clear_aid_table(result);
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_get_aid_table_size(int *AIDTableSize, net_nfc_error_e *result)
{
	if (g_interface.get_aid_tablesize != NULL)
	{
		return g_interface.get_aid_tablesize(AIDTableSize, result);
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_set_route_entry
	(net_nfc_se_entry_type_e type, net_nfc_se_tech_protocol_type_e value, net_nfc_se_type_e route, int power, net_nfc_error_e *result)
{
	if (g_interface.set_routing_entry != NULL)
	{
		return g_interface.set_routing_entry(type, value, route, power, result);
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_secure_element_set_clear_routing_entry
	(net_nfc_se_entry_type_e type, net_nfc_error_e *result)
{
	if (g_interface.clear_routing_entry != NULL)
	{
		return g_interface.clear_routing_entry(type, result);
	}
	else
	{
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_set_screen_state(net_nfc_screen_state_type_e screen_state, net_nfc_error_e *result)
{
	if (g_interface.set_screen_state!= NULL)
	{
		return g_interface.set_screen_state(screen_state , result);
	}
	else
	{
		*result = NET_NFC_UNKNOWN_ERROR;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
