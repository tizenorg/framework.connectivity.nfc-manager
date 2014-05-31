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
#include <dlfcn.h>
#include <unistd.h>

#include <pmapi.h>/*for pm lock*/

#include "net_nfc_oem_controller.h"
#include "net_nfc_controller_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_server_ipc_private.h"
#include "net_nfc_server_dispatcher_private.h"

#define NET_NFC_OEM_LIBRARY_PATH "/usr/lib/libnfc-plugin.so"

static net_nfc_oem_interface_s g_interface;

void *net_nfc_controller_onload()
{
	void* handle = NULL;
	bool (*onload)(net_nfc_oem_interface_s *interfaces);

	FILE *fp;
	char cpuinfo_buffer[1024] = { 0, };
	size_t bytes_read;
	char *match_revision;
	int revision;
	char *token;
	char *token_cpuinfo[10];
	int i = 0;
	const char *library_path;

	fp = fopen("/proc/cpuinfo", "r");
	bytes_read = fread(cpuinfo_buffer, 1, sizeof(cpuinfo_buffer) - 1, fp);/* Read the cpuinfo to bytes_read */
	fclose(fp);

	match_revision = strstr(cpuinfo_buffer, "Hardware");
	if (match_revision != NULL)
	{
		token = strtok(match_revision, " :\n");

		while (token != NULL && i < 5)
		{
			i++;
			DEBUG_SERVER_MSG("token = %s", token);

			token = strtok(NULL, " :\n");

			token_cpuinfo[i] = token;
			DEBUG_SERVER_MSG("temp[%d]'s value = %s", i, token_cpuinfo[i]);
		}

		revision = strtol(token_cpuinfo[3], 0, 16);
		DEBUG_SERVER_MSG("revision = %d", revision);

		if ((!(strncmp(token_cpuinfo[1], "SLP_PQ", 6)) && (revision >= 7))) //|| !(strncmp(token_cpuinfo[1] , "REDWOOD" , 7)))
		{
			DEBUG_SERVER_MSG("It's SLP_PQ && Revision 7!! || REDWOOD revC.");
			library_path = "/usr/lib/libnfc-plugin-65nxp.so";

		}
		else if (!(strncmp(token_cpuinfo[1], "REDWOOD", 7)))
		{
			DEBUG_SERVER_MSG("It's REDWOOD revC.");
			library_path = "/usr/lib/libnfc-plugin-lsi.so";
		}
		else
		{
			DEBUG_SERVER_MSG("It's NOT!!!! SLP_PQ && Revision 7!!");
			library_path = "/usr/lib/libnfc-plugin.so";
		}
	}
	else
	{
		DEBUG_SERVER_MSG("It doesn't have Hardware info!!");
		library_path = "/usr/lib/libnfc-plugin.so";
	}

	if ((handle = dlopen(library_path/*NET_NFC_OEM_LIBRARY_PATH*/, RTLD_LAZY)) != NULL)
	{
		if ((onload = dlsym(handle, "onload")) != NULL)
		{
			if (onload(&g_interface) == true)
			{
				DEBUG_SERVER_MSG("success to load library");
				return handle;
			}
			else
			{
				DEBUG_ERR_MSG("failed to load library");
			}
		}
		else
		{
			DEBUG_ERR_MSG("can not find symbol onload");
		}

		dlclose(handle);
		handle = NULL;
	}
	else
	{
		DEBUG_ERR_MSG("dlopen is failed");
	}

	return handle;
}

bool net_nfc_controller_unload(void* handle)
{
	memset(&g_interface, 0x00, sizeof(net_nfc_oem_interface_s));

	if (handle != NULL)
	{
		dlclose(handle);
		handle = NULL;
	}
	return true;
}

bool net_nfc_controller_init(net_nfc_error_e* result)
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
	se_transaction_listener_cb se_transaction_listener, llcp_event_listener_cb llcp_event_listener, net_nfc_error_e* result)
{
	if (g_interface.register_listener != NULL)
	{
		return g_interface.register_listener(target_detection_listener, se_transaction_listener, llcp_event_listener, result);
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

bool net_nfc_controller_check_firmware_version(net_nfc_error_e* result)
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

bool net_nfc_controller_update_firmware(net_nfc_error_e* result)
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

bool net_nfc_controller_get_stack_information(net_nfc_stack_information_s* stack_info, net_nfc_error_e* result)
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

bool net_nfc_controller_confiure_discovery(net_nfc_discovery_mode_e mode, net_nfc_event_filter_e config, net_nfc_error_e* result)
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

bool net_nfc_controller_get_secure_element_list(net_nfc_secure_element_info_s* list, int* count, net_nfc_error_e* result)
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

bool net_nfc_controller_set_secure_element_mode(net_nfc_secure_element_type_e element_type, net_nfc_secure_element_mode_e mode, net_nfc_error_e* result)
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

	ret_val = pm_lock_state(LCD_NORMAL, GOTO_STATE_NOW, 0);

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

	ret_val = pm_unlock_state(LCD_NORMAL, PM_RESET_TIMER);

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

bool net_nfc_controller_check_target_presence(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
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

bool net_nfc_controller_connect(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
{
	int ret_val = 0;

	ret_val = pm_lock_state(LCD_NORMAL, GOTO_STATE_NOW, 0);

	DEBUG_SERVER_MSG("net_nfc_controller_connect pm_lock_state [%d]!!", ret_val);

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

bool net_nfc_controller_disconnect(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
{
	int ret_val = 0;

	ret_val = pm_unlock_state(LCD_NORMAL, PM_RESET_TIMER);

	DEBUG_ERR_MSG("net_nfc_controller_disconnect pm_lock_state [%d]!!", ret_val);

	if (g_interface.disconnect != NULL)
	{
		net_nfc_server_free_current_tag_info();

		return g_interface.disconnect(handle, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_check_ndef(net_nfc_target_handle_s* handle, uint8_t *ndef_card_state, int* max_data_size, int* real_data_size, net_nfc_error_e* result)
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

bool net_nfc_controller_read_ndef(net_nfc_target_handle_s* handle, data_s** data, net_nfc_error_e* result)
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

bool net_nfc_controller_write_ndef(net_nfc_target_handle_s* handle, data_s* data, net_nfc_error_e* result)
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

bool net_nfc_controller_make_read_only_ndef(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
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

bool net_nfc_controller_format_ndef(net_nfc_target_handle_s* handle, data_s* secure_key, net_nfc_error_e* result)
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

bool net_nfc_controller_transceive(net_nfc_target_handle_s* handle, net_nfc_transceive_info_s* info, data_s** data, net_nfc_error_e* result)
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

bool net_nfc_controller_is_ready(net_nfc_error_e* result)
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

bool net_nfc_controller_llcp_config(net_nfc_llcp_config_info_s * config, net_nfc_error_e* result)
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
bool net_nfc_controller_llcp_check_llcp(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
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
bool net_nfc_controller_llcp_activate_llcp(net_nfc_target_handle_s* handle, net_nfc_error_e* result)
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
bool net_nfc_controller_llcp_create_socket(net_nfc_llcp_socket_t* socket, net_nfc_socket_type_e socketType, uint16_t miu, uint8_t rw, net_nfc_error_e* result, void * user_param)
{
	if (g_interface.create_llcp_socket != NULL)
	{
		return g_interface.create_llcp_socket(socket, socketType, miu, rw, result, user_param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_bind(net_nfc_llcp_socket_t socket, uint8_t service_access_point, net_nfc_error_e* result)
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
bool net_nfc_controller_llcp_listen(net_nfc_target_handle_s* handle, uint8_t* service_access_name, net_nfc_llcp_socket_t socket, net_nfc_error_e* result, void * user_param)
{
	if (g_interface.listen_llcp_socket != NULL)
	{
		return g_interface.listen_llcp_socket(handle, service_access_name, socket, result, user_param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_accept(net_nfc_llcp_socket_t socket, net_nfc_error_e* result)
{
	if (g_interface.accept_llcp_socket != NULL)
	{
		return g_interface.accept_llcp_socket(socket, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_reject(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, net_nfc_error_e* result)
{
	if (g_interface.reject_llcp != NULL)
	{
		return g_interface.reject_llcp(handle, socket, result);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_connect_by_url(net_nfc_target_handle_s * handle, net_nfc_llcp_socket_t socket, uint8_t* service_access_name, net_nfc_error_e* result, void * user_param)
{
	int ret_val = 0;

	ret_val = pm_lock_state(LCD_NORMAL, GOTO_STATE_NOW, 0);

	DEBUG_SERVER_MSG("net_nfc_controller_llcp_connect_by_url pm_lock_state [%d]!!", ret_val);

	if (g_interface.connect_llcp_by_url != NULL)
	{
		return g_interface.connect_llcp_by_url(handle, socket, service_access_name, result, user_param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_connect(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, uint8_t service_access_point, net_nfc_error_e* result, void * user_param)
{
	int ret_val = 0;

	ret_val = pm_lock_state(LCD_NORMAL, GOTO_STATE_NOW, 0);

	DEBUG_SERVER_MSG("net_nfc_controller_llcp_connect pm_lock_state [%d]!!", ret_val);

	if (g_interface.connect_llcp != NULL)
	{
		return g_interface.connect_llcp(handle, socket, service_access_point, result, user_param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_disconnect(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, net_nfc_error_e* result, void * user_param)
{
	int ret_val = 0;

	ret_val = pm_unlock_state(LCD_NORMAL, PM_RESET_TIMER);

	DEBUG_SERVER_MSG("net_nfc_controller_llcp_disconnect pm_lock_state [%d]!!", ret_val);

	if (g_interface.disconnect_llcp != NULL)
	{
		return g_interface.disconnect_llcp(handle, socket, result, user_param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_socket_close(net_nfc_llcp_socket_t socket, net_nfc_error_e* result)
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
bool net_nfc_controller_llcp_recv(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, data_s* data, net_nfc_error_e* result, void * user_param)
{
	if (g_interface.recv_llcp != NULL)
	{
		return g_interface.recv_llcp(handle, socket, data, result, user_param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_send(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, data_s* data, net_nfc_error_e* result, void * user_param)
{
	if (g_interface.send_llcp != NULL)
	{
		return g_interface.send_llcp(handle, socket, data, result, user_param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_recv_from(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, data_s* data, net_nfc_error_e* result, void * user_param)
{
	if (g_interface.recv_from_llcp != NULL)
	{
		return g_interface.recv_from_llcp(handle, socket, data, result, user_param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}
bool net_nfc_controller_llcp_send_to(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, data_s* data, uint8_t service_access_point, net_nfc_error_e* result, void * user_param)
{
	if (g_interface.send_to_llcp != NULL)
	{
		return g_interface.send_to_llcp(handle, socket, data, service_access_point, result, user_param);
	}
	else
	{
		*result = NET_NFC_DEVICE_DOES_NOT_SUPPORT_NFC;
		DEBUG_SERVER_MSG("interface is null");
		return false;
	}
}

bool net_nfc_controller_llcp_get_remote_config(net_nfc_target_handle_s* handle, net_nfc_llcp_config_info_s *config, net_nfc_error_e* result)
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
bool net_nfc_controller_llcp_get_remote_socket_info(net_nfc_target_handle_s* handle, net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_option_s * option, net_nfc_error_e* result)
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

bool net_nfc_controller_sim_test(net_nfc_error_e* result)
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

bool net_nfc_controller_prbs_test(net_nfc_error_e* result, uint32_t tech, uint32_t rate)
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

bool net_nfc_controller_test_mode_on(net_nfc_error_e* result)
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

bool net_nfc_controller_test_mode_off(net_nfc_error_e* result)
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

bool net_nfc_controller_support_nfc(net_nfc_error_e* result)
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

