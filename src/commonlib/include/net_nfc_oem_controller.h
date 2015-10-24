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

#ifndef __NET_NFC_OEM_CONTROLLER_H__
#define __NET_NFC_OEM_CONTROLLER_H__

#include "net_nfc_typedef_internal.h"

typedef bool (*net_nfc_oem_controller_init)(net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_deinit)(void);
typedef bool (*net_nfc_oem_controller_register_listener)(target_detection_listener_cb target_detection_listener, se_transaction_listener_cb se_transaction_listener, llcp_event_listener_cb llcp_event_listener, hce_apdu_listener_cb hce_apdu_listener, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_unregister_listener)(void);
typedef bool (*net_nfc_oem_controller_support_nfc)(net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_get_firmware_version)(data_s **data, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_check_firmware_version)(net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_update_firmware)(net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_get_stack_information)(net_nfc_stack_information_s *stack_info, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_configure_discovery)(net_nfc_discovery_mode_e mode, net_nfc_event_filter_e config, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_exception_handler)(void);

/* tag api */
typedef bool (*net_nfc_oem_controller_connect)(net_nfc_target_handle_s *handle, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_disconnect)(net_nfc_target_handle_s *handle, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_check_target_presence)(net_nfc_target_handle_s *handle, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_check_ndef)(net_nfc_target_handle_s *handle, uint8_t *ndef_card_state, int *max_data_size, int *real_data_size, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_read_ndef)(net_nfc_target_handle_s *handle, data_s **data, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_write_ndef)(net_nfc_target_handle_s *handle, data_s *data, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_make_read_only_ndef)(net_nfc_target_handle_s *handle, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_format_ndef)(net_nfc_target_handle_s *handle, data_s *secure_key, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_transceive)(net_nfc_target_handle_s *handle, net_nfc_transceive_info_s *info, data_s **data, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_is_ready)(net_nfc_error_e *result);

/* llcp api */
typedef bool (*net_nfc_oem_controller_llcp_config)(net_nfc_llcp_config_info_s *config, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_llcp_check_llcp)(net_nfc_target_handle_s *handle, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_llcp_activate_llcp)(net_nfc_target_handle_s *handle, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_llcp_create_socket)(net_nfc_llcp_socket_t *socket, net_nfc_socket_type_e socketType, uint16_t miu, uint8_t rw, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_bind)(net_nfc_llcp_socket_t socket, uint8_t service_access_point, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_llcp_listen)(net_nfc_target_handle_s *handle, uint8_t *service_access_name, net_nfc_llcp_socket_t socket, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_accept)(net_nfc_llcp_socket_t socket, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_connect_by_url)(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, uint8_t *service_access_name, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_connect)(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, uint8_t service_access_point, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_disconnect)(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_socket_close)(net_nfc_llcp_socket_t socket, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_llcp_recv)(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, data_s *data, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_send)(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, data_s *data, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_recv_from)(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, data_s *data, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_send_to)(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, data_s *data, uint8_t service_access_point, net_nfc_error_e *result, void *user_param);
typedef bool (*net_nfc_oem_controller_llcp_reject)(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_llcp_get_remote_config)(net_nfc_target_handle_s *handle, net_nfc_llcp_config_info_s *config, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_llcp_get_remote_socket_info)(net_nfc_target_handle_s *handle, net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_option_s *option, net_nfc_error_e *result);

/* secure element api */
typedef bool (*net_nfc_oem_controller_get_secure_element_list)(net_nfc_secure_element_info_s *list, int* count, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_set_secure_element_mode)(net_nfc_secure_element_type_e element_type, net_nfc_secure_element_mode_e mode, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_secure_element_open)(net_nfc_secure_element_type_e element_type, net_nfc_target_handle_s **handle, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_secure_element_get_atr)(net_nfc_target_handle_s *handle, data_s **atr, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_secure_element_send_apdu)(net_nfc_target_handle_s *handle, data_s *command, data_s **response, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_secure_element_close)(net_nfc_target_handle_s *handle, net_nfc_error_e *result);

/* test api */
typedef bool (*net_nfc_oem_controller_sim_test)(net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_prbs_test)(net_nfc_error_e *result , int tech , int rate);
typedef bool (*net_nfc_oem_controller_test_mode_on)(net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_test_mode_off)(net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_eedata_register_set)(net_nfc_error_e *result , uint32_t mode , uint32_t reg_id , data_s *data);
typedef bool (*net_nfc_oem_controller_ese_test)(net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_test_set_se_tech_type)(net_nfc_error_e *result, net_nfc_se_type_e type, uint32_t tech);

/* hce api*/
typedef bool (*net_nfc_oem_controller_hce_response_apdu)(net_nfc_target_handle_s *handle, data_s *command, net_nfc_error_e *result);

typedef bool (*net_nfc_oem_controller_secure_element_route_aid)(data_s *aid, net_nfc_se_type_e se_type,
	int power, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_secure_element_unroute_aid)(data_s *aid, net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_secure_element_commit_routing)(net_nfc_error_e *result);

typedef bool (*net_nfc_oem_controller_secure_element_set_default_route)(
	net_nfc_se_type_e switch_on,
	net_nfc_se_type_e switch_off,
	net_nfc_se_type_e battery_off, net_nfc_error_e *result);

typedef bool (*net_nfc_oem_controller_secure_element_clear_aid_table)(net_nfc_error_e *result);
typedef bool (*net_nfc_oem_controller_secure_element_get_aid_tablesize)(int *AIDTableSize,
	net_nfc_error_e *result);

typedef bool (*net_nfc_oem_controller_secure_element_set_route_entry)
	(net_nfc_se_entry_type_e type, net_nfc_se_tech_protocol_type_e value,
	net_nfc_se_type_e route, int power, net_nfc_error_e *result);

typedef bool (*net_nfc_oem_controller_secure_element_clear_routing_entry)
	(net_nfc_se_entry_type_e type, net_nfc_error_e *result);

typedef bool (*net_nfc_oem_controller_set_screen_state)
	(net_nfc_screen_state_type_e screen_state, net_nfc_error_e *result);



typedef struct _net_nfc_oem_interface_s
{
	net_nfc_oem_controller_init init;
	net_nfc_oem_controller_deinit deinit;
	net_nfc_oem_controller_register_listener register_listener;
	net_nfc_oem_controller_unregister_listener unregister_listener;
	net_nfc_oem_controller_get_firmware_version get_firmware_version;
	net_nfc_oem_controller_check_firmware_version check_firmware_version;
	net_nfc_oem_controller_update_firmware update_firmeware;
	net_nfc_oem_controller_get_stack_information get_stack_information;
	net_nfc_oem_controller_configure_discovery configure_discovery;
	net_nfc_oem_controller_get_secure_element_list get_secure_element_list;
	net_nfc_oem_controller_set_secure_element_mode set_secure_element_mode;
	net_nfc_oem_controller_connect connect;
	net_nfc_oem_controller_connect disconnect;
	net_nfc_oem_controller_check_ndef check_ndef;
	net_nfc_oem_controller_check_target_presence check_presence;
	net_nfc_oem_controller_read_ndef read_ndef;
	net_nfc_oem_controller_write_ndef write_ndef;
	net_nfc_oem_controller_make_read_only_ndef make_read_only_ndef;
	net_nfc_oem_controller_transceive transceive;
	net_nfc_oem_controller_format_ndef format_ndef;
	net_nfc_oem_controller_exception_handler exception_handler;
	net_nfc_oem_controller_is_ready is_ready;

	net_nfc_oem_controller_llcp_config config_llcp;
	net_nfc_oem_controller_llcp_check_llcp check_llcp_status;
	net_nfc_oem_controller_llcp_activate_llcp activate_llcp;
	net_nfc_oem_controller_llcp_create_socket create_llcp_socket;
	net_nfc_oem_controller_llcp_bind bind_llcp_socket;
	net_nfc_oem_controller_llcp_listen listen_llcp_socket;
	net_nfc_oem_controller_llcp_accept accept_llcp_socket;
	net_nfc_oem_controller_llcp_connect_by_url connect_llcp_by_url;
	net_nfc_oem_controller_llcp_connect connect_llcp;
	net_nfc_oem_controller_llcp_disconnect disconnect_llcp;
	net_nfc_oem_controller_llcp_socket_close close_llcp_socket;
	net_nfc_oem_controller_llcp_recv recv_llcp;
	net_nfc_oem_controller_llcp_send send_llcp;
	net_nfc_oem_controller_llcp_recv_from recv_from_llcp;
	net_nfc_oem_controller_llcp_send_to send_to_llcp;
	net_nfc_oem_controller_llcp_reject reject_llcp;
	net_nfc_oem_controller_llcp_get_remote_config get_remote_config;
	net_nfc_oem_controller_llcp_get_remote_socket_info get_remote_socket_info;

	net_nfc_oem_controller_sim_test sim_test;
	net_nfc_oem_controller_prbs_test prbs_test;
	net_nfc_oem_controller_test_mode_on test_mode_on;
	net_nfc_oem_controller_test_mode_off test_mode_off;
	net_nfc_oem_controller_ese_test ese_test;

	net_nfc_oem_controller_support_nfc support_nfc;
	net_nfc_oem_controller_eedata_register_set eedata_register_set;

	net_nfc_oem_controller_secure_element_open secure_element_open;
	net_nfc_oem_controller_secure_element_get_atr secure_element_get_atr;
	net_nfc_oem_controller_secure_element_send_apdu secure_element_send_apdu;
	net_nfc_oem_controller_secure_element_close secure_element_close;

	net_nfc_oem_controller_test_set_se_tech_type test_set_se_tech_type;

	net_nfc_oem_controller_hce_response_apdu hce_response_apdu;
	net_nfc_oem_controller_secure_element_route_aid route_aid;
	net_nfc_oem_controller_secure_element_unroute_aid unroute_aid;
	net_nfc_oem_controller_secure_element_commit_routing commit_routing;
	net_nfc_oem_controller_secure_element_set_default_route set_default_route;
	net_nfc_oem_controller_secure_element_clear_aid_table clear_aid_table;
	net_nfc_oem_controller_secure_element_get_aid_tablesize get_aid_tablesize;


	net_nfc_oem_controller_secure_element_set_route_entry set_routing_entry;
	net_nfc_oem_controller_secure_element_clear_routing_entry clear_routing_entry;
	net_nfc_oem_controller_set_screen_state set_screen_state;
} net_nfc_oem_interface_s;

#endif //__NET_NFC_OEM_CONTROLLER_H__
