/*
  * Copyright 2012  Samsung Electronics Co., Ltd
  *
  * Licensed under the Flora License, Version 1.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://www.tizenopensource.org/license
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */


#ifndef __NET_NFC_LLCP_H__
#define __NET_NFC_LLCP_H__

#include "net_nfc_typedef.h"

#ifdef __cplusplus
  extern "C" {
#endif

/**

@addtogroup NET_NFC_MANAGER_LLCP
@{
	This document is for the APIs reference document

        NFC Manager defines are defined in <nfc-manager-def.h>

        @li @c #net_nfc_initialize                  Initialize the nfc device.

*/

/**

	This function creates a socket can handle connection oriented or connectless connection. To create the socket, socket option should be specified.
	The option structure has three attributes.

	\par Sync (or) Async: Async

	@param[out]		socket		The socket handler that generated by this function
	@param[in]		options		This describe the socket types (MIU, RW, Connection type) please, refer the comments

	@return		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER	parameter(s) has(have) illigal NULL pointer(s)

*/

net_nfc_error_e net_nfc_create_llcp_socket (net_nfc_llcp_socket_t * socket, net_nfc_llcp_socket_option_h options);

/**
	Register socket callback, this callback should register to get socket activities
	you can register callback any time just after getting socket handler.
	when events is delivered before register callback, all event's will be ignored.
	we recommand register callbac just after create a socket.

	@param[in]		socket 		socket handle
	@param[in]		cb			callback function
	@param[in]		user_param	user parameter that will be deliver when the callback is called

	@return 		return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved

*/

net_nfc_error_e net_nfc_set_llcp_socket_callback (net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_cb cb, void * user_param);

/**
	unregister callback from socket.

	@param[in]		socket 		socket handle

	@return 		return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_NOT_REGISTERED	callback was not registered
*/

net_nfc_error_e net_nfc_unset_llcp_socket_callback (net_nfc_llcp_socket_t socket);

/**
	listen the remote connection with service name and sap number. The service name is a string.

	Please, refer SAP values range <br>
	- 00 ~ 15 : Identifies the Well-Known Service Access Points <br>
	- 16 ~ 31 : Identifies Services in the local service environment and are advertised by local SDP <br>
	- 32 ~ 61 : Identifies Services in the local service environment and are NOT advertised by local SDP <br>

	please follow well known name prefix
	well known service name should be "urn:nfc:sn:<servicename>"
	external service name "urn:nfc:xsn:<domain>:<servicename>"

	@param[in]		socket 		socket handler
	@param[in]		service_name	service name URI, (maxium length is 256)
	@param[in]		sap			the sap number that will be bind
	@param[in]		trans_param	user parameter

	@return		return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_ALLOC_FAIL			memory allocation is failed
	@exception NET_NFC_INSUFFICIENT_STORAGE	it reached maximum number of socket.
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_INVALID_STATE		interanl error
	@exception NET_NFC_ALREADY_REGISTERED	SAP number is already in used

*/


net_nfc_error_e net_nfc_listen_llcp (net_nfc_llcp_socket_t socket, const char * service_name , sap_t sap, void * trans_param);

/**

	disconnect current connection

	@param[in]		socket 		socket handler
	@param[in]		trans_param	user parameter

	@return		return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_INVALID_STATE		interanl error
	@exception NET_NFC_LLCP_SOCKET_DISCONNECTED		socket is disconnected

*/

net_nfc_error_e net_nfc_disconnect_llcp (net_nfc_llcp_socket_t socket , void * trans_param);

/**
	close the socket. if you call the this function before call disconnect, automatically, call disonnection inside socket close

	@param[in]		socket		socket handler
	@param[in]		trans_param	user parameter

	@return 	return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_INVALID_STATE		interanl error

*/


net_nfc_error_e net_nfc_close_llcp_socket(net_nfc_llcp_socket_t socket , void * trans_param);


/**
	send data to remote device. it return callback event when the sending is completed. This api is for connection oriented socket

	@param[in]		socket		socket handler
	@param[in]		data			raw data to send to remote device
	@param[in]		trans_param	user parameter

	@return 	return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_INVALID_STATE		interanl error
	@exception NET_NFC_LLCP_SOCKET_FRAME_REJECTED	requested data is rejected
	@exception NET_NFC_LLCP_SOCKET_DISCONNECTED		socket is disconnected

*/

net_nfc_error_e net_nfc_send_llcp (net_nfc_llcp_socket_t socket, data_h  data , void * trans_param);


/**
	recieve data from remote device, received data will be delivered in callback function,
	cast the data pointer into "data_h". This api is for connection oriented socket.

	@param[in]		socket		socket handler
	@param[in]		req_length	length of data will be read
	@param[in]		trans_param	user parameter

	@return 	return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_INVALID_STATE		interanl error
	@exception NET_NFC_LLCP_SOCKET_FRAME_REJECTED	requested data is rejected
	@exception NET_NFC_LLCP_SOCKET_DISCONNECTED		socket is disconnected
*/

net_nfc_error_e net_nfc_receive_llcp (net_nfc_llcp_socket_t socket, size_t req_length, void * trans_param);



/**
	send data to remote device. it return callback event when the sending is completed.
	this API is for connectionless socket

	@param[in]		socket		socket handler
	@param[in]		data			raw data to send to remote device
	@param[in]		trans_param	user parameter

	@return 	return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_INVALID_STATE		interanl error
	@exception NET_NFC_LLCP_SOCKET_FRAME_REJECTED	requested data is rejected
	@exception NET_NFC_LLCP_SOCKET_DISCONNECTED		socket is disconnected
*/

net_nfc_error_e net_nfc_send_to_llcp (net_nfc_llcp_socket_t socket,sap_t dsap, data_h  data , void * trans_param);


/**
	recieve data from remote device, received data will be delivered in callback function,
	cast the data pointer into "data_h".
	this API is for connectionless socket

	@param[in]		socket		socket handler
	@param[in]		req_length	length of data will be read
	@param[in]		trans_param	user parameter

	@return 	return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_INVALID_STATE		interanl error
	@exception NET_NFC_LLCP_SOCKET_FRAME_REJECTED	requested data is rejected
	@exception NET_NFC_LLCP_SOCKET_DISCONNECTED		socket is disconnected
	@exception NET_NFC_ALREADY_REGISTERED	SAP number is already in used
*/

net_nfc_error_e net_nfc_receive_from_llcp (net_nfc_llcp_socket_t socket, sap_t ssap, size_t req_length, void * trans_param);


/**
	connect to the remote device with destiantion sap number you should know the sap number (0 ~ 61)

	@param[in]		socket		socket handler
	@param[in]		sap			sap (Service Access Point) of remote device
	@param[in]		trans_param	user parameter

	@return 	return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_INVALID_STATE		interanl error
	@exception NET_NFC_LLCP_SOCKET_FRAME_REJECTED	requested data is rejected
	@exception NET_NFC_LLCP_SOCKET_DISCONNECTED		socket is disconnected
*/

net_nfc_error_e net_nfc_connect_llcp_with_sap (net_nfc_llcp_socket_t socket, sap_t sap , void * trans_param);


/**
	connect to the remote device's service name.

	@param[in]		socket		socket handler
	@param[in]		service_name 	service name of the
	@param[in]		trans_param	user parameter

	@return 	return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception NET_NFC_OPERATION_FAIL	Operation is failed because of the internal oal error
	@exception NET_NFC_INVALID_STATE		interanl error
*/

net_nfc_error_e net_nfc_connect_llcp (net_nfc_llcp_socket_t socket, const char * service_name , void * trans_param);


/**

	get local infomation of local device. the device infomation can be configurable with "net_nfc_llcp_set_configure" function

	@param[out]		config		configuration info

	@return 	return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/

net_nfc_error_e net_nfc_get_llcp_local_configure (net_nfc_llcp_config_info_h * config);

/**

	get local infomation of remote device.

	@param[in]		handle		target handle that be optained just after the target detect
	@param[out]		config		configuration handle

	@return 	return the result of the calling the function

*/

net_nfc_error_e net_nfc_get_llcp_remote_configure (net_nfc_target_handle_h handle, net_nfc_llcp_config_info_h * config);

/**

	configure the local device's llcp options this function is optional if you didn't configure local device all the value will be set with default values

	@param[in]		config		configuration handle
	@param[in]		trans_param	user parameter

	@return 	return the result of the calling the function

	@exception NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/

net_nfc_error_e net_nfc_set_llcp_local_configure (net_nfc_llcp_config_info_h config , void * trans_param);

/**
	this function return the current local socket options. if you need to know the remote connection's socket
	info please call "net_nfc_llcp_get_remote_socket_option" function

	@param[in]		socket		socket handler
	@param[out]		option		infomation of the socket

	@return 	return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
*/


net_nfc_error_e net_nfc_get_llcp_local_socket_option (net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_option_h * option);

/**

	this function return the current remote  socket options.

	@param[in]		socket		socket handler
	@param[out]		option		infomation of the socket

	@return 	return the result of the calling the function

	@exception NET_NFC_LLCP_INVALID_SOCKET	invalied socket handler is recieved
*/

net_nfc_error_e net_nfc_get_llcp_remote_socket_option (net_nfc_llcp_socket_t socket, net_nfc_llcp_socket_option_h * option);

/**
	this function create the attribtues of socket.

	- MIU (Maximum Information Unit) : Maximum size of infomation unit of LLC PDU (you may assume a packet in network system)
		An LLC SHALL NOT send any LLC PDU with an information field that is larger than the Link MIU determined for the remote LLC.
		An LLC MAY discard any received LLC PDU with an information field that is larger than the local LLCs Link MIU value.
		The default value is 128, and range of this value is 128 - 1152 <br>
	- RW (Receive Window Size) : Rnage 1 -15 (default is 1), if the value is 0 it does not accept I PDU's on that data link connection.
	A receive window size of one indicates that the local LLC will acknowledge every I PDU before accepting additional I PDUs.<br>
	- Socket types :  two types of socket are connection oriented and connection less. the default value is connection oriented <br>


	@param[out]		option		socket option handler
	@param[in]		miu			Maximum Information Unit
	@param[in]		rw			Receive Window Size
	@param[in]		type			socket type (connection oriented or connection less)

	@return		return the result of the calling the function

	@exception	NET_NFC_OUT_OF_BOUND	given parameter is out of bound
	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/

net_nfc_error_e net_nfc_create_llcp_socket_option (net_nfc_llcp_socket_option_h * option, uint16_t miu, uint8_t rw, net_nfc_socket_type_e type);

/**
	create default socket option handler. this function create handler and set the all of the socket option with default values
	@param[out]		option		option handler

	@return 	return the result of the calling the function

	@exception	NET_NFC_OUT_OF_BOUND	given parameter is out of bound
	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/

net_nfc_error_e net_nfc_create_llcp_socket_option_default (net_nfc_llcp_socket_option_h * option);

/**
	this function help to get miu values from socket option

	@param[in]		option 		socket option handle
	@param[out]		miu			maximum infomation unit

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_get_llcp_socket_option_miu (net_nfc_llcp_socket_option_h option, uint16_t * miu);

/**
	this function help to set miu value to the socket option handle

	@param[in]		option 		socket option handle
	@param[out]		miu			maximum infomation unit

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_set_llcp_socket_option_miu (net_nfc_llcp_socket_option_h option, uint16_t miu);

/**
	this function help to get rt value from the socket option handle

	@param[in]		option 		socket option handle
	@param[out]		rt			receive window size

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_get_llcp_socket_option_rw (net_nfc_llcp_socket_option_h option, uint8_t * rt);

/**
	this function help to set miu value to the socket option handle

	@param[in]		option 		socket option handle
	@param[out]		rt			maximum infomation unit

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)

*/
net_nfc_error_e net_nfc_set_llcp_socket_option_rw (net_nfc_llcp_socket_option_h option, uint8_t rt);

/**
	this function help to get socket type value from the socket option handle

	@param[in]		option 		socket option handle
	@param[out]		type			socket type connection oriented or connectionless

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_get_llcp_socket_option_type (net_nfc_llcp_socket_option_h option, net_nfc_socket_type_e * type);

/**
	this function help to set socket type value to the socket option handle

	@param[in]		option 		socket option handle
	@param[out]		type			socket type connection oriented or connectionless

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_set_llcp_socket_option_type (net_nfc_llcp_socket_option_h option, net_nfc_socket_type_e type);

/**
	free the socket option handle

	@param[in]		option 		socket option handle

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
*/
net_nfc_error_e net_nfc_free_llcp_socket_option (net_nfc_llcp_socket_option_h  option);


 /**
 	This function create llcp_config_info handler that contains the llcp configuration.
	After creating this handler and put his configuration "net_nfc_set_llcp_local_configure" function

	note:

	@param[out] 	config		configuration handler
	@param[in]	miu			Maximum Information Unit
	@param[in]	wks			well knwon service (please refer the note to get detail infomation)
	@param[in]	lto			link time out value
	@param[in]	option		option bits that describe the service support

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception 	NET_NFC_ALLOC_FAIL			memory allocation is failed
	@exception	NET_NFC_OUT_OF_BOUND	given parameter is out of bound

	Note:
	- The WKS parameter SHALL be encoded as a 16-bit field. The most-significant bit of the 16-bit field value SHALL signify
	SAP address 0Fh and the least-significant bit SHALL signify SAP address 00h. The other bits SHALL signify SAP addresses
	corresponding to their respective bit positions. A bit set to ?1? SHALL indicate that a service listener is bound to the corresponding
	well-known service access point. A bit set to ?0? SHALL indicate that no service listener is bound to the corresponding well-known
	service access point.<br>

	- The option field contains a single 8-bit byte representing a set of flags which indicate the link service class of
	the sending LLC and the support of optional features implemented by the sending LLC.<br>
 */
 net_nfc_error_e net_nfc_create_llcp_configure (net_nfc_llcp_config_info_h * config,uint16_t  miu, uint16_t  wks, uint8_t  lto, uint8_t  option);


 /**
 	this function create config info handle with default values.

	@param[out] 	config		configuration handler

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception 	NET_NFC_ALLOC_FAIL			memory allocation is failed
 */

 net_nfc_error_e net_nfc_create_llcp_configure_default (net_nfc_llcp_config_info_h * config);

 /**
 	getting miu value from config info handle

 	@param[in]		config 	config info handle
	@param[out]		miu		maxium information unit

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
 */

 net_nfc_error_e net_nfc_get_llcp_configure_miu (net_nfc_llcp_config_info_h config, uint16_t * miu);
 /**
 	getting wks value from config info handle

 	@param[in]		config 	config info handle
	@param[out]		wks		well-known service list

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
 */
 net_nfc_error_e net_nfc_get_llcp_configure_wks (net_nfc_llcp_config_info_h config, uint16_t * wks);
 /**
 	getting lto value from config info handle

 	@param[in]		config 	config info handle
	@param[out]		lto		link timeout value

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
 */
 net_nfc_error_e net_nfc_get_llcp_configure_lto (net_nfc_llcp_config_info_h config, uint8_t * lto);
 /**
 	getting miu value from config info handle

 	@param[in]		config 	config info handle
	@param[out]		option	option of socket type supports

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
 */
 net_nfc_error_e net_nfc_get_llcp_configure_option (net_nfc_llcp_config_info_h config, uint8_t * option);
 /**
  	setting the miu value to config info handle

 	@param[in]		config 	config info handle
	@param[in]		miu		maxium information unit

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
	@exception	NET_NFC_OUT_OF_BOUND	given parameter is out of bound
 */
 net_nfc_error_e net_nfc_set_llcp_configure_miu (net_nfc_llcp_config_info_h config, uint16_t  miu);
 /**
   	setting the miu value to config info handle

 	@param[in]		config 	config info handle
	@param[in]		wks		well-known service list

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
 */
 net_nfc_error_e net_nfc_set_llcp_configure_wks (net_nfc_llcp_config_info_h config, uint16_t  wks);
 /**
   	setting the miu value to config info handle

 	@param[in]		config 	config info handle
	@param[in]		lto		link timeout value

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
 */
 net_nfc_error_e net_nfc_set_llcp_configure_lto (net_nfc_llcp_config_info_h config, uint8_t  lto);
 /**
   	setting the miu value to config info handle

 	@param[in]		config 	config info handle
	@param[in]		option	option of socket type supports

	@return 	return the result of the calling the function

	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
 */
 net_nfc_error_e net_nfc_set_llcp_configure_option (net_nfc_llcp_config_info_h config, uint8_t	option);
 /**
 	free the configuration info

 	@param[in]		config 	config info handle

 	@return 	return the result of the calling the function

 	@exception 	NET_NFC_NULL_PARAMETER		parameter(s) has(have) illigal NULL pointer(s)
 */
 net_nfc_error_e net_nfc_free_llcp_configure (net_nfc_llcp_config_info_h config);


 /**
@}
*/

net_nfc_error_e net_nfc_get_current_target_handle(void* trans_param);

#ifdef __cplusplus
 }
#endif


#endif


