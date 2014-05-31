/*
  * Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
  *
  * Licensed under the Flora License, Version 1.1 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at

  *     http://floralicense.org/license/
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

#include "net_nfc_tag.h"
#include "net_nfc_typedef_private.h"
#include "net_nfc_client_ipc_private.h"
#include "net_nfc_debug_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_client_nfc_private.h"
#include "net_nfc_tag_jewel.h"
#include "net_nfc_target_info.h"

#include <string.h>

#ifndef NET_NFC_EXPORT_API
#define NET_NFC_EXPORT_API __attribute__((visibility("default")))
#endif



#define JEWEL_CMD_REQA 0x26
#define JEWEL_CMD_WUPA 0x52
#define JEWEL_CMD_RID 0x78
#define JEWEL_CMD_RALL 0x00
#define JEWEL_CMD_READ 0x01
#define JEWEL_CMD_WRITE_E 0x53
#define JEWEL_CMD_WRITE_NE 0x1A
#define JEWEL_TAG_KEY	"UID"

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_jewel_read_id (net_nfc_target_handle_h handle, void* trans_param)
{
	if(handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if(!net_nfc_tag_is_connected()){
		return NET_NFC_OPERATION_FAIL;
	}

	client_context_t* client_context_tmp = net_nfc_get_client_context();
	net_nfc_target_info_s* target_info = NULL;

	if((target_info = client_context_tmp->target_info) == NULL){
		return NET_NFC_NO_DATA_FOUND;
	}

	if(target_info->devType != NET_NFC_JEWEL_PICC){
		DEBUG_CLIENT_MSG("only Jewel tag is available");
		return NET_NFC_NOT_ALLOWED_OPERATION;
	}

	uint8_t send_buffer[9] = {0x00, };
	send_buffer[0] = JEWEL_CMD_RID;

	net_nfc_util_compute_CRC(CRC_B, send_buffer, 9);

	DEBUG_MSG_PRINT_BUFFER(send_buffer, 9);

	data_s rawdata;

	rawdata.buffer = send_buffer;
	rawdata.length = 9;

	return net_nfc_transceive(handle, (data_h)&rawdata, trans_param);


}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_jewel_read_byte (net_nfc_target_handle_h handle,  uint8_t block, uint8_t byte, void* trans_param)
{
	if(handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if(block > 0xE || byte > 0x7 ){

		return NET_NFC_OUT_OF_BOUND;
	}

	if(!net_nfc_tag_is_connected()){
		return NET_NFC_OPERATION_FAIL;
	}

	client_context_t* client_context_tmp = net_nfc_get_client_context();
	net_nfc_target_info_s* target_info = NULL;

	if((target_info = client_context_tmp->target_info) == NULL){
		return NET_NFC_NO_DATA_FOUND;
	}

	if(target_info->devType != NET_NFC_JEWEL_PICC){
		DEBUG_CLIENT_MSG("only Jewel tag is available");
		return NET_NFC_NOT_ALLOWED_OPERATION;
	}

	data_h UID = NULL;

	if(net_nfc_get_tag_info_value((net_nfc_target_info_h)target_info, JEWEL_TAG_KEY, &UID) != NET_NFC_OK){
		return NET_NFC_NO_DATA_FOUND;
	}


	if(((data_s*)UID)->length != 4){

		return NET_NFC_OUT_OF_BOUND;
	}

	uint8_t send_buffer[9] = {0x00, };

	/* command */
	send_buffer[0] = JEWEL_CMD_READ;

	/* addr */
	send_buffer[1] = (((block << 3) & 0x78) | (byte & 0x7));

	/* data */
	send_buffer[2] = 0x00;

	/* UID0 ~ 3 */
	memcpy(&(send_buffer[3]), ((data_s*)UID)->buffer, ((data_s*)UID)->length);

	net_nfc_util_compute_CRC(CRC_B, send_buffer, 9);

	DEBUG_MSG_PRINT_BUFFER(send_buffer, 9);

	data_s rawdata;

	rawdata.buffer = send_buffer;
	rawdata.length = 9;

	return net_nfc_transceive(handle, (data_h)&rawdata, trans_param);
}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_jewel_read_all (net_nfc_target_handle_h handle, void* trans_param)
{
	if(handle == NULL )
		return NET_NFC_NULL_PARAMETER;

	if(!net_nfc_tag_is_connected()){
		return NET_NFC_OPERATION_FAIL;
	}

	client_context_t* client_context_tmp = net_nfc_get_client_context();
	net_nfc_target_info_s* target_info = NULL;

	if((target_info = client_context_tmp->target_info) == NULL){
		return NET_NFC_NO_DATA_FOUND;
	}

	if(target_info->devType != NET_NFC_JEWEL_PICC){
		DEBUG_CLIENT_MSG("only Jewel tag is available");
		return NET_NFC_NOT_ALLOWED_OPERATION;
	}

	data_h UID = NULL;

	if(net_nfc_get_tag_info_value((net_nfc_target_info_h)target_info, JEWEL_TAG_KEY, &UID) != NET_NFC_OK){
		return NET_NFC_NO_DATA_FOUND;
	}

	if(((data_s*)UID)->length != 4){

		return NET_NFC_OUT_OF_BOUND;
	}

	uint8_t send_buffer[9] = {0x00, };

	/* command */
	send_buffer[0] = JEWEL_CMD_RALL;

	/* addr */
	send_buffer[1] = 0x00;

	/* data */
	send_buffer[2] = 0x00;

	/* UID0 ~ 3 */
	memcpy(&(send_buffer[3]), ((data_s*)UID)->buffer, ((data_s*)UID)->length);

	net_nfc_util_compute_CRC(CRC_B, send_buffer, 9);

	DEBUG_MSG_PRINT_BUFFER(send_buffer, 9);


	data_s rawdata;

	rawdata.buffer = send_buffer;
	rawdata.length = 9;

	return net_nfc_transceive(handle, (data_h)&rawdata, trans_param);


}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_jewel_write_with_erase (net_nfc_target_handle_h handle, uint8_t block, uint8_t byte, uint8_t data, void* trans_param)
{
	if(handle == NULL)
		return NET_NFC_NULL_PARAMETER;


	if(block > 0xE || byte > 0x7 ){

		return NET_NFC_OUT_OF_BOUND;
	}

	if(!net_nfc_tag_is_connected()){
		return NET_NFC_OPERATION_FAIL;
	}

	client_context_t* client_context_tmp = net_nfc_get_client_context();
	net_nfc_target_info_s* target_info = NULL;

	if((target_info = client_context_tmp->target_info) == NULL){
		return NET_NFC_NO_DATA_FOUND;
	}

	if((target_info = client_context_tmp->target_info) == NULL){
		return NET_NFC_NO_DATA_FOUND;
	}

	data_h UID = NULL;

	if(net_nfc_get_tag_info_value((net_nfc_target_info_h)target_info, JEWEL_TAG_KEY, &UID) != NET_NFC_OK){
		return NET_NFC_NO_DATA_FOUND;
	}

	if(((data_s*)UID)->length != 4){

		return NET_NFC_OUT_OF_BOUND;
	}


	uint8_t send_buffer[9] = {0x00, };

	/* command */
	send_buffer[0] = JEWEL_CMD_WRITE_E;

	/* addr */
	send_buffer[1] = (((block << 3) & 0x78) | (byte & 0x7));

	/* data */
	send_buffer[2] = data;

	/* UID0 ~ 3 */
	memcpy(&(send_buffer[3]), ((data_s*)UID)->buffer, ((data_s*)UID)->length);

	net_nfc_util_compute_CRC(CRC_B, send_buffer, 9);

	DEBUG_MSG_PRINT_BUFFER(send_buffer, 9);

	data_s rawdata;

	rawdata.buffer = send_buffer;
	rawdata.length = 9;

	return net_nfc_transceive(handle, (data_h)&rawdata, trans_param);

}

NET_NFC_EXPORT_API net_nfc_error_e net_nfc_jewel_write_with_no_erase (net_nfc_target_handle_h handle, uint8_t block, uint8_t byte, uint8_t data, void* trans_param)
{
	if(handle == NULL)
		return NET_NFC_NULL_PARAMETER;

	if(block > 0xE || byte > 0x7 ){

		return NET_NFC_OUT_OF_BOUND;
	}

	if(!net_nfc_tag_is_connected()){
		return NET_NFC_OPERATION_FAIL;
	}

	client_context_t* client_context_tmp = net_nfc_get_client_context();
	net_nfc_target_info_s* target_info = NULL;

	if((target_info = client_context_tmp->target_info) == NULL){
		return NET_NFC_NO_DATA_FOUND;
	}

	if(target_info->devType != NET_NFC_JEWEL_PICC){
		DEBUG_CLIENT_MSG("only Jewel tag is available");
		return NET_NFC_NOT_ALLOWED_OPERATION;
	}

	data_h UID = NULL;

	if(net_nfc_get_tag_info_value((net_nfc_target_info_h)target_info, JEWEL_TAG_KEY, &UID) != NET_NFC_OK){
		return NET_NFC_NO_DATA_FOUND;
	}

	if(((data_s*)UID)->length != 4){

		return NET_NFC_OUT_OF_BOUND;
	}

	uint8_t send_buffer[9] = {0x00, };

	/* command */
	send_buffer[0] = JEWEL_CMD_WRITE_NE;

	/* addr */
	send_buffer[1] = (((block << 3) & 0x78) | (byte & 0x7));

	/* data */
	send_buffer[2] = data;

	/* UID0 ~ 3 */
	memcpy(&(send_buffer[3]), ((data_s*)UID)->buffer, ((data_s*)UID)->length);

	net_nfc_util_compute_CRC(CRC_B, send_buffer, 9);

	DEBUG_MSG_PRINT_BUFFER(send_buffer, 9);

	data_s rawdata;

	rawdata.buffer = send_buffer;
	rawdata.length = 9;

	return net_nfc_transceive(handle, (data_h)&rawdata, trans_param);
}

