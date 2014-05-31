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


#ifndef __NDEF_TOOL_H
#define __NDEF_TOOL_H

#include "net_nfc_typedef.h"

enum
{
	OPERATION_ERROR,
	OPERATION_DISPLAY,
	OPERATION_APPEND,
	OPERATION_REMOVE,
	OPERATION_SIGN,
	OPERATION_VERIFY,
	OPERATION_READ_TAG,
	OPERATION_WRITE_TAG,
	OPERATION_RECEIVE_NDEF,
	OPERATION_SEND_NDEF,
	OPERATION_ON, /* hidden operation */
	OPERATION_OFF, /* hidden operation */
};

int ndef_tool_read_ndef_message_from_file(const char *file_name, ndef_message_h *msg);
int ndef_tool_write_ndef_message_to_file(const char *file_name, ndef_message_h msg);

void ndef_tool_display_ndef_message_from_file(const char *file_name);
void ndef_tool_display_discovered_tag(net_nfc_target_info_h target);
void ndef_tool_display_discovered_target(net_nfc_target_handle_h handle);

bool ndef_tool_sign_message_from_file(const char *file_name, int begin_index, int end_index, char *cert_file, char *password);
bool ndef_tool_verify_message_from_file(const char *file_name);

int ndef_tool_read_ndef_from_tag(const char *file);
int ndef_tool_write_ndef_to_tag(const char *file);
int ndef_tool_receive_ndef_via_p2p(const char *file);
int ndef_tool_send_ndef_via_p2p(const char *file);




#endif /* __NDEF_TOOL_H */

