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
#ifndef __NET_NFC_MANAGER_UTIL_INTERNAL_H__
#define __NET_NFC_MANAGER_UTIL_INTERNAL_H__

#define NET_NFC_MANAGER_DATA_PATH		"/opt/usr/share/nfc-manager-daemon"
#define NET_NFC_MANAGER_DATA_PATH_MESSAGE	"message"
#define NET_NFC_MANAGER_DATA_PATH_CONFIG	"config"
#define NET_NFC_MANAGER_NDEF_FILE_NAME		"ndef-message.txt"
#define NET_NFC_MANAGER_LLCP_CONFIG_FILE_NAME	"nfc-manager-config.txt"

#define NET_NFC_MANAGER_SOUND_PATH_TASK_START	"/usr/share/nfc-manager-daemon/sounds/Operation_sdk.wav"
#define NET_NFC_MANAGER_SOUND_PATH_TASK_END	"/usr/share/nfc-manager-daemon/sounds/Operation_sdk.wav"
#define NET_NFC_MANAGER_SOUND_PATH_TASK_ERROR	"/usr/share/nfc-manager-daemon/sounds/Operation_sdk.wav"

#define BUFFER_LENGTH_MAX			1024

#define READ_BUFFER_LENGTH_MAX			BUFFER_LENGTH_MAX
#define WRITE_BUFFER_LENGTH_MAX			BUFFER_LENGTH_MAX
#define NET_NFC_MAX_LLCP_SOCKET_BUFFER		BUFFER_LENGTH_MAX

typedef enum
{
	NET_NFC_TASK_START = 0x00,
	NET_NFC_TASK_END,
	NET_NFC_TASK_ERROR
} net_nfc_sound_type_e;

void net_nfc_manager_util_play_sound(net_nfc_sound_type_e sound_type);

#endif //__NET_NFC_MANAGER_UTIL_INTERNAL_H__
