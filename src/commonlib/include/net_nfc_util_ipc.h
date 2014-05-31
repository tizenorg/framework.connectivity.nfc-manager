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

#ifndef NET_NFC_UTIL_IPC_H_
#define NET_NFC_UTIL_IPC_H_

#define NET_NFC_SERVER_ADDRESS				"127.0.0.1"
#define NET_NFC_SERVER_PORT				3000
#define NET_NFC_SERVER_DOMAIN				"/tmp/nfc-manager-server-domain"

#define NET_NFC_MAX_MESSAGE_LENGTH			(1024 * 512)

#define NET_NFC_FLAGS_SYNC_CALL				(1 << 0)
#define NET_NFC_FLAGS_NO_RESPONSE			(1 << 1)

#define NET_NFC_IS_FLAGS_SET(__var, __flag)		(((__var) & (__flag)) == (__flag))
#define NET_NFC_SET_FLAGS(__var, __flag)		(__var) |= (__flag)
#define NET_NFC_UNSET_FLAGS(__var, __flag)		(__var) &= ~(__flag)

#define NET_NFC_FLAGS_SET_SYNC_CALL(__var)		NET_NFC_SET_FLAGS(__var, NET_NFC_FLAGS_SYNC_CALL)
#define NET_NFC_FLAGS_UNSET_SYNC_CALL(__var)		NET_NFC_UNSET_FLAGS(__var, NET_NFC_FLAGS_SYNC_CALL)
#define NET_NFC_FLAGS_IS_SYNC_CALL(__var)		NET_NFC_IS_FLAGS_SET(__var, NET_NFC_FLAGS_SYNC_CALL)

#define NET_NFC_FLAGS_SET_NO_RESPONSE(__var)		NET_NFC_SET_FLAGS(__var, NET_NFC_FLAGS_NO_RESPONSE)
#define NET_NFC_FLAGS_UNSET_NO_RESPONSE(__var)		NET_NFC_UNSET_FLAGS(__var, NET_NFC_FLAGS_NO_RESPONSE)
#define NET_NFC_FLAGS_IS_NO_RESPONSE(__var)		NET_NFC_IS_FLAGS_SET(__var, NET_NFC_FLAGS_NO_RESPONSE)

int net_nfc_util_get_va_list_length(va_list list);
int net_nfc_util_fill_va_list(uint8_t *buffer, int length, va_list list);
void net_nfc_util_set_non_block_socket(int socket);

#endif /* NET_NFC_UTIL_IPC_H_ */
