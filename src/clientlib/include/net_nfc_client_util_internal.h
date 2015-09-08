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

#ifndef __NET_NFC_CLIENT_UTIL_INTERNAL_H__
#define __NET_NFC_CLIENT_UTIL_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _NetNfcCallback
{
	void *callback;
	void *user_data;
}
NetNfcCallback;

#ifdef __cplusplus
}
#endif

#endif //__NET_NFC_CLIENT_UTIL_INTERNAL_H__
