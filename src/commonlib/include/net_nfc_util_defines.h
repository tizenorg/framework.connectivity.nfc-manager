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

#ifndef __NET_NFC_UTIL_DEFINES__
#define __NET_NFC_UTIL_DEFINES__

#define NET_NFC_UTIL_MSG_TYPE_REQUEST 0
#define NET_NFC_UTIL_MSG_TYPE_RESPONSE 1

#define CONN_HANOVER_MAJOR_VER 1
#define CONN_HANOVER_MINOR_VER 2

#define CONN_HANDOVER_BT_CARRIER_MIME_NAME "application/vnd.bluetooth.ep.oob"
#define CONN_HANDOVER_WIFI_BSS_CARRIER_MIME_NAME "application/vnd.wfa.wsc"
#define CONN_HANDOVER_WIFI_IBSS_CARRIER_MIME_NAME "application/vnd.wfa.wsc;mode=ibss"

#define BLUETOOTH_ADDRESS_LENGTH 6
#define HIDDEN_BT_ADDR_FILE "/opt/etc/.bd_addr"

/* define vconf key */
#define NET_NFC_DISABLE_LAUNCH_POPUP_KEY "memory/private/nfc-manager/popup_disabled"//"memory/nfc/popup_disabled"

#endif
