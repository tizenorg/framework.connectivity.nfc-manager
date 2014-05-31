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


#ifndef NET_NFC_SERVICE_VCONF_H
#define NET_NFC_SERVICE_VCONF_H

void net_nfc_service_vconf_register_notify_listener();
void net_nfc_service_vconf_unregister_notify_listener();
bool _net_nfc_check_pprom_is_completed ();
void _net_nfc_set_pprom_is_completed ();


#endif
