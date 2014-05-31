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


#ifndef NET_NFC_SERVICE_LLCP_HANDOVER_PRVIATE_H_
#define NET_NFC_SERVICE_LLCP_HANDOVER_PRVIATE_H_

#include "net_nfc_typedef_private.h"

typedef struct _carrier_record
{
	ndef_record_s *record;
	net_nfc_conn_handover_carrier_type_e type;
	net_nfc_conn_handover_carrier_state_e state;
} carrier_record_s;

net_nfc_error_e net_nfc_service_llcp_handover_send_request_msg(net_nfc_request_connection_handover_t *msg);

bool net_nfc_service_llcp_connection_handover_selector(net_nfc_llcp_state_t *state, net_nfc_error_e *result);
bool net_nfc_service_llcp_connection_handover_requester(net_nfc_llcp_state_t *state, net_nfc_error_e *result);

#endif /* NET_NFC_SERVICE_LLCP_HANDOVER_PRVIATE_H_ */
