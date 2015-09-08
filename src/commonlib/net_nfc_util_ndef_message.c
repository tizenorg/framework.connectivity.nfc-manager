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


#include "net_nfc_debug_internal.h"
#include "net_nfc_util_defines.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_util_ndef_message.h"
#include "net_nfc_util_ndef_record.h"

typedef struct _ndef_header_t
{
	uint8_t tnf : 3;
	uint8_t il : 1;
	uint8_t sr : 1;
	uint8_t cf : 1;
	uint8_t me : 1;
	uint8_t mb : 1;
	uint8_t type_len;
	uint8_t payload_len[0];
}
__attribute__((packed)) ndef_header_t;

#define GET_PAYLOAD_LEN(__x)	((__x->sr) ? (__x->payload_len[0]) : \
	((__x->payload_len[0] << 24) | (__x->payload_len[1] << 16) | \
	(__x->payload_len[2] << 8) | (__x->payload_len[3])))

static net_nfc_error_e __net_nfc_repair_record_flags(ndef_message_s *ndef_message);

net_nfc_error_e net_nfc_util_check_ndef_message_rawdata(data_s *rawdata)
{
	uint32_t offset = 0, records = 0;
	uint8_t *buffer;
	uint32_t length, id_len, payload_len;
	ndef_header_t *header = NULL;

	if (rawdata == NULL || rawdata->buffer == NULL || rawdata->length == 0)
		return NET_NFC_NULL_PARAMETER;

	buffer = rawdata->buffer;
	length = rawdata->length;

	while (offset < length) {
		/* header */
		header = (ndef_header_t *)(buffer + offset);

		offset += sizeof(*header);

		if (offset >= length) {
			DEBUG_ERR_MSG("header field failed, records [%d], offset [%d], length [%d]", records, offset, length);
			return NET_NFC_BUFFER_TOO_SMALL;
		}

		/* MB check */
		if (records == 0 && header->mb == 0) {
			DEBUG_ERR_MSG("message doesn't begin with mb flag, records [%d], offset [%d], length [%d]", records, offset, length);
			return NET_NFC_INVALID_FORMAT;
		}

		if (header->sr == 1) {
			offset++;
		} else {
			offset += 4;
		}

		if (offset > length) {
			DEBUG_ERR_MSG("payload length field failed, records [%d], offset [%d], length [%d]", records, offset, length);
			return NET_NFC_BUFFER_TOO_SMALL;
		}

		payload_len = GET_PAYLOAD_LEN(header);

		/* id */
		id_len = 0;
		if (header->il == true) {
			id_len = buffer[offset++];

			if (offset >= length) {
				DEBUG_ERR_MSG("id length field failed, records [%d], offset [%d], length [%d]", records, offset, length);
				return NET_NFC_BUFFER_TOO_SMALL;
			}
		}

		/* calc data len */
		offset += header->type_len + id_len + payload_len;
		if (offset > length) {
			DEBUG_ERR_MSG("data fields failed, records [%d], offset [%d], length [%d]", records, offset, length);
			return NET_NFC_BUFFER_TOO_SMALL;
		}

		records++;

		if (header->me == 1) {
			break;
		}
	}

	if (header != NULL && header->me == 0) {
		DEBUG_ERR_MSG("me field is not set, records [%d], offset [%d], length [%d]", records, offset, length);
		return NET_NFC_NDEF_BUF_END_WITHOUT_ME;
	}

	if (offset < length) {
		DEBUG_ERR_MSG("remain more buffer, records [%d], offset [%d], length [%d]", records, offset, length);
		return NET_NFC_OUT_OF_BOUND;
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_convert_rawdata_to_ndef_message(data_s *rawdata, ndef_message_s *ndef)
{
	ndef_record_s *newRec = NULL;
	ndef_record_s *prevRec = NULL;
	uint8_t *current = NULL;
	uint8_t *last = NULL;
	uint8_t ndef_header = 0;
	net_nfc_error_e	result = NET_NFC_OK;

	if (rawdata == NULL || ndef == NULL)
		return NET_NFC_NULL_PARAMETER;

	current = rawdata->buffer;
	last = current + rawdata->length;

	if(rawdata->length < 3)
		return NET_NFC_INVALID_FORMAT;

	for(ndef->recordCount = 0; current < last; ndef->recordCount++)
	{
		ndef_header = *current++;

		if(ndef->recordCount == 0)
		{
			/* first record has MB field */
			if((ndef_header & NET_NFC_NDEF_RECORD_MASK_MB) == 0)
				return NET_NFC_INVALID_FORMAT;

			/* first record should not be a chunked record */
			if((ndef_header & NET_NFC_NDEF_RECORD_MASK_TNF) == NET_NFC_NDEF_TNF_UNCHANGED)
				return NET_NFC_INVALID_FORMAT;
		}

		_net_nfc_util_alloc_mem(newRec, sizeof(ndef_record_s));
		if (newRec == NULL)
		{
			result = NET_NFC_ALLOC_FAIL;
			goto error;
		}

		/* ndef header set */
		if (ndef_header & NET_NFC_NDEF_RECORD_MASK_MB)
		{
			newRec->MB = 1;
		}
		if (ndef_header & NET_NFC_NDEF_RECORD_MASK_ME)
		{
			newRec->ME = 1;
		}
		if (ndef_header & NET_NFC_NDEF_RECORD_MASK_CF)
		{
			newRec->CF = 1;
		}
		if (ndef_header & NET_NFC_NDEF_RECORD_MASK_SR)
		{
			newRec->SR = 1;
		}
		if (ndef_header & NET_NFC_NDEF_RECORD_MASK_IL)
		{
			newRec->IL = 1;
		}

		newRec->TNF = ndef_header & NET_NFC_NDEF_RECORD_MASK_TNF;

		newRec->type_s.length = *current++;

		/* SR = 1 -> payload is 1 byte, SR = 0 -> payload is 4 bytes */
		if(ndef_header & NET_NFC_NDEF_RECORD_MASK_SR)
		{
			newRec->payload_s.length = *current++;
		}
		else
		{
			newRec->payload_s.length = (uint32_t)((*current) << 24);
			current++;

			newRec->payload_s.length += (uint32_t)((*current) << 16);
			current++;

			newRec->payload_s.length += (uint32_t)((*current) << 8);
			current++;

			newRec->payload_s.length += (uint32_t)((*current));
			current++;
		}

		/* ID length check */
		if(ndef_header & NET_NFC_NDEF_RECORD_MASK_IL)
		{
			newRec->id_s.length = *current++;
		}
		else
		{
			newRec->id_s.length = 0;
		}

		/* to do : chunked record */


		/* empty record check */
		if((ndef_header & NET_NFC_NDEF_RECORD_MASK_TNF) == NET_NFC_NDEF_TNF_EMPTY)
		{
			if(newRec->type_s.length != 0 || newRec->id_s.length != 0 || newRec->payload_s.length != 0)
			{
				result = NET_NFC_INVALID_FORMAT;
				goto error;
			}
		}

		if((ndef_header & NET_NFC_NDEF_RECORD_MASK_TNF) == NET_NFC_NDEF_TNF_UNKNOWN)
		{
			if(newRec->type_s.length != 0)
			{
				result = NET_NFC_INVALID_FORMAT;
				goto error;
			}
		}

		/* put Type buffer */
		if(newRec->type_s.length > 0)
		{
			_net_nfc_util_alloc_mem(newRec->type_s.buffer, newRec->type_s.length);
			if (newRec->type_s.buffer == NULL)
			{
				result = NET_NFC_ALLOC_FAIL;
				goto error;
			}

			memcpy(newRec->type_s.buffer, current, newRec->type_s.length);
			current += newRec->type_s.length;
		}
		else
		{
			newRec->type_s.buffer = NULL;
		}

		/* put ID buffer */
		if(newRec->id_s.length > 0)
		{
			_net_nfc_util_alloc_mem(newRec->id_s.buffer, newRec->id_s.length);
			if (newRec->id_s.buffer == NULL)
			{
				result = NET_NFC_ALLOC_FAIL;
				goto error;
			}

			memcpy(newRec->id_s.buffer, current, newRec->id_s.length);
			current += newRec->id_s.length;
		}
		else
		{
			newRec->id_s.buffer = NULL;
		}

		/* put Payload buffer */
		if(newRec->payload_s.length > 0)
		{
			_net_nfc_util_alloc_mem(newRec->payload_s.buffer, newRec->payload_s.length);
			if (newRec->payload_s.buffer == NULL)
			{
				result = NET_NFC_ALLOC_FAIL;
				goto error;
			}

			memcpy(newRec->payload_s.buffer, current, newRec->payload_s.length);
			current += newRec->payload_s.length;
		}
		else
		{
			newRec->payload_s.buffer = NULL;
		}

		if (ndef->recordCount == 0)
			ndef->records = newRec;
		else
			prevRec->next = newRec;

		prevRec = newRec;
		newRec = NULL;

		if(ndef_header & NET_NFC_NDEF_RECORD_MASK_ME)
		{
			break;
		}
	}

	ndef->recordCount++;

	if((current != last) || ((ndef_header & NET_NFC_NDEF_RECORD_MASK_ME) == 0))
	{
		result = NET_NFC_INVALID_FORMAT;
		goto error;
	}

	return NET_NFC_OK;

error:

	DEBUG_ERR_MSG("parser error");

	if (newRec)
	{
		_net_nfc_util_free_mem(newRec->type_s.buffer);
		_net_nfc_util_free_mem(newRec->id_s.buffer);
		_net_nfc_util_free_mem(newRec->payload_s.buffer);
		_net_nfc_util_free_mem(newRec);
	}

	prevRec = ndef->records;

	while(prevRec)
	{
		ndef_record_s *tmpRec = NULL;

		_net_nfc_util_free_mem(prevRec->type_s.buffer);
		_net_nfc_util_free_mem(prevRec->id_s.buffer);
		_net_nfc_util_free_mem(prevRec->payload_s.buffer);

		tmpRec = prevRec->next;
		_net_nfc_util_free_mem(prevRec);
		prevRec = tmpRec;
	}

	ndef->records = NULL;

	return result;
}

net_nfc_error_e net_nfc_util_convert_ndef_message_to_rawdata(ndef_message_s *ndef, data_s *rawdata)
{
	ndef_record_s *record = NULL;
	uint8_t *current = NULL;
	uint8_t ndef_header;

	if (rawdata == NULL || ndef == NULL)
		return NET_NFC_NULL_PARAMETER;

	record = ndef->records;
	current = rawdata->buffer;

	while(record)
	{
		ndef_header = 0x00;

		if(record->MB)
			ndef_header |= NET_NFC_NDEF_RECORD_MASK_MB;
		if(record->ME)
			ndef_header |= NET_NFC_NDEF_RECORD_MASK_ME;
		if(record->CF)
			ndef_header |= NET_NFC_NDEF_RECORD_MASK_CF;
		if(record->SR)
			ndef_header |= NET_NFC_NDEF_RECORD_MASK_SR;
		if(record->IL)
			ndef_header |= NET_NFC_NDEF_RECORD_MASK_IL;

		ndef_header |= record->TNF;

		*current++ = ndef_header;

		/* check empty record */
		if(record->TNF == NET_NFC_NDEF_TNF_EMPTY)
		{
			/* set type length to zero */
			*current++ = 0x00;

			/* set payload length to zero */
			*current++ = 0x00;

			/* set ID length to zero */
			if(record->IL)
			{
				*current++ = 0x00;
			}

			record = record->next;

			continue;
		}

		/* set type length */
		if(record->TNF == NET_NFC_NDEF_TNF_UNKNOWN || record->TNF == NET_NFC_NDEF_TNF_UNCHANGED)
		{
			*current++ = 0x00;
		}
		else
		{
			*current++ = record->type_s.length;
		}

		/* set payload length */
		if(record->SR)
		{
			*current++ = (uint8_t)(record->payload_s.length & 0x000000FF);
		}
		else
		{
			*current++ = (uint8_t)((record->payload_s.length & 0xFF000000) >> 24);
			*current++ = (uint8_t)((record->payload_s.length & 0x00FF0000) >> 16);
			*current++ = (uint8_t)((record->payload_s.length & 0x0000FF00) >> 8);
			*current++ = (uint8_t)(record->payload_s.length & 0x000000FF) ;
		}

		/* set ID length */
		if(record->IL)
		{
			*current++ = record->id_s.length;
		}

		/* set type buffer */
		if((record->TNF != NET_NFC_NDEF_TNF_UNKNOWN) && (record->TNF != NET_NFC_NDEF_TNF_UNCHANGED))
		{
			memcpy(current, record->type_s.buffer, record->type_s.length);
			current += record->type_s.length;
		}

		/* set ID buffer */
		memcpy(current, record->id_s.buffer, record->id_s.length);
		current += record->id_s.length;

		/* set payload buffer */
		memcpy(current, record->payload_s.buffer, record->payload_s.length);
		current += record->payload_s.length;

		record = record->next;
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_append_record(ndef_message_s *msg, ndef_record_s *record)
{
	if (msg == NULL || record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (msg->recordCount == 0)
	{
		// set short message and append
		record->MB = 1;
		record->ME = 1;
		record->next = NULL;

		msg->records = record;

		msg->recordCount++;

		DEBUG_MSG("record is added to NDEF message :: count [%d]", msg->recordCount);
	}
	else
	{
		ndef_record_s *current = NULL;
		ndef_record_s *prev = NULL;

		// set flag :: this record is FIRST
		current = msg->records;

		if (current != NULL)
		{
			// first node
			current->MB = 1;
			current->ME = 0;

			prev = current;

			// second node
			current = current->next;

			while (current != NULL)
			{
				current->MB = 0;
				current->ME = 0;
				prev = current;
				current = current->next;
			}

			// set flag :: this record is END
			record->MB = 0;
			record->ME = 1;

			prev->next = record;
			msg->recordCount++;
		}

	}

	return NET_NFC_OK;
}

uint32_t net_nfc_util_get_ndef_message_length(ndef_message_s *message)
{
	ndef_record_s *current;
	int total = 0;

	if (message == NULL)
		return 0;

	current = message->records;

	while (current != NULL)
	{
		total += net_nfc_util_get_record_length(current);
		current = current->next;
	}

	return total;
}

void net_nfc_util_print_ndef_message(ndef_message_s *msg)
{
	int idx = 0, idx2 = 0;
	ndef_record_s *current = NULL;
	char buffer[1024];

	if (msg == NULL)
	{
		return;
	}

	//                123456789012345678901234567890123456789012345678901234567890
	DEBUG_MSG("========== NDEF Message ====================================\n");
	DEBUG_MSG("Total NDEF Records count: %d\n", msg->recordCount);
	current = msg->records;
	for (idx = 0; idx < msg->recordCount; idx++)
	{
		if (current == NULL)
		{
			DEBUG_ERR_MSG("Message Record is NULL!! unexpected error");
			DEBUG_MSG("============================================================\n");
			return;
		}
		DEBUG_MSG("---------- Record -----------------------------------------\n");
		DEBUG_MSG("MB:%d ME:%d CF:%d SR:%d IL:%d TNF:0x%02X\n",
			current->MB, current->ME, current->CF, current->SR, current->IL, current->TNF);
		DEBUG_MSG("TypeLength:%d  PayloadLength:%d  IDLength:%d\n",
			current->type_s.length, current->payload_s.length, current->id_s.length);
		if (current->type_s.buffer != NULL)
		{
			memcpy(buffer, current->type_s.buffer, current->type_s.length);
			buffer[current->type_s.length] = '\0';
			DEBUG_MSG("Type: %s\n", buffer);
		}
		if (current->id_s.buffer != NULL)
		{
			memcpy(buffer, current->id_s.buffer, current->id_s.length);
			buffer[current->id_s.length] = '\0';
			SECURE_LOGD("ID: %s\n", buffer);
		}
		if (current->payload_s.buffer != NULL)
		{
			DEBUG_MSG("Payload: ");
			for (idx2 = 0; idx2 < current->payload_s.length; idx2++)
			{
				if (idx2 % 16 == 0)
					DEBUG_MSG("\n\t");
				DEBUG_MSG("%02X ", current->payload_s.buffer[idx2]);
			}
			DEBUG_MSG("\n");
		}
		current = current->next;
	}
	//                123456789012345678901234567890123456789012345678901234567890
	DEBUG_MSG("============================================================\n");

}

net_nfc_error_e net_nfc_util_free_ndef_message(ndef_message_s *msg)
{
	int idx = 0;
	ndef_record_s *prev, *current;

	if (msg == NULL)
		return NET_NFC_NULL_PARAMETER;

	current = msg->records;

	for (idx = 0; idx < msg->recordCount; idx++)
	{
		if (current == NULL)
			break;

		prev = current;
		current = current->next;

		net_nfc_util_free_record(prev);
	}

	_net_nfc_util_free_mem(msg);

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_create_ndef_message(ndef_message_s **ndef_message)
{
	if (ndef_message == NULL) {
		return NET_NFC_NULL_PARAMETER;
	}

	_net_nfc_util_alloc_mem(*ndef_message, sizeof(ndef_message_s));
	if (*ndef_message == NULL) {
		return NET_NFC_ALLOC_FAIL;
	}

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_remove_record_by_index(ndef_message_s *ndef_message, int index)
{
	int current_idx = 0;
	ndef_record_s *prev;
	ndef_record_s *next;
	ndef_record_s *current;

	if (ndef_message == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (index < 0 || index >= ndef_message->recordCount)
	{
		return NET_NFC_OUT_OF_BOUND;
	}

	if (index == 0)
	{
		current = ndef_message->records;
		next = ndef_message->records->next;
		ndef_message->records = next;
	}
	else
	{
		prev = ndef_message->records;
		for (; current_idx < index - 1; current_idx++)
		{
			prev = prev->next;
			if (prev == NULL)
			{
				return NET_NFC_INVALID_FORMAT;
			}
		}
		current = prev->next;
		if (current == NULL)
		{
			return NET_NFC_INVALID_FORMAT;
		}
		next = current->next;
		prev->next = next;
	}

	net_nfc_util_free_record(current);
	(ndef_message->recordCount)--;

	return __net_nfc_repair_record_flags(ndef_message);
}

net_nfc_error_e net_nfc_util_get_record_by_index(ndef_message_s *ndef_message, int index, ndef_record_s **record)
{
	ndef_record_s *current;
	int idx = 0;

	if (ndef_message == NULL || record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (index < 0 || index >= ndef_message->recordCount)
	{
		return NET_NFC_OUT_OF_BOUND;
	}

	current = ndef_message->records;

	for (; current != NULL && idx < index; idx++)
	{
		current = current->next;
	}

	*record = current;

	return NET_NFC_OK;
}

net_nfc_error_e net_nfc_util_append_record_by_index(ndef_message_s *ndef_message, int index, ndef_record_s *record)
{
	int idx = 0;
	ndef_record_s *prev;
	ndef_record_s *next;

	if (ndef_message == NULL || record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	if (index < 0 || index > ndef_message->recordCount)
	{
		return NET_NFC_OUT_OF_BOUND;
	}

	prev = ndef_message->records;

	if (index == 0)
	{
		ndef_message->records = record;
		record->next = prev;
	}
	else
	{
		for (; idx < index - 1; idx++)
		{
			prev = prev->next;
			if (prev == NULL)
			{
				return NET_NFC_INVALID_FORMAT;
			}
		}
		next = prev->next;
		prev->next = record;
		record->next = next;
	}
	(ndef_message->recordCount)++;

	return __net_nfc_repair_record_flags(ndef_message);
}

net_nfc_error_e net_nfc_util_search_record_by_type(ndef_message_s *ndef_message, net_nfc_record_tnf_e tnf, data_s *type, ndef_record_s **record)
{
	int idx = 0;
	ndef_record_s *tmp_record;
	uint32_t type_length;
	uint8_t *buf;

	if (ndef_message == NULL || type == NULL || record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	type_length = type->length;
	buf = type->buffer;

	/* remove prefix of nfc specific urn */
	if (type_length > 12)
	{
		if (memcmp(buf, "urn:nfc:ext:", 12) == 0 ||
			memcmp(buf, "urn:nfc:wkt:", 12) == 0)
		{
			buf += 12;
			type_length -= 12;
		}
	}

	tmp_record = ndef_message->records;

	for (; idx < ndef_message->recordCount; idx++)
	{
		if (tmp_record == NULL)
		{
			*record = NULL;

			return NET_NFC_INVALID_FORMAT;
		}

		if (tmp_record->TNF == tnf &&
			type_length == tmp_record->type_s.length &&
			memcmp(buf, tmp_record->type_s.buffer, type_length) == 0)
		{
			*record = tmp_record;

			return NET_NFC_OK;
		}

		tmp_record = tmp_record->next;
	}

	return NET_NFC_NO_DATA_FOUND;
}

net_nfc_error_e net_nfc_util_search_record_by_id(ndef_message_s *ndef_message, data_s *id, ndef_record_s **record)
{
	int idx = 0;
	ndef_record_s *record_in_msg;
	uint32_t id_length;
	uint8_t *buf;

	if (ndef_message == NULL || id == NULL || record == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	id_length = id->length;
	buf = id->buffer;

	record_in_msg = ndef_message->records;

	for (; idx < ndef_message->recordCount; idx++)
	{
		if (record_in_msg == NULL)
		{
			*record = NULL;

			return NET_NFC_INVALID_FORMAT;
		}
		if (id_length == record_in_msg->id_s.length &&
			memcmp(buf, record_in_msg->id_s.buffer, id_length) == 0)
		{
			*record = record_in_msg;

			return NET_NFC_OK;
		}

		record_in_msg = record_in_msg->next;
	}

	return NET_NFC_NO_DATA_FOUND;
}

static net_nfc_error_e __net_nfc_repair_record_flags(ndef_message_s *ndef_message)
{
	int idx = 0;
	ndef_record_s *record;

	if (ndef_message == NULL)
	{
		return NET_NFC_NULL_PARAMETER;
	}

	record = ndef_message->records;

	if (ndef_message->recordCount == 1)
	{
		if (record == NULL)
		{
			return NET_NFC_INVALID_FORMAT;
		}

		record->MB = 1;
		record->ME = 1;

		return NET_NFC_OK;
	}

	for (idx = 0; idx < ndef_message->recordCount; idx++)
	{
		if (record == NULL)
		{
			return NET_NFC_INVALID_FORMAT;
		}

		if (idx == 0)
		{
			record->MB = 1;
			record->ME = 0;
		}
		else if (idx == ndef_message->recordCount - 1)
		{
			record->MB = 0;
			record->ME = 1;
		}
		else
		{
			record->MB = 0;
			record->ME = 0;
		}
		record = record->next;
	}

	return NET_NFC_OK;
}

void net_nfc_util_foreach_ndef_records(ndef_message_s *msg,
	net_nfc_foreach_ndef_records_cb func, void *user_data)
{
	ndef_record_s *record;

	if (msg == NULL || func == NULL)
		return;

	record = msg->records;

	while (record != NULL) {
		func(record, user_data);

		record = record->next;
	}

}
