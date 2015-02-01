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

#include <stdlib.h>
#include <string.h>

#include "vconf.h"
#include "feedback.h"
#include "wav_player.h"
#include <mm_sound_private.h>

#include "net_nfc_debug_internal.h"
#include "net_nfc_util_internal.h"
#include "net_nfc_manager_util_internal.h"

void net_nfc_manager_util_play_sound(net_nfc_sound_type_e sound_type)
{
	int bSoundOn = 0;
	int bVibrationOn = 0;

	if (vconf_get_bool(VCONFKEY_SETAPPL_SOUND_STATUS_BOOL, &bSoundOn) != 0)
	{
		DEBUG_MSG("vconf_get_bool failed for Sound");
		return;
	}

	if (vconf_get_bool(VCONFKEY_SETAPPL_VIBRATION_STATUS_BOOL, &bVibrationOn) != 0)
	{
		DEBUG_MSG("vconf_get_bool failed for Vibration");
		return;
	}

	if ((sound_type > NET_NFC_TASK_ERROR) || (sound_type < NET_NFC_TASK_START))
	{
		DEBUG_MSG("Invalid Sound Type");
		return;
	}

	if (bVibrationOn)
	{
		DEBUG_MSG("Play Vibration");

		if (FEEDBACK_ERROR_NONE == feedback_initialize())
		{
			if (FEEDBACK_ERROR_NONE ==  feedback_play_type(FEEDBACK_TYPE_VIBRATION, FEEDBACK_PATTERN_SIP))
			{
				DEBUG_MSG("feedback_play_type success");
			}

			feedback_deinitialize();
		}
	}

	if (bSoundOn)
	{
		char *sound_path = NULL;

		DEBUG_MSG("Play Sound");

		switch (sound_type)
		{
		case NET_NFC_TASK_START :
			sound_path = strdup(NET_NFC_MANAGER_SOUND_PATH_TASK_START);
			break;
		case NET_NFC_TASK_END :
			sound_path = strdup(NET_NFC_MANAGER_SOUND_PATH_TASK_END);
			break;
		case NET_NFC_TASK_ERROR :
			sound_path = strdup(NET_NFC_MANAGER_SOUND_PATH_TASK_ERROR);
			break;
		}

		if (sound_path != NULL)
		{
			sound_manager_set_session_type(SOUND_SESSION_TYPE_NOTIFICATION);
			if (MM_ERROR_NONE  == wav_player_start(sound_path, SOUND_TYPE_NOTIFICATION, NULL, NULL, NULL))
//			if (MM_ERROR_NONE  == mm_sound_play_keysound(sound_path, VOLUME_TYPE_NOTIFICATION))
			{
				DEBUG_MSG("wav_player_start success");
			}

			_net_nfc_util_free_mem(sound_path);
		}
		else
		{
			DEBUG_ERR_MSG("Invalid Sound Path");
		}
	}
}
