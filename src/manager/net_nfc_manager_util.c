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
#include "svi.h"
#include "wav_player.h"

#include "net_nfc_debug_private.h"
#include "net_nfc_util_private.h"
#include "net_nfc_manager_util_private.h"

static void _play_sound_callback(int id, void *data)
{
	DEBUG_MSG("_play_sound_callback");

	if (WAV_PLAYER_ERROR_NONE != wav_player_stop(id))
	{
		DEBUG_MSG("wav_player_stop failed");
	}
}

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
		int svi_handle = -1;

		DEBUG_MSG("Play Vibration");

		if (SVI_SUCCESS == svi_init(&svi_handle))
		{
			if (SVI_SUCCESS == svi_play_vib(svi_handle, SVI_VIB_TOUCH_SIP))
			{
				DEBUG_MSG("svi_play_vib success");
			}

			svi_fini(svi_handle);
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
			if (WAV_PLAYER_ERROR_NONE == wav_player_start(sound_path, SOUND_TYPE_MEDIA, _play_sound_callback, NULL, NULL))
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

