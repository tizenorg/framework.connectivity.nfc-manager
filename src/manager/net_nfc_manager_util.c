/*
 * Copyright (c) 2000-2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * This file is part of nfc-manager
 *
 * PROPRIETARY/CONFIDENTIAL
 *
 * This software is the confidential and proprietary information of
 * SAMSUNG ELECTRONICS ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered
 * into with SAMSUNG ELECTRONICS.
 *
 * SAMSUNG make no representations or warranties about the suitability
 * of the software, either express or implied, including but not limited
 * to the implied warranties of merchantability, fitness for a particular
 * purpose, or non-infringement. SAMSUNG shall not be liable for any
 * damages suffered by licensee as a result of using, modifying or
 * distributing this software or its derivatives.
 *
 */

#include <stdlib.h>
#include <string.h>

#include "net_nfc_manager_util_private.h"
#include "net_nfc_debug_private.h"


void __net_nfc_manager_util_free_mem (void** mem, char * filename, unsigned int line)
{
	if (mem == NULL || *mem == NULL)
	{
		//DEBUG_MSG ("FILE: %s, LINE:%d, Invalid parameter in mem free util (pinter is NULL)\n", filename, line);
		return;
	}
	free(*mem);
	*mem = NULL;
}

void __net_nfc_manager_util_alloc_mem(void** mem, int size, char * filename, unsigned int line)
{
	if (mem == NULL || size <= 0)
	{
		//DEBUG_MSG ("FILE: %s, LINE:%d, Invalid parameter in mem alloc util\n", filename, line);
		return;
	}

//	DEBUG_MSG("size to malloc() = [%d]", size);

	if (*mem != NULL)
	{
//		DEBUG_MSG("FILE: %s, LINE:%d, WARNING: Pointer is already allocated or it was not initialized with NULL\n", filename, line);
	}

	*mem = malloc (size);

	if (*mem != NULL)
	{
		memset (*mem, 0x0, size);
	}
	else
	{
//		DEBUG_MSG("FILE: %s, LINE:%d, Allocation is failed\n", filename, line);
	}
}

