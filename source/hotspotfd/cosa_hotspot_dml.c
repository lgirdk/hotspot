/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/


/**************************************************************************

    module: cosa_hotspot_dml.c

    For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the 
		COSA Data Model Library - Hotspot Component	
    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        Raghavendra Kammara

    -------------------------------------------------------------------

    revision:

        01/14/2011    initial revision.

**************************************************************************/

#include "ansc_platform.h"
#include "cosa_hotspot_dml.h"
#include "dhcpsnooper.h"

#include <telemetry_busmessage_sender.h>
#include "safec_lib_common.h"

BOOL HotspotConnectedDevice_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* strValue)
{
	int l_iAddOrDelete, l_iSsidIndex, l_iRssi; 
    char l_cMacAddr[20] = {0};
	errno_t rc = -1;
    int ind = -1;
    char *ret = NULL;

    rc = strcmp_s("ClientChange", strlen("ClientChange"),ParamName, &ind);
    ERR_CHK(rc);
    if ((ind == 0) && (rc == EOK))
    {   
                ret = strrchr(strValue, '|');
                if((ret != NULL) && (strlen(++ret) >= sizeof(l_cMacAddr)))
                    return FALSE;

                rc = sscanf_s(strValue, "%d|%d|%d|%s", &l_iAddOrDelete, &l_iSsidIndex, &l_iRssi, l_cMacAddr);
                if(rc < EOK || rc == EOF)
                {
                    ERR_CHK(rc);
                    return FALSE;
                }

		if (1 == l_iAddOrDelete)
		{
		        CcspTraceInfo(("Added case, Client with MAC:%s will be added\n", l_cMacAddr));
		        t2_event_d("WIFI_INFO_Hotspot_client_connected", 1);
			updateRssiForClient(l_cMacAddr, l_iRssi);
		}
		else
		{
		        CcspTraceInfo(("Removal case, Client with MAC:%s will be removed \n", l_cMacAddr));
		        t2_event_d("WIFI_INFO_Hotspot_client_disconnected", 1);
			snoop_RemoveClientListEntry(l_cMacAddr);
		}	
        return TRUE;
    }
    return FALSE;
}

ULONG
HotspotConnectedDevice_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
	errno_t rc = -1;
	int ind = -1;
    /* check the parameter name and return the corresponding value */
	rc = strcmp_s("ClientChange", strlen("ClientChange"),ParamName, &ind);
    ERR_CHK(rc);
    if ((ind == 0) && (rc == EOK))
    {
        return 0;
    }
	return 1;
}
