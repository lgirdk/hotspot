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
#include <ctype.h>
#define MAC_ADDRESS_BYTES 18
#define MAC_ADDRESS_CHECK_INCR 3

/* Validates the colon separated hexadecimal format xx:xx:xx:xx:xx:xx */
static int isValidMAC(char *macAddress)
{
    int i;
    for (i = 0; i < MAC_ADDRESS_BYTES/MAC_ADDRESS_CHECK_INCR; i++)
    {
        if (!(isxdigit(macAddress[0])) || (!isxdigit(macAddress[1])) || !(macAddress[2] == ((i ==(MAC_ADDRESS_BYTES/MAC_ADDRESS_CHECK_INCR)-1) ? '\0' : ':')))
                return -1;
        macAddress+=MAC_ADDRESS_CHECK_INCR;
    }
    return 0;
}


BOOL HotspotConnectedDevice_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* strValue)
{
    UNREFERENCED_PARAMETER(hInsContext);
    int l_iAddOrDelete, l_iSsidIndex, l_iRssi;
    char l_cMacAddr[17];
    errno_t rc = -1;
    int ind = -1;
    char *ret = NULL;
    int count =0;

    if(strValue == NULL){
       CcspTraceError(("Received null strValue\n"));
       return FALSE;
    }
    rc = memset_s(l_cMacAddr, sizeof(l_cMacAddr), '\0', sizeof(l_cMacAddr));
    ERR_CHK(rc);

    rc = strcmp_s("ClientChange", strlen("ClientChange"),ParamName, &ind);
    ERR_CHK(rc);
    if (ind != 0 || rc != EOK) {
        return FALSE;
    }
   for (ret = strValue; *ret ; ++ret) {
    if (*ret == '|' && ++count == 3) {
            ++ret;    // ret points to first char after 3rd "|"
            break;
        }
    }
    if (count != 3) {
        return FALSE;
    }
    if (strlen(ret) > sizeof(l_cMacAddr)) {
        CcspTraceError(("Invalid Client MAC address length %zu, expected %zu\n", strlen(ret), sizeof(l_cMacAddr)));
        return FALSE;
    }
    if(isValidMAC(ret) != 0)
    {
            CcspTraceError(("Invalid Client MAC address Format\n"));
            return FALSE;
    }

    CcspTraceInfo(("Received Client MAC and other details: %s\n", strValue));
    rc = sscanf_s(strValue, "%d|%d|%d|%s", &l_iAddOrDelete, &l_iSsidIndex, &l_iRssi, l_cMacAddr);
    if(rc < EOK || rc == EOF || rc != 4)     // 3rd condition, so sscanf_s must find exactly 4 values
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

ULONG
HotspotConnectedDevice_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pValue);
    UNREFERENCED_PARAMETER(pUlSize);
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
