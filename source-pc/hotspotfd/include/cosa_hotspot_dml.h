/**
 * description: This file defines the apis for objects to support Data Model Library.
 */
#include "slap_definitions.h"

BOOL HotspotConnectedDevice_SetParamStringValue(ANSC_HANDLE hInsContext, char* ParamName, char* strValue);
ULONG HotspotConnectedDevice_GetParamStringValue(ANSC_HANDLE hInsContext,char* ParamName, char* pValue, ULONG* pUlSize); 
