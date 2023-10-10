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


#include "libHotspot.h"
#include "libHotspotApi.h"
#include "webconfig_framework.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

/**************************************************************************/
/*      GLOBAL and STATIC  VARIABLES                                      */
/**************************************************************************/
/* Array for mapping vlan and brdige interface */
#if (defined(_XB6_PRODUCT_REQ_) && !defined(_XB7_PRODUCT_REQ_))
vlanSyncData_s gVlanSyncData[] = {
     {VAP_NAME_4, "ath4", "brlan2", 0x1, 5, 1},
     {VAP_NAME_5, "ath5", "brlan3", 0x2, 6, 2},
     {VAP_NAME_8, "ath8", "brlan4", 0x4, 9, 3},
     {VAP_NAME_9, "ath9", "brlan5", 0x8, 10, 4}
};
#elif defined(_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
vlanSyncData_s gVlanSyncData[] = {
     {VAP_NAME_4, "wl0.3", "brlan2", 0x1, 5, 1},
     {VAP_NAME_5, "wl1.3", "brlan3", 0x2, 6, 2},
     {VAP_NAME_8, "wl0.5", "brlan4", 0x4, 9, 3},
     {VAP_NAME_9, "wl1.5", "brlan5", 0x8, 10, 4},
     {VAP_NAME_11, "wl2.3", "bropen6g", 0x16, 19, 46},
     {VAP_NAME_12, "wl2.5", "brsecure6g", 0x32, 21, 47}
};
#elif defined(_XB7_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
vlanSyncData_s gVlanSyncData[] = {
#if defined(_INTEL_WAV_)
     {VAP_NAME_4, "wlan0.2", "brlan2", 0x1, 5, 1},
     {VAP_NAME_5, "wlan2.2", "brlan3", 0x2, 6, 2},
     {VAP_NAME_8, "wlan0.4", "brlan4", 0x4, 9, 3},
     {VAP_NAME_9, "wlan2.4", "brlan5", 0x8, 10, 4}
#else
     {VAP_NAME_4, "wl0.3", "brlan2", 0x1, 5, 1},
     {VAP_NAME_5, "wl1.3", "brlan3", 0x2, 6, 2},
     {VAP_NAME_8, "wl0.5", "brlan4", 0x4, 9, 3},
     {VAP_NAME_9, "wl1.5", "brlan5", 0x8, 10, 4}
#endif
};
#elif defined (_XB7_PRODUCT_REQ_)|| defined (_XF3_PRODUCT_REQ_)
vlanSyncData_s gVlanSyncData[] = {
#if defined(_INTEL_WAV_)
     {VAP_NAME_4, "wlan0.2", "brlan2", 0x1, 5, 1},
     {VAP_NAME_5, "wlan2.2", "brlan3", 0x2, 6, 2},
     {VAP_NAME_8, "wlan0.4", "brlan4", 0x4, 9, 3},
     {VAP_NAME_9, "wlan2.4", "brlan5", 0x8, 10, 4}
#else
     {VAP_NAME_4, "wl0.2", "brlan2", 0x1, 5, 1},
     {VAP_NAME_5, "wl1.2", "brlan3", 0x2, 6, 2},
     {VAP_NAME_8, "wl0.4", "brlan4", 0x4, 9, 3},
     {VAP_NAME_9, "wl1.4", "brlan5", 0x8, 10, 4}
#endif
};
#elif defined(_COSA_INTEL_XB3_ARM_)
vlanSyncData_s gVlanSyncData[] = {
     {VAP_NAME_4, NULL, "brlan2", 0x1, 5, 3, 1},
     {VAP_NAME_5, NULL, "brlan3", 0x2, 6, 4, 2},
     {VAP_NAME_8, NULL, "brlan4", 0x4, 9, 7, 3},
     {VAP_NAME_9, NULL, "brlan5", 0x8, 10, 8, 4}
};
#elif defined (_CBR_PRODUCT_REQ_)
vlanSyncData_s gVlanSyncData[] = {
     {VAP_NAME_4, "wl0.2", "brlan2", 0x1, 5, 1},
     {VAP_NAME_5, "wl1.2", "brlan3", 0x2, 6, 2},
     {VAP_NAME_8, "wl0.4", "brlan4", 0x4, 9, 3},
     {VAP_NAME_9, "wl1.4", "brlan5", 0x8, 10, 4},
     {VAP_NAME_10, "wl1.7", "brpublic", 0x16, 16, 45}
};
#else
vlanSyncData_s gVlanSyncData[] = {
     {VAP_NAME_4, "NULL", "NULL", 0x1, 0, 0},
     {VAP_NAME_5, "NULL", "NULL", 0x2, 0, 0},
     {VAP_NAME_8, "NULL", "NULL", 0x4, 0, 0},
     {VAP_NAME_9, "NULL", "NULL", 0x8, 0, 0}
};
#endif

int gVlanSyncDataSize = ARRAY_SIZE(gVlanSyncData);
