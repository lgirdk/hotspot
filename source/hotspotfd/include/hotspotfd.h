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

#ifndef __HOTSPOTFD_HEADER__
#define __HOTSPOTFD_HEADER__

#define __HAVE_SYSEVENT_STARTUP_PARAMS__
#define __HAVE_SYSEVENT__

#ifdef __HAVE_SYSEVENT__
#include <sysevent/sysevent.h>
#endif

#include <stdbool.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#define kMax_IPAddressLength            40

#define kHotspotfd_events                   "hotspotfd-update"

#define kHotspotfd_primary                  "hotspotfd-primary"                // ip address of primary
#define khotspotfd_secondary                "hotspotfd-secondary"              // ip address of secondary
#define khotspotfd_keep_alive               "hotspotfd-keep-alive"             // time in secs between pings
#define khotspotfd_keep_alive_threshold     "hotspotfd-threshold"              // failed ping's before switching EP
#define khotspotfd_max_secondary            "hotspotfd-max-secondary"          // max. time allowed on secondary
#define kHotspotfd_tunnelEP                 "hotspotfd-tunnelEP"               // Indicates an EP change
#define khotspotfd_keep_alive_policy        "hotspotfd-policy"                 // ICMP ping pr NONE
#define khotspotfd_keep_alive_count         "hotspotfd-count"                  // pings per keep-alive interval

#define khotspotfd_dead_interval            "hotspotfd-dead-interval"          // pings per minute when both EP's are down

#define khotspotfd_enable                   "hotspotfd-enable"
#define khotspotfd_log_enable               "hotspotfd-log-enable"
#define khotspotfd_wan_status               "wan-status"
#define khotspotfd_current_wan_ipaddr_v4    "current_wan_ipaddr"
#define khotspotfd_current_wan_ipaddr_v6    "wan6_ipaddr"

#define kHotspotfd_primary_len                  kMax_IPAddressLength             
#define khotspotfd_secondary_len                kMax_IPAddressLength           
#define kHotspotfd_tunnelEP_len                 kMax_IPAddressLength

#ifdef FEATURE_SUPPORT_MAPT_NAT46
#define SYSEVENT_MAPT_CONFIG_FLAG "mapt_config_flag"
#endif

typedef struct
{
    char primaryEP[kMax_IPAddressLength];
    bool primaryIsActive;
    bool primaryIsAlive;

    char secondaryEP[kMax_IPAddressLength];
    bool secondaryIsActive;
    bool secondaryIsAlive;

    unsigned int keepAlivesSent;
    unsigned int keepAlivesReceived;
    unsigned int keepAliveInterval;
    unsigned int keepAliveThreshold;
    unsigned int keepAliveCount;
    unsigned int secondaryMaxTime;
    unsigned int switchedBackToPrimary;
    
    unsigned int discardedChecksumCnt;
    unsigned int discaredSequenceCnt;
    unsigned int deadInterval;

}  hotspotfd_statistics_s;

#define kKeepAlive_Statistics           765889 // key used for shared memory
#define kKeepAlive_SharedMemSize        sizeof(hotspotfd_statistics_s)

void hotspot_start();
#endif
