/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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

FILE *file;
typedef void* ANSC_HANDLE;
ANSC_HANDLE bus_handle;
CCSP_MESSAGE_BUS_INFO busInfo;

typedef struct {
    const char* vapName;
    const char* vapInterface;
    const char* bridgeName;
    char bitVal;
    int ssidIdx;
#if defined(_COSA_INTEL_XB3_ARM_)
    int instance;
#endif
    int queue_num;
} vlanSyncData_s;

#define VAP_NAME_4    "hotspot_open_2g"
#define VAP_NAME_5    "hotspot_open_5g"
#define VAP_NAME_8    "hotspot_secure_2g"
#define VAP_NAME_9    "hotspot_secure_5g"
#define VAP_NAME_11   "hotspot_open_6g"
#define VAP_NAME_12   "hotspot_secure_6g"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
vlanSyncData_s gVlanSyncData[] = {
     {VAP_NAME_4, "wl0.3", "brlan2", 0x1, 5, 1},
     {VAP_NAME_5, "wl1.3", "brlan3", 0x2, 6, 2},
     {VAP_NAME_8, "wl0.5", "brlan4", 0x4, 9, 3},
     {VAP_NAME_9, "wl1.5", "brlan5", 0x8, 10, 4},
     {VAP_NAME_11, "wl2.3", "bropen6g", 0x16, 19, 46},
     {VAP_NAME_12, "wl2.5", "brsecure6g", 0x32, 21, 47}
};
int gVlanSyncDataSize = ARRAY_SIZE(gVlanSyncData);


#define PACKETSIZE              64
#define kMax_IPAddressLength    40
#define kMax_InterfaceLength    20
#define HOTSPOTFD_STATS_PATH    "/var/tmp/hotspotfd.log"

typedef struct
{
    const char    *msgStr;
    HotspotfdType mType;
} Hotspotfd_MsgItem;

struct icmphdr
{
  u_int8_t type;                /* message type */
  u_int8_t code;                /* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t        id;
      u_int16_t        sequence;
    } echo;                        /* echo datagram */
    u_int32_t        gateway;        /* gateway address */
    struct
    {
      u_int16_t        __unused;
      u_int16_t        mtu;
    } frag;                        /* path mtu discovery */
  } un;
};

struct packet {
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

extern unsigned int gKeepAliveInterval;
extern unsigned int gKeepAliveIntervalFailure;
extern unsigned int gKeepAliveThreshold;
extern bool gPrimaryIsActive;
extern bool gSecondaryIsActive;
extern unsigned int gKeepAlivesSent;
extern unsigned int gKeepAlivesReceived;
extern unsigned int gSecondaryMaxTime;
extern unsigned int gSwitchedBackToPrimary;
extern bool gPrimaryIsAlive;
extern bool gSecondaryIsAlive;
extern char gpPrimaryEP[kMax_IPAddressLength];
extern char gpSecondaryEP[kMax_IPAddressLength];
extern unsigned int gKeepAlivePolicy;
extern bool gKeepAliveEnable;
extern bool gKeepAliveLogEnable;
extern unsigned int gKeepAliveCount;
extern int prevPingStatus;
extern int gShm_fd;
extern hotspotfd_statistics_s * gpStats;
extern int gShm_snoop_fd;
extern snooper_statistics_s * gpSnoop_Stats;
extern int  gKeepAliveChecksumCnt;
extern int  gKeepAliveSequenceCnt;
extern int  gDeadInterval;
extern char gKeepAliveInterface[kMax_InterfaceLength];
extern bool gbFirstPrimarySignal;
extern bool gbFirstSecondarySignal;
extern bool gPriStateIsDown;
extern bool gSecStateIsDown;
extern bool gBothDnFirstSignal;
extern bool gTunnelIsUp;
extern bool gVapIsUp;
extern bool wanFailover;
extern char old_wan_ipv4[kMax_IPAddressLength];
extern char old_wan_ipv6[kMax_IPAddressLength];
extern int gSnoopNumberOfClients;
extern char ssid_reset_mask;
