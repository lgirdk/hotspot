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

#ifndef __SNOOPER_HEADER__
#define __SNOOPER_HEADER__

#ifdef __HAVE_SYSEVENT__
#include <sysevent/sysevent.h>
#endif

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <stdbool.h>
#include<netinet/ip.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/shm.h>
#include<signal.h>
#include <arpa/inet.h>
#include <limits.h>


#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

//#define __686__
#define __HAVE_SYSEVENT_STARTUP_PARAMS__
#define __GET_REQUESTED_IP_ADDRESS__
#define __HAVE_SYSEVENT__

#define kSnooper_events                     "snooper-update"

#define kSnooper_enable                     "snooper-enable"
#define kSnooper_circuit_enable             "snooper-circuit-enable"
#define kSnooper_remote_enable              "snooper-remote-enable"
#define kSnooper_debug_enable               "snooper-debug-enable"
#define kSnooper_log_enable                 "snooper-log-enable"
#define kSnooper_max_clients                "snooper-max-clients"

#define kSnooper_circuit_id0                "snooper-queue0-circuitID"
#define kSnooper_circuit_id1                "snooper-queue1-circuitID"
#define kSnooper_circuit_id2                "snooper-queue2-circuitID"
#define kSnooper_circuit_id3                "snooper-queue3-circuitID"
#define kSnooper_circuit_id4                "snooper-queue4-circuitID"
#define kSnooper_circuit_id5                "snooper-queue5-circuitID"
#define ksnooper_circuit_id6                "snooper-queue6-circuitID"

#define kSnooper_ssid_index0                 "snooper-ssid0-index"
#define kSnooper_ssid_index1                 "snooper-ssid1-index"
#define kSnooper_ssid_index2                 "snooper-ssid2-index"
#define kSnooper_ssid_index3                 "snooper-ssid3-index"
#define kSnooper_ssid_index4                 "snooper-ssid4-index"
#define kSnooper_ssid_index5                 "snooper-ssid5-index"
#define ksnooper_ssid_index6                 "snooper-ssid6-index"

#ifdef WAN_FAILOVER_SUPPORTED
#define kcurrent_wan_interface                "current_wan_ifname"
#define ktest_current_wan_interface           "test_current_wan_ifname"
#endif

#define kSnooper_circuit_id_len             30
#define kSnooper_MaxClients                 30

#define kSnooper_MaxRemoteLen   20
#define kSnooper_MaxMacAddrLen  18
#define kSnooper_MaxHostNameLen 64
#define kSnooper_MaxStatusLen   10
#define kSnooper_MaxIpAddrLen   20 
#define kSnooper_MaxCircuitLen  80

#define kSnoop_DefaultQueue             1
#define kSnoop_DefaultNumberOfQueues    6
#define kSnoop_MaxNumberOfQueues        6

#define kSnoop_LOG_ERR     1
#define kSnoop_LOG_INFO    2
#define kSnoop_LOG_NOISE   3
#define kSnoop_FILE_NAME   "dhcpsnooper.c"

#define kSnoop_DHCP_Option53_Offset 270
#define kSnoop_DHCP_Options_Start   28

#define kSnoop_DHCP_Discover        1
#define kSnoop_DHCP_Offer           2
#define kSnoop_DHCP_Request         3
#define kSnoop_DHCP_Decline         4
#define kSnoop_DHCP_ACK             5
#define kSnoop_DHCP_Release         7
#define kSnoop_DHCP_Inform          8

#define SNOOP_LOG_PATH    "/var/tmp/dhcp_snooperd.log"
#define kSnoop_max_sysevent_len     80
#define kSnoop_LM_Delay 15

#define snooper_dbg(fmt...) {    \
        if (kSnoop_LOG_NOISE <= glog_level ) {\
        printf("%s:%s:%d> ", kSnoop_FILE_NAME, __FUNCTION__, __LINE__); printf(fmt); }}

#define snooper_err(fmt...) {    \
        if (kSnoop_LOG_ERR <= glog_level ) {\
        printf("%s:%s:%d> ",kSnoop_FILE_NAME, __FUNCTION__, __LINE__); printf(fmt); }}

#define kSnoop_MaxCircuitLen    80
#define kSnoop_DefaultCircuitID "00:10:A4:23:B6:C0;xfinityWiFi;o"
#define kSnoop_MaxRemoteLen 20
#define kSnoop_DefaultRemoteID "00:10:A4:23:B6:C1"
#define kSnoop_MaxNumAssociatedDevices  30
#define kSnoop_DefaultMaxNumberOfClients   kSnooper_MaxClients
#define kSnoop_MaxCircuitIDs        7
#define MAX_NUM_TRIES 15

#define READ 0
#define WRITE 1
#define READ_ERR -1
#define CLOSE_ERR -1

/* What to do about packets we're asked to relay that
   already have a relay option: */
enum agent_relay_mode_t
{   forward_and_append,     /* Forward and append our own relay option. */
    forward_and_replace,    /* Forward, but replace theirs with ours. */
    forward_untouched,      /* Forward without changes. */
    discard
};


typedef struct 
{
    char remote_id[kSnooper_MaxRemoteLen];      // This is the client MAC address
    char circuit_id[kSnooper_MaxCircuitLen];    // This contains the SSID;AP-MAC;Security
    char ipv4_addr[kSnooper_MaxIpAddrLen];
    char dhcp_status[kSnooper_MaxStatusLen];
    char hostname[kSnooper_MaxHostNameLen];
    int rssi;
	int noOfTriesForOnlineCheck;
} snooper_client_list;

struct mylist_head {
    struct mylist_head *n, *p;
};

typedef struct
{
    struct mylist_head list;

    snooper_client_list client;

} snooper_priv_client_list;

typedef struct
{
    bool snooper_enabled;
    bool snooper_debug_enabled;
    bool snooper_circuit_id_enabled;
    bool snooper_remote_id_enabled;

    int  snooper_first_queue;   
    int  snooper_num_queues;
    int  snooper_max_queues;
    int  snooper_dhcp_packets;

    int  snooper_max_clients;
    int  snooper_num_clients;

    snooper_client_list snooper_clients[kSnooper_MaxClients];

}  snooper_statistics_s;

#define kSnooper_Statistics           865889 // key used for shared memory
#define kSnooper_SharedMemSize        sizeof(snooper_statistics_s)
#define DNSMASQ_LEASES_FILE 		  "/nvram/dnsmasq.leases"

void *dhcp_snooper_init(void *); 
void updateRssiForClient(char* pRemote_id, int rssi);
void snoop_RemoveClientListEntry(char *pRemote_id);
uint16_t snoop_ipChecksum(struct iphdr * header);
void snoop_log(void);
#endif
