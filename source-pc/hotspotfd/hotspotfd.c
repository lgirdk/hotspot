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

#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <strings.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>

#ifdef __HAVE_SYSEVENT_STARTUP_PARAMS__
    #include <sysevent/sysevent.h>
    #include <syscfg/syscfg.h>
#endif

#include <pthread.h>
#include<signal.h>

#include "debug.h"
#include "hotspotfd.h"
#include "ccsp_trace.h"
#include "dhcpsnooper.h"

#define PACKETSIZE  64
#define kDefault_KeepAliveInterval      60 
#define kDefault_KeepAliveIntervalFailure      300 
#define kDefault_KeepAliveThreshold     5
#define kDefault_KeepAlivePolicy        2
#define kDefault_KeepAliveCount         1

#define kDefault_PrimaryTunnelEP        "172.30.0.1" 
#define kDefault_SecondaryTunnelEP      "172.40.0.1" 

//#define kDefault_SecondaryMaxTime       300 // max. time allowed on secondary EP in secs.
#define kDefault_SecondaryMaxTime       43200  //zqiu: according to XWG-CP-15, default time is 12 hours

#define HOTSPOTFD_STATS_PATH    "/var/tmp/hotspotfd.log"

#define kMax_InterfaceLength            20
#define DEBUG_INI_NAME "/etc/debug.ini"

struct packet {
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

unsigned int gKeepAliveInterval     = kDefault_KeepAliveInterval;
unsigned int gKeepAliveIntervalFailure     = kDefault_KeepAliveIntervalFailure;
unsigned int gKeepAliveThreshold    = kDefault_KeepAliveThreshold;

static bool gPrimaryIsActive = true;     // start with primary EP, assume active
static bool gSecondaryIsActive = false;

static unsigned int gKeepAlivesSent = 0;     // aggregate of primary & secondary
static unsigned int gKeepAlivesReceived = 0; // aggregate of primary & secondary
static unsigned int gSecondaryMaxTime = kDefault_SecondaryMaxTime;
static unsigned int gSwitchedBackToPrimary = 0;

static bool gPrimaryIsAlive = false; 
static bool gSecondaryIsAlive = false; 

static char gpPrimaryEP[kMax_IPAddressLength];
static char gpSecondaryEP[kMax_IPAddressLength];
static unsigned int gKeepAlivePolicy = kDefault_KeepAlivePolicy;
static bool gKeepAliveEnable = false;
static bool gKeepAliveLogEnable = true;
static unsigned int gKeepAliveCount = kDefault_KeepAliveCount;

#ifdef __HAVE_SYSEVENT__
static int sysevent_fd;
static token_t sysevent_token;
static int sysevent_fd_gs;
static token_t sysevent_token_gs;
static pthread_t sysevent_tid;
#endif

static int gShm_fd;
static hotspotfd_statistics_s * gpStats;
static int gShm_snoop_fd;
snooper_statistics_s * gpSnoop_Stats;
static int  gKeepAliveChecksumCnt = 0;  
static int  gKeepAliveSequenceCnt = 0;   
static int  gDeadInterval = 5 * kDefault_KeepAliveInterval;   
static char gKeepAliveInterface[kMax_InterfaceLength];

static bool gbFirstPrimarySignal = true;
static bool gbFirstSecondarySignal = true;

static pthread_mutex_t keep_alive_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool gPriStateIsDown = false;
static bool gSecStateIsDown = false;
static bool gBothDnFirstSignal = false;

static bool gTunnelIsUp = false;

static pthread_t dhcp_snooper_tid;
static pthread_t dhcp_snooper_sysevent_tid;
static pthread_t lm_tid;
int gSnoopNumberOfClients = 0; //shared variable across hotspotfd and dhcp_snooperd

bool gSnoopEnable = true;
bool gSnoopDebugEnabled = false;
bool gSnoopLogEnabled = true;
bool gSnoopCircuitEnabled = true;
bool gSnoopRemoteEnabled = true;
int gSnoopFirstQueueNumber = kSnoop_DefaultQueue;
int gSnoopNumberOfQueues = kSnoop_DefaultNumberOfQueues;


int gSnoopMaxNumberOfClients = kSnoop_DefaultMaxNumberOfClients;
char gSnoopCircuitIDList[kSnoop_MaxCircuitIDs][kSnoop_MaxCircuitLen];
char gSnoopSyseventCircuitIDs[kSnoop_MaxCircuitIDs][kSnooper_circuit_id_len] = { 
    kSnooper_circuit_id0,
    kSnooper_circuit_id1,
    kSnooper_circuit_id2,
    kSnooper_circuit_id3,
    kSnooper_circuit_id4
};

char gSnoopSSIDList[kSnoop_MaxCircuitIDs][kSnoop_MaxCircuitLen];
int  gSnoopSSIDListInt[kSnoop_MaxCircuitIDs];
char gSnoopSyseventSSIDs[kSnoop_MaxCircuitIDs][kSnooper_circuit_id_len] = { 
    kSnooper_ssid_index0,
    kSnooper_ssid_index1,
    kSnooper_ssid_index2,
    kSnooper_ssid_index3,
    kSnooper_ssid_index4
};

static bool hotspotfd_isClientAttached(bool *pIsNew)
{
    static bool num_devices_0=0;
    if (gSnoopNumberOfClients > 0) { 
        if(pIsNew && num_devices_0==0) 
            *pIsNew=true;
        num_devices_0 = gSnoopNumberOfClients;
        return true;
    }    
    num_devices_0 = gSnoopNumberOfClients;
    return false;
}

////////////////////////////////////////////////////////////////////////////////
/// \brief hotspotfd_checksum
///
///  Standard 1s complement checksum. 
///    
/// \param - pdata  - pointer to data
/// \param - len    - data length
/// 
/// \return - 0 = ping successful, 1 = ping not OK
/// 
////////////////////////////////////////////////////////////////////////////////
static unsigned short hotspotfd_checksum(void *pdata, int len)
{
    unsigned short *buf = pdata;
    unsigned int sum = 0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;

    if ( len == 1 )
        sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum; 

    return result;
}

////////////////////////////////////////////////////////////////////////////////
/// \brief hotspotfd_ping
///
///  Create message and send it. 
///    
/// \param - address to ping
/// 
/// \return - 0 = ping successful, 1 = ping not OK
/// 
////////////////////////////////////////////////////////////////////////////////
static int _hotspotfd_ping(char *address)
{
    const int val = 255;
    int i, sd;
    struct packet pckt;
    struct sockaddr_in r_addr;
    int loop;
    struct hostent *hname;
    struct sockaddr_in addr_ping,*addr;
    int pid = -1;
    struct protoent *proto = NULL;
    int cnt = 1;
    int status = STATUS_FAILURE;
    struct ifreq ifr;
    unsigned netaddr;
    static int l_iPingCount = 0;

    // This is the number of ping's to send out
    // per keep alive interval
    unsigned keepAliveCount = gKeepAliveCount;
printf("------- ping >>\n");
    pid = getpid();
    proto = getprotobyname("ICMP");
    hname = gethostbyname(address);
    bzero(&addr_ping, sizeof(addr_ping));

    netaddr = inet_addr(address);
    msg_debug("netaddr: %08x\n", netaddr);

    if (hname) {
        addr_ping.sin_family = hname->h_addrtype;
    } else {
        return status;
    }

    addr_ping.sin_port = 0;
    addr_ping.sin_addr.s_addr = *(long*)hname->h_addr;

    addr = &addr_ping;

    sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
	msg_debug("%s sd=%d\n", __func__, sd);
    do {

        if ( sd < 0 ) {
            perror("socket");
            status = STATUS_FAILURE;
            break;
        }

        // Bind to a specific interface only 
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), gKeepAliveInterface);
        if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
            perror("Error on SO_BINDTODEVICE");
            status = STATUS_FAILURE;
            break;
        }

        if ( setsockopt(sd, SOL_IP, IP_TTL, &val, sizeof(val)) != 0) {
            perror("Set TTL option");
            status = STATUS_FAILURE;
            break;
        }

        if ( fcntl(sd, F_SETFL, O_NONBLOCK) != 0 ) {
            perror("Request nonblocking I/O");
            status = STATUS_FAILURE;
            break;
        }

        if (l_iPingCount == 15)		
		{
			CcspTraceInfo(("Sending ICMP ping to:%s\n", address));
			l_iPingCount = 0;
		}
		else
			l_iPingCount++;

        for (loop = 0;loop < 10; loop++) {
            socklen_t len = sizeof(r_addr); 

            if ( recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &len) > 0 ) {

                msg_debug("pckt.hdr.checksum: %d\n", pckt.hdr.checksum);
                msg_debug("pckt.hdr.code    : %d\n", pckt.hdr.code);
                msg_debug("pckt.hdr.type    : %d\n", pckt.hdr.type);
#if 0
                printf("%s:%d> data\n", __FUNCTION__, __LINE__);
                for (i = 0; i < 50; i++) {

                    printf("%02x ", pckt.msg[i]);
                    if (j==7) {
                        printf(" ");
                    }

                    j++;
                    if (j==16) {
                        printf("\n");
                        j=0;
                    }

                }
                printf("\n");
#endif
                if (!memcmp(&pckt.msg[4], &netaddr, sizeof(netaddr))) {
                    msg_debug("EP address matches ping address\n");
                    status = STATUS_SUCCESS;
                } else {
                    status = STATUS_FAILURE;
                }

                break;
            }

            bzero(&pckt, sizeof(pckt));
            pckt.hdr.type = ICMP_ECHO;
            pckt.hdr.un.echo.id = pid;

            for ( i = 0; i < sizeof(pckt.msg)-1; i++ )
                pckt.msg[i] = i+'0';

            pckt.msg[i] = 0;
            pckt.hdr.un.echo.sequence = cnt++;
            pckt.hdr.checksum = hotspotfd_checksum(&pckt, sizeof(pckt));

            if ( sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0 )
                perror("sendto");

            usleep(300000);

        } 

    } while (--keepAliveCount);

    if ( sd >= 0 ) {
        close(sd);
    }
printf("------- ping %d << status\n");
    return status;
}

static int hotspotfd_ping(char *address, bool checkClient) {
    //zqiu: do not ping WAG if no client attached, and no new client join in
printf("------------------ %s \n", __func__); 
    if(checkClient && !hotspotfd_isClientAttached( NULL) )
        return  STATUS_SUCCESS;
    return  _hotspotfd_ping(address);
}

static int hotspotfd_sleep(int sec, bool l_tunnelAlive) {
	bool isNew=false;	
	time_t l_sRefTime, l_sNowTime;
	struct tm * timeinfo;
	int l_dSeconds;
	int l_iRefSec;
	
	time(&l_sRefTime);
	timeinfo = localtime(&l_sRefTime);
	l_iRefSec = sec;
	
	if(sec == gKeepAliveIntervalFailure)
	{
		CcspTraceInfo(("GRE Tunnel is down sleep for:%d sec\n", gKeepAliveIntervalFailure));
	}	

	msg_debug("Current Time before sleep: %s, sleep for %d secs Tunnel Alive / not:%d\n", asctime(timeinfo), l_iRefSec, l_tunnelAlive);
    while(sec>0) {
		if (l_tunnelAlive)
		{
			hotspotfd_isClientAttached(&isNew);
			if(isNew) 
				return sec;
		}
		sleep(5);
		sec -= 5;
		time(&l_sNowTime);
		l_dSeconds = difftime(l_sNowTime, l_sRefTime);
		if (l_iRefSec <= l_dSeconds)
		{
			timeinfo = localtime(&l_sNowTime);
			msg_debug("Leaving hotspotfd_sleep at :%s", asctime(timeinfo));
			return sec;
		}
    }
	time(&l_sNowTime);
	timeinfo = localtime(&l_sNowTime);
	msg_debug("Leaving hotspotfd_sleep at :%s", asctime(timeinfo));
    return sec;
}

static void hotspotfd_SignalHandler(int signo)
{
    msg_debug("Received signal: %d\n", signo);

#ifdef __HAVE_SYSEVENT__
    msg_debug("Closing sysevent and shared memory\n");
    sysevent_close(sysevent_fd, sysevent_token);
    sysevent_close(sysevent_fd_gs, sysevent_token_gs);
#endif

    close(gShm_fd);
    close(gShm_snoop_fd);
    exit(0);
}

static void hotspotfd_log(void)
{
    static FILE *out;

    out = fopen(HOTSPOTFD_STATS_PATH, "w");

    if (out != NULL) {

        fprintf(out, "gKeepAliveEnable: %d\n", gKeepAliveEnable);
        fprintf(out, "gpPrimaryEP: %s\n", gpPrimaryEP);
        fprintf(out, "gPrimaryIsActive: %d\n", gPrimaryIsActive);
        fprintf(out, "gPrimaryIsAlive: %d\n\n", gPrimaryIsAlive);

        fprintf(out, "gpSecondaryEP: %s\n", gpSecondaryEP);
        fprintf(out, "gSecondaryIsActive: %d\n", gSecondaryIsActive);
        fprintf(out, "gSecondaryIsAlive: %d\n\n", gSecondaryIsAlive);

        fprintf(out, "gKeepAlivesSent: %u\n", gKeepAlivesSent);
        fprintf(out, "gKeepAlivesReceived: %u\n", gKeepAlivesReceived);
        fprintf(out, "gKeepAliveInterval: %u\n", gKeepAliveInterval);
        fprintf(out, "gKeepAliveCount: %u\n", gKeepAliveCount);
        fprintf(out, "gKeepAliveThreshold: %u\n\n", gKeepAliveThreshold);
        fprintf(out, "gSecondaryMaxTime: %u\n", gSecondaryMaxTime);
        fprintf(out, "gSwitchedBackToPrimary %u times\n", gSwitchedBackToPrimary);
        fprintf(out, "gKeepAliveInterface: %s\n", gKeepAliveInterface);

        fprintf(out, "gPriStateIsDown: %u\n", gPriStateIsDown);
        fprintf(out, "gSecStateIsDown: %u\n", gSecStateIsDown);
        fprintf(out, "gBothDnFirstSignal: %u\n", gBothDnFirstSignal);

        fclose(out);

        // Save statistics to shared memory for the hotspot library
        strcpy(gpStats->primaryEP, gpPrimaryEP); 
        gpStats->primaryIsActive = gPrimaryIsActive;               
        gpStats->primaryIsAlive = gPrimaryIsAlive;                

        strcpy(gpStats->secondaryEP, gpSecondaryEP);
        gpStats->secondaryIsActive = gSecondaryIsActive;             
        gpStats->secondaryIsAlive = gSecondaryIsAlive;              

        gpStats->keepAlivesSent = gKeepAlivesSent;        
        gpStats->keepAlivesReceived = gKeepAlivesReceived;    
        gpStats->keepAliveInterval = gKeepAliveInterval;     
        gpStats->keepAliveCount = gKeepAliveCount;     
        gpStats->keepAliveThreshold = gKeepAliveThreshold;    
        gpStats->secondaryMaxTime = gSecondaryMaxTime;      
        gpStats->switchedBackToPrimary = gSwitchedBackToPrimary; 

        gpStats->discardedChecksumCnt = gKeepAliveChecksumCnt;  
        gpStats->discaredSequenceCnt = gKeepAliveSequenceCnt;  

        gpStats->deadInterval = gDeadInterval;
    }

}

static bool hotspotfd_isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

#ifdef __HAVE_SYSEVENT__
static void *hotspotfd_sysevent_handler(void *data)
{
    async_id_t hotspotfd_primary_id;
    async_id_t hotspotfd_secondary_id; 
    async_id_t hotspotfd_keep_alive_id;
    async_id_t hotspotfd_keep_alive_threshold_id;
    async_id_t hotspotfd_max_secondary_id;
    async_id_t hotspotfd_policy_id;
    async_id_t hotspotfd_enable_id;
    async_id_t hotspotfd_log_enable_id;
    async_id_t hotspotfd_keep_alive_count_id;
    
	async_id_t snoop_enable_id;
    async_id_t snoop_debug_enable_id;
    async_id_t snoop_log_enable_id;
    async_id_t snoop_circuit_enable_id;
    async_id_t snoop_remote_enable_id;
    async_id_t snoop_max_clients_id;
    async_id_t snoop_circuit_ids[kSnoop_MaxCircuitIDs]; 
    async_id_t snoop_ssids_ids[kSnoop_MaxCircuitIDs];

    int i = 0;

    sysevent_setnotification(sysevent_fd, sysevent_token, kHotspotfd_primary,              &hotspotfd_primary_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_secondary,            &hotspotfd_secondary_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_keep_alive,           &hotspotfd_keep_alive_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_keep_alive_threshold, &hotspotfd_keep_alive_threshold_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_max_secondary,        &hotspotfd_max_secondary_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_keep_alive_policy,    &hotspotfd_policy_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_enable,               &hotspotfd_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_log_enable,           &hotspotfd_log_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_keep_alive_count,     &hotspotfd_keep_alive_count_id);

    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_enable,          &snoop_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_debug_enable,    &snoop_debug_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_log_enable,      &snoop_log_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_circuit_enable,  &snoop_circuit_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_remote_enable,   &snoop_remote_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_max_clients,     &snoop_max_clients_id);

    for(i=0; i<kSnoop_MaxCircuitIDs; i++) 
	{
        sysevent_setnotification(sysevent_fd, sysevent_token, gSnoopSyseventCircuitIDs[i], &snoop_circuit_ids[i]);
    }

    for(i=0; i<kSnoop_MaxCircuitIDs; i++) 
	{
        sysevent_setnotification(sysevent_fd, sysevent_token, gSnoopSyseventSSIDs[i], &snoop_ssids_ids[i]);
    }

    for (;;) {
        char name[25], val[100];
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
        async_id_t getnotification_id;

        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_id);

        if (err) {
            CcspTraceError(("error in sysevent getnotification %d\n", err));
        } else {
            if (strcmp(name, kHotspotfd_primary)==0) {
                msg_debug("Received %s sysevent\n", kHotspotfd_primary);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                strcpy(gpPrimaryEP, val);

                msg_debug("gpPrimaryEP: %s\n", gpPrimaryEP);

                pthread_mutex_lock(&keep_alive_mutex);
                gbFirstPrimarySignal = true;
                pthread_mutex_unlock(&keep_alive_mutex);
            } else if (strcmp(name, khotspotfd_secondary)==0) {
                msg_debug("Received %s sysevent\n", khotspotfd_secondary);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                strcpy(gpSecondaryEP, val);

                msg_debug("gpSecondaryEP: %s\n", gpSecondaryEP);

                pthread_mutex_lock(&keep_alive_mutex);
                gbFirstSecondarySignal = true;
                pthread_mutex_unlock(&keep_alive_mutex);

            } else if (strcmp(name, khotspotfd_keep_alive)==0) {
                msg_debug("Received %s sysevent\n", khotspotfd_keep_alive);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gKeepAliveInterval = atoi(val);

                msg_debug("gKeepAliveInterval: %u\n", gKeepAliveInterval);

            } else if (strcmp(name, khotspotfd_keep_alive_threshold)==0) {
                msg_debug("Received %s sysevent\n", khotspotfd_keep_alive_threshold);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gKeepAliveThreshold = atoi(val);

                msg_debug("gKeepAliveThreshold: %u\n", gKeepAliveThreshold);

            } else if (strcmp(name, khotspotfd_max_secondary)==0) {
                msg_debug("Received %s sysevent\n", khotspotfd_max_secondary);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSecondaryMaxTime = atoi(val);

                msg_debug("gSecondaryMaxTime: %u\n", gSecondaryMaxTime);

            } else if (strcmp(name, khotspotfd_keep_alive_policy)==0) {
                msg_debug("Received %s sysevent\n", khotspotfd_keep_alive_policy);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gKeepAlivePolicy = atoi(val);

                msg_debug("gKeepAlivePolicy: %s\n", (gKeepAlivePolicy == 1 ? "NONE" : "ICMP"));

            } else if (strcmp(name, khotspotfd_enable)==0) {
                msg_debug("Received %s sysevent\n", khotspotfd_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                if (atoi(val) == 0) {
                    gKeepAliveEnable = false;
                    CcspTraceError(("Keep alive enable is false, ICMP ping wont be sent\n"));
                } else {
                    gKeepAliveEnable = true;
                }
                msg_debug("gKeepAliveEnable: %u\n", gKeepAliveEnable);

            } else if (strcmp(name, khotspotfd_keep_alive_count)==0) {
                msg_debug("Received %s sysevent\n", khotspotfd_keep_alive_count);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gKeepAliveCount = atoi(val);

                msg_debug("gKeepAliveCount: %u\n", gKeepAliveCount);

            } else if (strcmp(name, khotspotfd_log_enable)==0) {
                msg_debug("Received %s sysevent\n", khotspotfd_log_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gKeepAliveLogEnable = atoi(val);

                msg_debug("gKeepAliveLogEnable: %u\n", gKeepAliveLogEnable);

            } else if (strcmp(name, khotspotfd_dead_interval)==0) {
                msg_debug("Received %s sysevent\n", khotspotfd_dead_interval);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gDeadInterval = atoi(val);

                msg_debug("gDeadInterval: %u\n", gDeadInterval);
            }
            else if (strcmp(name, kSnooper_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopEnable = atoi(val);

                CcspTraceInfo(("gSnoopEnable: %u\n", gSnoopEnable));

            } else if (strcmp(name, kSnooper_debug_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_debug_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopDebugEnabled = atoi(val);

                CcspTraceInfo(("gSnoopDebugEnabled: %u\n", gSnoopDebugEnabled));

            } else if (strcmp(name, kSnooper_log_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_log_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopLogEnabled = atoi(val);

                CcspTraceInfo(("gSnoopDebugEnabled: %u\n", gSnoopLogEnabled));

            } else if (strcmp(name, kSnooper_circuit_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_circuit_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopCircuitEnabled = atoi(val);

                CcspTraceInfo(("gSnoopCircuitEnabled: %u\n", gSnoopCircuitEnabled));

            } else if (strcmp(name, kSnooper_remote_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_remote_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopRemoteEnabled = atoi(val);

                CcspTraceInfo(("gSnoopRemoteEnabled: %u\n", gSnoopRemoteEnabled));

            } else if (strcmp(name, kSnooper_max_clients)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_max_clients);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopMaxNumberOfClients = atoi(val);

                CcspTraceInfo(("gSnoopMaxNumberOfClients: %u\n", gSnoopMaxNumberOfClients));

            } 

            for(i=0; i<kSnoop_MaxCircuitIDs; i++) {

                if (strcmp(name, gSnoopSyseventCircuitIDs[i])==0) {
					CcspTraceInfo(("CircuitID list case\n"));
	                strcpy(gSnoopCircuitIDList[i], val); 
                    break;
                }
            }

            for(i=0; i<kSnoop_MaxCircuitIDs; i++) {

                if (strcmp(name, gSnoopSyseventSSIDs[i])==0) {
					CcspTraceInfo(("gSnoopSSIDListInt case\n"));
                    strcpy(gSnoopSSIDList[i], val);
                    gSnoopSSIDListInt[i] = atoi(val);
                    break;
                }
            }
		}
        hotspotfd_log();
    }

    return 0;
}
#endif

bool deleteSharedMem(int key, bool snooper)
{
    int maxkey, id, shmid = 0;
    struct shm_info shm_info;
    struct shmid_ds shmds;

    maxkey = shmctl(0, SHM_INFO, (void *) &shm_info);
    for(id = 0; id <= maxkey; id++) {
        shmid = shmctl(id, SHM_STAT, &shmds);

        char shmidchar[16];
        snprintf(shmidchar, sizeof(shmidchar), "%d", shmid);
        if (shmid < 0)
            continue;
        if(shmds.shm_segsz > 0 && key == shmds.shm_perm.__key) {
            CcspTraceError(("Existing shared memory segment %s found! key: %d size:%d. Deleting!\n",shmidchar, shmds.shm_perm.__key, shmds.shm_segsz));
            if (snooper) {
                snooper_statistics_s *snStats;
		        snStats = (snooper_statistics_s *)shmat(shmid, 0, 0);
                if (snStats == ((snooper_statistics_s *)-1))
                {
                    perror("shmat error");
                    snStats = NULL;
                    return false;
                }
                if (shmdt(snStats))
                {
                    perror("shmdt");
                    return false;
                }
            } else {
                hotspotfd_statistics_s *htStats;
		        htStats = (hotspotfd_statistics_s *)shmat(shmid, 0, 0);
                if (htStats == ((hotspotfd_statistics_s *)-1))
                {
                    perror("shmat error");
                    htStats = NULL;
                    return false;
                }
                if (shmdt(htStats))
                {
                    perror("shmdt");
                    return false;
                }
            }

            if (shmctl(shmid, IPC_RMID, 0) < 0)
            {
                perror("shmctl");
                return false;
            }
            break;
        }
    }

    return true;
}
static int hotspotfd_setupSharedMemory(void)
{
    int status = STATUS_SUCCESS;

    do {
        // Create shared memory segment to get link state
        if ((gShm_fd = shmget(kKeepAlive_Statistics, kKeepAlive_SharedMemSize, IPC_CREAT | 0666)) < 0) {
            if (errno == EEXIST || errno == EINVAL)
            {
                // The key already exists in shared memory. We will try to delete and re-create
                if (true == deleteSharedMem(kKeepAlive_Statistics, false))
                {
                    if ((gShm_fd = shmget(kKeepAlive_Statistics, kKeepAlive_SharedMemSize, IPC_CREAT | 0666)) < 0) {
                        perror("shmget");
                        status = STATUS_FAILURE;
                        CcspTraceError(("shmget failed while setting up hotspot shared memory\n")); 
                        break;
                    }
                } else {
                    perror("delete shared memory failed");
                    CcspTraceError(("Failed while trying to delete existing hotspot shared memory\n")); 
                    status = STATUS_FAILURE;
                    break;
                }
            } else {
                // other error besides "already exists" or "wrong size"
                perror("shmget");
                status = STATUS_FAILURE;
                CcspTraceError(("shmget failed while setting up hotspot shared memory: %d\n", errno)); 
                break;
            }
        }

        // Attach the segment to our data space.
        if ((gpStats = (hotspotfd_statistics_s *)shmat(gShm_fd, NULL, 0)) == (hotspotfd_statistics_s *) -1) {
            CcspTraceError(("shmat failed while setting up hotspot shared memory segment\n")); 

            perror("shmat");

            status = STATUS_FAILURE;
            break;
        }

		// Create shared memory segment to get link state
        if ((gShm_snoop_fd = shmget(kSnooper_Statistics, kSnooper_SharedMemSize, IPC_CREAT | 0666)) < 0) { 
            if (errno == EEXIST || errno == EINVAL)
            {
                // The key already exists in shared memory. We will try to delete and re-create
                if (true == deleteSharedMem(kSnooper_Statistics, true))
                {
                    if ((gShm_snoop_fd = shmget(kSnooper_Statistics, kSnooper_SharedMemSize, IPC_CREAT | 0666)) < 0) {
                        perror("shmget");
                        status = STATUS_FAILURE;
                        CcspTraceError(("shmget failed while setting up snooper shared memory\n")); 
                        break;
                    }
                } else {
                    perror("delete shared memory failed");
                    CcspTraceError(("Failed while trying to delete existing snooper shared memory\n")); 
                    status = STATUS_FAILURE;
                    break;
                }
            } else {
                // other error besides "already exists" or "wrong size"
                perror("shmget");
                status = STATUS_FAILURE;
                CcspTraceError(("shmget failed while setting up snooper shared memory: %d\n", errno)); 
                break;
            }
        }

        // Attach the segment to our data space.
        if ((gpSnoop_Stats = (snooper_statistics_s *)shmat(gShm_snoop_fd, NULL, 0)) == (snooper_statistics_s *) -1) {
            CcspTraceError(("shmat failed while setting up snooper shared memory segment\n")); 

            perror("shmat");

            status = STATUS_FAILURE;
            break;
        }

    } while (0);

    return status;
}

#ifdef __HAVE_SYSEVENT_STARTUP_PARAMS__
static int hotspotfd_getStartupParameters(void)
{
    int status = STATUS_SUCCESS;
	int i;
    char buf[kMax_IPAddressLength];

    do {
        // Primary EP 
        if ((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, kHotspotfd_primary, buf, sizeof(buf)))) {
            CcspTraceError(("sysevent_get failed to get %s: %d\n", kHotspotfd_primary, status)); 
            status = STATUS_FAILURE;
            break;
        }

        if (hotspotfd_isValidIpAddress(buf)) {
            strcpy(gpPrimaryEP, buf);

            msg_debug("Loaded sysevent %s with %s\n", kHotspotfd_primary, gpPrimaryEP); 
        } else {
            CcspTraceError(("hotspotfd_isValidIpAddress: %s: %d\n", kHotspotfd_primary, status));

            status = STATUS_FAILURE;
            break;
        }

        // Secondary EP
        if ((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, khotspotfd_secondary, buf, sizeof(buf)))) {
            CcspTraceError(("sysevent_get failed to get %s: %d\n", khotspotfd_secondary, status)); 
            status = STATUS_FAILURE;
            break;
        }

        if (hotspotfd_isValidIpAddress(buf)) {
            strcpy(gpSecondaryEP, buf);

            msg_debug("Loaded sysevent %s with %s\n", khotspotfd_secondary, gpSecondaryEP); 
        } else {

            CcspTraceError(("hotspotfd_isValidIpAddress: %s: %d\n", khotspotfd_secondary, status));

            status = STATUS_FAILURE;
            break;
        }

        // Keep Alive Interval
        if ((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, khotspotfd_keep_alive, buf, sizeof(buf)))) {
            CcspTraceError(("sysevent_get failed to get %s: %d\n", khotspotfd_keep_alive, status)); 
            status = STATUS_FAILURE;
            break;
        }

        gKeepAliveInterval = atoi(buf);
        if (gKeepAliveInterval > 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_keep_alive, gKeepAliveInterval); 
        } else {

            CcspTraceError(("Invalid gKeepAliveInterval: %d\n", gKeepAliveInterval)); 
            status = STATUS_FAILURE;
            break;
        }

        // Keep Alive Threshold
        if ((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, khotspotfd_keep_alive_threshold, buf, sizeof(buf)))) {
            CcspTraceError(("sysevent_get failed to get %s: %d\n", khotspotfd_keep_alive_threshold, status)); 
            status = STATUS_FAILURE;
            break;
        }

        gKeepAliveThreshold = atoi(buf);
        if (gKeepAliveThreshold > 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_keep_alive_threshold, gKeepAliveThreshold); 

        } else {

            CcspTraceError(("Invalid gKeepAliveThreshold: %d\n", gKeepAliveThreshold)); 
            status = STATUS_FAILURE;
            break;
        }

        // Keep alive Max. Secondary
        if ((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, khotspotfd_max_secondary, buf, sizeof(buf)))) {
            CcspTraceError(("sysevent_get failed to get %s: %d\n", khotspotfd_max_secondary, status)); 
            status = STATUS_FAILURE;
            break;
        }

        gSecondaryMaxTime = atoi(buf);
        if (gSecondaryMaxTime > 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_max_secondary, gSecondaryMaxTime); 

        } else {

            CcspTraceError(("Invalid gSecondaryMaxTime: %d\n", gSecondaryMaxTime)); 
            status = STATUS_FAILURE;
            break;
        }

        // Keep Alive Policy
        if ((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, khotspotfd_keep_alive_policy, buf, sizeof(buf)))) {
            CcspTraceError(("sysevent_get failed to get %s: %d\n", khotspotfd_keep_alive_policy, status)); 
            status = STATUS_FAILURE;
            break;
        }

        gKeepAlivePolicy = atoi(buf);
        if (gKeepAlivePolicy >= 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_keep_alive_policy, gKeepAlivePolicy); 

        } else {

            CcspTraceError(("Invalid gKeepAlivePolicy: %d\n", gKeepAlivePolicy)); 
            status = STATUS_FAILURE;
            break;
        }

        // Keep Alive Count
        if ((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, khotspotfd_keep_alive_count, buf, sizeof(buf)))) {
            CcspTraceError(("sysevent_get failed to get %s: %d\n", khotspotfd_keep_alive_count, status)); 
            status = STATUS_FAILURE;
            break;
        }

        gKeepAliveCount = atoi(buf);
        if (gKeepAliveCount > 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_keep_alive_count, gKeepAliveCount); 

        } else {
            CcspTraceError(("Invalid gKeepAliveCount: %d\n", gKeepAliveCount)); 
            status = STATUS_FAILURE;
            break;
        }

		//DHCP Snooper related
    	for(i=gSnoopFirstQueueNumber; i < gSnoopNumberOfQueues+gSnoopFirstQueueNumber; i++) 
		{
        	if((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, gSnoopSyseventCircuitIDs[i], 
            	                      gSnoopCircuitIDList[i], kSnoop_MaxCircuitLen))) 
			{
            	CcspTraceError(("sysevent_get failed to get %s: %d\n", gSnoopSyseventCircuitIDs[i], status)); 
            	status = STATUS_FAILURE;
            	break;
	        } 
			else 
			{
            	msg_debug("Loaded sysevent gSnoopSyseventCircuitIDs[%d]: %s with %s\n", 
                	      i, gSnoopSyseventCircuitIDs[i], 
                    	  gSnoopCircuitIDList[i]
            	);  
            	CcspTraceInfo(("Loaded sysevent gSnoopSyseventCircuitIDs[%d]: %s with %s\n", 
                		      i, gSnoopSyseventCircuitIDs[i], 
                      		  gSnoopCircuitIDList[i]
            	));  
        	}
    	}

    	for(i=gSnoopFirstQueueNumber; i < gSnoopNumberOfQueues+gSnoopFirstQueueNumber; i++) 
		{
	        if((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, gSnoopSyseventSSIDs[i], 
    	                              gSnoopSSIDList[i], kSnoop_MaxCircuitLen))) 
			{
	            CcspTraceError(("sysevent_get failed to get %s: %d\n", gSnoopSyseventSSIDs[i], status)); 
    	        status = STATUS_FAILURE;
        	    break;
	        } 
			else 
			{
	            if(gSnoopSSIDList[i]) 
				{
    	           gSnoopSSIDListInt[i] = atoi(gSnoopSSIDList[i]);
            	} 
				else 
				{
               		gSnoopSSIDListInt[i] = gSnoopFirstQueueNumber; 
            	}
            	msg_debug("Loaded sysevent %s with %d\n", gSnoopSyseventSSIDs[i], gSnoopSSIDListInt[i]); 
            	CcspTraceInfo(("Loaded sysevent %s with %d\n", gSnoopSyseventSSIDs[i], gSnoopSSIDListInt[i])); 
        	}
    	}

    	if(status == STATUS_SUCCESS) 
		{
	        if((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, kSnooper_circuit_enable, 
    	                              buf, kSnoop_max_sysevent_len))) 
			{
            	CcspTraceError(("sysevent_get failed to get %s: %d\n", kSnooper_circuit_enable, status)); 
            	status = STATUS_FAILURE;
        	} 
			else 
			{
	            gSnoopCircuitEnabled = atoi(buf);
    	        msg_debug("Loaded sysevent %s with %d\n", kSnooper_circuit_enable, gSnoopCircuitEnabled);  
        	    CcspTraceInfo(("Loaded sysevent %s with %d\n", kSnooper_circuit_enable, gSnoopCircuitEnabled));  
        	}
    	}

	    if(status == STATUS_SUCCESS) 
		{
	        if((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, kSnooper_remote_enable, 
    	                              buf, kSnoop_max_sysevent_len))) 
			{
	            CcspTraceError(("sysevent_get failed to get %s: %d\n", kSnooper_remote_enable, status)); 
    	        status = STATUS_FAILURE;
        	} 
			else 
			{
	            gSnoopRemoteEnabled = atoi(buf);
    	        msg_debug("Loaded sysevent %s with %d\n", kSnooper_remote_enable, gSnoopRemoteEnabled);  
        	    CcspTraceInfo(("Loaded sysevent %s with %d\n", kSnooper_remote_enable, gSnoopRemoteEnabled));  
	        }
    	}

	    if(status == STATUS_SUCCESS) 
		{
	        if((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, kSnooper_max_clients, 
    	                              buf, kSnoop_max_sysevent_len))) 
			{
	            CcspTraceError(("sysevent_get failed to get %s: %d\n", kSnooper_max_clients, status)); 
    	        gSnoopMaxNumberOfClients = kSnoop_DefaultMaxNumberOfClients;
        	    status = STATUS_FAILURE;
        	} 
			else 
			{
	            if(atoi(buf)) 
				{
    	            gSnoopMaxNumberOfClients = atoi(buf);
            	} 
            	msg_debug("Loaded sysevent %s with %d\n", kSnooper_max_clients, gSnoopMaxNumberOfClients);  
            	CcspTraceInfo(("Loaded sysevent %s with %d\n", kSnooper_max_clients, gSnoopMaxNumberOfClients));  
        	}
    	}   

    } while (0);

    return status;
}
#endif

static void hotspotfd_usage(void)
{
    printf("  Usage:  hotspotfd [-p<primary tunnel EP IP Address>] [-s<secondary tunnel EP IP Address>]\n");
    printf("                    [-i<keep alive interval (secs)>] [-t<keep alive threshold (multiple of intervals)>]\n");
    printf("                    [-m<maximum secondary EP time (secs)>] [-e<enable 0 or 1>} [-l<log enable 0 or 1>]\n");
    printf("                    [-n<network interface name>]\n\n");

    exit(0);
}

void hotspot_start()
{
    int cmd;
    bool run_in_foreground = false;
    unsigned int keepAliveThreshold = 0;
    unsigned int secondaryKeepAlives = 0;
	time_t secondaryEndPointstartTime;
	time_t currentTime ;
	int timeElapsed;

    //strcpy(gKeepAliveInterface, "erouter0");//LNT_EMU
      strcpy(gKeepAliveInterface, "eth0");
	gKeepAliveEnable = true;

#ifdef __HAVE_SYSEVENT__
    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, kHotspotfd_events, &sysevent_token);
	sysevent_fd_gs = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "hotspotfd-gs", &sysevent_token_gs);

    if (sysevent_fd >= 0 && sysevent_fd_gs >= 0) 
	{
		CcspTraceInfo(("Socket Descriptors for Hotspot Event handling and Get Set are :%d %d respectively\n", sysevent_fd, sysevent_fd_gs));
#ifdef __HAVE_SYSEVENT_STARTUP_PARAMS__
        if (hotspotfd_getStartupParameters() != STATUS_SUCCESS) {
            CcspTraceError(("Error while getting startup parameters\n"));
            hotspotfd_SignalHandler(0);
        }
#endif
        pthread_create(&sysevent_tid, NULL, hotspotfd_sysevent_handler, NULL);
    } else {
		CcspTraceError(("sysevent_open for event handling or get set has failed hotspotfd bring up aborted\n"));
        exit(1);
    }
#endif

    if (hotspotfd_setupSharedMemory() != STATUS_SUCCESS) {
		CcspTraceError(("Could not setup shared memory hotspotfd bring up aborted\n"));
        exit(1);
    }
    pthread_create(&dhcp_snooper_tid, NULL, dhcp_snooper_init, NULL);

    if (signal(SIGTERM, hotspotfd_SignalHandler) == SIG_ERR)
        msg_debug("Failed to catch SIGTERM\n");

    if (signal(SIGINT, hotspotfd_SignalHandler) == SIG_ERR)
        msg_debug("Failed to catch SIGTERM\n");

    if (signal(SIGKILL, hotspotfd_SignalHandler) == SIG_ERR)
        msg_debug("Failed to catch SIGTERM\n");

    CcspTraceInfo(("Hotspotfd process is up\n"));
    system("touch /tmp/hotspotfd_up");
    hotspotfd_log();

    keep_it_alive:

    while (gKeepAliveEnable == true) {
Try_primary:
        while (gPrimaryIsActive && (gKeepAliveEnable == true)) {

            gKeepAlivesSent++;

            if (gKeepAliveLogEnable) {
                hotspotfd_log();
            }

            if (hotspotfd_ping(gpPrimaryEP, gTunnelIsUp) == STATUS_SUCCESS) {
                gPrimaryIsActive = true;
                gSecondaryIsActive = false;
                gPrimaryIsAlive = true;
                gPriStateIsDown = false;
                gBothDnFirstSignal = true;

                gKeepAlivesReceived++;
                keepAliveThreshold = 0;

                if (gKeepAliveLogEnable) {
                    hotspotfd_log();
                }

                if (gbFirstPrimarySignal) {
					CcspTraceInfo(("Create Primary GRE Tunnel with endpoint:%s\n", gpPrimaryEP));				

                    if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, 
                                     kHotspotfd_tunnelEP, gpPrimaryEP, 0)) {

                        CcspTraceError(("sysevent set %s failed on primary\n", kHotspotfd_tunnelEP));
                    }
					gTunnelIsUp=true;
					
                    pthread_mutex_lock(&keep_alive_mutex);
                    gbFirstPrimarySignal = false;
                    pthread_mutex_unlock(&keep_alive_mutex);
                }

                msg_debug("Primary GRE Tunnel Endpoint is alive\n");
                msg_debug("gKeepAlivesSent: %u\n", gKeepAlivesSent);
                msg_debug("gKeepAlivesReceived: %u\n", gKeepAlivesReceived);
				if (gKeepAliveEnable == false) continue;
				hotspotfd_sleep(((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure), true); //Tunnel Alive case
                if (gKeepAliveEnable == false) continue;

            } else {

                gPrimaryIsAlive = false;
                pthread_mutex_lock(&keep_alive_mutex);
                gbFirstPrimarySignal = true;
                pthread_mutex_unlock(&keep_alive_mutex);

                keepAliveThreshold++;
				//if (gKeepAliveEnable == false) continue;
				//hotspotfd_sleep(((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure), false); //Tunnel not Alive case
                //if (gKeepAliveEnable == false) continue;

                if (keepAliveThreshold < gKeepAliveThreshold) {
					if (gKeepAliveEnable == false) continue;
					hotspotfd_sleep(((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure), false); //Tunnel not Alive case				
                    continue;
                } else {
                    gPrimaryIsActive = false;
                    gSecondaryIsActive = true;
					//ARRISXB3-2770 When there is switch in tunnel , existing tunnel should be destroyed and created with new reachable tunnel as GW.
					gbFirstSecondarySignal = true;
					//fix ends
                    keepAliveThreshold = 0;
                    gPriStateIsDown = true;

					CcspTraceInfo(("Primary GRE Tunnel Endpoint :%s is not alive Switching to Secondary Endpoint :%s\n", gpPrimaryEP,gpSecondaryEP));

                    if (gSecStateIsDown && gPriStateIsDown && gBothDnFirstSignal) {

                        gBothDnFirstSignal = false;

                        if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, 
                                         kHotspotfd_tunnelEP, "\0", 0)) {

                            CcspTraceError(("sysevent set %s failed on secondary\n", kHotspotfd_tunnelEP));
                        }
						gTunnelIsUp=false;
                    }
                    time(&secondaryEndPointstartTime);  
                }
            }
        }
Try_secondary:
        while (gSecondaryIsActive && (gKeepAliveEnable == true)) {

            gKeepAlivesSent++;

            if (gKeepAliveLogEnable) {
                hotspotfd_log();
            }

            if (hotspotfd_ping(gpSecondaryEP, gTunnelIsUp) == STATUS_SUCCESS) {
                gPrimaryIsActive = false;
                gSecondaryIsActive = true;
                gSecondaryIsAlive = true;
                gSecStateIsDown = false;
                gBothDnFirstSignal = true;

                gKeepAlivesReceived++;
                keepAliveThreshold = 0;

                secondaryKeepAlives++;

				time(&currentTime);
				timeElapsed = difftime(currentTime, secondaryEndPointstartTime);

                if (gKeepAliveLogEnable) {
                    hotspotfd_log();
                }

                // Check for absolute max. secondary active interval
                // TODO: If reached tunnel should be swicthed to primary
                //if (secondaryKeepAlives > gSecondaryMaxTime/60) {

				if( timeElapsed > gSecondaryMaxTime ) {

                    gPrimaryIsActive = true;
					//ARRISXB3-2770 When there is switch in tunnel , existing tunnel should be destroyed and created with new reachable tunnel as GW.
					gbFirstPrimarySignal = true;
					// fix ends
                    gSecondaryIsActive = false;
                    keepAliveThreshold = 0;
                    secondaryKeepAlives = 0;
					CcspTraceInfo(("Max. Secondary EP time:%d exceeded. Switching to Primary EP\n", gSecondaryMaxTime));

                    // TODO: Do we just destroy this tunnel and move over
                    // to the primary? What if the Primary is down then we switched
                    // for no reason?
                    // TODO: Need to try the Primary once before switching.
                    gSwitchedBackToPrimary++;
                    break;
                }

                if (gbFirstSecondarySignal) {
					CcspTraceInfo(("Create Secondary GRE tunnel with endpoint:%s\n", gpSecondaryEP));

                    if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, 
                                     kHotspotfd_tunnelEP, gpSecondaryEP, 0)) {

                        CcspTraceError(("sysevent set %s failed on secondary\n", kHotspotfd_tunnelEP)); 
                    }
					gTunnelIsUp=true;
					
                    pthread_mutex_lock(&keep_alive_mutex);
                    gbFirstSecondarySignal = false;
                    pthread_mutex_unlock(&keep_alive_mutex);
                }

                msg_debug("Secondary GRE Tunnel Endpoint is alive\n");
                msg_debug("gKeepAlivesSent: %u\n", gKeepAlivesSent);
                msg_debug("gKeepAlivesReceived: %u\n", gKeepAlivesReceived);
				if (gKeepAliveEnable == false) continue;
				hotspotfd_sleep(((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure), true); //Tunnel Alive case
                if (gKeepAliveEnable == false) continue;

            } else {
				CcspTraceInfo(("Secondary GRE Tunnel Endpoint:%s is not alive%s\n", gpSecondaryEP));	
                gSecondaryIsAlive = false;

                pthread_mutex_lock(&keep_alive_mutex);
                gbFirstSecondarySignal = true;
                pthread_mutex_unlock(&keep_alive_mutex);

                keepAliveThreshold++;
				//if (gKeepAliveEnable == false) continue;
				//hotspotfd_sleep(((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure), false); //Tunnel not Alive case
                //if (gKeepAliveEnable == false) continue;
                if (keepAliveThreshold < gKeepAliveThreshold) {
					if (gKeepAliveEnable == false) continue;
					hotspotfd_sleep(((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure), false); //Tunnel not Alive case
                    continue;
                } else {
                    gPrimaryIsActive = true;
                    gSecondaryIsActive = false;
                    keepAliveThreshold = 0;
                    secondaryKeepAlives = 0;
                    gSecStateIsDown = true;

                    if (gSecStateIsDown && gPriStateIsDown && gBothDnFirstSignal) {

                        gBothDnFirstSignal = false;

                        if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, 
                                         kHotspotfd_tunnelEP, "\0", 0)) {

                            CcspTraceError(("sysevent set %s failed on secondary\n", kHotspotfd_tunnelEP));
                        }
						gTunnelIsUp=false;
						break;
                    }
                }
            }
        }

		//gTunnelIsUp==false;
		while (gKeepAliveEnable == true) {
			gKeepAlivesSent++;
			if (hotspotfd_ping(gpPrimaryEP, gTunnelIsUp) == STATUS_SUCCESS) {
				gPrimaryIsActive = true;
                gSecondaryIsActive = false;
				goto Try_primary;
			}
			if (hotspotfd_ping(gpSecondaryEP, gTunnelIsUp) == STATUS_SUCCESS) {
				gPrimaryIsActive = false;
                gSecondaryIsActive = true;
				goto Try_secondary;
			}
			hotspotfd_sleep((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure, false);			
		}
    } 

    while (gKeepAliveEnable == false) {
        sleep(1);
    }

    goto keep_it_alive;

    exit(0);
}
