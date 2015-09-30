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

// -----------------------------------------------------------------------------
//
//                   Copyright 2013 Cisco Systems, Inc.
//
//                           5030 Sugarloaf Parkway
//                               P.O.Box 465447
//                          Lawrenceville, GA 30042
//
//                            CISCO CONFIDENTIAL
//              Unauthorized distribution or copying is prohibited
//                            All rights reserved
//
// No part of this computer software may be reprinted, reproduced or utilized
// in any form or by any electronic, mechanical, or other means, now known or
// hereafter invented, including photocopying and recording, or using any
// information storage and retrieval system, without permission in writing
// from Cisco Systems, Inc.
//
// -----------------------------------------------------------------------------
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

#define PACKETSIZE  64
#define kDefault_KeepAliveInterval      60 
#define kDefault_KeepAliveThreshold     5
#define kDefault_KeepAlivePolicy        2
#define kDefault_KeepAliveCount         1

#define kDefault_PrimaryTunnelEP        "172.30.0.1" 
#define kDefault_SecondaryTunnelEP      "172.40.0.1" 

#define kDefault_SecondaryMaxTime       300 // max. time allowed on secondary EP in secs.

#define HOTSPOTFD_STATS_PATH    "/var/tmp/hotspotfd.log"

#define kMax_InterfaceLength            20

struct packet {
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

unsigned int glog_level             = LOG_NOISE;
unsigned int gKeepAliveInterval     = kDefault_KeepAliveInterval;
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
static pthread_t sysevent_tid;
#endif

static int gShm_fd;
static hotspotfd_statistics_s * gpStats;
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
static int hotspotfd_ping(char *address)
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

    // This is the number of ping's to send out
    // per keep alive interval
    unsigned keepAliveCount = gKeepAliveCount;

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

    return status;
}

static void hotspotfd_SignalHandler(int signo)
{
    msg_debug("Received signal: %d\n", signo);

#ifdef __HAVE_SYSEVENT__
    msg_debug("Closing sysevent and shared memory\n");
    sysevent_close(sysevent_fd, sysevent_token);
#endif

    close(gShm_fd);
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

    sysevent_setnotification(sysevent_fd, sysevent_token, kHotspotfd_primary,              &hotspotfd_primary_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_secondary,            &hotspotfd_secondary_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_keep_alive,           &hotspotfd_keep_alive_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_keep_alive_threshold, &hotspotfd_keep_alive_threshold_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_max_secondary,        &hotspotfd_max_secondary_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_keep_alive_policy,    &hotspotfd_policy_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_enable,               &hotspotfd_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_log_enable,           &hotspotfd_log_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_keep_alive_count,     &hotspotfd_keep_alive_count_id);

    for (;;) {
        char name[25], val[20];
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
        async_id_t getnotification_id;

        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_id);

        if (err) {
            msg_err("err: %d\n", err);
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

                gKeepAliveEnable = atoi(val);

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
        }

        hotspotfd_log();
    }

    return 0;
}
#endif

static int hotspotfd_setupSharedMemory(void)
{
    int status = STATUS_SUCCESS;

    do {
        // Create shared memory segment to get link state
        if ((gShm_fd = shmget(kKeepAlive_Statistics, kKeepAlive_SharedMemSize, IPC_CREAT | 0666)) < 0) {
            msg_err("shmget failed\n"); 

            perror("shmget");
            status = STATUS_FAILURE;
            break;
        }

        // Attach the segment to our data space.
        if ((gpStats = (hotspotfd_statistics_s *)shmat(gShm_fd, NULL, 0)) == (hotspotfd_statistics_s *) -1) {
            msg_err("shmat failed\n"); 

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
    char buf[kMax_IPAddressLength];

    do {
        // Primary EP 
        if ((status = sysevent_get(sysevent_fd, sysevent_token, kHotspotfd_primary, buf, sizeof(buf)))) {
            msg_err("sysevent_get failed to get %s: %d\n", kHotspotfd_primary, status); 
            status = STATUS_FAILURE;
            break;
        }

        if (hotspotfd_isValidIpAddress(buf)) {
            strcpy(gpPrimaryEP, buf);

            msg_debug("Loaded sysevent %s with %s\n", kHotspotfd_primary, gpPrimaryEP); 
        } else {
            msg_err("hotspotfd_isValidIpAddress: %s: %d\n", kHotspotfd_primary, status);

            status = STATUS_FAILURE;
            break;
        }

        // Secondary EP
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_secondary, buf, sizeof(buf)))) {
            msg_err("sysevent_get failed to get %s: %d\n", khotspotfd_secondary, status); 
            status = STATUS_FAILURE;
            break;
        }

        if (hotspotfd_isValidIpAddress(buf)) {
            strcpy(gpSecondaryEP, buf);

            msg_debug("Loaded sysevent %s with %s\n", khotspotfd_secondary, gpSecondaryEP); 
        } else {

            msg_err("hotspotfd_isValidIpAddress: %s: %d\n", khotspotfd_secondary, status);

            status = STATUS_FAILURE;
            break;
        }

        // Keep Alive Interval
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_keep_alive, buf, sizeof(buf)))) {
            msg_err("sysevent_get failed to get %s: %d\n", khotspotfd_keep_alive, status); 
            status = STATUS_FAILURE;
            break;
        }

        gKeepAliveInterval = atoi(buf);
        if (gKeepAliveInterval > 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_keep_alive, gKeepAliveInterval); 
        } else {

            msg_err("Invalid gKeepAliveInterval: %d\n", gKeepAliveInterval); 
            status = STATUS_FAILURE;
            break;
        }

        // Keep Alive Threshold
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_keep_alive_threshold, buf, sizeof(buf)))) {
            msg_err("sysevent_get failed to get %s: %d\n", khotspotfd_keep_alive_threshold, status); 
            status = STATUS_FAILURE;
            break;
        }

        gKeepAliveThreshold = atoi(buf);
        if (gKeepAliveThreshold > 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_keep_alive_threshold, gKeepAliveThreshold); 

        } else {

            msg_err("Invalid gKeepAliveThreshold: %d\n", gKeepAliveThreshold); 
            status = STATUS_FAILURE;
            break;
        }

        // Keep alive Max. Secondary
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_max_secondary, buf, sizeof(buf)))) {
            msg_err("sysevent_get failed to get %s: %d\n", khotspotfd_max_secondary, status); 
            status = STATUS_FAILURE;
            break;
        }

        gSecondaryMaxTime = atoi(buf);
        if (gSecondaryMaxTime > 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_max_secondary, gSecondaryMaxTime); 

        } else {

            msg_err("Invalid gSecondaryMaxTime: %d\n", gSecondaryMaxTime); 
            status = STATUS_FAILURE;
            break;
        }

        // Keep Alive Policy
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_keep_alive_policy, buf, sizeof(buf)))) {
            msg_err("sysevent_get failed to get %s: %d\n", khotspotfd_keep_alive_policy, status); 
            status = STATUS_FAILURE;
            break;
        }

        gKeepAlivePolicy = atoi(buf);
        if (gKeepAlivePolicy >= 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_keep_alive_policy, gKeepAlivePolicy); 

        } else {

            msg_err("Invalid gKeepAlivePolicy: %d\n", gKeepAlivePolicy); 
            status = STATUS_FAILURE;
            break;
        }

        // Keep Alive Count
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_keep_alive_count, buf, sizeof(buf)))) {
            msg_err("sysevent_get failed to get %s: %d\n", khotspotfd_keep_alive_count, status); 
            status = STATUS_FAILURE;
            break;
        }

        gKeepAliveCount = atoi(buf);
        if (gKeepAliveCount > 0) {
            msg_debug("Loaded sysevent %s with %d\n", khotspotfd_keep_alive_count, gKeepAliveCount); 

        } else {

            msg_err("Invalid gKeepAliveCount: %d\n", gKeepAliveCount); 
            status = STATUS_FAILURE;
            break;
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

int main(int argc, char *argv[])
{
    int cmd;
    bool run_in_foreground = false;
    unsigned int keepAliveThreshold = 0;
    unsigned int secondaryKeepAlives = 0;

    strcpy(gKeepAliveInterface, "none");

    while ((cmd = getopt(argc, argv, "e:p:s:i:t:m:l:n:f::h::")) != -1) {
        switch (cmd) {
        case 'n':

            if (optarg && (strlen(optarg) >= 2) && (strlen(optarg) < kMax_InterfaceLength)) {
                strcpy(gKeepAliveInterface, optarg);
            } else {

                printf("Invalid network interface\n");
                exit(0);
            }

            break;
        case 'e':

            if (atoi(optarg) == 0) {
                gKeepAliveEnable = false;
            } else {
                gKeepAliveEnable = true;
            }

            break;
        case 'l':

            if (atoi(optarg) == 0) {
                gKeepAliveLogEnable = false;
            } else {
                gKeepAliveLogEnable = true;
            }

            break;
        case 'p': // Primary EP
            if (hotspotfd_isValidIpAddress(optarg)) {
                strcpy(gpPrimaryEP, optarg);
            } else {

                printf("Invalid Primary IP Address\n");
                printf("Assuming URI...\n");

                if ((strlen(optarg) < kMax_IPAddressLength) && strchr(optarg, '.')) {
                    strcpy(gpPrimaryEP, optarg);
                } else {

                    printf("Invalid Primary IP Address\n");
                    exit(0);
                }
            }
            break;

        case 's': // Secondary EP
            if (hotspotfd_isValidIpAddress(optarg)) {
                strcpy(gpSecondaryEP, optarg);
            } else {
                printf("Invalid Secondary IP Address\n");
                printf("Assuming URI...\n");

                if ((strlen(optarg) < kMax_IPAddressLength) && strchr(optarg, '.')) {
                    strcpy(gpSecondaryEP, optarg);
                } else {

                    printf("Invalid Secondary IP Address\n");
                    exit(0);
                }
            }
            break;

        case 'i':  // Keep alive interval
            gKeepAliveInterval = atoi(optarg);
            break;

        case 't':  // Keep alive threshold
            gKeepAliveThreshold = atoi(optarg);
            break;

        case 'm': // max. time allowed on Secondary EP
            gSecondaryMaxTime = atoi(optarg);
            break;

        case 'f':
            run_in_foreground = true;
            break;

        case 'h':
        default:
            printf("Unrecognized option '%c'.\n", cmd);
            hotspotfd_usage();
        }
    }

    msg_debug("gpPrimaryEP            : %s\n", gpPrimaryEP);
    msg_debug("gpSecondaryEP          : %s\n", gpSecondaryEP);
    msg_debug("run_in_foreground    : %d\n", run_in_foreground); 
    msg_debug("keep alive enabled   : %d\n", gKeepAliveEnable); 
    msg_debug("log enabled          : %d\n", gKeepAliveLogEnable); 
    msg_debug("keep alive interval  : %d\n", gKeepAliveInterval); 
    msg_debug("keep alive threshold : %d\n", gKeepAliveThreshold); 
    msg_debug("max secondary        : %d\n", gSecondaryMaxTime); 
    msg_debug("keep alive count     : %d\n", gKeepAliveCount); 
    msg_debug("Interface            : %s\n", gKeepAliveInterface); 


    if (!run_in_foreground) {
        msg_debug("Running in background\n");

        if (daemon(0,0) < 0) {
            msg_debug("Failed to daemonize: %s\n", strerror(errno));
        }

    } else {
        msg_debug("Running in foreground\n");
    }

#ifdef __HAVE_SYSEVENT__

    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, kHotspotfd_events, &sysevent_token);

    if (sysevent_fd >= 0) {
#ifdef __HAVE_SYSEVENT_STARTUP_PARAMS__
        if (hotspotfd_getStartupParameters() != STATUS_SUCCESS) {
            msg_err("Could not get sysevent startup parameters\n");

            hotspotfd_SignalHandler(0);

        }
#endif
        pthread_create(&sysevent_tid, NULL, hotspotfd_sysevent_handler, NULL);
    } else {
        msg_err("sysevent_open failed\n");
        exit(1);
    }
#endif

    if (hotspotfd_setupSharedMemory() != STATUS_SUCCESS) {
        msg_err("Could not setup shared memory\n");
        exit(1);
    }

    if (signal(SIGTERM, hotspotfd_SignalHandler) == SIG_ERR)
        msg_debug("Failed to catch SIGTERM\n");

    if (signal(SIGINT, hotspotfd_SignalHandler) == SIG_ERR)
        msg_debug("Failed to catch SIGTERM\n");

    if (signal(SIGKILL, hotspotfd_SignalHandler) == SIG_ERR)
        msg_debug("Failed to catch SIGTERM\n");

    hotspotfd_log();

    keep_it_alive:

    while (gKeepAliveEnable == true) {

        while (gPrimaryIsActive && (gKeepAliveEnable == true)) {

            gKeepAlivesSent++;

            if (gKeepAliveLogEnable) {
                hotspotfd_log();
            }

            if (hotspotfd_ping(gpPrimaryEP) == STATUS_SUCCESS) {
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
                    msg_debug("Create Primary GRE tunnel\n");

                    if (sysevent_set(sysevent_fd, sysevent_token, 
                                     kHotspotfd_tunnelEP, gpPrimaryEP, 0)) {

                        msg_err("sysevent set %s failed on primary\n", kHotspotfd_tunnelEP) 
                    }
                    pthread_mutex_lock(&keep_alive_mutex);
                    gbFirstPrimarySignal = false;
                    pthread_mutex_unlock(&keep_alive_mutex);
                }

                msg_debug("Primary GRE Tunnel Endpoint is alive\n");
                msg_debug("gKeepAlivesSent: %u\n", gKeepAlivesSent);
                msg_debug("gKeepAlivesReceived: %u\n", gKeepAlivesReceived);
                msg_debug("Primary GRE Tunnel Endpoint is alive\n");
                msg_debug("Sleeping for %d seconds...\n", gKeepAliveInterval);

                if (gKeepAliveEnable == false) continue;
                sleep(gKeepAliveInterval);
                if (gKeepAliveEnable == false) continue;

            } else {

                gPrimaryIsAlive = false;
                pthread_mutex_lock(&keep_alive_mutex);
                gbFirstPrimarySignal = true;
                pthread_mutex_unlock(&keep_alive_mutex);

                keepAliveThreshold++;
                if (gKeepAliveEnable == false) continue;
                sleep(gKeepAliveInterval);
                if (gKeepAliveEnable == false) continue;

                if (keepAliveThreshold < gKeepAliveThreshold) {
                    continue;
                } else {
                    gPrimaryIsActive = false;
                    gSecondaryIsActive = true;
                    keepAliveThreshold = 0;
                    gPriStateIsDown = true;

                    msg_debug("Primary GRE Tunnel Endpoint is not alive\n");
                    msg_debug("Switching Secondary Endpoint...\n");

                    if (gSecStateIsDown && gPriStateIsDown && gBothDnFirstSignal) {

                        gBothDnFirstSignal = false;

                        if (sysevent_set(sysevent_fd, sysevent_token, 
                                         kHotspotfd_tunnelEP, "\0", 0)) {

                            msg_err("sysevent set %s failed on secondary\n", kHotspotfd_tunnelEP) 
                        }
                    }
                }
            }
        }

        while (gSecondaryIsActive && (gKeepAliveEnable == true)) {

            gKeepAlivesSent++;

            if (gKeepAliveLogEnable) {
                hotspotfd_log();
            }

            if (hotspotfd_ping(gpSecondaryEP) == STATUS_SUCCESS) {
                gPrimaryIsActive = false;
                gSecondaryIsActive = true;
                gSecondaryIsAlive = true;
                gSecStateIsDown = false;
                gBothDnFirstSignal = true;

                gKeepAlivesReceived++;
                keepAliveThreshold = 0;

                secondaryKeepAlives++;

                if (gKeepAliveLogEnable) {
                    hotspotfd_log();
                }

                // Check for absolute max. secondary active interval
                // TODO: If reached tunnel should be swicthed to primary
                if (secondaryKeepAlives > gSecondaryMaxTime/60) {

                    gPrimaryIsActive = true;
                    gSecondaryIsActive = false;
                    keepAliveThreshold = 0;
                    secondaryKeepAlives = 0;
                    msg_debug("Max. Secondary EP time exceeded. Switching to Primary EP\n");

                    // TODO: Do we just destroy this tunnel and move over
                    // to the primary? What if the Primary is down then we switched
                    // for no reason?
                    // TODO: Need to try the Primary once before switching.
                    gSwitchedBackToPrimary++;
                    break;
                }

                if (gbFirstSecondarySignal) {
                    msg_debug("Create Secondary GRE tunnel\n");

                    if (sysevent_set(sysevent_fd, sysevent_token, 
                                     kHotspotfd_tunnelEP, gpSecondaryEP, 0)) {

                        msg_err("sysevent set %s failed on secondary\n", kHotspotfd_tunnelEP) 
                    }

                    pthread_mutex_lock(&keep_alive_mutex);
                    gbFirstSecondarySignal = false;
                    pthread_mutex_unlock(&keep_alive_mutex);
                }

                msg_debug("Secondary GRE Tunnel Endpoint is alive\n");
                msg_debug("gKeepAlivesSent: %u\n", gKeepAlivesSent);
                msg_debug("gKeepAlivesReceived: %u\n", gKeepAlivesReceived);
                msg_debug("Sleeping for %d seconds....\n", gKeepAliveInterval);
                if (gKeepAliveEnable == false) continue;
                sleep(gKeepAliveInterval);
                if (gKeepAliveEnable == false) continue;

            } else {
                msg_debug("Secondary GRE Tunnel Endpoint is not alive\n");

                gSecondaryIsAlive = false;

                pthread_mutex_lock(&keep_alive_mutex);
                gbFirstSecondarySignal = true;
                pthread_mutex_unlock(&keep_alive_mutex);

                keepAliveThreshold++;
                if (gKeepAliveEnable == false) continue;
                sleep(gKeepAliveInterval);
                if (gKeepAliveEnable == false) continue;

                if (keepAliveThreshold < gKeepAliveThreshold) {
                    continue;
                } else {
                    gPrimaryIsActive = true;
                    gSecondaryIsActive = false;
                    keepAliveThreshold = 0;
                    secondaryKeepAlives = 0;
                    gSecStateIsDown = true;

                    if (gSecStateIsDown && gPriStateIsDown && gBothDnFirstSignal) {

                        gBothDnFirstSignal = false;

                        if (sysevent_set(sysevent_fd, sysevent_token, 
                                         kHotspotfd_tunnelEP, "\0", 0)) {

                            msg_err("sysevent set %s failed on secondary\n", kHotspotfd_tunnelEP) 
                        }
                    }
                }
            }
        }

    } 

    while (gKeepAliveEnable == false) {
        sleep(1);
    }

    goto keep_it_alive;

    exit(0);
}
