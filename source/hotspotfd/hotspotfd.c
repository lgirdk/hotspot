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

unsigned int glog_level             = LOG_NOISE;
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

static bool gTunnelIsUp = false;

#define khotspotfd_Cmd1 "/fss/gw/usr/ccsp/ccsp_bus_client_tool eRT getvalues Device.WiFi.AccessPoint.%d.AssociatedDeviceNumberOfEntries"
#define READ 0
#define WRITE 1
#define CMD_ERR_TIMEOUT 10
#define READ_ERR -1
#define CLOSE_ERR -1

void sigquit()
{
	CcspTraceError(("Inside sigquit terminating child now\n"));
	_exit(1);
}

void killChild(pid_t childPid)
{
    if (!kill(childPid, SIGQUIT))
    {
    	CcspTraceInfo(("Kill of:%d is successful!!! \n", childPid));
    }
    else
    {
    	CcspTraceError(("Kill of:%d is not successful!!! error is:%d\n", childPid, errno));
    }
}

static pid_t popen2(const char *cmd, int *output_fp)
{
    int p_stdin[2], p_stdout[2];
    int exit_status, i, l_icloseStatus;
    bool l_bCloseFp = false;

    pid_t pid, endID;
    if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
        return -1;
    pid = fork();
    if (pid < 0) 
        return pid; 
    else if (pid == 0)
    {   
		signal(SIGQUIT, sigquit); 
        close(p_stdin[WRITE]);
        dup2(p_stdin[READ], READ);
        close(p_stdout[READ]);
        dup2(p_stdout[WRITE], WRITE);

		close(p_stdout[WRITE]);
		close(p_stdin[READ]);

		execl("/bin/sh", "sh", "-c", cmd, NULL);
        perror("execl");
        _exit(1);
    }

	close(p_stdin[READ]);
	close(p_stdout[WRITE]);
    close(p_stdin[WRITE]);

    if (output_fp == NULL)
        close(p_stdout[READ]);
    else
        *output_fp = p_stdout[READ];

    for(i = 0; i < 10; i++) 
	{
    	endID = waitpid(pid, &exit_status, WNOHANG|WUNTRACED);
        if (endID == -1) {            /* error calling waitpid       */
        	CcspTraceInfo(("waitPid Error\n"));
			l_bCloseFp = true;
            break;
        }
        else if (endID == 0) {        /* child still running         */
            printf("Parent waiting for child\n");
            sleep(1);
        }
        else if (endID == pid) {  /* child ended                 */
        	if (WIFEXITED(exit_status))
			{
            	msg_debug("Child ended normally \n");
			}	
            else if (WIFSIGNALED(exit_status))
			{
				CcspTraceInfo(("Child ended because of an uncaught signal \n", exit_status));
                l_bCloseFp = true;
			}
            else if (WIFSTOPPED(exit_status))
			{	
                CcspTraceInfo(("Child process has stopped \n", exit_status));
                l_bCloseFp = true;   
			}
            break;
        }
    }
    if (0 == endID)
    {
		CcspTraceInfo(("ccsp_bus_client_tool process:%d hung killing it\n", pid));
        signal(SIGCHLD, SIG_IGN);
        
		killChild(pid);
    
        l_icloseStatus = close(*output_fp);
		if (CLOSE_ERR == l_icloseStatus)
            CcspTraceInfo(("Error while closing output fp in popen2: %d\n", l_icloseStatus));
		
		return NULL;
    }
    if (true == l_bCloseFp)
	{    
		l_icloseStatus = close(*output_fp);
		if (CLOSE_ERR == l_icloseStatus)
        	CcspTraceInfo(("Error while closing output fp in popen2: %d\n", l_icloseStatus));

		return NULL;
	}
    msg_debug("popen2 pid for executing the command:%s is:%d exit_status is:%d\n", cmd, pid, exit_status);
    return pid;
}

static bool hotspotfd_isClientAttached(bool *pIsNew)
{
    FILE *fp=NULL;
    char buffer[1024]="";
    char path[PATH_MAX];
    char *pch=NULL;
    int num_devices = 0;
    int instance;
    static bool num_devices_0=0;
    int read_bytes, l_outputfp, l_icloseStatus;
	pid_t l_busClientPid;

    memset(path, 0x00, sizeof(path));
    for(instance=5; instance<=6; instance++) 
	{
		sprintf(buffer, khotspotfd_Cmd1, instance);

        l_busClientPid = popen2(buffer, &l_outputfp);
		if (NULL == l_busClientPid)
			continue;

        read_bytes = read(l_outputfp, path, (PATH_MAX-1));
        if (READ_ERR != read_bytes)
        {    
            msg_debug("Read is successful while checking number of devices bytes read:%d\n", read_bytes);
            pch = strstr(path, "ue:");
            if (pch) {
                num_devices = atoi(&pch[4]);
                msg_debug("cmd: %s\n", buffer);
                msg_debug("num_devices: %d\n", num_devices);
            }
        }
        else if (0 == read_bytes)
        {
            CcspTraceError(("EOF detected while reading number of devices\n"));
		    continue;
        }
        else //read error case -1 is returned
        {    
			CcspTraceError(("Read is un-successful hotspotfd error is:%d\n", errno));
	    }
        l_icloseStatus = close(l_outputfp);
        if (CLOSE_ERR == l_icloseStatus) 
		    CcspTraceInfo(("close status while closing output fp:%d\n", l_icloseStatus));

        if (num_devices > 0)
            break;
    }

    if (num_devices>0) {
		if(pIsNew && num_devices_0==0) 
			*pIsNew=true;
		num_devices_0=num_devices;
		return true;
	} 
	num_devices_0=num_devices;
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
            CcspTraceError(("shmget failed while setting up shared memory\n")); 

            perror("shmget");
            status = STATUS_FAILURE;
            break;
        }

        // Attach the segment to our data space.
        if ((gpStats = (hotspotfd_statistics_s *)shmat(gShm_fd, NULL, 0)) == (hotspotfd_statistics_s *) -1) {
            CcspTraceError(("shmat failed while setting up shared memory\n")); 

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
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_secondary, buf, sizeof(buf)))) {
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
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_keep_alive, buf, sizeof(buf)))) {
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
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_keep_alive_threshold, buf, sizeof(buf)))) {
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
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_max_secondary, buf, sizeof(buf)))) {
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
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_keep_alive_policy, buf, sizeof(buf)))) {
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
        if ((status = sysevent_get(sysevent_fd, sysevent_token, khotspotfd_keep_alive_count, buf, sizeof(buf)))) {
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
	time_t secondaryEndPointstartTime;
	time_t currentTime ;
	int timeElapsed;

	rdk_logger_init(DEBUG_INI_NAME);
   	pComponentName = "hotspotfd";

    strcpy(gKeepAliveInterface, "none");

    while ((cmd = getopt(argc, argv, "e:p:s:i:t:m:l:n:f::h::")) != -1) {
        switch (cmd) {
        case 'n':

            if (optarg && (strlen(optarg) >= 2) && (strlen(optarg) < kMax_InterfaceLength)) {
                strcpy(gKeepAliveInterface, optarg);
            } else {

				CcspTraceError(("Invalid network interface not bringing hotspotfd up\n"));
                exit(0);
            }

            break;
        case 'e':

            if (atoi(optarg) == 0) {
                gKeepAliveEnable = false;
                CcspTraceError(("Keep alive enable is false, ICMP ping wont be sent\n"));
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
				    CcspTraceError(("Invalid Primary IP Address provided not bringing hotspotfd up\n"));
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
				    CcspTraceError(("Invalid Secondary IP Address provided not bringing hotspotfd up\n"));
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
            CcspTraceWarning(("Failed to daemonize hotspotfd: %s\n", strerror(errno)));
        }

    } else {
        msg_debug("Running in foreground\n");
    }

#ifdef __HAVE_SYSEVENT__

    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, kHotspotfd_events, &sysevent_token);

    if (sysevent_fd >= 0) {
#ifdef __HAVE_SYSEVENT_STARTUP_PARAMS__
        if (hotspotfd_getStartupParameters() != STATUS_SUCCESS) {
            CcspTraceError(("Error while getting startup parameters\n"));

            hotspotfd_SignalHandler(0);

        }
#endif
        pthread_create(&sysevent_tid, NULL, hotspotfd_sysevent_handler, NULL);
    } else {
		CcspTraceError(("sysevent_open has failed hotspotfd bring up aborted\n"));
        exit(1);
    }
#endif

    if (hotspotfd_setupSharedMemory() != STATUS_SUCCESS) {
		CcspTraceError(("Could not setup shared memory hotspotfd bring up aborted\n"));
        exit(1);
    }

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

                    if (sysevent_set(sysevent_fd, sysevent_token, 
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

                        if (sysevent_set(sysevent_fd, sysevent_token, 
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

                    if (sysevent_set(sysevent_fd, sysevent_token, 
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

                        if (sysevent_set(sysevent_fd, sysevent_token, 
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
