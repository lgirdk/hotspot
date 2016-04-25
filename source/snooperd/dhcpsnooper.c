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

#include "dhcp.h"
#include "debug.h"
#include "dhcpsnooper.h"
#include "lm_api.h"
#include "ccsp_trace.h"

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

#define kSnoop_DefaultQueue             0
#define kSnoop_DefaultNumberOfQueues    1
#define kSnoop_MaxNumberOfQueues        4

#define SNOOP_LOG_PATH    "/var/tmp/dhcp_snooperd.log"
#define kSnoop_max_sysevent_len     80
#define kSnoop_LM_Delay 15

#define mylist_safe(p, q, h) \
         for (p = (h)->n, q = p->n; p != (h); \
                 p = q, q = p->n)

#define offf(t, m) ((size_t) &((t *)0)->m)

#define cof(p, t, m) ({                      \
         const typeof( ((t *)0)->m ) *__mptr = (p);    \
         (t *)( (char *)__mptr - offf(t, m) );})

#define mylist_entry(p, t, m) \
         cof(p, t, m)

#define DEBUG_INI_NAME "/etc/debug.ini"
struct mylist_head {
    struct mylist_head *n, *p;
};

static inline void SET_LIST_HEAD(struct mylist_head *l)
{
        l->n = l;
        l->p = l;
}

static inline void mylist_add(struct mylist_head *nn, struct mylist_head *h)
{   
        h->n->p = nn;
        nn->n = h->n;
        nn->p = h;
        h->n = nn;
}

static inline void mylist_del(struct mylist_head *e)
{

    e->n->p = e->p;
    e->p->n = e->n;

    e->n = 0;
    e->p = 0;
}

unsigned int glog_level = kSnoop_LOG_NOISE;

#define snooper_dbg(fmt...) {    \
        if (kSnoop_LOG_NOISE <= glog_level ) {\
        printf("%s:%s:%d> ", kSnoop_FILE_NAME, __FUNCTION__, __LINE__); printf(fmt); }}

#define snooper_err(fmt...) {    \
        if (kSnoop_LOG_ERR <= glog_level ) {\
        printf("%s:%s:%d> ",kSnoop_FILE_NAME, __FUNCTION__, __LINE__); printf(fmt); }}

#define kSnoop_MaxCircuitLen    80
#define kSnoop_DefaultCircuitID "00:10:A4:23:B6:C0;xfinityWiFi;o" 
static char gCircuit_id[kSnoop_MaxCircuitLen];

#define kSnoop_MaxRemoteLen 20
#define kSnoop_DefaultRemoteID "00:10:A4:23:B6:C1"
static char gRemote_id[kSnoop_MaxRemoteLen]; 

static bool gSnoopEnable = false;
static bool gSnoopDebugEnabled = false;
static bool gSnoopLogEnabled = true;
static bool gSnoopCircuitEnabled = true;
static bool gSnoopRemoteEnabled = true;
static int gSnoopDhcpMaxAgentOptionLen = DHCP_MTU_MIN;
static int gSnoopNumCapturedPackets = 0;
static int gSnoopFirstQueueNumber = kSnoop_DefaultQueue;
static int gSnoopNumberOfQueues = kSnoop_DefaultNumberOfQueues;

#define kSnoop_DefaultMaxNumberOfClients   kSnooper_MaxClients
static int gSnoopNumberOfClients = 0;
static int gSnoopMaxNumberOfClients = kSnoop_DefaultMaxNumberOfClients;

#define kSnoop_MaxCircuitIDs        5

// This is used to populate the client list
static char gSnoopCircuitIDList[kSnoop_MaxCircuitIDs][kSnoop_MaxCircuitLen];

// This is used to store the kSnooper_circuit_id<n> sysevents
static char gSnoopSyseventCircuitIDs[kSnoop_MaxCircuitIDs][kSnooper_circuit_id_len] = {
    kSnooper_circuit_id0, 
    kSnooper_circuit_id1, 
    kSnooper_circuit_id2, 
    kSnooper_circuit_id3, 
    kSnooper_circuit_id4 
};

// This is used to age associated devices per hotspot SSID
static char gSnoopSSIDList[kSnoop_MaxCircuitIDs][kSnoop_MaxCircuitLen];
static int  gSnoopSSIDListInt[kSnoop_MaxCircuitIDs]; 

// This is used to store the kSnooper_ssid_index<n> sysevents
static char gSnoopSyseventSSIDs[kSnoop_MaxCircuitIDs][kSnooper_circuit_id_len] = {
    kSnooper_ssid_index0, 
    kSnooper_ssid_index1, 
    kSnooper_ssid_index2, 
    kSnooper_ssid_index3, 
    kSnooper_ssid_index4 
};

#define kSnoop_MaxNumAssociatedDevices  30

typedef struct 
{
    struct mylist_head list;

    snooper_client_list client;

} snooper_priv_client_list;

static snooper_priv_client_list gSnoop_ClientList;

#ifdef __HAVE_SYSEVENT__
static int sysevent_fd;
static token_t sysevent_token;
static pthread_t sysevent_tid;
static pthread_t lm_tid;
#endif

static int gPriv_data[kSnoop_MaxNumberOfQueues];
static int gShm_fd;
static snooper_statistics_s * gpStats;

static int add_agent_options = 1;	/* If nonzero, add relay agent options. */

/* What to do about packets we're asked to relay that
   already have a relay option: */
enum agent_relay_mode_t
{	forward_and_append,		/* Forward and append our own relay option. */
	forward_and_replace,	/* Forward, but replace theirs with ours. */
	forward_untouched,		/* Forward without changes. */
	discard
};
static enum agent_relay_mode_t agent_relay_mode = forward_and_replace;

static char g_cHostnameForQueue[kSnoop_MaxCircuitIDs][kSnooper_MaxHostNameLen];
static char g_cInformIpForQueue[kSnoop_MaxCircuitIDs][INET_ADDRSTRLEN];

#if 0
static void snoop_setDhcpRelayAgentAddAgentOptions(int aao)
{
	agent_relay_mode = aao;
}

static enum agent_relay_mode_t snoop_getDhcpRelayAgentAddAgentOptions( )
{
	return agent_relay_mode;
}

static void snoop_setDhcpRelayAgentMode(enum agent_relay_mode_t mode)
{
	agent_relay_mode = mode;
}

static enum agent_relay_mode_t snoop_getDhcpRelayAgentMode( )
{
	return agent_relay_mode;
}
#endif

static void snoop_SignalHandler(int signo)
{
    snooper_priv_client_list * pNewClient;
    struct mylist_head *pos, *q;

	CcspTraceWarning(("Received signal: %d Closing sysevent and shared memory\n", signo));

#ifdef __HAVE_SYSEVENT__
    sysevent_close(sysevent_fd, sysevent_token);
#endif

    mylist_safe(pos, q, &gSnoop_ClientList.list){
		 pNewClient = mylist_entry(pos, snooper_priv_client_list, list);
		 mylist_del(pos);
		 free(pNewClient);
	}

    close(gShm_fd);
    exit(0);
}

static void snoop_AddClientListRSSI(int rssi, char *pRemote_id)
{
    snooper_priv_client_list * pNewClient;
    struct mylist_head * pos, * q;
    bool already_in_list = false;

    mylist_safe(pos, q, &gSnoop_ClientList.list) {

         pNewClient= mylist_entry(pos, snooper_priv_client_list, list);
         if(!strcmp(pNewClient->client.remote_id, pRemote_id)) {
             already_in_list = true;
             break;
         }
    }

    if(already_in_list) {
   
        pNewClient->client.rssi = rssi;
        strcpy(pNewClient->client.dhcp_status, "ACK");

        msg_debug("Added to client list:\n");
        msg_debug("rssi: %d\n", pNewClient->client.rssi);
    } 
    
}

static void snoop_AddClientListHostname(char *pHostname, char *pRemote_id, int queue_number)
{
    snooper_priv_client_list * pNewClient;
    struct mylist_head * pos, * q;
    bool already_in_list = false;

    mylist_safe(pos, q, &gSnoop_ClientList.list) {

         pNewClient= mylist_entry(pos, snooper_priv_client_list, list);
         if(!strcmp(pNewClient->client.remote_id, pRemote_id)) {
             already_in_list = true;
             break;
         }
    }

    if(already_in_list) {
   
        strcpy(pNewClient->client.hostname, pHostname);
        
        msg_debug("Added to client list:\n");
        msg_debug("hostname: %s\n", pNewClient->client.hostname);
    }
	else
	{
		strcpy(g_cHostnameForQueue[queue_number], pHostname);	
	}
}

static void snoop_AddClientListAddress(char *pIpv4_addr, char *pRemote_id, char *pCircuit_id)
{
    snooper_priv_client_list * pNewClient;
    struct mylist_head * pos, * q;
    bool already_in_list = false;

    mylist_safe(pos, q, &gSnoop_ClientList.list) {

         pNewClient= mylist_entry(pos, snooper_priv_client_list, list);
         if(!strcmp(pNewClient->client.remote_id, pRemote_id)) {
             already_in_list = true;
             break;
         }
    }

    if(already_in_list) {
   
        strcpy(pNewClient->client.ipv4_addr, pIpv4_addr);
        
        msg_debug("Added to client list:\n");
        msg_debug("ipv4_addr: %s\n", pNewClient->client.ipv4_addr);

        strcpy(pNewClient->client.circuit_id, pCircuit_id);
        msg_debug("pCircuit_id: %s\n", pNewClient->client.circuit_id);
    } 
    
}

static int snoop_addRelayAgentOptions(struct dhcp_packet *packet, unsigned length, int queue_number) {
    bool bDHCP = 0;
    bool bNext = 0;
    int max_msg_size;
    int circuit_id_len;
    int remote_id_len;
    unsigned option_length;
    char addr_str[INET_ADDRSTRLEN];
    char host_str[kSnooper_MaxHostNameLen];
    u_int8_t * option,*next_option;
	/* If we're not adding agent options to packets, we can skip
	   this. */
	if (!add_agent_options)
		return (length);

    u_int8_t * ptr,*max_len,*padding = NULL;

    if (!memcmp(packet->options, DHCP_OPTIONS_COOKIE, 4)) {

        max_len = ((u_int8_t *)packet) + gSnoopDhcpMaxAgentOptionLen;
        ptr = option = &packet->options[4];

        while ((option < max_len) && !bNext) {

            if (*option == DHO_PAD) {

                if (padding == NULL) {
                    padding = ptr;
                }

                if (ptr != option) {
                    *ptr++ = *option++;
                } else {
                    ptr = ++option; 
                }

            } else if (*option == DHO_DHCP_MESSAGE_TYPE) {
                bDHCP = 1;
                next_option = option + option[1] + 2;

                if (next_option > max_len) {
                    bNext = 1;
                    bDHCP = 0;
                    length = 0;
                } else {
                    padding = NULL;

        #ifdef __GET_REQUESTED_IP_ADDRESS__
                    /* Add the request IP address to the client list */
                    if (*option == DHO_DHCP_REQUESTED_ADDRESS) {
                        inet_ntop(AF_INET, &(option[2]), addr_str, INET_ADDRSTRLEN);
                        snoop_AddClientListAddress(addr_str, gRemote_id, gCircuit_id);
                    }
        #endif

                    /* Add the hostname to the client list */
                    if (*option == DHO_HOST_NAME) {
                        memcpy(host_str, &option[2], option[1]);
                        host_str[option[1]] = '\0';

                        snooper_dbg("host_str: %s\n", host_str);
                        snoop_AddClientListHostname(host_str, gRemote_id, queue_number);
                    }

                    if (ptr != option) {
                        memmove(ptr, option, option[1] + 2);
                        ptr += option[1] + 2;
                        option = next_option;
                    } else {
                        option = ptr = next_option;
                    }
                }

            } else if (*option == DHO_DHCP_MAX_MESSAGE_SIZE) {
                max_msg_size = ntohs(*(option + 2));
                if (max_msg_size < gSnoopDhcpMaxAgentOptionLen &&
                    max_msg_size >= DHCP_MTU_MIN) max_len = ((u_int8_t *)packet) + max_msg_size;
                next_option = option + option[1] + 2;
                if (next_option > max_len) {
                    bNext = 1;
                    bDHCP = 0;
                    length = 0;
                } else {
                    padding = NULL;

        #ifdef __GET_REQUESTED_IP_ADDRESS__
                    /* Add the request IP address to the client list */
                    if (*option == DHO_DHCP_REQUESTED_ADDRESS) {
                        inet_ntop(AF_INET, &(option[2]), addr_str, INET_ADDRSTRLEN);
                        snoop_AddClientListAddress(addr_str, gRemote_id, gCircuit_id);
                    }
        #endif

                    /* Add the hostname to the client list */
                    if (*option == DHO_HOST_NAME) {
                        memcpy(host_str, &option[2], option[1]);
                        host_str[option[1]] = '\0';

                        snooper_dbg("host_str: %s\n", host_str);
                        snoop_AddClientListHostname(host_str, gRemote_id, queue_number);
                    }

                    if (ptr != option) {
                        memmove(ptr, option, option[1] + 2);
                        ptr += option[1] + 2;
                        option = next_option;
                    } else {
                        option = ptr = next_option;
                    }
                }

            } else if (*option == DHO_END) {
                bNext = 1;

            } else if (*option == DHO_DHCP_AGENT_OPTIONS) {

                if (!bDHCP) {
                    next_option = option + option[1] + 2;
                    if (next_option > max_len) {
                        bNext = 1;
                        bDHCP = 0;
                        length = 0;
                    } else {
                        padding = NULL;

        #ifdef __GET_REQUESTED_IP_ADDRESS__
                        /* Add the request IP address to the client list */
                        if (*option == DHO_DHCP_REQUESTED_ADDRESS) {
                            inet_ntop(AF_INET, &(option[2]), addr_str, INET_ADDRSTRLEN);
                            snoop_AddClientListAddress(addr_str, gRemote_id, gCircuit_id);
                        }
        #endif
                        /* Add the hostname to the client list */
                        if (*option == DHO_HOST_NAME) {
                            memcpy(host_str, &option[2], option[1]);
                            host_str[option[1]] = '\0';

                            snooper_dbg("host_str: %s\n", host_str);
                            snoop_AddClientListHostname(host_str, gRemote_id, queue_number);
                        }

                        if (ptr != option) {
                            memmove(ptr, option, option[1] + 2);
                            ptr += option[1] + 2;
                            option = next_option;
                        } else {
                            option = ptr = next_option;
                        }
                    }
                }

                padding = NULL;

	            switch(agent_relay_mode) {
				case forward_and_append:
			  		goto skip;
			    case forward_untouched:
					return (length);
			    case discard:
					return (0);
			    case forward_and_replace:
			    	snooper_dbg("Skipping Client relay agent option['%d']\n", *option);
			    	break;
			    default:
					break;
				}

                option += option[1] + 2;

            } else {
			skip:
                next_option = option + option[1] + 2;
                if (next_option > max_len) {
                    bNext = 1;
                    bDHCP = 0;
                    length = 0;
                } else {
                    padding = NULL;

        #ifdef __GET_REQUESTED_IP_ADDRESS__
                    /* Add the request IP address to the client list */
                    if (*option == DHO_DHCP_REQUESTED_ADDRESS) {
                        inet_ntop(AF_INET, &(option[2]), addr_str, INET_ADDRSTRLEN);
                        snoop_AddClientListAddress(addr_str, gRemote_id, gCircuit_id);
                    }
        #endif

                    /* Add the hostname to the client list */
                    if (*option == DHO_HOST_NAME) {
                        memcpy(host_str, &option[2], option[1]);
                        host_str[option[1]] = '\0';

                        snooper_dbg("host_str: %s\n", host_str);
                        snoop_AddClientListHostname(host_str, gRemote_id, queue_number);
                    }

                    if (ptr != option) {
                        memmove(ptr, option, option[1] + 2);
                        ptr += option[1] + 2;
                        option = next_option;
                    } else {
                        option = ptr = next_option;
                    }
                }
            }
        }

        if (bDHCP) {

            if (padding != NULL) ptr = padding;

            option = ptr;

            circuit_id_len = strlen(gCircuit_id);
            remote_id_len = strlen(gRemote_id);

            if (gSnoopCircuitEnabled && gSnoopRemoteEnabled) {
                option_length = (circuit_id_len + 2) + (remote_id_len + 2);

            } else if (gSnoopCircuitEnabled && !gSnoopRemoteEnabled) {
                option_length = circuit_id_len + 2;

            } else if (!gSnoopCircuitEnabled && gSnoopRemoteEnabled) {
                option_length = remote_id_len + 2;
            }

            if ((option_length < 3) || (option_length > 255)) {
                snooper_err("Option length invalid: %d\n", option_length);
            }

            if (max_len - ptr >= option_length + 3) {

                if (gSnoopCircuitEnabled && gSnoopRemoteEnabled) {

                    *ptr++ = DHO_DHCP_AGENT_OPTIONS;
                    *ptr++ = ((circuit_id_len + 2) + (remote_id_len + 2));

                    /* Copy in the circuit id... */
                    *ptr++ = RAI_CIRCUIT_ID;
                    *ptr++ = circuit_id_len;

                    memcpy(ptr, gCircuit_id, circuit_id_len);
                    ptr += circuit_id_len;

                    /* Copy in the remote id... */
                    remote_id_len = strlen(gRemote_id);

                    *ptr++ = RAI_REMOTE_ID;
                    *ptr++ = remote_id_len;

                    memcpy(ptr, gRemote_id, remote_id_len);
                    ptr += remote_id_len;

                } else if (gSnoopCircuitEnabled && !gSnoopRemoteEnabled) {

                    *ptr++ = DHO_DHCP_AGENT_OPTIONS;
                    *ptr++ = (circuit_id_len + 2);

                    /* Copy in the circuit id... */
                    *ptr++ = RAI_CIRCUIT_ID;
                    *ptr++ = circuit_id_len;

                    memcpy(ptr, gCircuit_id, circuit_id_len);
                    ptr += circuit_id_len;

                } else if (!gSnoopCircuitEnabled && gSnoopRemoteEnabled) {

                    *ptr++ = DHO_DHCP_AGENT_OPTIONS;
                    *ptr++ = (remote_id_len + 2);

                    /* Copy in the remote id... */
                    *ptr++ = RAI_REMOTE_ID;
                    *ptr++ = remote_id_len;

                    memcpy(ptr, gRemote_id, remote_id_len);
                    ptr += remote_id_len;
                }

            }

            if (ptr < max_len) {
                *ptr++ = DHO_END;
            }

            length = ptr - ((u_int8_t *)packet);

            if (length < BOOTP_MIN_LEN) {
                length =  BOOTP_MIN_LEN;
                memset(ptr, DHO_PAD, BOOTP_MIN_LEN - length);
            }
        }
    }

    return length;
}

uint16_t snoop_udpChecksum(uint16_t len_udp, uint16_t * src_addr, uint16_t * dest_addr, uint16_t * buff)
{
    uint16_t prot_udp=17;
    uint16_t padd=0;
    uint16_t word16;
    uint32_t sum; 
    int i;

    // Find out if the length of data is even or odd number. If odd,
    // add a padding byte = 0 at the end of packet
#if 0
    if (padding&1==1) {
        padd=1;
        buff[len_udp]=0;
    }
#endif
    //initialize sum to zero
    sum=0;

    // make 16 bit words out of every two adjacent 8 bit words and 
    // calculate the sum of all 16 vit words
    for (i=0;i<len_udp+padd;i=i+2) {
        word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
        sum = sum + (unsigned long)word16;
    } 

    // add the UDP pseudo header which contains the IP source and destinationn addresses
    for (i=0;i<4;i=i+2) {
        word16 =((src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
        sum=sum+word16; 
    }

    for (i=0;i<4;i=i+2) {
        word16 =((dest_addr[i]<<8)&0xFF00)+(dest_addr[i+1]&0xFF);
        sum=sum+word16;     
    }

    // the protocol number and the length of the UDP packet
    sum = sum + prot_udp + len_udp;

    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    while (sum>>16)
        sum = (sum & 0xFFFF)+(sum >> 16);

    // Take the one's complement of sum
    sum = ~sum;

    return((uint16_t) sum);
}

uint16_t snoop_ipChecksum(struct iphdr * header)
{
    // clear existent IP header
    header->check = 0x0;

    // calc the checksum
    unsigned int nbytes = sizeof(struct iphdr);
    unsigned short *buf = (unsigned short *)header;
    unsigned int sum = 0;
    for (; nbytes > 1; nbytes -= 2) {
        sum += *buf++;
    }
    if (nbytes == 1) {
        sum += *(unsigned char*) buf;
    }
    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

static void snoop_log(void)
{
    FILE *logOut;
    int i = 0;
    snooper_priv_client_list * pClient;
    struct mylist_head * pos, * q;

    logOut = fopen(SNOOP_LOG_PATH, "w");

    if(!logOut) {
        CcspTraceError(("Could not open dhcp_snooperd.log file\n"));
    } else {
    
        fprintf(logOut, "gSnoopEnable: %d\n", gSnoopEnable);
        fprintf(logOut, "gSnoopDebugEnabled: %d\n", gSnoopDebugEnabled);

        fprintf(logOut, "Agent Circuit ID: %s\n", gCircuit_id);     
        fprintf(logOut, "Agent Remote ID: %s\n", gRemote_id);  

        fprintf(logOut, "gSnoopCircuitEnabled: %d\n", gSnoopCircuitEnabled);     
        fprintf(logOut, "gSnoopRemoteEnabled: %d\n", gSnoopRemoteEnabled);    

        fprintf(logOut, "gSnoopFirstQueueNumber: %d\n", gSnoopFirstQueueNumber);  
        fprintf(logOut, "gSnoopNumberOfQueues: %d\n", gSnoopNumberOfQueues);  

        for(i=gSnoopFirstQueueNumber; i < gSnoopNumberOfQueues+gSnoopFirstQueueNumber; i++) {
            fprintf(logOut, "gSnoopCircuitIDList[%d]: %s\n", i, gSnoopCircuitIDList[i]); 
        }

        fprintf(logOut, "kSnoop_MaxNumberOfQueues: %d\n", kSnoop_MaxNumberOfQueues);  
        fprintf(logOut, "gSnoopNumCapturedPackets: %d\n", gSnoopNumCapturedPackets);

        fprintf(logOut, "gSnoopMaxNumberOfClients: %d\n", gSnoopMaxNumberOfClients);
        fprintf(logOut, "gSnoopNumberOfClients: %d\n", gSnoopNumberOfClients);

        fprintf(logOut, "Client list:\n");
        mylist_safe(pos, q, &gSnoop_ClientList.list) {
    
             pClient= mylist_entry(pos, snooper_priv_client_list, list);

             fprintf(logOut, "pClient->client.remote_id: %s\n", pClient->client.remote_id); 
             fprintf(logOut, "pClient->client.circuit_id: %s\n", pClient->client.circuit_id); 
             fprintf(logOut, "pClient->client.ipv4_addr: %s\n", pClient->client.ipv4_addr); 
             fprintf(logOut, "pClient->client.hostname: %s\n", pClient->client.hostname);
             fprintf(logOut, "pClient->client.dhcp_status: %s\n", pClient->client.dhcp_status); 
             fprintf(logOut, "pClient->client.rssi: %d\n\n", pClient->client.rssi); 
        }

        fclose(logOut);

        gpStats->snooper_enabled = gSnoopEnable;
        gpStats->snooper_debug_enabled = gSnoopDebugEnabled;
        gpStats->snooper_circuit_id_enabled = gSnoopCircuitEnabled;
        gpStats->snooper_remote_id_enabled = gSnoopRemoteEnabled;

        gpStats->snooper_first_queue = gSnoopFirstQueueNumber;   
        gpStats->snooper_num_queues = gSnoopNumberOfQueues;
        gpStats->snooper_max_queues = kSnoop_MaxNumberOfQueues;
        gpStats->snooper_dhcp_packets = gSnoopNumCapturedPackets;

        gpStats->snooper_max_clients = gSnoopMaxNumberOfClients;
        gpStats->snooper_num_clients = gSnoopNumberOfClients;

        i = 0;
        mylist_safe(pos, q, &gSnoop_ClientList.list) {
    
             pClient= mylist_entry(pos, snooper_priv_client_list, list);

             printf("pClient->client.circuit_id[%d]: %s\n", i, pClient->client.circuit_id);
             printf("pClient->client.dhcp_status[%d]: %s\n", i, pClient->client.dhcp_status);
             printf("pClient->client.hostname[%d]: %s\n", i, pClient->client.hostname);
             printf("pClient->client.ipv4_addr[%d]: %s\n", i, pClient->client.ipv4_addr);
             printf("pClient->client.remote_id[%d]: %s\n", i, pClient->client.remote_id);
             printf("pClient->client.rssi[%d]: %d\n", i, pClient->client.rssi);

             memcpy(&gpStats->snooper_clients[i], &pClient->client, sizeof(snooper_client_list));
             i++;
        }
    }
}

static void snoop_RemoveClientListEntry(char *pRemote_id)
{
    bool already_in_list = false;
    struct mylist_head * pos, * q;
    snooper_priv_client_list * pNewClient;
    
    mylist_safe(pos, q, &gSnoop_ClientList.list) {

         pNewClient= mylist_entry(pos, snooper_priv_client_list, list);
         if(!strcmp(pNewClient->client.remote_id, pRemote_id)) {
             already_in_list = true;
             break;
         }
    }

    if(already_in_list) {

        mylist_del(pos);
        free(pNewClient);

        gSnoopNumberOfClients--;

        msg_debug("Removed from client list: %s\n", pRemote_id);
        msg_debug("Number of clients: %d\n", gSnoopNumberOfClients); 
    }
}

static void snoop_AddClientListEntry(char *pRemote_id, char *pCircuit_id, 
                                  char *pDhcp_status, char *pIpv4_addr, char *pHostname)
{
    snooper_priv_client_list * pNewClient;
    struct mylist_head * pos, * q;
    bool already_in_list = false;

    mylist_safe(pos, q, &gSnoop_ClientList.list) {

         pNewClient= mylist_entry(pos, snooper_priv_client_list, list);
         if(!strcmp(pNewClient->client.remote_id, pRemote_id)) {
             already_in_list = true;
             break;
         }
    }

    if(!already_in_list) {

        if(gSnoopNumberOfClients < gSnoopMaxNumberOfClients) { 
    
            pNewClient= (snooper_priv_client_list *)malloc(sizeof(snooper_priv_client_list));

            strcpy(pNewClient->client.remote_id, pRemote_id);
            strcpy(pNewClient->client.circuit_id, pCircuit_id);
            strcpy(pNewClient->client.dhcp_status, pDhcp_status);
            strcpy(pNewClient->client.ipv4_addr, pIpv4_addr);
            strcpy(pNewClient->client.hostname, pHostname);
            pNewClient->client.rssi = 0;
			pNewClient->client.noOfTriesForOnlineCheck = 0;

            mylist_add(&pNewClient->list, &gSnoop_ClientList.list);
            gSnoopNumberOfClients++;

            msg_debug("Added to client list:\n");
            msg_debug("remote_id: %s\n", pNewClient->client.remote_id);
            msg_debug("circuit_id: %s\n", pNewClient->client.circuit_id);
            msg_debug("dhcp_status: %s\n", pNewClient->client.dhcp_status);
            msg_debug("ipv4_addr: %s\n", pNewClient->client.ipv4_addr);
            msg_debug("hostname: %s\n", pNewClient->client.hostname);
            msg_debug("rssi: %d\n", pNewClient->client.rssi);

            msg_debug("gSnoopNumberOfClients: %d\n", gSnoopNumberOfClients);

        } else {
            CcspTraceError(("Max. number of clients %d already in list\n", gSnoopNumberOfClients));
        }
    } else {
        msg_debug("Client %s already in list.\n", pRemote_id);
    }
    
}

static int snoop_removeRelayAgentOptions(struct dhcp_packet *packet, unsigned length, int queue_number)
{
    int is_dhcp = 0, mms;
    unsigned optlen;
    u_int8_t *op = NULL, *nextop = NULL, *sp = NULL, *max = NULL, *end_pad = NULL;

    int circuit_id_len; 
    int remote_id_len;
    char addr_str[INET_ADDRSTRLEN];
    char host_str[kSnooper_MaxHostNameLen];

    max = ((u_int8_t *)packet) + gSnoopDhcpMaxAgentOptionLen;

    /* Commence processing after the cookie. */
    sp = op = &packet->options[4];

	if (NULL == op)
	{
		CcspTraceError(("Bad DHCP packet received, not proceeding further"));
		return length;
	}

    while (op < max) {

        snooper_dbg("*op: %d\n", *op);
        switch (*op) {

        /* Skip padding... */
        case DHO_PAD:
            /* Remember the first pad byte so we can commandeer
             * padded space.
             *
             * XXX: Is this really a good idea?  Sure, we can
             * seemingly reduce the packet while we're looking,
             * but if the packet was signed by the client then
             * this padding is part of the checksum(RFC3118),
             * and its nonpresence would break authentication.
             */
            if (end_pad == NULL)
                end_pad = sp;

            if (sp != op)
                *sp++ = *op++;
            else
                sp = ++op;

            continue;

            /* If we see a message type, it's a DHCP packet. */
        case DHO_DHCP_MESSAGE_TYPE:
            is_dhcp = 1;
            goto skip;
            /*
             * If there's a maximum message size option, we
             * should pay attention to it
             */
        case DHO_DHCP_MAX_MESSAGE_SIZE:
            mms = ntohs(*(op + 2));
            if (mms < gSnoopDhcpMaxAgentOptionLen &&
                mms >= DHCP_MTU_MIN)
                max = ((u_int8_t *)packet) + mms;
            goto skip;

            /* Quit immediately if we hit an End option. */
        case DHO_END:
            return length;

        case DHO_DHCP_AGENT_OPTIONS:
			msg_debug("DHCP packet length before option-82 removal is:%d\n", length);
			int l_iSkipBytes = *(op + 1) + 2;
			nextop = op + op[1] + 2;
            if (nextop > max)
                return(0);
			
	    op = nextop;
	    while (*op != DHO_END)
	    {
		memmove(sp, op, op[1] + 2);
                sp += op[1] + 2;
                op = op[1] + 2;
	    }
	    *(sp) = DHO_END;
            length = length - l_iSkipBytes;
	    msg_debug("DHCP packet length after option-82 removal is:%d\n", length);
	    break;			

            skip:
            /* Skip over other options. */
        default:
            /* Fail if processing this option will exceed the
             * buffer(op[1] is malformed).
             */
            nextop = op + op[1] + 2;
            if (nextop > max)
                return(0);

            end_pad = NULL;

#ifdef __GET_REQUESTED_IP_ADDRESS__
            /* Add the request IP address to the client list */
            if(*op == DHO_DHCP_REQUESTED_ADDRESS) {
                inet_ntop(AF_INET, &(op[2]), addr_str, INET_ADDRSTRLEN);
                snoop_AddClientListAddress(addr_str, gRemote_id, gCircuit_id);
            }
#endif          

            /* Add the hostname to the client list */
            if(*op == DHO_HOST_NAME) {
                memcpy(host_str, &op[2], op[1]); 
                host_str[op[1]] = '\0';
                
                snooper_dbg("host_str: %s\n", host_str);                
                snoop_AddClientListHostname(host_str, gRemote_id, queue_number);
            }

            if (sp != op) {
                memmove(sp, op, op[1] + 2);
                sp += op[1] + 2;
                op = nextop;
            } else
                op = sp = nextop;

            break;
        }
    }
    return(length);
}

static bool snoop_isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));

    return (result != 0 && sa.sin_addr.s_addr != 0);
}

static int snoop_packetHandler(struct nfq_q_handle * myQueue, struct nfgenmsg *msg,struct nfq_data *pkt, void *cbData) 
{
    uint32_t queue_id;
    int queue_number = *(int *)cbData;
    //uint16_t checksum;
    struct nfqnl_msg_packet_hdr *header;
    int i;
    int j=0;
    int len;
    int new_data_len;
    unsigned char * pktData;
    struct iphdr *iph;
    char ipv4_addr[INET_ADDRSTRLEN];

    // The iptables queue number is passed when this handler is registered
    // with nfq_create_queue
    msg_debug("queue_number: %d\n", queue_number);

    if ((header = nfq_get_msg_packet_hdr(pkt))) {
        queue_id = ntohl(header->packet_id);
        msg_debug("queue_id: %u\n", queue_id);
    }

    // bootp starts at pktData[28] 
    len = nfq_get_payload(pkt, &pktData);

    if(gSnoopDebugEnabled) {
        if (len) {
            printf("%s:%d> data\n", __FUNCTION__, __LINE__);
            for (i = 0; i < len; i++) {
    
                printf("%02x ", pktData[i]);
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
        }
    
        printf("%s:%d>  pktData[%d]: %02x\n", __FUNCTION__, __LINE__,  
               kSnoop_DHCP_Option53_Offset, pktData[kSnoop_DHCP_Option53_Offset]);
    
        switch (pktData[kSnoop_DHCP_Option53_Offset]) {
        
        case kSnoop_DHCP_Discover:
            printf("%s:%d>  DHCP Discover\n", __FUNCTION__, __LINE__);
            break;
        case kSnoop_DHCP_Offer:
            printf("%s:%d>  DHCP Offer\n", __FUNCTION__, __LINE__);
            break;
        case kSnoop_DHCP_Request:
            printf("%s:%d>  DHCP Request\n", __FUNCTION__, __LINE__);
            break;
        case kSnoop_DHCP_ACK:
            printf("%s:%d>  DHCP ACK\n", __FUNCTION__, __LINE__);
            break;
        case kSnoop_DHCP_Release:
            printf("%s:%d>  DHCP Release\n", __FUNCTION__, __LINE__);
            break;
        default:
        	printf("%s:%d>  DHCP message['%d'] not supported! \n", __FUNCTION__, __LINE__, pktData[kSnoop_DHCP_Option53_Offset]);
        	break;
        }
    }

    // If gSnoopEnable is not set then just send the packet out
    if (((pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_Request) || (pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_Discover) ||
         (pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_Decline) || (pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_Release) || (pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_Inform))
        && gSnoopEnable && (gSnoopCircuitEnabled || gSnoopRemoteEnabled)) {
                                                           
        strcpy(gCircuit_id, gSnoopCircuitIDList[queue_number]);
        msg_debug("gCircuit_id: %s\n", gCircuit_id);

        sprintf(gRemote_id, "%02x:%02x:%02x:%02x:%02x:%02x", 
                pktData[56], pktData[57], pktData[58], pktData[59], pktData[60], pktData[61]); 
        msg_debug("gRemote_id: %s\n", gRemote_id);

        new_data_len = snoop_addRelayAgentOptions((struct dhcp_packet *)&pktData[kSnoop_DHCP_Options_Start], len, queue_number);

        // Adjust the IP payload length
#ifdef __686__
        *(uint16_t *)(pktData+2) = bswap_16(new_data_len+kSnoop_DHCP_Options_Start);
#else
        *(uint16_t *)(pktData+2) = new_data_len+kSnoop_DHCP_Options_Start;
#endif

        msg_debug("pktData[2]: %02x\n", pktData[2]);
        msg_debug("pktData[3]: %02x\n", pktData[3]);

        iph = (struct iphdr *) pktData;
        iph->check = snoop_ipChecksum(iph);

        msg_debug("iph->check: %02x\n", bswap_16(iph->check));
        msg_debug("iph->ihl: %d\n", iph->ihl);

        // Adjust the UDP payload length
#ifdef __686__
        *(uint16_t *)(pktData+24) = bswap_16(new_data_len+8);
        //*(uint16_t *)(pktData+24) = htons(new_data_len+8);
#else
        *(uint16_t *)(pktData+24) = htons(new_data_len+8);
#endif

        msg_debug("pktData[24]: %02x\n", pktData[24]);
        msg_debug("pktData[25]: %02x\n", pktData[25]);

#ifndef __CALCULATE_UDP_CHECKSUM__
        // Zero the UDP checksum which is optional
        *(uint16_t *)(pktData+26) = 0;
#else   
        {
            uint16_t len_udp;
            uint16_t * src_addr = (uint16_t *)&iph->saddr;
            uint16_t * dest_addr = (uint16_t *)&iph->daddr;
            uint16_t * buff = (uint16_t *)(pktData+22);

            checksum = snoop_udpChecksum(new_data_len+8, src_addr, dest_addr, buff);
            msg_debug("udp checksum: %04x\n", checksum);
        }
#endif

        msg_debug("pktData[24]: %02x\n", pktData[24]);
        msg_debug("pktData[25]: %02x\n", pktData[25]);
        msg_debug("new_data_len: %d\n", new_data_len);

        if(gSnoopDebugEnabled) {

            j=14;
            printf("00 00 00 00 00 00 00 00  00 00 00 00 00 00 ");
    
            for (i = 0; i < new_data_len+kSnoop_DHCP_Options_Start; i++) {
                printf("%02x ", pktData[i]);
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
        }

        msg_debug("Number of captured packets: %d\n", ++gSnoopNumCapturedPackets);

        snoop_log();

		if (pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_Inform) 
		{
			inet_ntop(AF_INET, &(pktData[40]), ipv4_addr, INET_ADDRSTRLEN);
			strcpy(g_cInformIpForQueue[queue_number], ipv4_addr);
		}

		if( pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_Release) 
		{
            snoop_RemoveClientListEntry(gRemote_id); //Remote id is already initialized
        }
        return nfq_set_verdict(myQueue, queue_id, NF_ACCEPT, new_data_len + kSnoop_DHCP_Options_Start, pktData);

    } else {

        if ( (pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_Offer) ||
		 	 (pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_ACK))
		{
            msg_debug("%s:%d>  DHCP Offer / DHCP Ack:%d received from server \n", __FUNCTION__, __LINE__, pktData[kSnoop_DHCP_Option53_Offset]);
			new_data_len = snoop_removeRelayAgentOptions((struct dhcp_packet *)&pktData[kSnoop_DHCP_Options_Start], len, queue_number);

            // Copy client MAC address
            sprintf(gRemote_id, "%02x:%02x:%02x:%02x:%02x:%02x", 
                    pktData[56], pktData[57], pktData[58], pktData[59], pktData[60], pktData[61]);

        	// Adjust the IP payload length
#ifdef __686__
	        *(uint16_t *)(pktData+2) = bswap_16(new_data_len);
#else
	        *(uint16_t *)(pktData+2) = new_data_len;
#endif

        	msg_debug("pktData[2]: %02x\n", pktData[2]);
	        msg_debug("pktData[3]: %02x\n", pktData[3]);

    	    iph = (struct iphdr *) pktData;
	        iph->check = snoop_ipChecksum(iph);

    	    msg_debug("iph->check: %02x\n", bswap_16(iph->check));
	        msg_debug("iph->ihl: %d\n", iph->ihl);

    	    // Adjust the UDP payload length
#ifdef __686__
	        *(uint16_t *)(pktData+24) = bswap_16(new_data_len - 20);
#else
	        *(uint16_t *)(pktData+24) = htons(new_data_len - 20);
#endif

    	    msg_debug("pktData[24]: %02x\n", pktData[24]);
        	msg_debug("pktData[25]: %02x\n", pktData[25]);

#ifndef __CALCULATE_UDP_CHECKSUM__
	        // Zero the UDP checksum which is optional
    	    *(uint16_t *)(pktData+26) = 0;
#else   
        	{
            	uint16_t len_udp;
	            uint16_t * src_addr = (uint16_t *)&iph->saddr;
    	        uint16_t * dest_addr = (uint16_t *)&iph->daddr;
        	    uint16_t * buff = (uint16_t *)(pktData+22);

            	checksum = snoop_udpChecksum(new_data_len-20, src_addr, dest_addr, buff);
	            msg_debug("udp checksum: %04x\n", checksum);
    	    }
#endif
	        msg_debug("pktData[24]: %02x\n", pktData[24]);
    	    msg_debug("pktData[25]: %02x\n", pktData[25]);
        	msg_debug("new_data_len: %d\n", new_data_len);

	    	if(gSnoopDebugEnabled) {

    	        j=14;
        	    printf("00 00 00 00 00 00 00 00  00 00 00 00 00 00 ");
    
            	for (i = 0; i < new_data_len; i++) {
                	printf("%02x ", pktData[i]);
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
       		}

	        msg_debug("Number of captured packets: %d\n", ++gSnoopNumCapturedPackets);

			if( pktData[kSnoop_DHCP_Option53_Offset] == kSnoop_DHCP_ACK) 
			{
				strcpy(gCircuit_id, gSnoopCircuitIDList[queue_number]);
		        msg_debug("gCircuit_id: %s\n", gCircuit_id);
       
		     	// Copy client MAC address
	            sprintf(gRemote_id, "%02x:%02x:%02x:%02x:%02x:%02x", 
    	                pktData[56], pktData[57], pktData[58], pktData[59], pktData[60], pktData[61]);
        		msg_debug("gRemote_id: %s\n", gRemote_id);

				inet_ntop(AF_INET, &(pktData[44]), ipv4_addr, INET_ADDRSTRLEN);
				char l_cHostName[kSnooper_MaxHostNameLen];
				if (!snoop_isValidIpAddress(ipv4_addr) && snoop_isValidIpAddress(g_cInformIpForQueue[queue_number]))
				{
					strcpy(ipv4_addr,g_cInformIpForQueue[queue_number]);
					CcspTraceWarning(("ipaddress in DHCP ACK is 0.0.0.0 get it from inform:%s\n", ipv4_addr));					
					if (!snoop_isValidIpAddress(ipv4_addr))
					{
						CcspTraceWarning(("IP Address in DHCP Inform is also not valid something went wrong"));
					}
				}
				strcpy(l_cHostName, g_cHostnameForQueue[queue_number]);
				snoop_AddClientListEntry(gRemote_id, gCircuit_id, "ACK", ipv4_addr, l_cHostName);

        	}
    	    snoop_log();

        	return nfq_set_verdict(myQueue, queue_id, NF_ACCEPT, new_data_len, pktData);
		}
        snoop_log();

        msg_debug("Number of captured packets: %d\n", ++gSnoopNumCapturedPackets);

        return nfq_set_verdict(myQueue, queue_id, NF_ACCEPT, 0, NULL);
    }
}

#ifdef __HAVE_SYSEVENT__
static void *snoop_sysevent_handler(void *data)
{
    async_id_t snoop_enable_id;
    async_id_t snoop_debug_enable_id;
    async_id_t snoop_log_enable_id;
    async_id_t snoop_circuit_enable_id;
    async_id_t snoop_remote_enable_id;
    async_id_t snoop_max_clients_id;

    async_id_t snoop_circuit_ids[kSnoop_MaxCircuitIDs]; 
    async_id_t snoop_ssids_ids[kSnoop_MaxCircuitIDs];

    int i = 0;

    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_enable,          &snoop_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_debug_enable,    &snoop_debug_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_log_enable,      &snoop_log_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_circuit_enable,  &snoop_circuit_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_remote_enable,   &snoop_remote_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_max_clients,     &snoop_max_clients_id);

    for(i=0; i<kSnoop_MaxCircuitIDs; i++) {

        sysevent_setnotification(sysevent_fd, sysevent_token, gSnoopSyseventCircuitIDs[i], &snoop_circuit_ids[i]);
    }

    for(i=0; i<kSnoop_MaxCircuitIDs; i++) {

        sysevent_setnotification(sysevent_fd, sysevent_token, gSnoopSyseventSSIDs[i], &snoop_ssids_ids[i]);
    }

    for (;;) {
        char name[25], val[60];
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
        async_id_t getnotification_id;

        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_id);

        if (err) {
            CcspTraceError(("Error during sysevent get err: %d\n", err));
        } else {

            if (strcmp(name, kSnooper_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopEnable = atoi(val);

                msg_debug("gSnoopEnable: %u\n", gSnoopEnable);

            } else if (strcmp(name, kSnooper_debug_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_debug_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopDebugEnabled = atoi(val);

                msg_debug("gSnoopDebugEnabled: %u\n", gSnoopDebugEnabled);

            } else if (strcmp(name, kSnooper_log_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_log_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopLogEnabled = atoi(val);

                msg_debug("gSnoopDebugEnabled: %u\n", gSnoopLogEnabled);

            } else if (strcmp(name, kSnooper_circuit_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_circuit_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopCircuitEnabled = atoi(val);

                msg_debug("gSnoopCircuitEnabled: %u\n", gSnoopCircuitEnabled);

            } else if (strcmp(name, kSnooper_remote_enable)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_remote_enable);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopRemoteEnabled = atoi(val);

                msg_debug("gSnoopRemoteEnabled: %u\n", gSnoopRemoteEnabled);

            } else if (strcmp(name, kSnooper_max_clients)==0) {
                msg_debug("Received %s sysevent\n", kSnooper_max_clients);
                msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);

                gSnoopMaxNumberOfClients = atoi(val);

                msg_debug("gSnoopMaxNumberOfClients: %u\n", gSnoopMaxNumberOfClients);

            } 

            for(i=0; i<kSnoop_MaxCircuitIDs; i++) {

                if (strcmp(name, gSnoopSyseventCircuitIDs[i])==0) {

                    strcpy(gSnoopCircuitIDList[i], val); 
                    break;
                }
            }

            for(i=0; i<kSnoop_MaxCircuitIDs; i++) {

                if (strcmp(name, gSnoopSyseventSSIDs[i])==0) {

                    strcpy(gSnoopSSIDList[i], val);
                    gSnoopSSIDListInt[i] = atoi(val);
                    break;
                }
            }

            snoop_log();
        }
    }

    return 0;
}
#endif

#ifdef __USE_LM_HANDLER__
static int mac_string_to_array(char *pStr, unsigned char array[6])
{
    int tmp[6],n,i;
	if(pStr == NULL)
		return -1;
		
    memset(array,0,6);
    n = sscanf(pStr,"%02x:%02x:%02x:%02x:%02x:%02x",&tmp[0],&tmp[1],&tmp[2],&tmp[3],&tmp[4],&tmp[5]);
    if(n==6){
        for(i=0;i<n;i++)
            array[i] = (unsigned char)tmp[i];
        return 0;
    }

    return -1;
}

static void printf_host(LM_host_t *pHost){
    int i;   
    LM_ip_addr_t *pIp;
    char str[100];

    printf("Device %s Mac %02x:%02x:%02x:%02x:%02x:%02x -> \n\t%s mediaType:%d \n", pHost->hostName, pHost->phyAddr[0], pHost->phyAddr[1], pHost->phyAddr[2], pHost->phyAddr[3], pHost->phyAddr[4], pHost->phyAddr[5],(pHost->online == 1 ? "Online" : "offline"), pHost->mediaType);
    printf("\tL1 interface %s, L3 interface %s comments %s RSSI %d\n", pHost->l1IfName, pHost->l3IfName, pHost->comments, pHost->RSSI);
    printf("\tIPv4 address list:\n");
    for(i = 0; i < pHost->ipv4AddrAmount ;i++){
        pIp = &(pHost->ipv4AddrList[i]);
        inet_ntop(AF_INET, pIp->addr, str, 100);
        printf("\t\t%d. %s %d\n", i+1, str, pIp->addrSource);
    }
    printf("IPv6 address list:\n");
    for(i = 0; i < pHost->ipv6AddrAmount ;i++){
        pIp = &(pHost->ipv6AddrList[i]);
        inet_ntop(AF_INET6, pIp->addr, str, 100);
        printf("\t\t%d. %s %d\n", i+1, str, pIp->addrSource);
    }
}

static void *snoop_mac_handler(void *data)
{
    unsigned char mac[6];
    LM_cmd_common_result_t result;
    char tmp[18];
    struct mylist_head * pos, * q;
    snooper_priv_client_list * pClient;
    int status;

    for (;;) {

        mylist_safe(pos, q, &gSnoop_ClientList.list) {

            pClient= mylist_entry(pos, snooper_priv_client_list, list);

            strncpy(tmp, pClient->client.remote_id, 17);
            tmp[18] = '\0';

            mac_string_to_array(tmp, mac);

            msg_debug("Checking client mac: %s\n", tmp);

            memset(&result, 0, sizeof(result));
            status = lm_get_host_by_mac((char *)mac, &result);

            if(status != -1) {
                if (result.result == LM_CMD_RESULT_OK) {

                    //printf_host(&(result.data.host));

                    if(result.data.host.online) {
                        msg_debug("lm_get_host_by_mac: client mac online: %s\n", tmp);
                    } else {

                        msg_debug("lm_get_host_by_mac: client mac offline: %s\n", tmp);
                        snoop_RemoveClientListEntry(pClient->client.remote_id);
                    }
    
                } else if(result.result == LM_CMD_RESULT_NOT_FOUND) {

                    msg_debug("lm_get_host_by_mac: client mac not found: %s\n", tmp);
                    snoop_RemoveClientListEntry(pClient->client.remote_id);

                } else {
                    msg_err("lm_get_host_by_mac: error: %d\n", result.result);
                }

                snoop_log();
            }
        }

        msg_debug("sleeping %d secs.\n", kSnoop_LM_Delay);
        sleep(kSnoop_LM_Delay);
        
    }

    return 0;
}
#else

#define kSnooper_Cmd1 "/fss/gw/usr/ccsp/ccsp_bus_client_tool eRT getvalues Device.WiFi.AccessPoint.%d.AssociatedDeviceNumberOfEntries"
#define kSnooper_Cmd2 "/fss/gw/usr/ccsp/ccsp_bus_client_tool eRT getvalues Device.WiFi.AccessPoint.%d.AssociatedDevice.%d.MACAddress"
#define kSnooper_Cmd3  "/fss/gw/usr/ccsp/ccsp_bus_client_tool eRT getvalues Device.WiFi.AccessPoint.%d.AssociatedDevice.%d.SignalStrength"

#define READ 0
#define WRITE 1
#define READ_ERR -1

pid_t busClientToolPid = NULL;
int input_fp, output_fp;

static char buffer[128];
typedef struct {
    char mac[18];
    int rssi;
} snooper_assoc_client_list;

static snooper_assoc_client_list gclient_data[kSnoop_MaxNumAssociatedDevices];


void killChild(pid_t childPid)
{
    if (!kill(childPid, 0))
    {
        CcspTraceInfo(("Kill of:%d is successful!!! \n", childPid));
    }
    else
    {
        CcspTraceInfo(("Kill is not successful!!! error is:%d\n", errno));
    }
    close(input_fp);
    close(output_fp);
}

static pid_t popen2(const char *cmd, int *input_fp, int *output_fp)
{
	int p_stdin[2], p_stdout[2];
	int exit_status, i;

    pid_t pid, endID;
    if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
        return -1;
    pid = fork();
    if (pid < 0)
        return pid;
    else if (pid == 0)
    {
		close(p_stdin[WRITE]);
        dup2(p_stdin[READ], READ);
        close(p_stdout[READ]);
        dup2(p_stdout[WRITE], WRITE);
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        perror("execl");
        exit(1);
    }
    if (input_fp == NULL)
        close(p_stdin[WRITE]);
    else
        *input_fp = p_stdin[WRITE];
    if (output_fp == NULL)
        close(p_stdout[READ]);
    else
        *output_fp = p_stdout[READ];

	for(i = 0; i < 10; i++) 
    {
        endID = waitpid(pid, &exit_status, WNOHANG|WUNTRACED);
        if (endID == -1) {            /* error calling waitpid       */
            perror("waitpid error");
			break;	
        }
        else if (endID == 0) {        /* child still running         */
            printf("Parent waiting for child\n");
            sleep(1);
        }
        else if (endID == pid) {  /* child ended                 */
            if (WIFEXITED(exit_status))
                printf("Child ended normally.n");
            else if (WIFSIGNALED(exit_status))
                printf("Child ended because of an uncaught signal.n");
            else if (WIFSTOPPED(exit_status))
                printf("Child process has stopped.n");
            break;

        }
    }
	if (endID == 0)
	{
		killChild(pid);
	}	
	msg_debug("popen2 pid for executing the command:%s is:%d exit_status is:%d\n", cmd, pid, exit_status);
    return pid;
}

void killBus()
{
	int status;
	if(!waitpid(busClientToolPid, &status, WNOHANG))	
	{
		CcspTraceError(("ccsp_bus_client_tool command is still running kill the process:%d\n", busClientToolPid));
		if (!kill(busClientToolPid, 0))
		{
			msg_debug("Kill is successful!!! \n");
		}
		else
		{
			msg_debug("Kill is not successful!!! error is:%d\n", errno);			
		}
	}
	else
	{
		msg_debug("Waitpid is not successful!!! errno:%d\n", errno);		
	}
	close(input_fp); 
	close(output_fp);
}

static int snoop_getNumAssociatedDevicesPerSSID(int index)
{
    FILE *fp;
    char path[PATH_MAX];
    char *pch;
	int read_bytes, num_devices = 0;

    sprintf(buffer, kSnooper_Cmd1, index); 

	busClientToolPid = popen2(buffer, &input_fp, &output_fp);
	
	read_bytes = read(output_fp, path, PATH_MAX);
	if (READ_ERR != read_bytes)
	{	
		msg_debug("Read is successful while getting number of devices bytes read:%d\n", read_bytes);
		pch = strstr(path, "ue:");
	    if (pch) { 
   			num_devices = atoi(&pch[4]);

        	if(num_devices > kSnoop_MaxNumAssociatedDevices) {
        		CcspTraceError(("num_devices :%d exceeds max. value:%d\n", num_devices, kSnoop_MaxNumAssociatedDevices));
	            num_devices = kSnoop_MaxNumAssociatedDevices;
    	    }
        	msg_debug("num_devices: %d\n", num_devices);
	    }
	}
	else //read error case -1 is returned
	{
		CcspTraceError(("Read is un-successful Associated Devices error is:%d\n", errno));		
	}
	close(input_fp); 
	close(output_fp);

    return num_devices;
}

static int snoop_getAssociatedDevicesData(int index, int num_devices, int start_index)
{
    int status = 0;
    FILE *fp;
    char path[PATH_MAX];
    char *pch;
    char mac[18];
    int i, j, k = start_index, rssi;
	int read_bytes;

    // Get MAC addresses of associated clients
    for(i=1; i <= num_devices; i++) {

        sprintf(buffer, kSnooper_Cmd2, index, i); 
  
	    busClientToolPid = popen2(buffer, &input_fp, &output_fp);
    
    	read_bytes = read(output_fp, path, PATH_MAX);
		if (READ_ERR != read_bytes)
		{	
			msg_debug("Read is successful while getting MAC bytes read:%d\n", read_bytes);
	    	pch = strstr(path, "ue:");
			if (pch) { 
                strncpy(mac, &pch[4], 17); 
	    	    mac[17] = '\0';
            	for(j=0; j<= strlen(mac); j++) {
	            	 mac[j] = tolower(mac[j]);
	            }

    	        msg_debug("mac: %s\n", mac);
        	    if(k < kSnoop_MaxNumAssociatedDevices) {
           			strcpy(gclient_data[k++].mac, mac);
	            } else {
    	        	CcspTraceError(("Exceeded max. allowed clients (%d)\n", kSnoop_MaxNumAssociatedDevices));
            	}
        	}
		}
		else //read error case -1 is returned
		{
			CcspTraceError(("Read is un-successful getting MAC error is:%d\n", errno));		
		}
	    close(input_fp); 
    	close(output_fp);
    }

    // Get RSSI level of associated clients
    k = start_index;
    for(i=1; i <= num_devices; i++) {

        sprintf(buffer, kSnooper_Cmd3, index, i); 
        busClientToolPid = popen2(buffer, &input_fp, &output_fp);

        read_bytes = read(output_fp, path, PATH_MAX);
		if (READ_ERR != read_bytes)
		{	
			msg_debug("Read is successful while getting RSSI bytes read:%d\n", read_bytes);
			pch = strstr(path, "ue:");
	        if (pch) {
				rssi = atoi(&pch[4]);
        	    msg_debug("rssi: %d\n", rssi);
            	if(k < kSnoop_MaxNumAssociatedDevices) {
        	    	gclient_data[k++].rssi = rssi;
	            } else {
    	        	CcspTraceError(("Exceeded max. allowed clients (%d)\n", kSnoop_MaxNumAssociatedDevices));
        	    }
        	}
		}
		else //read error case -1 is returned
		{
			CcspTraceError(("Read is un-successful getting RSSI error is:%d\n", errno));		
		}
        close(input_fp);
        close(output_fp);
    }
    return status;
}

static int snoop_getAllAssociatedDevicesData(void)
{
    int i, start_index = 0;
    int num_devices;

    memset(gclient_data, 0, sizeof(gclient_data)); 

    for(i=gSnoopFirstQueueNumber; i < gSnoopNumberOfQueues + gSnoopFirstQueueNumber; i++) {
        num_devices = snoop_getNumAssociatedDevicesPerSSID(gSnoopSSIDListInt[i]);

        if(num_devices) {
            snoop_getAssociatedDevicesData(gSnoopSSIDListInt[i], num_devices, start_index);
            start_index += num_devices;
        }
    }

    return start_index;
}

static bool snoop_IsMacInList(int num_devices, char * pRemote_id)
{
    int i;
    bool inList = false;

    msg_debug("Checking for mac: %s\n", pRemote_id);
    msg_debug("num_devices: %d\n", num_devices);

    for(i=0; i< num_devices; i++) {

        msg_debug("gclient_data[%d].mac: %s  pRemote_id: %s\n", i, gclient_data[i].mac, pRemote_id);

        if(!strcmp(gclient_data[i].mac, pRemote_id)) {
            msg_debug("Found mac: %s\n", gclient_data[i].mac);

            snoop_AddClientListRSSI(gclient_data[i].rssi, pRemote_id);

            inList = true;
            break;
        }
    }

    return inList;
}

#define MAX_NUM_TRIES 15
static void *snoop_mac_handler(void *data)
{ 
    int num_devices;
    struct mylist_head * pos, * q;
    snooper_priv_client_list * pClient;

    for (;;) {

        if (gSnoopEnable) {

			/*This loop is to update the associated devices list. If there are no devices connected to hotspot
            we can avoid running of this loop*/
            if(gSnoopNumberOfClients > 0) { 
            // Get the total number of associated devices
            // on all public SSID's
            num_devices = snoop_getAllAssociatedDevicesData();

            mylist_safe(pos, q, &gSnoop_ClientList.list) {

                pClient= mylist_entry(pos, snooper_priv_client_list, list);

                if (snoop_IsMacInList(kSnoop_MaxNumAssociatedDevices, pClient->client.remote_id) == false) {
					pClient->client.noOfTriesForOnlineCheck++;
					//Since there is a delay in updation of Wifi object AssociatedDevices, there is inconsistency in hot spot client list. 
					//Checking for mutiple times before removing the client from hot spot client list.
					if(pClient->client.noOfTriesForOnlineCheck > MAX_NUM_TRIES ) {
		                snoop_RemoveClientListEntry(pClient->client.remote_id);
		                msg_debug("Removed mac: %s from client list\n", pClient->client.remote_id);
					} 
                } else {
					//reset the count to Zero.
					pClient->client.noOfTriesForOnlineCheck = 0;
				}
				
            }

            snoop_log();
            msg_debug("sleeping %d secs.\n", kSnoop_LM_Delay);
		}	
            sleep(kSnoop_LM_Delay);
        }
    }

    return 0;
}
#endif

#ifdef __HAVE_SYSEVENT_STARTUP_PARAMS__
static int snoop_getStartupParameters(void)
{
    int status = STATUS_SUCCESS;
    int i;
    char buf[kSnoop_max_sysevent_len+1];

    for(i=gSnoopFirstQueueNumber; i < gSnoopNumberOfQueues+gSnoopFirstQueueNumber; i++) {

        if((status = sysevent_get(sysevent_fd, sysevent_token, gSnoopSyseventCircuitIDs[i], 
                                  gSnoopCircuitIDList[i], kSnoop_MaxCircuitLen))) {

            CcspTraceError(("sysevent_get failed to get %s: %d\n", gSnoopSyseventCircuitIDs[i], status)); 
            status = STATUS_FAILURE;
            break;

        } else {
            msg_debug("Loaded sysevent gSnoopSyseventCircuitIDs[%d]: %s with %s\n", 
                      i, gSnoopSyseventCircuitIDs[i], 
                      gSnoopCircuitIDList[i]
            );  
        }
    }

    for(i=gSnoopFirstQueueNumber; i < gSnoopNumberOfQueues+gSnoopFirstQueueNumber; i++) {

        if((status = sysevent_get(sysevent_fd, sysevent_token, gSnoopSyseventSSIDs[i], 
                                  gSnoopSSIDList[i], kSnoop_MaxCircuitLen))) {

            CcspTraceError(("sysevent_get failed to get %s: %d\n", gSnoopSyseventSSIDs[i], status)); 
            status = STATUS_FAILURE;
            break;

        } else {

            if(gSnoopSSIDList[i]) {
               gSnoopSSIDListInt[i] = atoi(gSnoopSSIDList[i]);
            } else {
               gSnoopSSIDListInt[i] = gSnoopFirstQueueNumber; 
            }
            msg_debug("Loaded sysevent %s with %d\n", gSnoopSyseventSSIDs[i], gSnoopSSIDListInt[i]); 
        }
    }

    if(status == STATUS_SUCCESS) {

        if((status = sysevent_get(sysevent_fd, sysevent_token, kSnooper_circuit_enable, 
                                  buf, kSnoop_max_sysevent_len))) {
        
            CcspTraceError(("sysevent_get failed to get %s: %d\n", kSnooper_circuit_enable, status)); 
            status = STATUS_FAILURE;
        } else {

            gSnoopCircuitEnabled = atoi(buf);
            msg_debug("Loaded sysevent %s with %d\n", kSnooper_circuit_enable, gSnoopCircuitEnabled);  
        }
    }

    if(status == STATUS_SUCCESS) {

        if((status = sysevent_get(sysevent_fd, sysevent_token, kSnooper_remote_enable, 
                                  buf, kSnoop_max_sysevent_len))) {

            CcspTraceError(("sysevent_get failed to get %s: %d\n", kSnooper_remote_enable, status)); 
            status = STATUS_FAILURE;
        } else {

            gSnoopRemoteEnabled = atoi(buf);
            msg_debug("Loaded sysevent %s with %d\n", kSnooper_remote_enable, gSnoopRemoteEnabled);  
        }
    }

    if(status == STATUS_SUCCESS) {

        if((status = sysevent_get(sysevent_fd, sysevent_token, kSnooper_max_clients, 
                                  buf, kSnoop_max_sysevent_len))) {

            CcspTraceError(("sysevent_get failed to get %s: %d\n", kSnooper_max_clients, status)); 
            gSnoopMaxNumberOfClients = kSnoop_DefaultMaxNumberOfClients;
            status = STATUS_FAILURE;
        } else {

            if(atoi(buf)) {
                gSnoopMaxNumberOfClients = atoi(buf);
            } 
            msg_debug("Loaded sysevent %s with %d\n", kSnooper_max_clients, gSnoopMaxNumberOfClients);  
        }
    }
    
    return status;
}
#endif

static int snoop_setupSharedMemory(void)
{
    int status = STATUS_SUCCESS;

    do {
        // Create shared memory segment to get link state
        if ((gShm_fd = shmget(kSnooper_Statistics, kSnooper_SharedMemSize, IPC_CREAT | 0666)) < 0) {
            CcspTraceError(("shmget failed while setting up shared memory\n")); 

            perror("shmget");
            status = STATUS_FAILURE;
            break;
        }

        // Attach the segment to our data space.
        if ((gpStats = (snooper_statistics_s *)shmat(gShm_fd, NULL, 0)) == (snooper_statistics_s *) -1) {
            CcspTraceError(("shmat failed whiler setting up shared memory\n")); 

            perror("shmat");

            status = STATUS_FAILURE;
            break;
        }

    } while (0);

    return status;
}

static void snoop_usage(void)
{
    printf("  Usage:  dhcp_snooperd [-e <enable>] [-f <run in foreground>] [-d <debug>] [-q <start queue>] [-n <number of queues>]\n");
    exit(0);
}

int main(int argc, char **argv) 
{
    struct nfq_handle *nfqHandle;
    int cmd;
    struct nfq_q_handle *myQueue;
    struct nfnl_handle *netlinkHandle;
    bool run_in_foreground = false;
    int status; 
    int fd, res, i, j=0;
    char buf[4096];

    rdk_logger_init(DEBUG_INI_NAME);
	pComponentName = "dhcp_snooperd";

    while ((cmd = getopt(argc, argv, "e:d:q:n:f::h::")) != -1) {
        switch (cmd) {
        case 'q':

            // Start or first queue number
            gSnoopFirstQueueNumber = atoi(optarg);

            break;

        case 'n':

            // Number of queues. These must be consecutive
            // with the first queue number equal to gSnoopFirstQueueNumber
            // Example: if gSnoopFirstQueueNumber = 2 and gSnoopNumberOfQueues = 2
            // then there would be two queues with the first queue starting 
            // at 2 e.g. the first queue = 2 and the second queue =3
            gSnoopNumberOfQueues = atoi(optarg);

            if((gSnoopNumberOfQueues > kSnoop_MaxNumberOfQueues) || (gSnoopNumberOfQueues < 1)) {
                CcspTraceError(("Invalid number of queues dhcp_snooperd bring up aborted:%d\n", gSnoopNumberOfQueues));
                exit(1);
            }

            break;

        case 'd':

            if (atoi(optarg) == 0) {
                gSnoopDebugEnabled = false;
            } else {
                gSnoopDebugEnabled = true;
            }

            break;

        case 'e':

            if (atoi(optarg) == 0) {
                gSnoopEnable = false;
            } else {
                gSnoopEnable = true;
            }

            break;

        case 'f':
            run_in_foreground = true;
            break;

        case 'h':
        default:
            CcspTraceError(("Unrecognized option '%c' dhcp_snooperd bring up aborted.\n", cmd));
            snoop_usage();
        }
    }

    printf("%s:%d> gSnoopDebugEnabled: %d\n", __FILE__, __LINE__, gSnoopDebugEnabled);
    printf("%s:%d> gSnoopEnable: %d\n", __FILE__, __LINE__, gSnoopEnable);
    printf("%s:%d> run_in_foreground: %d\n", __FILE__, __LINE__, run_in_foreground);

    if (!run_in_foreground) {
        msg_debug("Running in background\n");

        if (daemon(0,0) < 0) {
            CcspTraceError(("Failed to daemonize dhcp_snooperd: %s\n", strerror(errno)));
        }

    } else {
        msg_debug("Running in foreground\n");
    }

#ifdef __HAVE_SYSEVENT__
    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, kSnooper_events, &sysevent_token);

    if (sysevent_fd >= 0)
    {
#ifdef __HAVE_SYSEVENT_STARTUP_PARAMS__
        if(snoop_getStartupParameters() != STATUS_SUCCESS) {
            CcspTraceError(("Could not get sysevent startup parameters\n"));
            snoop_SignalHandler(0);
        }
#endif
        pthread_create(&sysevent_tid, NULL, snoop_sysevent_handler, NULL);
    } else {
        CcspTraceError(("sysevent_open failed\n"));
        exit(1);
    }
#endif

    // Get a queue connection handle
    if (!(nfqHandle = nfq_open())) {
        CcspTraceError(("Error in nfq_open()\n"));
        exit(1);
    }

    // Unbind the handler from processing any IP packets
    if ((status = nfq_unbind_pf(nfqHandle, AF_INET)) < 0) {
        CcspTraceError(("Error in nfq_unbind_pf(): %d\n", status));
        exit(1);
    }

    // Bind this handler to process IP packets
    if ((status = nfq_bind_pf(nfqHandle, AF_INET)) < 0) {
        CcspTraceError(("Error in nfq_bind_pf(): %d\n", status));
        exit(1);
    }

    for(i=gSnoopFirstQueueNumber; i < gSnoopNumberOfQueues + gSnoopFirstQueueNumber; i++) {

        // Pass the queue number to the packet handler
        gPriv_data[j] = i;

        // Copy default CircuitID's 
        //strcpy(gSnoopCircuitIDList[i], kSnoop_DefaultCircuitID); 

        // Install a callback on each of the iptables NFQUEUE queues
        if (!(myQueue = nfq_create_queue(nfqHandle,  i, &snoop_packetHandler, &gPriv_data[j++]))) {
    
            CcspTraceError(("Error in nfq_create_queue(): %p\n", myQueue));
            exit(1);
        } else {
            msg_debug("Registered packet handler for queue %d\n", i);

            // Turn on packet copy mode
            if ((status = nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff)) < 0) {

                CcspTraceError(("Error in nfq_set_mode(): %d\n", status));
                exit(1);
            }
        }
    }

    netlinkHandle = nfq_nfnlh(nfqHandle);
    fd = nfnl_fd(netlinkHandle);

    SET_LIST_HEAD(&gSnoop_ClientList.list);

    strcpy(gCircuit_id, kSnoop_DefaultCircuitID);
    strcpy(gRemote_id, kSnoop_DefaultRemoteID); 

    if(snoop_setupSharedMemory() != STATUS_SUCCESS) {
        CcspTraceError(("Error while setting shared memory\n"));
        exit(1);
    }

    if (signal(SIGTERM, snoop_SignalHandler) == SIG_ERR)
        msg_debug("Failed to catch SIGTERM\n");

    if (signal(SIGINT, snoop_SignalHandler) == SIG_ERR)
        msg_debug("Failed to catch SIGTERM\n");
    
	if (signal(SIGALRM, killBus) == SIG_ERR)
		msg_debug("Failed to catch SIGALM");

#ifdef __HAVE_SYSEVENT__
    if(pthread_create(&lm_tid, NULL, snoop_mac_handler, NULL))
    {
        CcspTraceError(("Call to pthread_create lm_tid failed\n"));
        exit(1);
    }
    {
        pthread_attr_t attr_snoop_mac_handler;
        int policy = 0;
        int min_prio_for_policy = SCHED_RR;
    
        pthread_attr_init(&attr_snoop_mac_handler);
        pthread_attr_getschedpolicy(&attr_snoop_mac_handler, &policy);
                                       
        min_prio_for_policy = sched_get_priority_min(policy);
        pthread_setschedprio(lm_tid, min_prio_for_policy);
    }
#endif
	
	CcspTraceInfo(("dhcp_snooperd process is up\n"));
	system("touch /tmp/dhcp_snooperd_up");
    snoop_log();

    while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {

        msg_debug("Call nfq_handle_packet\n");
        nfq_handle_packet(nfqHandle, buf, res);
    }

    nfq_destroy_queue(myQueue);

    nfq_close(nfqHandle);

    exit(0);

}

