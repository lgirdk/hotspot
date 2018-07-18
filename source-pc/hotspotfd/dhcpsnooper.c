/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/
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
/*
 * Copyright (c) 2004-2006 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1997-2003 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "dhcpsnooper.h"

#define mylist_safe(p, q, h) \
         for (p = (h)->n, q = p->n; p != (h); \
                 p = q, q = p->n)

#define offf(t, m) ((size_t) &((t *)0)->m)

#define cof(p, t, m) ({                      \
         const typeof( ((t *)0)->m ) *__mptr = (p);    \
         (t *)( (char *)__mptr - offf(t, m) );})

#define mylist_entry(p, t, m) \
         cof(p, t, m)

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
static char gCircuit_id[kSnoop_MaxCircuitLen];
static char gRemote_id[kSnoop_MaxRemoteLen]; 

extern bool gSnoopEnable;
extern bool gSnoopDebugEnabled;
extern bool gSnoopLogEnabled;
extern bool gSnoopCircuitEnabled;
extern bool gSnoopRemoteEnabled;
static int gSnoopDhcpMaxAgentOptionLen = DHCP_MTU_MIN;
static int gSnoopNumCapturedPackets = 0;
extern int gSnoopFirstQueueNumber;
extern int gSnoopNumberOfQueues;

extern int gSnoopNumberOfClients;
static int snoop_sysevent_fd;

extern int gSnoopMaxNumberOfClients;
extern char gSnoopCircuitIDList[kSnoop_MaxCircuitIDs][kSnoop_MaxCircuitLen];
extern char gSnoopSyseventCircuitIDs[kSnoop_MaxCircuitIDs][kSnooper_circuit_id_len];
extern char gSnoopSSIDList[kSnoop_MaxCircuitIDs][kSnoop_MaxCircuitLen];
extern int  gSnoopSSIDListInt[kSnoop_MaxCircuitIDs];
extern char gSnoopSyseventSSIDs[kSnoop_MaxCircuitIDs][kSnooper_circuit_id_len];

static snooper_priv_client_list gSnoop_ClientList;

static int gPriv_data[kSnoop_MaxNumberOfQueues];
extern snooper_statistics_s * gpSnoop_Stats;
static int add_agent_options = 1;	/* If nonzero, add relay agent options. */
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

static void snoop_AddClientListHostname(char *pHostname, char *pRemote_id, int queue_number)
{
    snooper_priv_client_list * pNewClient;
    struct mylist_head * pos, * q;
    bool already_in_list = false;

    mylist_safe(pos, q, &gSnoop_ClientList.list) {

         pNewClient= mylist_entry(pos, snooper_priv_client_list, list);
         if(!strcasecmp(pNewClient->client.remote_id, pRemote_id)) {
             already_in_list = true;
             break;
         }
    }

    if(already_in_list) 
	{
		CcspTraceInfo(("Client:%s is present update hostname:%s\n", pRemote_id, pHostname));
        strcpy(pNewClient->client.hostname, pHostname);
    }
	strcpy(g_cHostnameForQueue[queue_number], pHostname);	
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

void snoop_log(void)
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

        gpSnoop_Stats->snooper_enabled = gSnoopEnable;
        gpSnoop_Stats->snooper_debug_enabled = gSnoopDebugEnabled;
        gpSnoop_Stats->snooper_circuit_id_enabled = gSnoopCircuitEnabled;
        gpSnoop_Stats->snooper_remote_id_enabled = gSnoopRemoteEnabled;

        gpSnoop_Stats->snooper_first_queue = gSnoopFirstQueueNumber;   
        gpSnoop_Stats->snooper_num_queues = gSnoopNumberOfQueues;
        gpSnoop_Stats->snooper_max_queues = kSnoop_MaxNumberOfQueues;
        gpSnoop_Stats->snooper_dhcp_packets = gSnoopNumCapturedPackets;

        gpSnoop_Stats->snooper_max_clients = gSnoopMaxNumberOfClients;
        gpSnoop_Stats->snooper_num_clients = gSnoopNumberOfClients;

        i = 0;
        mylist_safe(pos, q, &gSnoop_ClientList.list) {
    
             pClient= mylist_entry(pos, snooper_priv_client_list, list);

             printf("pClient->client.circuit_id[%d]: %s\n", i, pClient->client.circuit_id);
             printf("pClient->client.dhcp_status[%d]: %s\n", i, pClient->client.dhcp_status);
             printf("pClient->client.hostname[%d]: %s\n", i, pClient->client.hostname);
             printf("pClient->client.ipv4_addr[%d]: %s\n", i, pClient->client.ipv4_addr);
             printf("pClient->client.remote_id[%d]: %s\n", i, pClient->client.remote_id);
             printf("pClient->client.rssi[%d]: %d\n", i, pClient->client.rssi);

             memcpy(&gpSnoop_Stats->snooper_clients[i], &pClient->client, sizeof(snooper_client_list));
             i++;
        }
    }
}

void snoop_RemoveClientListEntry(char *pRemote_id)
{
    bool already_in_list = false;
    struct mylist_head * pos, * q;
    snooper_priv_client_list * pNewClient;
    
    mylist_safe(pos, q, &gSnoop_ClientList.list) {

         pNewClient= mylist_entry(pos, snooper_priv_client_list, list);
         if(!strcasecmp(pNewClient->client.remote_id, pRemote_id)) {
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
		snoop_log();
    }
}

/*
This function is to check whether the XfinityWifi Client was previously a private client 
*/
static void snoop_CheckClientIsPrivate(char *pRemote_id)
{
    FILE *l_dnsfp = NULL;
    char l_cBuf[200] = {0}; 
    int ret, l_iLeaseTime; 
    char l_cDhcpClientAddr[20] = {0}; 
    char l_cIpAddr[255] = {0}; 
    char l_cHostName[255] = {0}; 

    if ((l_dnsfp = fopen(DNSMASQ_LEASES_FILE, "r")) == NULL)
    {    
        CcspTraceError(("dnsmasq.leases file open failed\n"));
        return;
    }    

    while (fgets(l_cBuf, sizeof(l_cBuf), l_dnsfp)!= NULL)
    {    
        ret = sscanf(l_cBuf, "%d %s %s %s", &l_iLeaseTime, l_cDhcpClientAddr, l_cIpAddr, l_cHostName);
        if(ret != 4)
            continue;

        if (!strcasecmp(pRemote_id, l_cDhcpClientAddr))
        {
            CcspTraceInfo(("Private Client Check: Xfinitywifi Client :%s was a private client \n", pRemote_id));
            break;
        }
    }
    fclose(l_dnsfp);
}

static void snoop_AddClientListEntry(char *pRemote_id, char *pCircuit_id, 
                                  char *pDhcp_status, char *pIpv4_addr, char *pHostname, int rssi)
{
    snooper_priv_client_list * pNewClient;
    struct mylist_head * pos, * q;
    bool already_in_list = false;

    mylist_safe(pos, q, &gSnoop_ClientList.list) {

         pNewClient= mylist_entry(pos, snooper_priv_client_list, list);
         if(!strcasecmp(pNewClient->client.remote_id, pRemote_id)) {
             already_in_list = true;
             break;
         }
    }

    if(!already_in_list) {

        if(gSnoopNumberOfClients < gSnoopMaxNumberOfClients) { 
    
            pNewClient= (snooper_priv_client_list *)malloc(sizeof(snooper_priv_client_list));
			memset(pNewClient, 0x00, sizeof(pNewClient));

			if (NULL == pCircuit_id)
			{
				strcpy(pNewClient->client.remote_id, pRemote_id);
			}
			else
			{
				strcpy(pNewClient->client.remote_id, pRemote_id);
    	        strcpy(pNewClient->client.circuit_id, pCircuit_id);
        	    strcpy(pNewClient->client.dhcp_status, pDhcp_status);
            	strcpy(pNewClient->client.ipv4_addr, pIpv4_addr);
	            strcpy(pNewClient->client.hostname, pHostname);
			}
            pNewClient->client.rssi = rssi;
            pNewClient->client.noOfTriesForOnlineCheck = 0; 
            mylist_add(&pNewClient->list, &gSnoop_ClientList.list);
            gSnoopNumberOfClients++;

        } else {
            CcspTraceError(("Max. number of clients %d already in list\n", gSnoopNumberOfClients));
        }
    } else {
        msg_debug("Client %s already in list.\n", pRemote_id);
		if ((NULL != pCircuit_id && '\0' != pCircuit_id[0]))
		{
			strcpy(pNewClient->client.remote_id, pRemote_id);
            strcpy(pNewClient->client.circuit_id, pCircuit_id);
            strcpy(pNewClient->client.dhcp_status, pDhcp_status);
            strcpy(pNewClient->client.ipv4_addr, pIpv4_addr);
            strcpy(pNewClient->client.hostname, pHostname);
		}
		else
		{
	        pNewClient->client.rssi = rssi;
		}
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
	    //>>zqiu: to fix the busy loop
	    int count=0;
	    while (*op != DHO_END)
	    {
		count++;
		if(count>1024) {
			fprintf(stderr, "-- %s busyloop here\n", __func__);
			msg_debug("%s busyloop here\n", __func__);
			break;
		}
		memmove(sp, op, op[1] + 2);
                sp += op[1] + 2;
                //op = op[1] + 2;
		op += op[1] + 2;
	    }
	    //<<
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
    FILE *fp = NULL;//LNT_EMU
    char str[1024];
    int wificlientindex = 0 ;
    int count = 0;
    unsigned long wifi_count = 0;
    int signalstrength = 0;


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

        /*
         snoop_udpChecksum function is removed as the UDP Checksum is not added 
         in any of the DHCP packets, it is always set to zero.
        */
        // Zero the UDP checksum which is optional
        *(uint16_t *)(pktData+26) = 0;

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

        	/*
         	 snoop_udpChecksum function is removed as the UDP Checksum is not added 
         	 in any of the DHCP packets it is always set to zero.
        	*/
        	// Zero the UDP checksum which is optional
        	*(uint16_t *)(pktData+26) = 0;

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
#if 1//LNT_EMU
             	fp = popen("iw dev wlan0_0 station dump | grep avg | tr -s ' ' | cut -d ' ' -f 2 > publicwifi_signalstrength.txt","r");
             	pclose(fp);
             	fp = popen("cat publicwifi_signalstrength.txt | wc -l","r");
        	fgets(str, sizeof(str)-1, fp);
        	wifi_count = (unsigned long) atol ( str );
	        pclose(fp);
        	fp = popen("cat publicwifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
	        if(fp)
        	{
	       for(count = 0 ; count < wifi_count ; count++)
        	{
                	fgets(str,1024,fp);
                	signalstrength = atoi(str);
                	snoop_AddClientListEntry(gRemote_id, gCircuit_id, "ACK", ipv4_addr, l_cHostName, signalstrength);
        	}	
        	}			
	        pclose(fp);
#endif

		//		snoop_AddClientListEntry(gRemote_id, gCircuit_id, "ACK", ipv4_addr, l_cHostName, 0);LNT_EMU
                snoop_CheckClientIsPrivate(gRemote_id);  
        	}
    	    snoop_log();

        	return nfq_set_verdict(myQueue, queue_id, NF_ACCEPT, new_data_len, pktData);
		}
        snoop_log();

        msg_debug("Number of captured packets: %d\n", ++gSnoopNumCapturedPackets);

        return nfq_set_verdict(myQueue, queue_id, NF_ACCEPT, 0, NULL);
    }
}

void updateRssiForClient(char* pRemote_id, int rssi)
{
	bool already_in_list = false;
    struct mylist_head * pos, * q; 
    snooper_priv_client_list * pNewClient;
    
    mylist_safe(pos, q, &gSnoop_ClientList.list) 
	{
         pNewClient= mylist_entry(pos, snooper_priv_client_list, list);
         if(!strcasecmp(pNewClient->client.remote_id, pRemote_id)) {
             already_in_list = true;
			 pNewClient->client.rssi = rssi;
			 snoop_log();
         }
    }
	if (false == already_in_list)	
	{
		msg_debug("Client :%s is not present Add to the clientlist\n", pRemote_id);
		snoop_AddClientListEntry(pRemote_id, NULL, NULL, NULL, NULL, rssi);
	}
}

void *dhcp_snooper_init(void *data)
{
	struct nfq_handle *nfqHandle;
    struct nfq_q_handle *myQueue;
    struct nfnl_handle *netlinkHandle;
    int status; 
    int fd, res, i, j=0;
    char buf[4096];

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
    msg_debug("%s fd=%d\n", __func__, fd);
    SET_LIST_HEAD(&gSnoop_ClientList.list);

    strcpy(gCircuit_id, kSnoop_DefaultCircuitID);
    strcpy(gRemote_id, kSnoop_DefaultRemoteID); 

	CcspTraceInfo(("dhcp_snooper thread inited\n"));
    snoop_log();

    while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) 
	{
        msg_debug("Call nfq_handle_packet\n");
        nfq_handle_packet(nfqHandle, buf, res);
    }
    nfq_destroy_queue(myQueue);
    nfq_close(nfqHandle);
    exit(0);
}

