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

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <net/if_arp.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include "ansc_platform.h"
#include "libnetfilter_queue/libnetfilter_queue.h"
#include "safec_lib_common.h"
#include "secure_wrapper.h"

#ifdef FEATURE_SUPPORT_MAPT_NAT46
#include <sysevent/sysevent.h>
#define SYSEVENT_MAPT_CONFIG_FLAG "mapt_config_flag"
#define SYSEVENT_MAPT_IP_ADDRESS "mapt_ip_address"
#endif

/**************************************************
******** MACRO DEFINITIONS **************************
**************************************************/
#ifdef TRUE
    #undef TRUE
#endif

#ifdef FALSE
    #undef FALSE
#endif

#define TRUE    0
#define FALSE   -1

#define PID_FILE        "/var/hotspot_arpd.pid"
#define TUNNEL_INTF     "erouter0"
#define ETH_ALEN        6
#define IP_ALEN         4
#define ETHER_HLEN      14
#define VLAN_HLEN       4
#define GRE_HLEN        4
#define ETHER_VLAN_HLEN (ETHER_HLEN+VLAN_HLEN)
#define ARP_PACKET_LEN  28
#define RAW_ARP_LEN     (ETHER_HLEN+ARP_PACKET_LEN)
#define MAX_BUFSIZE     100         /* max buffer for ip gre arp packet */
#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2


#define DPRINTF(format, args...) \
    if (debug_flag) printf(format, ##args)
    

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

/***************************************************
********* TYPE DEFINITIONS ****************************
****************************************************/
typedef struct arp_pkt {  
    unsigned short htype;  
    unsigned short ptype;  
    unsigned char hlen;  
    unsigned char plen;  
    unsigned short opcode;  
    unsigned char sender_mac[ETH_ALEN];  
    unsigned long sender_ip;  
    unsigned char target_mac[ETH_ALEN];  
    unsigned long target_ip;
}arp_pkt_t;

typedef struct if_s {
    /* Coverity Fix CID:135319 BUFFER_SIZE */
    char ifname[16];
    int ifindex;
    unsigned char mac[ETH_ALEN];
    struct in_addr ip;
}if_t;

typedef struct nfqueue_data_s {
    struct nfq_handle *handle;
    struct nfq_q_handle *q_handle;
    int (*nfq_callback)(struct nfq_q_handle *qh,
                        struct nfgenmsg *nfmsg,
                        struct nfq_data *nfad, 
                        void *data);
}nfqueue_data_t;

typedef void (*SIG_HANDLER)(int);

/*******************************************************
********* FUNCTION DEFINITIONS ****************************
********************************************************/
static int hotspot_arpd_init(void);
static void hotspot_arpd_cleanup(void);
static int write_pid_to_file(void);
static int get_interface_by_ifname(if_t *target);
static int is_gre_arp_request(const unsigned char *arpreq);
unsigned short ip_checksum(struct iphdr * header);
static int 
hotspot_arpd_nfqueue_cb(struct nfq_q_handle *qh, 
               struct nfgenmsg *nfmsg,
               struct nfq_data *nfa, 
               void *data);
static void hotspot_arpd_nfqueue_handler(void *);

/*******************************************************
********* STATIC DEFINITIONS ******************************
********************************************************/
static int verbose = 0;
static int debug_flag = 0;
static unsigned short gQueueNum = 0;

static if_t erouter = {
    .ifname = TUNNEL_INTF
};

static nfqueue_data_t g_nfqueue = {
    .nfq_callback = &hotspot_arpd_nfqueue_cb
};
    
static void usage(void)
{
    printf("\n*************************************\n");
    printf("Usage: hotspot_arpd options\n");
    printf("options:\n");
    printf("        -i interface as tunnel endpoint, default erouter0\n");
    printf("        -q NFQUEUE queue number\n");
    printf("        -v display verbose log\n");
    printf("        -d display debug log\n");
    printf("\n*************************************\n");
}

SIG_HANDLER signal_set(int signo, SIG_HANDLER func)
{
    int ret;
    struct sigaction sig, osig;

    sig.sa_handler = func;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;
#ifdef SA_RESTART
    sig.sa_flags |= SA_RESTART;
#endif /* end SA_RESTART */

    ret = sigaction(signo, &sig, &osig);
    if (ret < 0)
        return (SIG_ERR);
    return (osig.sa_handler);
}

static void signal_init(void)
{
    signal_set(SIGPIPE, SIG_IGN);
}

int main (int argc, char *argv[])
{
    int opt, rc = -1;
	errno_t rc1 = -1;

    while ((opt = getopt(argc, argv, "i:q:vdh")) != -1){
        switch(opt){
        case 'v':
            verbose = 1;
            break;
        case 'd':
            debug_flag = 1;
            break;
        case 'i':   /* interface name */
            /* Coverity Fix CID:135541 BUFFER_SIZE_WARNING */
		    rc1 = strcpy_s(erouter.ifname, sizeof(erouter.ifname), optarg);
            if(rc1 != EOK)
			{
			    ERR_CHK(rc);
				return -1;
			}
            DPRINTF("Interface name %s provided!\n", erouter.ifname);
            break;
        case 'q':
            gQueueNum = (unsigned short)atoi(optarg);
            DPRINTF("NFQUEUE number %d!\n", gQueueNum);
            break;
        case '?':
            if (optopt == 'i' || optopt == 'q')
                printf("Option -%c requires an argument!\n", optopt);
            else
                printf("Unknown option character -%c!\n", optopt);
            return -1;
        default:
            usage();
            exit(-1);
        }
    }

    if (hotspot_arpd_init() < 0)
        goto exit;

    v_secure_system("touch /tmp/hotspot_arpd_up");
    hotspot_arpd_nfqueue_handler((void*)&g_nfqueue);

//cleanup:
    hotspot_arpd_cleanup();

exit:
    return rc;
}

static void go_background(void)
{
    if (fork())
        exit(0);
}

static void hotspot_arpd_cleanup(void)
{
    return;
}

static int hotspot_arpd_init(void)
{   
    int rc = 0;
    
    go_background();
    signal_init();    
    if (get_interface_by_ifname(&erouter) < 0 ||
        write_pid_to_file() < 0){
        rc = -1;
        goto exit;
    }

exit:    
    return rc;
}

static int write_pid_to_file(void)
{
    FILE *fp = NULL;

    if ((fp = fopen(PID_FILE, "w+")) == NULL){
        printf("fopen failed!\n");
        return -1;
    }
    fprintf(fp, "%d", getpid());
    (void)fclose(fp);
    return 0;
}

static int get_interface_by_ifname(if_t *target)
{
    int fd;
    struct ifreq req;
	errno_t rc = -1;

    if ((NULL == target) || ('\0' == target->ifname[0])){
        printf("Invalid parameters!\n");
        return FALSE;
    }

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd == -1){
        printf("Failed to create socket on PF_INET:DGRAM!\n");
        return FALSE;
    }

    bzero(&req, sizeof(req));
	rc = strcpy_s(req.ifr_name, sizeof(req.ifr_name), target->ifname);
    if(rc != EOK)
	{
	    ERR_CHK(rc);
		close(fd);
		return FALSE;
	}
    req.ifr_name[sizeof(req.ifr_name)-1] = '\0';
    if (ioctl(fd, SIOCGIFHWADDR, &req) == -1){
        printf("Failed to ioctl SIOCGIFHWADDR!\n");
        close(fd);
        return FALSE;
    }
	rc = memcpy_s(target->mac, sizeof(target->mac), &req.ifr_hwaddr.sa_data[0], ETH_ALEN);
    if(rc != EOK)
    {
        ERR_CHK(rc);
		close(fd);
        return FALSE;
    }

    if (ioctl(fd, SIOCGIFINDEX, &req) == -1){
        printf("Failed to ioctl SIOCGIFINDEX!\n");
        close(fd);
        return FALSE;
    }
    target->ifindex = req.ifr_ifindex;

    int mapt_ipv4 = 0;
#ifdef FEATURE_SUPPORT_MAPT_NAT46
    int sysevent_fd_gs;
    token_t sysevent_token_gs;
    char buf[32]={0};
    sysevent_fd_gs = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "hotspot_arpd", &sysevent_token_gs);

    if(sysevent_fd_gs >= 0)
    {
        sysevent_get(sysevent_fd_gs, sysevent_token_gs, SYSEVENT_MAPT_CONFIG_FLAG, buf, sizeof(buf));

        if (strncmp(buf,"set", 3) == 0)
        {
            sysevent_get(sysevent_fd_gs, sysevent_token_gs, SYSEVENT_MAPT_IP_ADDRESS, buf, sizeof(buf));

            if(inet_aton(buf,&(target->ip)))
            {
                mapt_ipv4 = 1;
            }
        }
        sysevent_close(sysevent_fd_gs, sysevent_token_gs);
    }
#endif
    if(0 == mapt_ipv4)
    {
        if (ioctl(fd, SIOCGIFADDR, &req) == -1){
            printf("Failed to ioctl SIOCGIFADDR!\n");
            close(fd);
            return FALSE;
        }
        target->ip = ((struct sockaddr_in *)&req.ifr_addr)->sin_addr;
    }

    close(fd);
    
    DPRINTF("%s ifindex %d MAC %02x:%02x:%02x:%02x:%02x:%02x IP %s!\n",
            target->ifname, target->ifindex,
            target->mac[0], target->mac[1], target->mac[2],
            target->mac[3], target->mac[4], target->mac[5],
            inet_ntoa(target->ip));

    return TRUE;
    
}

static int is_gre_arp_request(const unsigned char *arpreq)
{
    unsigned char *pkt_ptr = (unsigned char*)arpreq;
    struct iphdr *iphdr_ptr;
    int outer_iphdr_len = 0;
    unsigned short gre_flags, gre_proto;

    if (!arpreq){
        printf("What ??? Invalid parameter!\n");
        return FALSE;
    }
 
    /* get icmp ip header */
    iphdr_ptr = (struct iphdr *)pkt_ptr;
    outer_iphdr_len = iphdr_ptr->ihl << 2;

    /* skip icmp ip header */
    pkt_ptr += outer_iphdr_len;
    /* skip icmp header
     * type (1) code (1) chksum (2) unused (2) next-hop mtu (2)
     */
    pkt_ptr += 8;

    /* now points original GRE ARP REQUEST */
    iphdr_ptr = (struct iphdr *)pkt_ptr;
    pkt_ptr += iphdr_ptr->ihl << 2;

    gre_flags = ((unsigned short *)pkt_ptr)[0];
    gre_proto = ((unsigned short *)pkt_ptr)[1];
    DPRINTF("GRE FLAGS 0x%02x PROTO 0x%02x!\n", gre_flags, gre_proto);

    return (gre_proto == htons(ETH_P_ARP)) ? TRUE : FALSE;
}

static int arp_isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));

    return (((result != 0) && (sa.sin_addr.s_addr != 0)) ? TRUE: FALSE);
}

static int is_a_valid_gre_arp_request(unsigned char* arp_packet)
{
    struct iphdr *pIphdr;
    unsigned char sender_ip[4];
    unsigned char *pArpReq;
    errno_t rc = -1;

    pIphdr = (struct iphdr *)arp_packet;
    arp_packet += (pIphdr->ihl << 2) + 8;   /*skip original ip and icmp header*/
    pArpReq = arp_packet;

    pArpReq += (pIphdr->ihl << 2);
    DPRINTF("ARP reply: outer ip header done!\n");

    pArpReq += 4;
    DPRINTF("ARP reply: GRE header done!\n");

    pArpReq += 8;
	rc = memcpy_s(sender_ip, sizeof(sender_ip), &pArpReq[6], IP_ALEN);
    if(rc != EOK)
    {
        ERR_CHK(rc);
        return FALSE;
    }
    return (arp_isValidIpAddress(sender_ip));
}

/*
 * function: build_gre_arp_reply_packet 
 * parameter: 
 *    packet: icmp unreachable (input)
 *    length: icmp unreachable length (input and output)
 * return: 
 *    GRE ARP REPLY buffer 
 */
static unsigned char* 
build_gre_arp_reply_packet(
        unsigned char* packet, 
        int *length)
{
    struct iphdr *pIphdr;
    arp_pkt_t *pArp;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4], target_ip[4];
    unsigned long _beIp;
    unsigned char *pArpReq;
    errno_t rc = -1;
	
    pIphdr = (struct iphdr *)packet;
    packet += (pIphdr->ihl << 2) + 8;   /*skip original ip and icmp header*/
    *length -= (pIphdr->ihl << 2) + 8;
    pArpReq = packet;

    /*req_ptr now points to GRE ARP REQUEST */
    pIphdr = (struct iphdr *)pArpReq;
    _beIp = pIphdr->saddr;
    // pIphdr->id    += htons(1);
    pIphdr->ttl   = 64;
    pIphdr->saddr = erouter.ip.s_addr;
    pIphdr->daddr = _beIp;
    pIphdr->check = ip_checksum(pIphdr);

    pArpReq += (pIphdr->ihl << 2);
    DPRINTF("ARP reply: outer ip header done!\n");
    
    /* No need to change GRE header */
    pArpReq += 4;
    DPRINTF("ARP reply: GRE header done!\n");

    /* build arp reply */
    pArp           = (arp_pkt_t *)pArpReq;
    pArp->opcode   = ARPOP_REPLY;

    pArpReq += 8;
	
	rc = memcpy_s(sender_mac, sizeof(sender_mac), &pArpReq[0], ETH_ALEN);
    if(rc != EOK)
    {
        ERR_CHK(rc);
		*length = 0;
        return NULL;
    }
	rc = memcpy_s(sender_ip, sizeof(sender_ip), &pArpReq[6], IP_ALEN);
    if(rc != EOK)
    {
        ERR_CHK(rc);
		*length = 0;
        return NULL;
    }
	rc = memcpy_s(target_ip, sizeof(target_ip), &pArpReq[16], IP_ALEN);
    if(rc != EOK)
    {
        ERR_CHK(rc);
		*length = 0;
        return NULL;
    }
    
	rc = memcpy_s(&pArpReq[0], ETH_ALEN, erouter.mac, ETH_ALEN);   /* sender hardware address */
    if(rc != EOK)
    {
        ERR_CHK(rc);
		*length = 0;
        return NULL;
    }
    rc = memcpy_s(&pArpReq[6], IP_ALEN, target_ip, IP_ALEN);       /* sender protocol address */
    if(rc != EOK)
    {
        ERR_CHK(rc);
		*length = 0;
        return NULL;
    }
    rc = memcpy_s(&pArpReq[10], ETH_ALEN, sender_mac, ETH_ALEN);  /* target hardware address */
    if(rc != EOK)
    {
        ERR_CHK(rc);
		*length = 0;
        return NULL;
    }      
    rc = memcpy_s(&pArpReq[16], IP_ALEN, sender_ip, IP_ALEN);  /* target protocol address */ 
    if(rc != EOK)
    {
        ERR_CHK(rc);
		*length = 0;
        return NULL;
    }            
    DPRINTF("ARP reply: arp payload done!\n");

    return packet;

}

unsigned short ip_checksum(struct iphdr * header)
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

static int 
hotspot_arpd_nfqueue_cb(
    struct nfq_q_handle *qh, 
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfa, 
    void *data)
{
    UNREFERENCED_PARAMETER(nfmsg);
    UNREFERENCED_PARAMETER(data);
    unsigned char *payload;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    int ret, id = 0, i, j = 0;

    ph = nfq_get_msg_packet_hdr(nfa);
    if(ph) {
        id = ntohl(ph->packet_id);
        DPRINTF("hw_protocol 0x%04x hook_num %u id %u!\n", ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(nfa);
    if(hwph) {
        DPRINTF("hw_address %02x:%02x:%02x:%02x:%02x:%02x\n",
                hwph->hw_addr[0], hwph->hw_addr[1], hwph->hw_addr[2],
                hwph->hw_addr[3], hwph->hw_addr[4], hwph->hw_addr[5]);
    }

    /* 
        This is for sure an ICMP packet with OUTPUT chain and outdev erouter0 
        We need to grab the ICMP payload and check IP header and first 8 bytes of original datagram's data
        We are handling ICMP type=3 and Code=3 Destination Unreachable and port unreachable
        Payload should be with following format:
        Type (1 octet) + Code (1 octet) + Chksum (2 octets)
        unused (2 octets) + Next-Hop MTU (2 octets)
        IP header and additional data (20+4+14+28)
        */
    ret = nfq_get_payload(nfa, &payload);
    if (ret < 0){
        DPRINTF("NFQUEUE nfq_get_payload failed!\n");
        goto accept;
    }
    DPRINTF("NFQUEUE get payload length %d!\n", ret);
    if (verbose) {
        DPRINTF("\n");
        for(i = 0; i < ret; i++) {
            DPRINTF("0x%02x ", payload[i]);
            if (j==7) DPRINTF(" ");
            j++;
            if (j==16) {
                DPRINTF("\n");
                j=0;
            }
        }
        DPRINTF("\n");
    }

    if (ret< 80 ) {
        DPRINTF("NFQUEUE payload format error!\n");
        goto accept;
    }

    /* Not GRE ARP REQUEST, we let it go */
    if (is_gre_arp_request(payload) < 0){
        DPRINTF("NFQUEUE not GRE ARP REQUEST!\n");
        goto accept;
    }

    if (!is_a_valid_gre_arp_request(payload))
    {
        DPRINTF("NFQUEUE not a valid GRE ARP REQUEST!\n");
        goto accept;
    }
    /*
     * PAYLOAD: icmp ip header + icmp header + GRE ARP REQUEST
     */
    payload = build_gre_arp_reply_packet(payload, &ret);

    if (verbose) {
        DPRINTF("REPLY length %d packet:\n\n", ret);
        for(i = 0,j = 0; i < ret; i++) {
            DPRINTF("0x%02x ", payload[i]);
            if (j==7) DPRINTF(" ");
            j++;
            if (j==16) {
                DPRINTF("\n");
                j=0;
            }
        }
        DPRINTF("\n");
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, ret, payload);

accept:
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static int hotspot_arpd_nfqueue_init(nfqueue_data_t *nfq)
{
    int rc = 0;
    
    /* opening library handle */
    nfq->handle = nfq_open();
    if (!nfq->handle){
        DPRINTF("NFQUEUE nfq_open failed!\n");
        rc = -1;
        goto exit;
    }

    /* unbinding existing nf_queue handler for AF_INET */
    if (nfq_unbind_pf(nfq->handle, AF_INET) < 0){
        DPRINTF("NFQUEUE nfq_unbind_pf failed!\n");
        goto nfq_unopen; 
    }

    /* binding nfnetlink_queue as nf_queue handler for AF_INET */
    if (nfq_bind_pf(nfq->handle, AF_INET) < 0){
        DPRINTF("NFQUEUE nfq_bind_pf failed!\n");
        rc = -1;
        goto nfq_unopen;
    }

    /* binding this socket to queue */
    nfq->q_handle = nfq_create_queue(nfq->handle, gQueueNum, nfq->nfq_callback, NULL);
    if (!nfq->q_handle){
        DPRINTF("NFQUEUE nfq_create_queue failed!\n");
        rc = -1;
        goto nfq_unopen;
    }

    /* setting copy_packet mode */
    if (nfq_set_mode(nfq->q_handle, NFQNL_COPY_PACKET, 0xffff) < 0){
        DPRINTF("NFQUEUE nfq_set_mode failed!\n");
        rc = -1;
        goto nfq_q_destroy;
    }

    return rc;
    
nfq_q_destroy:
    nfq_destroy_queue(nfq->q_handle);
nfq_unopen:
    nfq_close(nfq->handle);
exit:
    return rc;
}

static void hotspot_arpd_nfqueue_handler(void *data)
{    
    nfqueue_data_t *nfqueue = (nfqueue_data_t *)data;
    struct nfnl_handle *nh;
    int fd, res;
    char buf[4096];

    if (hotspot_arpd_nfqueue_init(nfqueue) < 0){
        printf("NFQUEUE init failed!\n");
        return;
    }

    nh = nfq_nfnlh(nfqueue->handle);
    fd = nfnl_fd(nh);

    DPRINTF("NFQUEUE fd %d!\n", fd);

    while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
        DPRINTF("NFQUEUE fd %d received %d bytes!\n", fd, res);
        nfq_handle_packet(nfqueue->handle, buf, res);
    }    

    /* should never reach here */
    DPRINTF("NFQUEUE closing queue handle!\n");
    nfq_destroy_queue(nfqueue->q_handle);
    DPRINTF("NFQUEUE closing handle!\n");
    nfq_close(nfqueue->handle);
}

