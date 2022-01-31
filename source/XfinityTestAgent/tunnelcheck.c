/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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

/**************************************************************************

    module: tunnelcheck.c

    For Hotspot GRE tunnel health check binary

    -------------------------------------------------------------------

    description:

        source code for the GRE health check binary
    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        Akilesh Karthikeyan

    -------------------------------------------------------------------

    revision:

        01/28/2022    initial revision.

**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <linux/if_ether.h>
#include <features.h>
#include <linux/if_packet.h>

#include<netinet/ip.h>
#include<netinet/udp.h>
#include "secure_wrapper.h"
#include "cap.h"

#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312

#define IPV6_ADDR_GLOBAL        0x0000U

typedef struct dhcp_packet_struct{
        u_int8_t  op;                   /* operation code */
        u_int8_t  htype;                /* hardware address type */
        u_int8_t  hlen;                 /* hardware address length */
        u_int8_t  hops;                 /* number of hops */
        u_int32_t xid;                  /* transaction id */
        u_int16_t secs;                 /* time elapsed */
        u_int16_t flags;
        struct in_addr ciaddr;          /* IP address of this client */
        struct in_addr yiaddr;          /* IP address offered by the server */
        struct in_addr siaddr;          /* IP address of the DHCP server */
        struct in_addr giaddr;          /* IP address of DHCP relay */
        unsigned char chaddr [MAX_DHCP_CHADDR_LENGTH];      /* hardware address of the client */
        char sname [MAX_DHCP_SNAME_LENGTH];    /* name of the DHCP server */
        char file [MAX_DHCP_FILE_LENGTH];      /* boot file name */
        char options[MAX_DHCP_OPTIONS_LENGTH]; /* DHCP options */
}dhcp_packet;

typedef struct offer_info_struct{
    struct in_addr offered_addr;
    u_int32_t xid;
    struct in_addr server_addr;
}offer_info;

#define BOOTREQUEST     1
#define BOOTREPLY       2

#define ETHERNET_HARDWARE_ADDRESS            1
#define ETHERNET_HARDWARE_ADDRESS_LENGTH     6

#define DHCP_OPTION_MESSAGE_TYPE        53
#define DHCP_OPTION_BROADCAST_ADDRESS   28
#define DHCP_OPTION_REQUESTED_ADDRESS   50
#define DHCP_OPTION_SERVER_IDENTIFIER   54

#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNACK        6
#define DHCPRELEASE     7
#define DHCP_BROADCAST_FLAG 32768

#define DHCP_SERVER_PORT   67
#define DHCP_CLIENT_PORT   68

#define XFINITYTESTLOG "/rdklogs/logs/xfinityTestAgent.log"

unsigned int wanmac[6];
unsigned char client_hardware_address[MAX_DHCP_CHADDR_LENGTH]="";
u_int32_t packet_xid=0;

char network_interface_name[20]="brTest";
char vlan_id[10]="4091";
int dhcpoffer_timeout=5;
int size_g;
static cap_user appcaps;

int get_hardware_address(int,char *);
int send_dhcp_discover(int);
int send_dhcp_request(int, offer_info);
int send_dhcp_release(int, offer_info);
offer_info get_dhcp_offer(int);

int dhcp_msg_type(dhcp_packet *offer_packet);
uint32_t get_dhcp_server_identifier(dhcp_packet *offer_packet);
int create_dhcp_socket(void);
int create_raw_socket(int);
int close_dhcp_socket(int);
int send_dhcp_packet(void *,int,int,struct sockaddr_in *);
int receive_dhcp_packet(void *,int,int,int,struct sockaddr_in *);

char* timestamputc(char* );
void *checkglobalipv6(void *);
int parse_if_inet6(const char*);

void create_testinterfaces(void);
void delete_testinterfaces(void);
void print_usage(void);
void drop_root_privilege(void);

FILE* xfinitylogfp;

int main(int argc, char **argv){
    int dhcp_socket,raw_socket;
    int ifindex;
    char timestr[30];
    offer_info offinfo,ackinfo;
    pthread_t slaacthread;
    drop_root_privilege();

    if(argc < 2 || argc > 4){
      print_usage();
      return 0;
    }
    if(argc == 2)
        strncpy(network_interface_name,argv[1],sizeof(network_interface_name));

    if(argc >= 3)
        strncpy(vlan_id,argv[2],sizeof(vlan_id));

    xfinitylogfp = fopen(XFINITYTESTLOG,"a");
    if (xfinitylogfp == NULL) {
        return 0;
    }

    if(argc >= 3)
        create_testinterfaces();

    /* Create a separtae thread for performing SLAAC */
    pthread_create(&slaacthread, NULL, checkglobalipv6, NULL);

    /* create socket for performing DORA */
    dhcp_socket=create_dhcp_socket();

    /* get HW address and the ifindex for creating raw socket */
    ifindex = get_hardware_address(dhcp_socket,network_interface_name);

    raw_socket=create_raw_socket(ifindex);
    if(raw_socket == -1){
        fprintf(xfinitylogfp,"%s : Failed to create socket\n",timestamputc(timestr));
        fclose(xfinitylogfp);
        return 0;
    }
    if(argc == 4){
        if( 6 == sscanf(argv[3],"%x:%x:%x:%x:%x:%x",&wanmac[0],&wanmac[1],&wanmac[2],&wanmac[3],&wanmac[4],&wanmac[5])){
            int itr;
            for(itr=0; itr < ETHERNET_HARDWARE_ADDRESS_LENGTH; itr++)
                client_hardware_address[itr] = wanmac[itr];
        }
        else{
            fprintf(xfinitylogfp,"INVALID MAC. Proceeding with the Test interface's MAC");
        }
    }

    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv4_XfinityHealthCheck_dora_start\n",timestamputc(timestr));

    /* send the DISCOVER packet out and wait for OFFER packet */
    send_dhcp_discover(dhcp_socket);
    offinfo = get_dhcp_offer(raw_socket);

    if(offinfo.xid != 0){
        /* send the REQUEST packet out and wait for ACK packet */
        send_dhcp_request(dhcp_socket,offinfo);
        ackinfo = get_dhcp_offer(raw_socket);

        if(ackinfo.xid != 0){
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv4_XfinityHealthCheck_completed, address assigned: %s \n",timestamputc(timestr), inet_ntoa(ackinfo.offered_addr));
            send_dhcp_release(dhcp_socket,ackinfo);
        }
        else{
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : Server didnt send Ack. IPv4_XfinityHealthCheck_completed, address offered: %s \n",timestamputc(timestr), inet_ntoa(offinfo.offered_addr));
        }

    }
    else{
        fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv4_XfinityHealthCheck_dora_timeout No OFFER\n",timestamputc(timestr));
    }
    /* We can close both the sockets */
    close_dhcp_socket(dhcp_socket);
    close_dhcp_socket(raw_socket);
    pthread_join(slaacthread, NULL);

    if(argc>=3)
        delete_testinterfaces();
    fclose(xfinitylogfp);

    return 0;
}

void drop_root_privilege()
{
    appcaps.caps = NULL;
    appcaps.user_name = NULL;
    init_capability();
    drop_root_caps(&appcaps);
    update_process_caps(&appcaps);
    read_capability(&appcaps);
}


void print_usage(void){
    printf("\n\
 Usage:\n\
       1. To test DHCP in existing interface\n\
           xfinitytest [interface]\n\
       2. To test DHCP by creating new VLAN from gretap0\n\
           xfinitytest brTest [VLAN ID]\n\
       3. To set a custom MAC during the second usecase\n\
           xfinitytest brTest [VLAN ID] [MAC]\n\n");
}

void create_testinterfaces(void){
    char timestr[30];
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : Creating the test interfaces\n",timestamputc(timestr));
    v_secure_system("vconfig add gretap0 %s", vlan_id);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : VLAN %s created on gretap0\n",timestamputc(timestr), vlan_id);
    v_secure_system("brctl addbr %s", network_interface_name);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : Bridge %s created\n",timestamputc(timestr), network_interface_name);
    v_secure_system("brctl addif %s gretap0.%s", network_interface_name, vlan_id);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : gretap.%s is added to the bridge %s\n",timestamputc(timestr), vlan_id, network_interface_name);
    v_secure_system("echo 0 > /proc/sys/net/ipv6/conf/brTest/forwarding");
    v_secure_system("echo 1 > /proc/sys/net/ipv6/conf/brTest/autoconf");
    v_secure_system("ip link set %s up; ip link set gretap0.%s up", network_interface_name, vlan_id);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : The interfaces are ready for health check\n",timestamputc(timestr));
}

void delete_testinterfaces(void){
    char timestr[30];
    v_secure_system("ip link set gretap0.%s down; ip link set %s down", vlan_id, network_interface_name);
    v_secure_system("brctl delbr %s", network_interface_name);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : Bridge %s is deleted\n",timestamputc(timestr), network_interface_name);
    v_secure_system("vconfig rem gretap0.%s", vlan_id);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : VLAN %s is removed\n",timestamputc(timestr), vlan_id);
}

int parse_if_inet6(const char* ifname){
    FILE *inet6_fp;
    int scope, prefix;
    unsigned char ipv6_addr[16];
    char dname[IFNAMSIZ];
    char address[INET6_ADDRSTRLEN];
    char timestr[30];

    inet6_fp = fopen("/proc/net/if_inet6", "r");
    if (inet6_fp == NULL) {
        return 0;
    }

/* We are storing each line in if_inet6 into 19 variables */
    while (19 == fscanf(inet6_fp, " %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %*x %x %x %*x %s",
                        &ipv6_addr[0], &ipv6_addr[1], &ipv6_addr[2], &ipv6_addr[3], &ipv6_addr[4], &ipv6_addr[5], &ipv6_addr[6], &ipv6_addr[7],
                        &ipv6_addr[8], &ipv6_addr[9], &ipv6_addr[10], &ipv6_addr[11], &ipv6_addr[12], &ipv6_addr[13], &ipv6_addr[14],
                        &ipv6_addr[15], &prefix, &scope, dname))
    {

        if (strcmp(ifname, dname) != 0) {
         /* Search for the line with the details of test interface */
            continue;
        }

        if (inet_ntop(AF_INET6, ipv6_addr, address, sizeof(address)) == NULL) {
            continue;
        }

        if(scope == IPV6_ADDR_GLOBAL){
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv6_XfinityHealthCheck_slaac_completed, address assigned is %s\n",timestamputc(timestr),address);
            fclose(inet6_fp);
            return 1;
        }
    }

    fclose(inet6_fp);
    return 0;
}

void *checkglobalipv6(void *vargp){
    char timestr[30];
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv6_XfinityHealthCheck_slaac_start\n",timestamputc(timestr));
    time_t start_time;
    time_t current_time;
    time(&start_time);
    int global_ip_found;
    while(1){
        time(&current_time);
        if((current_time - start_time) >= 10){
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv6_XfinityHealthCheck_slaac_timeout\n",timestamputc(timestr));
            break;
        }

        global_ip_found = parse_if_inet6(network_interface_name);
        if(global_ip_found == 1)
            break;
        sleep(1);
    }
    return vargp;
}

char* timestamputc(char *buf){
    time_t gtime;
    struct tm brokentime;
    gtime=time(NULL);
    gmtime_r(&gtime, &brokentime);
    asctime_r(&brokentime, buf);
    buf[strlen(buf)-1] = '\0';
    return buf;
}

int get_hardware_address(int sock,char *interface_name){

    int ifindex;
    struct ifreq ifr;

    strncpy((char *)&ifr.ifr_name,interface_name,sizeof(ifr.ifr_name));
    /* get the hardware address of the test interface */
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
        fprintf(xfinitylogfp,"Could not get the hardware address of interface '%s'\n",interface_name);
        exit(-1);
    }
    memcpy(&client_hardware_address[0],&ifr.ifr_hwaddr.sa_data,6);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == 0) {
        ifindex = ifr.ifr_ifindex;
        return ifindex;
    }
    return -1;
}

/* Create a socket to send DHCP packets */
int create_dhcp_socket(void){
    struct sockaddr_in newsocket;
    struct ifreq interface;
    int sock;
    int flag=1;

    /* Listen on DHCP port for packets from any L3 address */
    memset(&newsocket,0,sizeof(newsocket));
    newsocket.sin_family=AF_INET;
    newsocket.sin_port=htons(DHCP_CLIENT_PORT);
    newsocket.sin_addr.s_addr = INADDR_ANY;
    memset(&newsocket.sin_zero,0,sizeof(newsocket.sin_zero));

    sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(sock<0){
         fprintf(xfinitylogfp,"Error: Socket creation failed\n");
         exit(-1);
    }

    flag=1;
    /* set the broadcast option to receive broadcast packets */
    if(setsockopt(sock,SOL_SOCKET,SO_BROADCAST,(char *)&flag,sizeof flag)<0){
        fprintf(xfinitylogfp,"Error: Could not set broadcast option\n");
        exit(-1);
    }

    if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char *)&flag,sizeof(flag))<0){
        fprintf(xfinitylogfp,"Error: Could not set reuse address option\n");
        exit(-1);
    }

    /* bind socket to interface */
    strncpy(interface.ifr_ifrn.ifrn_name,network_interface_name,IFNAMSIZ);
    if(setsockopt(sock,SOL_SOCKET,SO_BINDTODEVICE,(char *)&interface,sizeof(interface))<0){
        fprintf(xfinitylogfp,"Error: Could not bind the socket to interface %s\n",network_interface_name);
        exit(-1);
    }

        /* bind the socket */
    if(bind(sock,(struct sockaddr *)&newsocket,sizeof(newsocket))<0){
        fprintf(xfinitylogfp,"Error: bind failed \n");
        exit(-1);
    }

    return sock;
}

/* sends a DHCP packet */
int send_dhcp_packet(void *buf, int buf_size, int sock, struct sockaddr_in *destaddr){
    int ret;
    ret=sendto(sock,(char *)buf,buf_size,0,(struct sockaddr *)destaddr,sizeof(*destaddr));
    if(ret<0)
        return -1;
    return 0;
}

/* This functions send a DHCP discover packet */
int send_dhcp_discover(int sock){
    char timestr[30];
    dhcp_packet dhcp_discover_packet;
    struct sockaddr_in dest_sockaddr;

    memset(&dhcp_discover_packet,0,sizeof(dhcp_discover_packet));

    dhcp_discover_packet.op=BOOTREQUEST;
    dhcp_discover_packet.htype=ETHERNET_HARDWARE_ADDRESS;
    dhcp_discover_packet.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;
    dhcp_discover_packet.hops=0;
    /* create a random transaction ID */
    srand(time(NULL));
    packet_xid=random();
    dhcp_discover_packet.xid=htonl(packet_xid);
    dhcp_discover_packet.secs=0;
    /* Broadcast flag is set */
    dhcp_discover_packet.flags=htons(DHCP_BROADCAST_FLAG);
    memcpy(dhcp_discover_packet.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);
    /* Magic cookie */
    dhcp_discover_packet.options[0]='\x63';
    dhcp_discover_packet.options[1]='\x82';
    dhcp_discover_packet.options[2]='\x53';
    dhcp_discover_packet.options[3]='\x63';
    dhcp_discover_packet.options[4]=DHCP_OPTION_MESSAGE_TYPE;
    dhcp_discover_packet.options[5]='\x01';
    dhcp_discover_packet.options[6]=DHCPDISCOVER;
    dhcp_discover_packet.options[7]=255;

    /* The Discover packet must be broadcasted */
    dest_sockaddr.sin_family=AF_INET;
    dest_sockaddr.sin_port=htons(DHCP_SERVER_PORT);
    dest_sockaddr.sin_addr.s_addr=INADDR_BROADCAST;
    memset(&dest_sockaddr.sin_zero,0,sizeof(dest_sockaddr.sin_zero));
    send_dhcp_packet(&dhcp_discover_packet,sizeof(dhcp_discover_packet),sock,&dest_sockaddr);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : DISCOVER packet is sent\n",timestamputc(timestr));

    return 0;
}

/* sends a DHCPREQUEST broadcast message */
int send_dhcp_request(int sock, offer_info offinfo){
    dhcp_packet request_packet;
    char timestr[30];
    struct sockaddr_in dest_sockaddr;

    memset(&request_packet,0,sizeof(request_packet));

    request_packet.op=BOOTREQUEST;
    request_packet.htype=ETHERNET_HARDWARE_ADDRESS;
    request_packet.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;
    request_packet.hops=0;
    request_packet.xid=offinfo.xid;
    request_packet.secs=0;
    /* Broadcast flag is set */
    request_packet.flags=htons(DHCP_BROADCAST_FLAG);
    memcpy(request_packet.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);
    /* Magic cookie */
    request_packet.options[0]='\x63';
    request_packet.options[1]='\x82';
    request_packet.options[2]='\x53';
    request_packet.options[3]='\x63';
    /* DHCP message type */
    request_packet.options[4]=DHCP_OPTION_MESSAGE_TYPE;
    request_packet.options[5]='\x01';
    request_packet.options[6]=DHCPREQUEST;
    /* the IP address we are requesting */
    request_packet.options[7]=DHCP_OPTION_REQUESTED_ADDRESS;
    request_packet.options[8]='\x04';
    memcpy(&request_packet.options[9],&offinfo.offered_addr,sizeof(struct in_addr));

    if(offinfo.server_addr.s_addr != 0){
    /* the IP address of the server which sent the OFFER */
        request_packet.options[13]=DHCP_OPTION_SERVER_IDENTIFIER;
        request_packet.options[14]='\x04';
        memcpy(&request_packet.options[15],&offinfo.server_addr,sizeof(struct in_addr));

        /* End option */
        request_packet.options[19]=255;
    }
    else{
        request_packet.options[13]=255;
    }
    /* Broadcast the DHCPREQUEST packet */
    dest_sockaddr.sin_family=AF_INET;
    dest_sockaddr.sin_port=htons(DHCP_SERVER_PORT);
    dest_sockaddr.sin_addr.s_addr=INADDR_BROADCAST;
    memset(&dest_sockaddr.sin_zero,0,sizeof(dest_sockaddr.sin_zero));
    send_dhcp_packet(&request_packet,sizeof(request_packet),sock,&dest_sockaddr);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : REQUEST packet is sent\n",timestamputc(timestr));

    return 0;
}

/* sends a DHCPRELEASE message */
int send_dhcp_release(int sock, offer_info ackinfo){
    char timestr[30];
    dhcp_packet release_packet;
    struct sockaddr_in sockaddr_server;

    memset(&release_packet,0,sizeof(release_packet));
    release_packet.op=BOOTREQUEST;
    release_packet.htype=ETHERNET_HARDWARE_ADDRESS;
    release_packet.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;
    release_packet.hops=0;
    /* A random transaction ID is generated */
    srand(time(NULL));
    packet_xid=random();
    release_packet.xid=htonl(packet_xid);
    release_packet.secs=0;
    /* Broadcast flag is set */
    release_packet.flags=htons(DHCP_BROADCAST_FLAG);
    memcpy(release_packet.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);
    /* Magic cookie */
    release_packet.options[0]='\x63';
    release_packet.options[1]='\x82';
    release_packet.options[2]='\x53';
    release_packet.options[3]='\x63';
    /* DHCP message type */
    release_packet.options[4]=DHCP_OPTION_MESSAGE_TYPE;
    release_packet.options[5]='\x01';
    release_packet.options[6]=DHCPRELEASE;

    if(ackinfo.server_addr.s_addr != 0){
        /* the IP address of the server */
        release_packet.options[7]=DHCP_OPTION_SERVER_IDENTIFIER;
        release_packet.options[8]='\x04';
        memcpy(&release_packet.options[9],&ackinfo.server_addr,sizeof(struct in_addr));
        /* END option */
        release_packet.options[13]=255;
    }
    else{
        release_packet.options[7]=255;
    }
    /* send the DHCPRELEASE packet to server address */
    sockaddr_server.sin_family=AF_INET;
    sockaddr_server.sin_port=htons(DHCP_SERVER_PORT);
    sockaddr_server.sin_addr.s_addr=ackinfo.server_addr.s_addr;
    memset(&sockaddr_server.sin_zero,0,sizeof(sockaddr_server.sin_zero));
    send_dhcp_packet(&release_packet,sizeof(release_packet),sock,&sockaddr_server);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : RELEASE packet is sent\n",timestamputc(timestr));

    return 0;
}

/* Try to get DHCP OFFER or ACK packet */
offer_info get_dhcp_offer(int sock){
    dhcp_packet offer_packet;
    char *packetbuf;
    char timestr[30];
    struct sockaddr_in source;
    int result=0;
    int x;
    time_t start_time;
    time_t curr_time;
    struct iphdr *iph;
    int iphdrlen;
    offer_info offinfo;
    int dhcpmsg;
    time(&start_time);
    packetbuf = (char *)malloc(600);
    memset(&offinfo,0,sizeof(offinfo));
    /* receive till timeout */
    while(1){

        time(&curr_time);
        if((curr_time-start_time)>=dhcpoffer_timeout)
            break;

        memset(&source,0,sizeof(source));
        memset(&offer_packet,0,sizeof(offer_packet));
        result=0;
        result=receive_dhcp_packet(packetbuf,sizeof(offer_packet),sock,dhcpoffer_timeout,&source);

        if(result!=0){
         /* No packet received */
            continue;
        }

        if(size_g < 28){
         /* packet is too small.*/
            continue;
        }
        iph = (struct iphdr *)packetbuf;
        iphdrlen = iph->ihl*4;
        if(iph->protocol == IPPROTO_UDP){
            source.sin_addr.s_addr = iph->saddr;
            source.sin_port = (packetbuf[iphdrlen] << 8) + packetbuf[iphdrlen + 1];
        }
        else{
         /* NOT UDP packet. SKIPPING */
            continue;
        }
        if(source.sin_port != DHCP_SERVER_PORT){
         /* NOT a DHCP packet */
            continue;
        }
        memcpy(&offer_packet,packetbuf+8+iphdrlen,sizeof(offer_packet));

        /* check packet xid to see if its the same as the one we used in the discover packet */
        if(ntohl(offer_packet.xid)!=packet_xid){
            continue;
        }

        /* check hardware address */
        result=0;
        for(x=0;x<ETHERNET_HARDWARE_ADDRESS_LENGTH;x++){
            if(offer_packet.chaddr[x]!=client_hardware_address[x])
                result=-1;
        }
        if(result==-1){
         /* DHCP hardware address mismatch */
            continue;
        }
        dhcpmsg = dhcp_msg_type(&offer_packet);
        switch(dhcpmsg){
        case DHCPOFFER:
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : OFFER packet is received\n",timestamputc(timestr));
            offinfo.xid = offer_packet.xid;
            offinfo.offered_addr.s_addr = offer_packet.yiaddr.s_addr;
            offinfo.server_addr.s_addr = get_dhcp_server_identifier(&offer_packet);
            return offinfo;
        case DHCPACK:
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : ACK packet is received\n",timestamputc(timestr));
            offinfo.xid = offer_packet.xid;
            offinfo.offered_addr.s_addr = offer_packet.yiaddr.s_addr;
            offinfo.server_addr.s_addr = get_dhcp_server_identifier(&offer_packet);
            return offinfo;
        case DHCPNACK:
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv4_XfinityHealthCheck_dora_nak\n",timestamputc(timestr));

        default:
         /* Not ACK or OFFER packet */
            continue;
        }
    }

    return offinfo;
}

/* receives a DHCP packet */
int receive_dhcp_packet(void *buf, int buf_size, int sock, int timeout, struct sockaddr_in *address){
    struct timeval timev;
    fd_set readfds;
    int ret;
    socklen_t address_size;
    struct sockaddr_in pkt_source_address;

    timev.tv_sec=timeout;
    timev.tv_usec=0;
    FD_ZERO(&readfds);
    FD_SET(sock,&readfds);
    select(sock+1,&readfds,NULL,NULL,&timev);

    if(!FD_ISSET(sock,&readfds)){
        return -1;
    }
    else{
        memset(&pkt_source_address,0,sizeof(pkt_source_address));
        address_size=sizeof(pkt_source_address);
        ret=recvfrom(sock,(char *)buf,buf_size,0,(struct sockaddr *)&pkt_source_address,&address_size);
        size_g = ret;

        if(ret==-1){
            fprintf(xfinitylogfp,"Error during recvfrom, errno:(%d): %s\n",errno,strerror(errno));
            return -1;
        }
        else{
            memcpy(address,&pkt_source_address,sizeof(pkt_source_address));
            return 0;
        }
    }
    return 0;
 }

int create_raw_socket(int ifindex){
    int fd;
    struct sockaddr_ll sock;
    char buf[30];
    int errstr;

    if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
        errstr = strerror_r(errno,buf,30);
        fprintf(xfinitylogfp,"socket call failed %d: %s",errstr,buf);
        return -1;
    }

    sock.sll_family = AF_PACKET;
    sock.sll_protocol = htons(ETH_P_IP);
    sock.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
        errstr = strerror_r(errno,buf,30);
        fprintf(xfinitylogfp,"bind call failed: %s", buf);
        close(fd);
        return -1;
    }

    return fd;

}

/* closes the socket */
int close_dhcp_socket(int sock){
    close(sock);
    return 0;
}

/* Get DHCP option 53 */
int dhcp_msg_type(dhcp_packet *offer_packet)
{
    int itr1;
    int itr2;
    unsigned option_type;
    unsigned option_length;

    if(offer_packet==NULL)
    {
        return -1;
    }
    /* Go through all DHCP options present */
    for(itr1=4;itr1<MAX_DHCP_OPTIONS_LENGTH;){
        if((int)offer_packet->options[itr1]<=0)
        {
            break;
        }
        /* get option type and length */
        option_type=offer_packet->options[itr1++];
        option_length=offer_packet->options[itr1++];

        /* get option data */
        if(option_type==DHCP_OPTION_MESSAGE_TYPE)
        {
            return offer_packet->options[itr1];
        }

        /* skip the unnecessary data */
        else
        {
            for(itr2=0;itr2<(int)option_length;itr2++,itr1++);
        }
    }
    fprintf(xfinitylogfp,"Option 53 not found");
    return 0;
}

/* Get the DHCP option 54 */
uint32_t get_dhcp_server_identifier(dhcp_packet *offer_packet)
{
    int itr1;
    int itr2;
    unsigned option_type;
    unsigned option_length;
    struct in_addr server_ip;

    if(offer_packet==NULL)
    {
        return 0;
    }
    /* Go through all DHCP options present */
    for(itr1=4;itr1<MAX_DHCP_OPTIONS_LENGTH;){
        if((int)offer_packet->options[itr1]<=0)
        {
            break;
        }
        /* get option type and length */
        option_type=offer_packet->options[itr1++];
        option_length=offer_packet->options[itr1++];

        /* get option data */
        if(option_type==DHCP_OPTION_SERVER_IDENTIFIER)
        {
            memcpy(&server_ip, &offer_packet->options[itr1], sizeof(struct in_addr));
            return server_ip.s_addr;
        }
        /* skip the unnecessary data */
        else
        {
            for(itr2=0;itr2<(int)option_length;itr2++,itr1++);
        }
    }
    fprintf(xfinitylogfp,"Option 54 not found\n");
    return 0;
}

