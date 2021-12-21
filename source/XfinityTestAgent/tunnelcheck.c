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

/**** Common definitions ****/

#define STATE_OK          0
#define STATE_WARNING     1
#define STATE_CRITICAL    2
#define STATE_UNKNOWN     -1

#define OK                0
#define ERROR             -1

#define FALSE             0
#define TRUE              1


/**** DHCP definitions ****/

#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312

/**** IPV6 type ****/

#define IPV6_ADDR_GLOBAL        0x0000U
#define IPV6_ADDR_LOOPBACK      0x0010U
#define IPV6_ADDR_LINKLOCAL     0x0020U
#define IPV6_ADDR_SITELOCAL     0x0040U
#define IPV6_ADDR_COMPATv4      0x0080U

typedef struct dhcp_packet_struct{
        u_int8_t  op;                   /* packet type */
        u_int8_t  htype;                /* type of hardware address for this machine (Ethernet, etc) */
        u_int8_t  hlen;                 /* length of hardware address (of this machine) */
        u_int8_t  hops;                 /* hops */
        u_int32_t xid;                  /* random transaction id number - chosen by this machine */
        u_int16_t secs;                 /* seconds used in timing */
        u_int16_t flags;                /* flags */
        struct in_addr ciaddr;          /* IP address of this machine (if we already have one) */
        struct in_addr yiaddr;          /* IP address of this machine (offered by the DHCP server) */
        struct in_addr siaddr;          /* IP address of DHCP server */
        struct in_addr giaddr;          /* IP address of DHCP relay */
        unsigned char chaddr [MAX_DHCP_CHADDR_LENGTH];      /* hardware address of this machine */
        char sname [MAX_DHCP_SNAME_LENGTH];    /* name of DHCP server */
        char file [MAX_DHCP_FILE_LENGTH];      /* boot file name (used for diskless booting?) */
    char options[MAX_DHCP_OPTIONS_LENGTH];  /* options */
        }dhcp_packet;


typedef struct dhcp_offer_struct{
    struct in_addr server_address;   /* address of DHCP server that sent this offer */
    struct in_addr offered_address;  /* the IP address that was offered to us */
    u_int32_t lease_time;            /* lease time in seconds */
    u_int32_t renewal_time;          /* renewal time in seconds */
    u_int32_t rebinding_time;        /* rebinding time in seconds */
    struct dhcp_offer_struct *next;
        }dhcp_offer;

typedef struct offer_info_struct{
    struct in_addr offered_addr;
    u_int32_t xid;
    struct in_addr server_addr;
        }offer_info;

#define BOOTREQUEST     1
#define BOOTREPLY       2

#define DHCPDISCOVER    1
#define DHCPOFFER       2
#define DHCPREQUEST     3
#define DHCPDECLINE     4
#define DHCPACK         5
#define DHCPNACK        6
#define DHCPRELEASE     7

#define DHCP_OPTION_MESSAGE_TYPE        53
#define DHCP_OPTION_HOST_NAME           12
#define DHCP_OPTION_BROADCAST_ADDRESS   28
#define DHCP_OPTION_REQUESTED_ADDRESS   50
#define DHCP_OPTION_LEASE_TIME          51
#define DHCP_OPTION_RENEWAL_TIME        58
#define DHCP_OPTION_REBINDING_TIME      59
#define DHCP_OPTION_SERVER_IDENTIFIER   54

#define DHCP_INFINITE_TIME              0xFFFFFFFF

#define DHCP_BROADCAST_FLAG 32768

#define DHCP_SERVER_PORT   67
#define DHCP_CLIENT_PORT   68

#define ETHERNET_HARDWARE_ADDRESS            1     /* used in htype field of dhcp packet */
#define ETHERNET_HARDWARE_ADDRESS_LENGTH     6     /* length of Ethernet hardware addresses */

#define XFINITYTESTLOG "/rdklogs/logs/xfinityTestAgent.log"

unsigned int wanmac[6];
unsigned char client_hardware_address[MAX_DHCP_CHADDR_LENGTH]="";
u_int32_t packet_xid=0;
u_int32_t dhcp_lease_time=0;
u_int32_t dhcp_renewal_time=0;
u_int32_t dhcp_rebinding_time=0;

char network_interface_name[20]="brTest";
char vlan_id[10]="4091";
int dhcpoffer_timeout=5;
int size_g;
static cap_user appcaps;

dhcp_offer *dhcp_offer_list=NULL;

int valid_responses=0;     /* number of valid DHCPOFFERs we received */
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

void print_ip_header(char*, int);
void print_udp_packet(char*, int);
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

    pthread_create(&slaacthread, NULL, checkglobalipv6, NULL);

    /* create socket for DHCP communications */
    dhcp_socket=create_dhcp_socket();

    /* get hardware address of client machine */
    ifindex = get_hardware_address(dhcp_socket,network_interface_name);

    raw_socket=create_raw_socket(ifindex);

    if(argc == 4){
        if( 6 == sscanf(argv[3],"%x:%x:%x:%x:%x:%x",&wanmac[0],&wanmac[1],&wanmac[2],&wanmac[3],&wanmac[4],&wanmac[5])){
            int itr;
            for(itr=0; itr < ETHERNET_HARDWARE_ADDRESS_LENGTH; itr++)
                client_hardware_address[itr] = wanmac[itr];
        }
        else{
            printf("INVALID MAC. Proceeding with the Test interface's MAC");
        }
    }

    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv4_XfinityHealthCheck_dora_start\n",timestamputc(timestr));
    /* send DHCPDISCOVER packet */
    send_dhcp_discover(dhcp_socket);

    /* wait for a DHCPOFFER packet */
    offinfo = get_dhcp_offer(raw_socket);

    if(offinfo.xid != 0){

        /* send DHCPREQUEST packet */
        send_dhcp_request(dhcp_socket,offinfo);

        /* wait for a DHCPACK packet */
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
    /* close socket we created */
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
    FILE *inet6fp;
    int scope, prefix;
    unsigned char ipv6[16];
    char dname[IFNAMSIZ];
    char address[INET6_ADDRSTRLEN];
    char timestr[30];

    inet6fp = fopen("/proc/net/if_inet6", "r");
    if (inet6fp == NULL) {
        return 0;
    }

/* We are storing each line in if_inet6 into 19 variables */
    while (19 == fscanf(inet6fp, " %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %*x %x %x %*x %s",
                        &ipv6[0], &ipv6[1], &ipv6[2], &ipv6[3], &ipv6[4], &ipv6[5], &ipv6[6], &ipv6[7], &ipv6[8], &ipv6[9], &ipv6[10],
                        &ipv6[11], &ipv6[12], &ipv6[13], &ipv6[14], &ipv6[15], &prefix, &scope, dname))
    {

        if (strcmp(ifname, dname) != 0) {
            continue;
        }

        if (inet_ntop(AF_INET6, ipv6, address, sizeof(address)) == NULL) {
            continue;
        }

        if(scope == IPV6_ADDR_GLOBAL){
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv6_XfinityHealthCheck_slaac_completed, address assigned is %s\n",timestamputc(timestr),address);
            fclose(inet6fp);
            return 1;
        }
    }

    fclose(inet6fp);
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

/* determines hardware address on client machine */
int get_hardware_address(int sock,char *interface_name){

    int ifindex;
    struct ifreq ifr;

    strncpy((char *)&ifr.ifr_name,interface_name,sizeof(ifr.ifr_name));
    /* try and grab hardware address of requested interface */
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
        fprintf(xfinitylogfp,"Error: Could not get hardware address of interface '%s'\n",interface_name);
        exit(STATE_UNKNOWN);
    }
    memcpy(&client_hardware_address[0],&ifr.ifr_hwaddr.sa_data,6);
/*
    fprintf(xfinitylogfp,"Hardware address: ");
    for (i=0; i<6; ++i)
        fprintf(xfinitylogfp,"%2.2x", client_hardware_address[i]);
    fprintf(xfinitylogfp, "\n");
*/
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == 0) {
//      fprintf(xfinitylogfp,"adapter index %d\n", ifr.ifr_ifindex);
        ifindex = ifr.ifr_ifindex;
        return ifindex;
    }
    return OK;
}


/* sends a DHCPDISCOVER broadcast message in an attempt to find DHCP servers */
int send_dhcp_discover(int sock){
    char timestr[30];
    dhcp_packet discover_packet;
    struct sockaddr_in sockaddr_broadcast;

    /* clear the packet data structure */
    memset(&discover_packet,0,sizeof(discover_packet));


    /* boot request flag (backward compatible with BOOTP servers) */
    discover_packet.op=BOOTREQUEST;

    /* hardware address type */
    discover_packet.htype=ETHERNET_HARDWARE_ADDRESS;

    /* length of our hardware address */
    discover_packet.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;

    discover_packet.hops=0;

    /* transaction id is supposed to be random */
    srand(time(NULL));
    packet_xid=random();
    discover_packet.xid=htonl(packet_xid);
    discover_packet.secs=0;

    /* tell server it should broadcast its response */
    discover_packet.flags=htons(DHCP_BROADCAST_FLAG);

    /* our hardware address */
    memcpy(discover_packet.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);

    /* first four bytes of options field is magic cookie (as per RFC 2132) */
    discover_packet.options[0]='\x63';
    discover_packet.options[1]='\x82';
    discover_packet.options[2]='\x53';
    discover_packet.options[3]='\x63';

    /* DHCP message type is embedded in options field */
    discover_packet.options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
    discover_packet.options[5]='\x01';               /* DHCP message option length in bytes */
    discover_packet.options[6]=DHCPDISCOVER;
    discover_packet.options[7]=255;

    /* send the DHCPDISCOVER packet to broadcast address */
    sockaddr_broadcast.sin_family=AF_INET;
    sockaddr_broadcast.sin_port=htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr=INADDR_BROADCAST;
    memset(&sockaddr_broadcast.sin_zero,0,sizeof(sockaddr_broadcast.sin_zero));

    /* send the DHCPDISCOVER packet out */
    send_dhcp_packet(&discover_packet,sizeof(discover_packet),sock,&sockaddr_broadcast);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : DISCOVER packet is sent\n",timestamputc(timestr));

    return OK;
}

/* sends a DHCPREQUEST broadcast message */
int send_dhcp_request(int sock, offer_info offinfo){
    dhcp_packet request_packet;
    char timestr[30];
    struct sockaddr_in sockaddr_broadcast;

    /* clear the packet data structure */
    memset(&request_packet,0,sizeof(request_packet));

    /* boot request flag (backward compatible with BOOTP servers) */
    request_packet.op=BOOTREQUEST;

    /* hardware address type */
    request_packet.htype=ETHERNET_HARDWARE_ADDRESS;

    /* length of our hardware address */
    request_packet.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;

    request_packet.hops=0;

    request_packet.xid=offinfo.xid;

    request_packet.secs=0;

    /* tell server it should broadcast its response */
    request_packet.flags=htons(DHCP_BROADCAST_FLAG);

    /* our hardware address */
    memcpy(request_packet.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);

    /* first four bytes of options field is magic cookie (as per RFC 2132) */
    request_packet.options[0]='\x63';
    request_packet.options[1]='\x82';
    request_packet.options[2]='\x53';
    request_packet.options[3]='\x63';

    /* DHCP message type is embedded in options field */
    request_packet.options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
    request_packet.options[5]='\x01';               /* DHCP message option length in bytes */
    request_packet.options[6]=DHCPREQUEST;

    /* the IP address we're requesting */
    request_packet.options[7]=DHCP_OPTION_REQUESTED_ADDRESS;
    request_packet.options[8]='\x04';
    memcpy(&request_packet.options[9],&offinfo.offered_addr,sizeof(struct in_addr));

    if(offinfo.server_addr.s_addr != 0){
    /* the IP address of the server */
        request_packet.options[13]=DHCP_OPTION_SERVER_IDENTIFIER;
        request_packet.options[14]='\x04';
        memcpy(&request_packet.options[15],&offinfo.server_addr,sizeof(struct in_addr));

        /* End option */
        request_packet.options[19]=255;
    }
    else{
        request_packet.options[13]=255;
    }
    /* send the DHCPREQUEST packet to broadcast address */
    sockaddr_broadcast.sin_family=AF_INET;
    sockaddr_broadcast.sin_port=htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr=INADDR_BROADCAST;
    memset(&sockaddr_broadcast.sin_zero,0,sizeof(sockaddr_broadcast.sin_zero));

    /* send the DHCPREQUEST packet out */
    send_dhcp_packet(&request_packet,sizeof(request_packet),sock,&sockaddr_broadcast);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : REQUEST packet is sent\n",timestamputc(timestr));

    return OK;
}

/* sends a DHCPRELEASE broadcast message in an attempt to find DHCP servers */
int send_dhcp_release(int sock, offer_info ackinfo){
    char timestr[30];
    dhcp_packet release_packet;
    struct sockaddr_in sockaddr_server;

    /* clear the packet data structure */
    memset(&release_packet,0,sizeof(release_packet));


    /* boot request flag (backward compatible with BOOTP servers) */
    release_packet.op=BOOTREQUEST;

    /* hardware address type */
    release_packet.htype=ETHERNET_HARDWARE_ADDRESS;

    /* length of our hardware address */
    release_packet.hlen=ETHERNET_HARDWARE_ADDRESS_LENGTH;

    release_packet.hops=0;

    /* transaction id is supposed to be random */
    srand(time(NULL));
    packet_xid=random();
    release_packet.xid=htonl(packet_xid);
    release_packet.secs=0;

    /* tell server it should broadcast its response */
    release_packet.flags=htons(DHCP_BROADCAST_FLAG);

    /* our hardware address */
    memcpy(release_packet.chaddr,client_hardware_address,ETHERNET_HARDWARE_ADDRESS_LENGTH);

    /* first four bytes of options field is magic cookie (as per RFC 2132) */
    release_packet.options[0]='\x63';
    release_packet.options[1]='\x82';
    release_packet.options[2]='\x53';
    release_packet.options[3]='\x63';

    /* DHCP message type is embedded in options field */
    release_packet.options[4]=DHCP_OPTION_MESSAGE_TYPE;    /* DHCP message type option identifier */
    release_packet.options[5]='\x01';               /* DHCP message option length in bytes */
    release_packet.options[6]=DHCPRELEASE;

    if(ackinfo.server_addr.s_addr != 0){
        /* the IP address of the server */
        release_packet.options[7]=DHCP_OPTION_SERVER_IDENTIFIER;
        release_packet.options[8]='\x04';
        memcpy(&release_packet.options[9],&ackinfo.server_addr,sizeof(struct in_addr));

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

    /* send the RELEASE packet out */
    send_dhcp_packet(&release_packet,sizeof(release_packet),sock,&sockaddr_server);
    fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : RELEASE packet is sent\n",timestamputc(timestr));

    return OK;
}

/* waits for a DHCPOFFER message from one or more DHCP servers */
offer_info get_dhcp_offer(int sock){
    dhcp_packet offer_packet;
    char *packetbuf;
    char timestr[30];
    struct sockaddr_in source;
    int result=OK;
    int responses=0;
    int x;
    time_t start_time;
    time_t current_time;
    struct iphdr *iph;
    int iphdrlen;
    offer_info offinfo;
    int dhcpmsg;
    time(&start_time);
    packetbuf = (char *)malloc(600);
    memset(&offinfo,0,sizeof(offinfo));
    /* receive as many responses as we can */
    for(responses=0,valid_responses=0;;){

        time(&current_time);
        if((current_time-start_time)>=dhcpoffer_timeout)
            break;

        memset(&source,0,sizeof(source));
        memset(&offer_packet,0,sizeof(offer_packet));

        result=OK;
        result=receive_dhcp_packet(packetbuf,sizeof(offer_packet),sock,dhcpoffer_timeout,&source);

        if(result!=OK){
//            fprintf(xfinitylogfp,"No packet received\n");
            continue;
        }
        else{
//            fprintf(xfinitylogfp,"Received a packet\n");
            responses++;
        }

        if(size_g < 28){
//            fprintf(xfinitylogfp,"packet is too small. size: %d\n",size_g);
            continue;
        }
        // print_ip_header(packetbuf,size_g);
        iph = (struct iphdr *)packetbuf;
        iphdrlen = iph->ihl*4;
        if(iph->protocol == IPPROTO_UDP){
         // print_udp_packet(packetbuf,size_g);
            source.sin_addr.s_addr = iph->saddr;
            source.sin_port = (packetbuf[iphdrlen] << 8) + packetbuf[iphdrlen + 1];
//            fprintf(xfinitylogfp,"packet is from %s:%d  \n",inet_ntoa(source.sin_addr),source.sin_port);
        }
        else{
//            fprintf(xfinitylogfp,"NOT UDP packet. SKIPPING\n");
            continue;
        }
        if(source.sin_port != DHCP_SERVER_PORT){
//            fprintf(xfinitylogfp,"NOT a DHCP packet");
            continue;
        }
        memcpy(&offer_packet,packetbuf+8+iphdrlen,sizeof(offer_packet));
//        fprintf(xfinitylogfp,"DHCP packet from IP address %s\n",inet_ntoa(source.sin_addr));
//        fprintf(xfinitylogfp,"DHCP packet XID: %lu (0x%X)\n",(unsigned long) ntohl(offer_packet.xid),ntohl(offer_packet.xid));


        /* check packet xid to see if its the same as the one we used in the discover packet */
        if(ntohl(offer_packet.xid)!=packet_xid){
//            fprintf(xfinitylogfp,"DHCP packet XID (%lu) did not match DHCPDISCOVER XID (%lu) - ignoring packet\n",(unsigned long) ntohl(offer_packet.xid),(unsigned long) packet_xid);
            continue;
        }

        /* check hardware address */
        result=OK;
//        fprintf(xfinitylogfp,"DHCP packet chaddr: ");

        for(x=0;x<ETHERNET_HARDWARE_ADDRESS_LENGTH;x++){
//            fprintf(xfinitylogfp,"%02X",(unsigned char)offer_packet.chaddr[x]);

            if(offer_packet.chaddr[x]!=client_hardware_address[x])
                result=ERROR;
        }
//        fprintf(xfinitylogfp,"\n");

        if(result==ERROR){
//            fprintf(xfinitylogfp,"DHCP hardware address did not match our own - ignoring packet\n");
            continue;
        }
        dhcpmsg = dhcp_msg_type(&offer_packet);
        switch(dhcpmsg){
        case DHCPOFFER:
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : OFFER packet is received\n",timestamputc(timestr));
            offinfo.xid = offer_packet.xid;
            offinfo.offered_addr.s_addr = offer_packet.yiaddr.s_addr;
            offinfo.server_addr.s_addr = get_dhcp_server_identifier(&offer_packet);
            valid_responses++;
            return offinfo;
        case DHCPACK:
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : ACK packet is received\n",timestamputc(timestr));
            offinfo.xid = offer_packet.xid;
            offinfo.offered_addr.s_addr = offer_packet.yiaddr.s_addr;
            offinfo.server_addr.s_addr = get_dhcp_server_identifier(&offer_packet);
            valid_responses++;
            return offinfo;
        case DHCPNACK:
            fprintf(xfinitylogfp,"%s : HOTSPOT_HEALTHCHECK : IPv4_XfinityHealthCheck_dora_nak\n",timestamputc(timestr));

        default:
//            fprintf(xfinitylogfp,"Not ACK or OFFER packet msgtype: %d",dhcpmsg);
            continue;
        }
    }

    return offinfo;
}


/* sends a DHCP packet */
int send_dhcp_packet(void *buffer, int buffer_size, int sock, struct sockaddr_in *dest){
    int result;

    result=sendto(sock,(char *)buffer,buffer_size,0,(struct sockaddr *)dest,sizeof(*dest));
    if(result<0)
        return ERROR;

    return OK;
}

/* receives a DHCP packet */
int receive_dhcp_packet(void *buffer, int buffer_size, int sock, int timeout, struct sockaddr_in *address){
    struct timeval tv;
    fd_set readfds;
    int recv_result;
    socklen_t address_size;
    struct sockaddr_in source_address;

    /* wait for data to arrive (up time timeout) */
    tv.tv_sec=timeout;
    tv.tv_usec=0;
    FD_ZERO(&readfds);
    FD_SET(sock,&readfds);
    select(sock+1,&readfds,NULL,NULL,&tv);

    /* make sure some data has arrived */
    if(!FD_ISSET(sock,&readfds)){
        return ERROR;
    }
    else{
        memset(&source_address,0,sizeof(source_address));
        address_size=sizeof(source_address);
        recv_result=recvfrom(sock,(char *)buffer,buffer_size,0,(struct sockaddr *)&source_address,&address_size);
        size_g = recv_result;

        if(recv_result==-1){
            fprintf(xfinitylogfp,"recvfrom() failed, ");
            fprintf(xfinitylogfp,"errno: (%d) -> %s\n",errno,strerror(errno));
            return ERROR;
        }
        else{
//            fprintf(xfinitylogfp,"length of received packet: %d\n",recv_result);
            memcpy(address,&source_address,sizeof(source_address));
            return OK;
        }
    }
    return OK;
 }


/* creates a socket for DHCP communication */
int create_dhcp_socket(void){
    struct sockaddr_in myname;
    struct ifreq interface;
    int sock;
    int flag=1;

        /* Set up the address we're going to bind to. */
    memset(&myname,0,sizeof(myname));
    myname.sin_family=AF_INET;
    myname.sin_port=htons(DHCP_CLIENT_PORT);
    myname.sin_addr.s_addr = INADDR_ANY;             /* listen on any address */
    memset(&myname.sin_zero,0,sizeof(myname.sin_zero));

        /* create a socket for DHCP communications */
    sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(sock<0){
         fprintf(xfinitylogfp,"Error: Could not create socket!\n");
         exit(STATE_UNKNOWN);
    }

    /* set the reuse address flag so we don't get errors when restarting */
    flag=1;
    if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char *)&flag,sizeof(flag))<0){
        fprintf(xfinitylogfp,"Error: Could not set reuse address option on DHCP socket!\n");
        exit(STATE_UNKNOWN);
    }

    /* set the broadcast option - we need this to listen to DHCP broadcast messages */
    if(setsockopt(sock,SOL_SOCKET,SO_BROADCAST,(char *)&flag,sizeof flag)<0){
        fprintf(xfinitylogfp,"Error: Could not set broadcast option on DHCP socket!\n");
        exit(STATE_UNKNOWN);
    }


    /* bind socket to interface */
    strncpy(interface.ifr_ifrn.ifrn_name,network_interface_name,IFNAMSIZ);
    if(setsockopt(sock,SOL_SOCKET,SO_BINDTODEVICE,(char *)&interface,sizeof(interface))<0){
        fprintf(xfinitylogfp,"Error: Could not bind socket to interface %s.  Check your privileges...\n",network_interface_name);
        exit(STATE_UNKNOWN);
    }

        /* bind the socket */
    if(bind(sock,(struct sockaddr *)&myname,sizeof(myname))<0){
        fprintf(xfinitylogfp,"Error: Could not bind to DHCP socket (port %d)!  Check your privileges...\n",DHCP_CLIENT_PORT);
        exit(STATE_UNKNOWN);
    }

    return sock;
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
/* closes DHCP socket */
int close_dhcp_socket(int sock){

    close(sock);

    return OK;
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
        return ERROR;
    }
    /* process all DHCP options present in the packet */
    for(itr1=4;itr1<MAX_DHCP_OPTIONS_LENGTH;){
        /* end of options */
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

        /* skip option data we're ignoring */
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
    /* process all DHCP options present in the packet */
    for(itr1=4;itr1<MAX_DHCP_OPTIONS_LENGTH;){

        /* end of options */
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
        /* skip option data we're ignoring */
        else
        {
            for(itr2=0;itr2<(int)option_length;itr2++,itr1++);
        }
    }
    fprintf(xfinitylogfp,"Option 54 not found\n");
    return 0;
}

void print_ip_header(char* Buffer, int Size)
{
    struct sockaddr_in source,dest;
    struct iphdr *iph;
    if(Size < (int)sizeof(struct iphdr))
        return;
    iph = (struct iphdr *)Buffer;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    fprintf(xfinitylogfp,"\n");
    fprintf(xfinitylogfp,"IP Header\n");
    fprintf(xfinitylogfp,"   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(xfinitylogfp,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(xfinitylogfp,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(xfinitylogfp,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(xfinitylogfp,"   |-Identification    : %d\n",ntohs(iph->id));
    //ffprintf(xfinitylogfp,logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //ffprintf(xfinitylogfp,logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //ffprintf(xfinitylogfp,logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(xfinitylogfp,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(xfinitylogfp,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(xfinitylogfp,"   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(xfinitylogfp,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(xfinitylogfp,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_udp_packet(char *Buffer , int Size)
{

    unsigned short iphdrlen;
    struct iphdr *iph;
    struct udphdr *udph;
    iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    if(Size < iphdrlen + 8)
        return;
    udph = (struct udphdr*)(Buffer + iphdrlen);
    fprintf(xfinitylogfp,"\n\n***********************UDP Packet*************************\n");

    fprintf(xfinitylogfp,"\nUDP Header\n");
    fprintf(xfinitylogfp,"   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(xfinitylogfp,"   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(xfinitylogfp,"   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(xfinitylogfp,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    fprintf(xfinitylogfp,"\n");
    fprintf(xfinitylogfp,"\n###########################################################\n");
}
