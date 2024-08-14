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
#include <netinet/icmp6.h>
#include "ssp_global.h"
#include "ansc_platform.h"
#include "libHotspot.h"
#include "libHotspotApi.h"
#ifdef WAN_FAILOVER_SUPPORTED
#include <rbus.h>
#endif

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
#include "safec_lib_common.h"
#include "secure_wrapper.h"
#include <telemetry_busmessage_sender.h>

#ifdef UNIT_TEST_DOCKER_SUPPORT
#define STATIC
#else
#define STATIC static
#endif

#define PACKETSIZE  64
#define IPv4_HEADER_OFFSET 20
#define ICMP_ECHO_STRING "ICMP test string"
#define kDefault_KeepAliveInterval      60 
#define kDefault_KeepAliveIntervalFailure      300 
#define kDefault_KeepAliveThreshold     5
#define kDefault_KeepAlivePolicy        2
#define kDefault_KeepAliveCount         1

#define kDefault_PrimaryTunnelEP        "172.30.0.1" 
#define kDefault_SecondaryTunnelEP      "172.40.0.1" 
//#define kDefault_SecondaryMaxTime       300 // max. time allowed on secondary EP in secs.
#define kDefault_SecondaryMaxTime       43200  //zqiu: according to XWG-CP-15, default time is 12 hours
#define kDefault_DummyEP        "dummy_EP"
#define HOTSPOTFD_STATS_PATH    "/var/tmp/hotspotfd.log"
#define HOTSPOT_ENABLED_SSIDS   "/tmp/.enabled_hotspot_ssids"

#define kMax_InterfaceLength            20
#define DEBUG_INI_NAME "/etc/debug.ini"

#ifdef WAN_FAILOVER_SUPPORTED
#define PSM_WAN_INT "dmsb.Mesh.WAN.Interface.Name"
#endif

extern  ANSC_HANDLE             bus_handle;
STATIC char ssid_reset_mask = 0x0;

#if defined (_BWG_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
#define SSIDVAL 5
#define PARAM_COUNT_ 5
#elif defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
#define SSIDVAL 6
#define PARAM_COUNT_ 6
#else
#define PARAM_COUNT_ 4
#define SSIDVAL 4
#endif
#ifdef WIFI_HAL_VERSION_3
#define RADIOVAL 2
#endif
struct packet {
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

unsigned int gKeepAliveInterval     = kDefault_KeepAliveInterval;
unsigned int gKeepAliveIntervalFailure     = kDefault_KeepAliveIntervalFailure;
unsigned int gKeepAliveThreshold    = kDefault_KeepAliveThreshold;

STATIC bool gPrimaryIsActive = true;     // start with primary EP, assume active
STATIC bool gSecondaryIsActive = false;

STATIC unsigned int gKeepAlivesSent = 0;     // aggregate of primary & secondary
STATIC unsigned int gKeepAlivesReceived = 0; // aggregate of primary & secondary
STATIC unsigned int gSecondaryMaxTime = kDefault_SecondaryMaxTime;
STATIC unsigned int gSwitchedBackToPrimary = 0;

STATIC bool gPrimaryIsAlive = false;
STATIC bool gSecondaryIsAlive = false;

STATIC char gpPrimaryEP[kMax_IPAddressLength];
STATIC char gpSecondaryEP[kMax_IPAddressLength];
STATIC unsigned int gKeepAlivePolicy = kDefault_KeepAlivePolicy;
STATIC bool gKeepAliveEnable = false;
STATIC bool gKeepAliveLogEnable = true;
STATIC unsigned int gKeepAliveCount = kDefault_KeepAliveCount;
STATIC int prevPingStatus = STATUS_FAILURE;

#ifdef __HAVE_SYSEVENT__
STATIC int sysevent_fd;
STATIC token_t sysevent_token;
STATIC int sysevent_fd_gs;
STATIC token_t sysevent_token_gs;
STATIC pthread_t sysevent_tid;
#endif

STATIC int gShm_fd;
STATIC hotspotfd_statistics_s * gpStats;
STATIC int gShm_snoop_fd;
snooper_statistics_s * gpSnoop_Stats;
STATIC int  gKeepAliveChecksumCnt = 0;
STATIC int  gKeepAliveSequenceCnt = 0;
STATIC int  gDeadInterval = 5 * kDefault_KeepAliveInterval;
STATIC char gKeepAliveInterface[kMax_InterfaceLength];

STATIC bool gbFirstPrimarySignal = true;
STATIC bool gbFirstSecondarySignal = true;

STATIC pthread_mutex_t keep_alive_mutex = PTHREAD_MUTEX_INITIALIZER;

STATIC bool gPriStateIsDown = false;
STATIC bool gSecStateIsDown = false;
STATIC bool gBothDnFirstSignal = true;

STATIC bool gTunnelIsUp = false;
STATIC bool gVapIsUp = true;
STATIC bool wanFailover = false; //Always false as long as wan failover does'nt happen

STATIC char old_wan_ipv4[kMax_IPAddressLength];
STATIC char old_wan_ipv6[kMax_IPAddressLength];

#ifdef WAN_FAILOVER_SUPPORTED
extern int hotspot_wan_failover(bool isRemoteWANEnabled);
extern int PsmGet(const char *param, char *value, int size);
STATIC pthread_t rbus_tid;
rbusHandle_t handle;
#endif

STATIC pthread_t dhcp_snooper_tid;

int gSnoopNumberOfClients = 0; //shared variable across hotspotfd and dhcp_snooperd

bool gSnoopEnable = true;
bool gSnoopDebugEnabled = false;
bool gSnoopLogEnabled = true;
bool gSnoopCircuitEnabled = true;
bool gSnoopRemoteEnabled = true;
int gSnoopFirstQueueNumber = kSnoop_DefaultQueue;
int gSnoopNumberOfQueues = kSnoop_DefaultNumberOfQueues;

bool gWebConfTun = true;

int gSnoopMaxNumberOfClients = kSnoop_DefaultMaxNumberOfClients;
char gSnoopCircuitIDList[kSnoop_MaxCircuitIDs][kSnoop_MaxCircuitLen];
char gSnoopSyseventCircuitIDs[kSnoop_MaxCircuitIDs][kSnooper_circuit_id_len] = { 
    kSnooper_circuit_id0,
    kSnooper_circuit_id1,
    kSnooper_circuit_id2,
    kSnooper_circuit_id3,
    kSnooper_circuit_id4,
    kSnooper_circuit_id5,
    ksnooper_circuit_id6
};

char gSnoopSSIDList[kSnoop_MaxCircuitIDs][kSnoop_MaxCircuitLen];
int  gSnoopSSIDListInt[kSnoop_MaxCircuitIDs];
char gSnoopSyseventSSIDs[kSnoop_MaxCircuitIDs][kSnooper_circuit_id_len] = { 
    kSnooper_ssid_index0,
    kSnooper_ssid_index1,
    kSnooper_ssid_index2,
    kSnooper_ssid_index3,
    kSnooper_ssid_index4,
    kSnooper_ssid_index5,
    ksnooper_ssid_index6
};

typedef struct
{
    char         *msgStr; 
    HotspotfdType mType;       
}Hotspotfd_MsgItem;

Hotspotfd_MsgItem hotspotfdMsgArr[] = {
    {"hotspotfd-primary",                             HOTSPOTFD_PRIMARY},
    {"hotspotfd-secondary",                           HOTSPOTFD_SECONDARY},
    {"hotspotfd-keep-alive",                          HOTSPOTFD_KEEPALIVE},
    {"hotspotfd-threshold",                           HOTSPOTFD_THRESHOLD},
    {"hotspotfd-max-secondary",                       HOTSPOTFD_MAXSECONDARY},
    {"hotspotfd-policy",                              HOTSPOTFD_POLICY},
    {"hotspotfd-enable",                              HOTSPOTFD_ENABLE},
    {"hotspotfd-count",                               HOTSPOTFD_COUNT},
    {"hotspotfd-log-enable",                          HOTSPOTFD_LOGENABLE},
    {"hotspotfd-dead-interval",                       HOTSPOTFD_DEADINTERVAL},
    {"wan-status",                                    HOTSPOTFD_WANSTATUS},
    {"snooper-enable",                                SNOOPER_ENABLE},
    {"snooper-debug-enable",                          SNOOPER_DEBUGENABLE},
    {"snooper-log-enable",                            SNOOPER_LOGENABLE},
    {"snooper-circuit-enable",                        SNOOPER_CIRCUITENABLE},
    {"snooper-remote-enable",                         SNOOPER_REMOTEENABLE},
    {"snooper-max-clients",                           SNOOPER_MAXCLIENTS},
    {"current_wan_ipaddr",                            HOTSPOTFD_CURRENT_WAN_IPADDR_V4},
    {"wan6_ipaddr",                                   HOTSPOTFD_CURRENT_WAN_IPADDR_V6}
#ifdef WAN_FAILOVER_SUPPORTED
    ,
    {"current_wan_ifname",                            CURRENT_WAN_IFNAME},
    {"test_current_wan_ifname",                       TEST_CURRENT_WAN_IFNAME}
#endif
    };

HotspotfdType Get_HotspotfdType(char * name)
{

    errno_t rc       = -1;
    int     ind      = -1;
    int     i      = 0;
    int     strlength      = 0;

    if( (!name) || (name[0] == '\0') )
       return HOTSPOTFD_ERROR;

    strlength = strlen( name );

    for (i = 0; i < HOTSPOTFD_ERROR; i++)
    {
       rc = strcmp_s( name, strlength, hotspotfdMsgArr[i].msgStr, &ind);
       ERR_CHK(rc);

       if((ind==0) && (rc == EOK))
       {
          msg_debug("Received %s sysevent\n", hotspotfdMsgArr[i].msgStr);
          return( hotspotfdMsgArr[i].mType );
       }
    }

    return HOTSPOTFD_ERROR;
}

STATIC bool set_tunnelstatus(char* status) {

    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t  *param_val = NULL;
    char  component[256]  = "eRT.com.cisco.spvtg.ccsp.pam";
    char dstPath[64]="/com/cisco/spvtg/ccsp/pam";
    const char tunparam[]="Device.X_COMCAST-COM_GRE.Tunnel.1.TunnelStatus";
    char* faultParam      = NULL;
    int   ret             = 0;

    param_val  = (parameterValStruct_t*)malloc(sizeof(parameterValStruct_t));
    if (NULL == param_val)
    {
        CcspTraceError(("Memory allocation failed in hotspot \n"));
        return FALSE;
    }

    param_val->parameterName = (char*)tunparam;
    param_val->parameterValue=AnscCloneString(status);
    CcspTraceInfo(("Setting tunnel status to %s\n", status));
    param_val->type = ccsp_string;

    ret = CcspBaseIf_setParameterValues(
            bus_handle,
            component,
            dstPath,
            0,
            0,
            param_val,
            1,
            TRUE,
            &faultParam
            );

    if( ( ret != CCSP_SUCCESS ) && ( faultParam!=NULL )) {
            CcspTraceError(("TunnelStatus set bus failed\n"));
            bus_info->freefunc( faultParam );
            if(param_val)
            {
                 free(param_val);
                 param_val = NULL;
            }
            return FALSE;
    }
    if(param_val)
    {
        free(param_val);
        param_val = NULL;
    }
    return TRUE;
}

STATIC void notify_tunnel_status(char *status)
{
    int ret;
    if(set_tunnelstatus(status))
    {
        CcspTraceInfo(("TunnelStatus set to %s in TR181\n", status));
    }
    else
    {
        CcspTraceError(("Error setting TunnelStatus in TR181 Data Model\n"));
    }
    ret = CcspBaseIf_SendSignal_WithData(bus_handle,
                                         "Device.X_COMCAST-COM_GRE.Tunnel.1.TunnelStatus", status);
    if ( ret != CCSP_SUCCESS )
    {
        CcspTraceError(("%s : TunnelStatus send rbus data failed,  ret value is %d\n",
                                                                               __FUNCTION__ ,ret));
    }
    if(strcmp("Down",status) == 0)
    {
        gVapIsUp = false;
    }
    else if(strcmp("Up",status) == 0)
    {
        gVapIsUp = true;
    }
}

STATIC bool set_validatessid() {

#if defined(RDK_ONEWIFI)
#if defined (_BWG_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
    const char *hotspot_ssids[]={"5","6","9","10","16"};
#elif defined (_XB8_PRODUCT_REQ_)
    const char *hotspot_ssids[]={"5","6","9","10","19","21"};
#else
    const char *hotspot_ssids[]={"5","6","9","10"};
#endif
    int i = 0;
    char enabled_ssids[32] = {0};
    FILE *ssid_fp = NULL;
    for (i = 0; i < SSIDVAL; i++)
    {
       if(ssid_reset_mask & (1<<i))
       {
           strcat_s(enabled_ssids, sizeof(enabled_ssids), hotspot_ssids[i]);
           CcspTraceInfo(("SSID %s should be enabled\n", hotspot_ssids[i]));
           strcat_s(enabled_ssids, sizeof(enabled_ssids), " ");
       }
       else
       {
           CcspTraceInfo(("SSID %s should be disabled\n", hotspot_ssids[i]));
       }
    }
    ssid_fp = fopen(HOTSPOT_ENABLED_SSIDS, "w");
    if(ssid_fp == NULL)
    {
        CcspTraceError(("Unable to open %s\n", HOTSPOT_ENABLED_SSIDS));
        return FALSE;
    }
    fprintf(ssid_fp, "%s", enabled_ssids);
    fclose(ssid_fp);
    ssid_fp = NULL;
    ssid_reset_mask = 0;
    return TRUE;
#else
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t  *param_val = NULL;
    char  component[256]  = "eRT.com.cisco.spvtg.ccsp.wifi";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";
    const char ap5[]="Device.WiFi.SSID.5.Enable";
    const char ap6[]="Device.WiFi.SSID.6.Enable";
    const char ap9[]="Device.WiFi.SSID.9.Enable";
    const char ap10[]="Device.WiFi.SSID.10.Enable";
#if defined (_BWG_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
    const char ap16[]="Device.WiFi.SSID.16.Enable";
    const char *paramNames[]={ap5,ap6,ap9,ap10,ap16};
#elif defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
    const char ap19[]="Device.WiFi.SSID.19.Enable";
    const char ap21[]="Device.WiFi.SSID.21.Enable";
    const char *paramNames[]={ap5,ap6,ap9,ap10,ap19,ap21};
#else
    const char *paramNames[]={ap5,ap6,ap9,ap10};
#endif
    char* faultParam      = NULL;
    int   ret             = 0; 
    int i = 0;
#ifdef WIFI_HAL_VERSION_3
    const char radio1[]="Device.WiFi.Radio.1.X_CISCO_COM_ApplySetting";
    const char radio2[]="Device.WiFi.Radio.2.X_CISCO_COM_ApplySetting";
    const char *paramNamesRadio[]={radio1,radio2};
#endif
  
    param_val  = (parameterValStruct_t*)malloc(sizeof(parameterValStruct_t) * PARAM_COUNT_);
    if (NULL == param_val)
    {  
        CcspTraceError(("Memory allocation failed in hotspot \n"));
        return FALSE;
    }
  
    for (i = 0; i < SSIDVAL; i++)
    {
       param_val[i].parameterName = (char*)paramNames[i];
       if(ssid_reset_mask & (1<<i))
       {   
           param_val[i].parameterValue=AnscCloneString("true");
           CcspTraceInfo(("Enabling ssid for the parameter  = %s\n", paramNames[i]));
       }   
       else
       {
           param_val[i].parameterValue=AnscCloneString("false");
           CcspTraceInfo(("Disabling ssid for the parameter  = %s\n", paramNames[i]));
       }   
       param_val[i].type = ccsp_boolean;
    }

    ret = CcspBaseIf_setParameterValues(
            bus_handle,
            component,
            dstPath,
            0,
            0,   
            param_val,
            PARAM_COUNT_,
            TRUE,
            &faultParam
            );   

    if( ( ret != CCSP_SUCCESS ) && ( faultParam!=NULL )) { 
            CcspTraceError((" ssidinfo set bus failed\n"));
            bus_info->freefunc( faultParam );
            if(param_val)
            {
                 free(param_val);
                 param_val = NULL;
            }
            return FALSE;
    }
    if(param_val)
    {
        free(param_val);
        param_val = NULL;
    }
#ifdef WIFI_HAL_VERSION_3
    //Applying Radio settings
    param_val = (parameterValStruct_t*)malloc(sizeof(parameterValStruct_t) * RADIOVAL);
    if(param_val == NULL)
    {
        CcspTraceError(("Memory allocation failed for Radio Param in hotspot \n"));
        return FALSE;
    }

    for(i = 0; i < RADIOVAL; i++)
    {
        param_val[i].parameterName = (char*)paramNamesRadio[i];
        param_val[i].parameterValue = AnscCloneString("true");
        param_val[i].type = ccsp_boolean;
    }
    ret = CcspBaseIf_setParameterValues(
            bus_handle,
            component,
            dstPath,
            0,
            0,
            param_val,
            RADIOVAL,
            TRUE,
            &faultParam
            );

    if( ( ret != CCSP_SUCCESS ) && ( faultParam != NULL)) {
            CcspTraceError(("radioinfo bus failed \n"));
            bus_info->freefunc(faultParam);
            if(param_val)
            {
                 free(param_val);
                 param_val = NULL;
            }
            return FALSE;
    }

    if(param_val)
    {
            free(param_val);
            param_val = NULL;
    }
#endif
    ssid_reset_mask = 0;
    return TRUE;
#endif
}



STATIC bool get_validate_ssid()
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char dstComponent[64]="eRT.com.cisco.spvtg.ccsp.wifi";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";
    const char ap5[]="Device.WiFi.SSID.5.Enable";
    const char ap6[]="Device.WiFi.SSID.6.Enable";
    const char ap9[]="Device.WiFi.SSID.9.Enable";
    const char ap10[]="Device.WiFi.SSID.10.Enable";
#if defined (_BWG_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
    const char ap16[]="Device.WiFi.SSID.16.Enable";
    const char *paramNames[]={ap5,ap6,ap9,ap10,ap16};
#elif defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
    const char ap19[]="Device.WiFi.SSID.19.Enable";
    const char ap21[]="Device.WiFi.SSID.21.Enable";
    const char *paramNames[]={ap5,ap6,ap9,ap10,ap19,ap21};
#else
    const char *paramNames[]={ap5,ap6,ap9,ap10};
#endif
    int  valNum = 0, i =0; 
    BOOL ret_b=FALSE;

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            (char**)paramNames,
            PARAM_COUNT_,
            &valNum,
            &valStructs);
    
    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s hotspot_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
         free_parameterValStruct_t(bus_handle, valNum, valStructs);
         return FALSE;
    }
    

    if(valStructs)
    {
#if defined (_BWG_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
      CcspTraceInfo(("Retrieving previous ssid info ssid 5 = %s ssid 6 = %s ssid 9 = %s ssid 10 = %s ssid 16 = %s\n",valStructs[0]->parameterValue,valStructs[1]->parameterValue, valStructs[2]->parameterValue,valStructs[3]->parameterValue,valStructs[4]->parameterValue));
#elif defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
      CcspTraceInfo(("Retrieving previous ssid info ssid 5 = %s ssid 6 = %s ssid 9 = %s ssid 10 = %s ssid 19 = %s ssid 21 = %s\n",valStructs[0]->parameterValue,valStructs[1]->parameterValue, valStructs[2]->parameterValue,valStructs[3]->parameterValue,valStructs[4]->parameterValue,valStructs[5]->parameterValue));
#else
      CcspTraceInfo(("Retrieving previous ssid info ssid 5 = %s ssid 6 = %s ssid 9 = %s ssid 10 = %s\n",valStructs[0]->parameterValue,valStructs[1]->parameterValue, valStructs[2]->parameterValue,valStructs[3]->parameterValue));
#endif
      for(i = 0; i < SSIDVAL; i++)
      {
           if (0 == strncmp("true", valStructs[i]->parameterValue, 4))
           {
               ssid_reset_mask |= (1<<i);
           }
           else
           {   
               ssid_reset_mask |= (0<<i);
           }     
      }
      ret_b = TRUE;
    }
    else
    {
           CcspTraceError((" ssid information not updated in valstrcuts \n"));
    }

    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    return ret_b;

}


STATIC bool hotspotfd_isClientAttached(bool *pIsNew)
{
    STATIC bool num_devices_0=0;
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
STATIC unsigned short hotspotfd_checksum(void *pdata, int len)
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
STATIC int _hotspotfd_ping(char *address)
{
    const int val = 255;
    int sd;
    struct packet pckt;
    struct sockaddr_storage r_addr;
    int loop;
    struct hostent *hname;
    struct sockaddr_in addr_ping_4;
    struct sockaddr_in6 addr_ping_6;
    unsigned char addr_type = AF_INET;
    struct protoent *proto = NULL;
    int cnt = 1;
    int status = STATUS_FAILURE;
    struct ifreq ifr;
    STATIC int l_iPingCount = 0;
    errno_t rc = -1;
    bool firstAttempt;

    //Determination of IP addr family
    unsigned char buf[sizeof(struct in6_addr)];
    int result = inet_pton(AF_INET6, address, buf);
    addr_type = (result == 1) ? AF_INET6 : AF_INET;

    // This is the number of ping's to send out
    // per keep alive interval
    unsigned keepAliveCount = gKeepAliveCount;
printf("------- ping >>\n");
     /*Coverity Fix CID 63000 unused value */
     int pid = getpid();
     proto = getprotobyname((addr_type == AF_INET6) ? "IPv6-ICMP" : "ICMP");
     hname = gethostbyname2(address, addr_type);
     bzero(&addr_ping_4, sizeof(addr_ping_4));
     bzero(&addr_ping_6, sizeof(addr_ping_6));

    if (hname) {
        addr_ping_6.sin6_family = addr_ping_4.sin_family = hname->h_addrtype;
    } else {
        CcspTraceError(("%s host NULL netaddr\n", __FUNCTION__));
        return status;
    }

    addr_ping_6.sin6_port = addr_ping_4.sin_port = 0;
    if(addr_type == AF_INET6) {
        result = inet_pton(AF_INET6, address, &addr_ping_6.sin6_addr);
        if(result == 0) {
            CcspTraceError(("%s inet_pton error\n", __func__));
            return status;
        }
    } else {
        addr_ping_4.sin_addr.s_addr = *(long*)hname->h_addr;
    }

    sd = socket(addr_type, SOCK_RAW, proto->p_proto);
    if ( sd < 0 ) {
            perror("socket");
            CcspTraceError(("%s Sock Error sd=%d\n", __func__, sd));
             return STATUS_FAILURE;
          
      }

    do {
        // Bind to a specific interface only 
        rc = memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));
		ERR_CHK(rc);
        rc = strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), gKeepAliveInterface);
		if(rc != EOK)
		{
                        CcspTraceError(("%s String copy failed\n", __func__));
			ERR_CHK(rc);
                          /* Coverity Fix CID 151796 RESOURCE_LEAK */
                         close(sd);
			return STATUS_FAILURE;
		}
        /*Coverity Fix CID 144091 Buffer Overflow */
        ifr.ifr_name[ sizeof(ifr.ifr_name) -1 ] = '\0';
        
        if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
            perror("Error on SO_BINDTODEVICE");
            CcspTraceError(("%s Error on SO_BINDTODEVICE..\n", __func__));
            status = STATUS_FAILURE;
            break;
        }

        if ( setsockopt(sd, (addr_type == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IP, IP_TTL, &val, sizeof(val)) != 0) {
            perror("Set TTL option");
            CcspTraceError(("%s Set TTL option failure\n", __func__));
            status = STATUS_FAILURE;
            break;
        }

        if ( fcntl(sd, F_SETFL, O_NONBLOCK) != 0 ) {
            perror("Request nonblocking I/O");
            CcspTraceError(("%s Request nonblocking I/O failure\n", __func__));
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

        firstAttempt = true;
        for (loop = 0;loop < 20; loop++) {
            socklen_t len = sizeof(r_addr);
//icmp echo and response both using same structure, memset before each operation
 
            memset(&pckt, 0, sizeof(pckt));

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
                if (!strncmp((char *)&pckt.msg[(addr_type == AF_INET6) ? 0 : IPv4_HEADER_OFFSET],
                                ICMP_ECHO_STRING, sizeof(ICMP_ECHO_STRING))) {
                    msg_debug("Echo strings matches\n");
                    status = STATUS_SUCCESS;
                } else {
                    CcspTraceInfo(("Echo strings didn't matches\n"));
                    status = STATUS_FAILURE;
                }

//For the very first ping, the buffer in recv may not have the response for the tunnel
//and hence attempt a ping again and check if there is a response for it
//Check 10 ICMP packets whether they are from the hotspot tunnel endpoint

                if(status == STATUS_SUCCESS){
                    keepAliveCount = 1;
                    break;
                }
                else if(!firstAttempt)
                    continue;
                else
                    firstAttempt = false;
            }

            memset(&pckt, 0, sizeof(pckt));
            pckt.hdr.type = (addr_type == AF_INET6) ? ICMP6_ECHO_REQUEST : ICMP_ECHO;
            pckt.hdr.un.echo.id = pid;

            strcpy((char *)&pckt.msg, ICMP_ECHO_STRING);

            pckt.hdr.un.echo.sequence = cnt++;
            pckt.hdr.checksum = hotspotfd_checksum(&pckt, sizeof(pckt));

            if ( sendto(sd, &pckt, sizeof(pckt), 0, (addr_type == AF_INET6) ? (struct sockaddr*)&addr_ping_6 : (struct sockaddr*)&addr_ping_4,
                        (addr_type == AF_INET6) ? sizeof(addr_ping_6) : sizeof(addr_ping_4)) <= 0 ) {
                perror("sendto");
                CcspTraceError(("sendto error"));
            }

            usleep(300000);

        }

    } while (--keepAliveCount);

    close(sd);
    
/* Coverity Fix CID :124917 PRINTF_ARGS*/
    CcspTraceInfo(("%s ------- ping %d << status\n", __func__, status));
    return status;
}

STATIC int hotspotfd_ping(char *address, bool checkClient) {
    //zqiu: do not ping WAG if no client attached, and no new client join in
printf("------------------ %s \n", __func__); 
#if !defined(_COSA_BCM_MIPS_)
    if((prevPingStatus == STATUS_SUCCESS) && checkClient && !hotspotfd_isClientAttached(NULL))
        return  STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(checkClient);
#endif
    prevPingStatus =  _hotspotfd_ping(address);
    return  prevPingStatus;
}

#if (defined (_COSA_BCM_ARM_) && !defined(_XB6_PRODUCT_REQ_)) 

#define kbrlan2_inst "3"
#define kbrlan3_inst "4"
#define kbrlan8_inst "8"
#define kbrlan9_inst "9"
#define kbrlan11_inst "11"
#define kmultinet_Sync "multinet-syncMembers"

STATIC void hotspotfd_syncMultinet(void)
{
	if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, kmultinet_Sync, kbrlan2_inst, 0)) {
		CcspTraceError(("sysevent set %s failed on brlan2\n", kmultinet_Sync));
        }

	if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, kmultinet_Sync, kbrlan3_inst, 0)) {
		CcspTraceError(("sysevent set %s failed on brlan3\n", kmultinet_Sync));
        }
#if defined (_CBR_PRODUCT_REQ_)
	if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, kmultinet_Sync, kbrlan8_inst, 0)) {
		CcspTraceError(("sysevent set %s failed on brlan8\n", kmultinet_Sync));
        }
	if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, kmultinet_Sync, kbrlan9_inst, 0)) {
		CcspTraceError(("sysevent set %s failed on brlan9\n", kmultinet_Sync));
        }
        if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, kmultinet_Sync, kbrlan11_inst, 0)) {
		CcspTraceError(("sysevent set %s failed on brpublic\n", kmultinet_Sync));
        }
#endif
}
#endif

STATIC int hotspotfd_sleep(int sec, bool l_tunnelAlive) {
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

STATIC void hotspotfd_SignalHandler(int signo)
{
    msg_debug("Received signal: %d\n", signo);

    if ( signo == SIGTERM ) {
        CcspTraceInfo(("Hotspotfd process is down and not running\n"));
    }

#ifdef __HAVE_SYSEVENT__
    msg_debug("Closing sysevent and shared memory\n");
    sysevent_close(sysevent_fd, sysevent_token);
    sysevent_close(sysevent_fd_gs, sysevent_token_gs);
#endif

    close(gShm_fd);
    close(gShm_snoop_fd);
    exit(0);
}

STATIC void hotspotfd_log(void)
{
    STATIC FILE *out;
	errno_t rc = -1;

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
        rc = strcpy_s(gpStats->primaryEP, sizeof(gpStats->primaryEP), gpPrimaryEP); 
		if(rc != EOK)
		{
			ERR_CHK(rc);
			return;
		}
        gpStats->primaryIsActive = gPrimaryIsActive;               
        gpStats->primaryIsAlive = gPrimaryIsAlive;                

        rc = strcpy_s(gpStats->secondaryEP, sizeof(gpStats->secondaryEP), gpSecondaryEP); 
		if(rc != EOK)
		{
			ERR_CHK(rc);
			return;
		}
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

STATIC bool hotspotfd_isValidIpAddress(char *ipAddress)
{
    unsigned char buf[sizeof(struct in6_addr)];
    int result = inet_pton(AF_INET, ipAddress, buf) | inet_pton(AF_INET6, ipAddress, buf);
    return result != 0;
}

#ifdef WAN_FAILOVER_SUPPORTED
STATIC bool hotspot_isRemoteWan(char *wan_interface)
{
     char psm_val[128] = {0};

     PsmGet(PSM_WAN_INT, psm_val, sizeof(psm_val));
     CcspTraceInfo(("HotspotTunnelEvent : Wan interface psm value %s\n", psm_val));
 
     if ( (strcmp(wan_interface, psm_val) == 0)){
         wanFailover = true;
#if !defined(RDK_ONEWIFI)
        if(TRUE == get_validate_ssid())
        {
            CcspTraceInfo(("SSID values are updated successfully before setting tunnel status down\n"));
        }
        else
        {
            CcspTraceInfo(("SSID values not are updated successfully before setting tunnel status down\n"));
        }
#endif
         notify_tunnel_status("Down");
         return true;
     }
     else{
         wanFailover = false;
#if !defined(RDK_ONEWIFI)
        if(TRUE == set_validatessid())
        {
            CcspTraceInfo(("SSID's updated before creating tunnels before setting tunnel status up. \n"));
        }
        else
        {
            CcspTraceInfo(("SSID's are not updated before creating tunnels before setting tunnel status up. \n"));
        }
#endif
         notify_tunnel_status("Up");
         return false;
     }
}

STATIC bool hotspot_check_wan_failover_status(char *val)
{
     char cbuff[20]={0};
     bool isRemoteWANEnabled = false;

     strncpy(cbuff, val, sizeof(cbuff));
     CcspTraceInfo(("HotspotTunnelEvent : %s New value of CurrentActiveInterface is -= %s\n",__FUNCTION__, cbuff));
     isRemoteWANEnabled = hotspot_isRemoteWan(cbuff);
     hotspot_wan_failover(isRemoteWANEnabled);
     if(isRemoteWANEnabled)
     {
         gPrimaryIsAlive = false;
         gPrimaryIsActive = true;    // Check Primary EP first after coming back to DOCSIS WAN
         gSecondaryIsAlive = false;
         gSecondaryIsActive = false;
         gPriStateIsDown = true;
         gSecStateIsDown = true;
         gBothDnFirstSignal = false;
         gTunnelIsUp=false;
         pthread_mutex_lock(&keep_alive_mutex);
         gbFirstPrimarySignal = true;
         gbFirstSecondarySignal = true;
         pthread_mutex_unlock(&keep_alive_mutex);
         CcspTraceInfo(("Primary and Secondary GRE flag set to true in %s\n", __FUNCTION__));
         if (sysevent_set(sysevent_fd_gs, sysevent_token_gs,
                                       kHotspotfd_tunnelEP, "", 0))
         {
             CcspTraceError(("sysevent set %s failed on %s\n", kHotspotfd_tunnelEP, __FUNCTION__));
         }
     }
     return true;
}
#endif

#ifdef __HAVE_SYSEVENT__
STATIC void *hotspotfd_sysevent_handler(void *data)
{
    UNREFERENCED_PARAMETER(data);
    async_id_t hotspotfd_primary_id;
    async_id_t hotspotfd_secondary_id; 
    async_id_t hotspotfd_keep_alive_id;
    async_id_t hotspotfd_keep_alive_threshold_id;
    async_id_t hotspotfd_max_secondary_id;
    async_id_t hotspotfd_policy_id;
    async_id_t hotspotfd_enable_id;
    async_id_t hotspotfd_log_enable_id;
    async_id_t hotspotfd_keep_alive_count_id;
    async_id_t hotspotfd_wan_status_id;
    
	async_id_t snoop_enable_id;
    async_id_t snoop_debug_enable_id;
    async_id_t snoop_log_enable_id;
    async_id_t snoop_circuit_enable_id;
    async_id_t snoop_remote_enable_id;
    async_id_t snoop_max_clients_id;
    async_id_t snoop_circuit_ids[kSnoop_MaxCircuitIDs]; 
    async_id_t snoop_ssids_ids[kSnoop_MaxCircuitIDs];
    async_id_t hotspotfd_current_wan_ipaddr_v4_id;
    async_id_t hotspotfd_current_wan_ipaddr_v6_id;
#ifdef WAN_FAILOVER_SUPPORTED
    async_id_t current_wan_interface_id;
    async_id_t test_current_wan_interface_id;
#endif
  
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
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_wan_status,           &hotspotfd_wan_status_id);

    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_enable,          &snoop_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_debug_enable,    &snoop_debug_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_log_enable,      &snoop_log_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_circuit_enable,  &snoop_circuit_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_remote_enable,   &snoop_remote_enable_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, kSnooper_max_clients,     &snoop_max_clients_id);
    sysevent_set_options(sysevent_fd, sysevent_token, khotspotfd_current_wan_ipaddr_v4,TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_current_wan_ipaddr_v4,&hotspotfd_current_wan_ipaddr_v4_id);
    sysevent_set_options(sysevent_fd, sysevent_token, khotspotfd_current_wan_ipaddr_v6,TUPLE_FLAG_EVENT);
    sysevent_setnotification(sysevent_fd, sysevent_token, khotspotfd_current_wan_ipaddr_v6,&hotspotfd_current_wan_ipaddr_v6_id);
#ifdef WAN_FAILOVER_SUPPORTED
    sysevent_setnotification(sysevent_fd, sysevent_token, kcurrent_wan_interface,      &current_wan_interface_id);
    sysevent_setnotification(sysevent_fd, sysevent_token, ktest_current_wan_interface, &test_current_wan_interface_id);
#endif

    for(i=0; i<kSnoop_MaxCircuitIDs; i++) 
	{
        sysevent_setnotification(sysevent_fd, sysevent_token, gSnoopSyseventCircuitIDs[i], &snoop_circuit_ids[i]);
    }

    for(i=0; i<kSnoop_MaxCircuitIDs; i++) 
	{
        sysevent_setnotification(sysevent_fd, sysevent_token, gSnoopSyseventSSIDs[i], &snoop_ssids_ids[i]);
    }

    for (;;) {
	/* Coverity Fix CID : 140441 STRING_OVERFLOW */
        char name[25], val[kMax_IPAddressLength];
        int namelen = sizeof(name);
        int vallen  = sizeof(val);
        int err;
		errno_t rc = -1;
		int ind = -1;
        async_id_t getnotification_id;

        err = sysevent_getnotification(sysevent_fd, sysevent_token, name, &namelen,  val, &vallen, &getnotification_id);

        if(!err)
        {
			HotspotfdType ret_value;            
            ret_value = Get_HotspotfdType(name);            
            msg_debug("name: %s, namelen: %d,  val: %s, vallen: %d\n", name, namelen, val, vallen);
            if (ret_value == HOTSPOTFD_PRIMARY) {
                rc = strcpy_s(gpPrimaryEP, sizeof(gpPrimaryEP), val); 
		        if(rc != EOK)
		        {
			       ERR_CHK(rc);
			       return NULL;
		        }

                msg_debug("gpPrimaryEP: %s\n", gpPrimaryEP);

		CcspTraceInfo((" GRE flag set to %d in sysevent handler \n", gbFirstPrimarySignal));				

                pthread_mutex_lock(&keep_alive_mutex);
                gbFirstPrimarySignal = true;
                pthread_mutex_unlock(&keep_alive_mutex);
            } else if (ret_value == HOTSPOTFD_SECONDARY) {
                rc = strcpy_s(gpSecondaryEP, sizeof(gpSecondaryEP), val); 
		        if(rc != EOK)
		        {
			       ERR_CHK(rc);
			       return NULL;
		        }

                msg_debug("gpSecondaryEP: %s\n", gpSecondaryEP);

                pthread_mutex_lock(&keep_alive_mutex);
                gbFirstSecondarySignal = true;
                pthread_mutex_unlock(&keep_alive_mutex);

            } else if (ret_value == HOTSPOTFD_KEEPALIVE) {
                gKeepAliveInterval = atoi(val);

                msg_debug("gKeepAliveInterval: %u\n", gKeepAliveInterval);

            } else if (ret_value == HOTSPOTFD_THRESHOLD) {
                gKeepAliveThreshold = atoi(val);

                msg_debug("gKeepAliveThreshold: %u\n", gKeepAliveThreshold);

            } else if (ret_value == HOTSPOTFD_MAXSECONDARY) {
                gSecondaryMaxTime = atoi(val);

                msg_debug("gSecondaryMaxTime: %u\n", gSecondaryMaxTime);

            } else if (ret_value == HOTSPOTFD_POLICY) {
                gKeepAlivePolicy = atoi(val);

                msg_debug("gKeepAlivePolicy: %s\n", (gKeepAlivePolicy == 1 ? "NONE" : "ICMP"));

            } else if (ret_value == HOTSPOTFD_ENABLE) {
                if (atoi(val) == 0) {
                    gKeepAliveEnable = false;
                    CcspTraceError(("Keep alive enable is false, ICMP ping wont be sent\n"));
                } else {
                    gKeepAliveEnable = true;
                }
                msg_debug("gKeepAliveEnable: %u\n", gKeepAliveEnable);

            } else if (ret_value == HOTSPOTFD_COUNT) {
                gKeepAliveCount = atoi(val);

                msg_debug("gKeepAliveCount: %u\n", gKeepAliveCount);

            } else if (ret_value == HOTSPOTFD_LOGENABLE) {
                gKeepAliveLogEnable = atoi(val);

                msg_debug("gKeepAliveLogEnable: %u\n", gKeepAliveLogEnable);

            } else if (ret_value == HOTSPOTFD_DEADINTERVAL) {
                gDeadInterval = atoi(val);

                msg_debug("gDeadInterval: %u\n", gDeadInterval);
            } else if (ret_value == HOTSPOTFD_WANSTATUS) {
                prevPingStatus = STATUS_FAILURE;

                CcspTraceInfo(("wan-status is changed to %s \n", val));
            }
            else if (ret_value == SNOOPER_ENABLE) {
                gSnoopEnable = atoi(val);

                CcspTraceInfo(("gSnoopEnable: %u\n", gSnoopEnable));

            } else if (ret_value == SNOOPER_DEBUGENABLE) {
                gSnoopDebugEnabled = atoi(val);

                CcspTraceInfo(("gSnoopDebugEnabled: %u\n", gSnoopDebugEnabled));

            } else if (ret_value == SNOOPER_LOGENABLE) {
                gSnoopLogEnabled = atoi(val);

                CcspTraceInfo(("gSnoopDebugEnabled: %u\n", gSnoopLogEnabled));

            } else if (ret_value == SNOOPER_CIRCUITENABLE) {
                gSnoopCircuitEnabled = atoi(val);

                CcspTraceInfo(("gSnoopCircuitEnabled: %u\n", gSnoopCircuitEnabled));

            } else if (ret_value == SNOOPER_REMOTEENABLE) {
                gSnoopRemoteEnabled = atoi(val);

                CcspTraceInfo(("gSnoopRemoteEnabled: %u\n", gSnoopRemoteEnabled));

            } else if (ret_value == SNOOPER_MAXCLIENTS) {
                gSnoopMaxNumberOfClients = atoi(val);

                CcspTraceInfo(("gSnoopMaxNumberOfClients: %u\n", gSnoopMaxNumberOfClients));

            } else if (ret_value == HOTSPOTFD_CURRENT_WAN_IPADDR_V4) {
                 CcspTraceInfo(("current_wan_ipaddr is changed to %s\n", val));
                 int ipaddr_length = strlen(val);
                 char current_EP[kMax_IPAddressLength];
                 memset(current_EP, '\0', sizeof(current_EP));
                 if (sysevent_get(sysevent_fd_gs, sysevent_token_gs, "gre_current_endpoint" , current_EP, sizeof(current_EP))) {
                    CcspTraceError(("sysevent_get failed to get gre_current_endpoint\n"));
                 }
                 if (current_EP[0] == '\0' || strncmp("dummy_EP", current_EP, strlen("dummy_EP")) == 0) {
                    CcspTraceInfo(("Tunnels are down previously, no need to recreate\n"));
                 }
                 else
                 {
                     if(ipAddress_version(current_EP) == 4){
                         if((strncmp(val, "0.0.0.0", ipaddr_length) == 0))
                         {
                             CcspTraceInfo(("current_wan_ipaddr is %s\n", val));
                         }
                         else if((strncmp(val,old_wan_ipv4, ipaddr_length) == 0))
                         {
                             CcspTraceInfo(("current_wan_ipaddr and old_wan_ipv4 are same \n"));
                         }
                         else
                         {
                             CcspTraceInfo(("current_wan_ipaddr and old_wan_ipv4 are not same \n"));
                             strcpy_s(old_wan_ipv4, sizeof(old_wan_ipv4), val);
                             if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, "old_wan_ipv4addr", old_wan_ipv4, 0)){
                                 CcspTraceError(("sysevent_set failed to set old_wan_ipv4addr\n"));
                             }
                             recreate_tunnel();
                         }
                     }
                 }
            } else if (ret_value == HOTSPOTFD_CURRENT_WAN_IPADDR_V6) {
                 CcspTraceInfo(("wan6_ipaddr is changed to %s\n", val));
                 int ipaddr_length = strlen(val);
                 char current_EP[kMax_IPAddressLength];
                 memset(current_EP, '\0', sizeof(current_EP));
                 if (sysevent_get(sysevent_fd_gs, sysevent_token_gs, "gre_current_endpoint" , current_EP, sizeof(current_EP))) {
                    CcspTraceError(("sysevent_get failed to get gre_current_endpoint\n"));
                 }
                 if (current_EP[0] == '\0' || strncmp("dummy_EP", current_EP, strlen("dummy_EP")) == 0) {
                    CcspTraceInfo(("Tunnels are down previously, no need to recreate\n"));
                 }
                 else
                 {
                     if(ipAddress_version(current_EP) == 6){

                        if((strncmp(val,old_wan_ipv6, ipaddr_length) == 0))
                        {
                             CcspTraceInfo(("wan6_ipaddr and old_wan_ipv6 are same \n"));
                        }
                        else
                        {
                             CcspTraceInfo(("wan6_ipaddr and old_wan_ipv6 are not same \n"));
                             strcpy_s(old_wan_ipv6, sizeof(old_wan_ipv6), val);
                             if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, "old_wan_ipv6addr", old_wan_ipv6, 0)){
                                CcspTraceError(("sysevent_set failed to set old_wan_ipv6addr\n"));
                             }
                             recreate_tunnel();
                        }
                     }
                 }
            }

#ifdef WAN_FAILOVER_SUPPORTED
            else if (ret_value == CURRENT_WAN_IFNAME || ret_value == TEST_CURRENT_WAN_IFNAME) {
                 hotspot_check_wan_failover_status(val);
            }
#endif
            int strlength;

            strlength = strlen(name);

            for(i=0; i<kSnoop_MaxCircuitIDs; i++) {
                rc = strcmp_s(name, strlength,gSnoopSyseventCircuitIDs[i], &ind);
                ERR_CHK(rc);
                if ((ind == 0) && (rc == EOK)) {
                    CcspTraceInfo(("CircuitID list case\n"));
					
                    rc = strcpy_s(gSnoopCircuitIDList[i], sizeof(gSnoopCircuitIDList[i]), val); 
					if (rc != EOK)
					{
						ERR_CHK(rc);
						return NULL;
					}
                    break;
                }
            }

            for(i=0; i<kSnoop_MaxCircuitIDs; i++) {
                rc = strcmp_s(name, strlength,gSnoopSyseventSSIDs[i], &ind);
                ERR_CHK(rc);
                if ((ind == 0) && (rc == EOK)) {
                    CcspTraceInfo(("gSnoopSSIDListInt case\n"));
					rc = strcpy_s(gSnoopSSIDList[i], sizeof(gSnoopSSIDList[i]), val); 
					if (rc != EOK)
					{
						ERR_CHK(rc);
						return NULL;
					}
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
            CcspTraceError(("Existing shared memory segment %s found! key: %d size:%zu. Deleting!\n",shmidchar, shmds.shm_perm.__key, shmds.shm_segsz));
            if (snooper) {
                snooper_statistics_s *snStats;
		        snStats = (snooper_statistics_s *)shmat(shmid, 0, 0);
                if (snStats == ((snooper_statistics_s *)-1))
                {
                    perror("shmat error");
                    snStats = NULL;
                    perror("shmat error");
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
                    perror("shmat error");
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
STATIC int hotspotfd_setupSharedMemory(void)
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
STATIC int hotspotfd_getStartupParameters(void)
{
    int status = STATUS_SUCCESS;
	int i;
    char buf[kMax_IPAddressLength];
	errno_t rc = -1;

    do {
        // Primary EP 
        if ((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, kHotspotfd_primary, buf, sizeof(buf)))) {
            CcspTraceError(("sysevent_get failed to get %s: %d\n", kHotspotfd_primary, status)); 
            status = STATUS_FAILURE;
            break;
        }

        if (hotspotfd_isValidIpAddress(buf)) {
			rc = strcpy_s(gpPrimaryEP, sizeof(gpPrimaryEP), buf); 
			if (rc != EOK)
			{
				ERR_CHK(rc);
				return STATUS_FAILURE;
			}

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
			rc = strcpy_s(gpSecondaryEP, sizeof(gpSecondaryEP), buf); 
			if (rc != EOK)
			{
				ERR_CHK(rc);
				return STATUS_FAILURE;
			}

            msg_debug("Loaded sysevent %s with %s\n", khotspotfd_secondary, gpSecondaryEP); 
        } else {

            CcspTraceError(("hotspotfd_isValidIpAddress: %s: %d\n", khotspotfd_secondary, status));

            status = STATUS_FAILURE;
            break;
        }

        if (sysevent_get(sysevent_fd_gs, sysevent_token_gs, "old_wan_ipv4addr" , old_wan_ipv4, sizeof(old_wan_ipv4))) {
             CcspTraceError(("sysevent_get failed to get current_wan_ipaddr\n"));
        }

        CcspTraceInfo(("old_wan_ipv4addr is  %s\n", old_wan_ipv4));

        if(!(hotspotfd_isValidIpAddress(old_wan_ipv4))) {

            if (sysevent_get(sysevent_fd_gs, sysevent_token_gs, "current_wan_ipaddr" , buf, sizeof(buf))) {
                 CcspTraceError(("sysevent_get failed to get current_wan_ipaddr\n"));
            }

            if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, "old_wan_ipv4addr", buf, 0)){
                CcspTraceError(("sysevent_set failed to set old_wan_ipv4addr\n"));
            }

            if (sysevent_get(sysevent_fd_gs, sysevent_token_gs, "old_wan_ipv4addr" , old_wan_ipv4, sizeof(old_wan_ipv4))) {
                 CcspTraceError(("sysevent_get failed to get current_wan_ipaddr\n"));
            }

            CcspTraceInfo(("Updated old_wan_ipv4addr is  %s\n", old_wan_ipv4));
        }

        if (sysevent_get(sysevent_fd_gs, sysevent_token_gs, "old_wan_ipv6addr" , old_wan_ipv6, sizeof(old_wan_ipv6))) {
             CcspTraceError(("sysevent_get failed to get wan6_ipaddr\n"));
        }

        CcspTraceInfo(("old_wan_ipv6addr is  %s\n", old_wan_ipv6));

        if(!(hotspotfd_isValidIpAddress(old_wan_ipv6))) {

            if (sysevent_get(sysevent_fd_gs, sysevent_token_gs, "wan6_ipaddr" , buf, sizeof(buf))) {
                 CcspTraceError(("sysevent_get failed to get wan6_ipaddr\n"));
            }

            if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, "old_wan_ipv6addr", buf, 0)){
                CcspTraceError(("sysevent_set failed to set old_wan_ipv6addr\n"));
            }

            if (sysevent_get(sysevent_fd_gs, sysevent_token_gs, "old_wan_ipv6addr" , old_wan_ipv6, sizeof(old_wan_ipv6))) {
                 CcspTraceError(("sysevent_get failed to get wan6_ipaddr\n"));
            }

            CcspTraceInfo(("Updated old_wan_ipv6addr is  %s\n", old_wan_ipv6));
        }

#ifdef FEATURE_SUPPORT_MAPT_NAT46
        // Keep Alive Interface
        if ((status = sysevent_get(sysevent_fd_gs, sysevent_token_gs, SYSEVENT_MAPT_CONFIG_FLAG, buf, sizeof(buf)))) {
            CcspTraceError(("sysevent_get failed to get %s: %d\n", SYSEVENT_MAPT_CONFIG_FLAG, status));
            status = STATUS_FAILURE;
            break;
        }

        if (strncmp(buf,"set", 3) == 0)
        {
          rc = strcpy_s(gKeepAliveInterface, sizeof(gKeepAliveInterface), "map0");
        }
        else
        {
#endif
          rc = strcpy_s(gKeepAliveInterface, sizeof(gKeepAliveInterface), "erouter0");
#ifdef FEATURE_SUPPORT_MAPT_NAT46
        }
#endif
        if(rc != EOK)
        {
          ERR_CHK(rc);
          status = STATUS_FAILURE;
          break;
        }
        msg_debug("gKeepAliveInterface = %s\n", gKeepAliveInterface);

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
        if ((int)gKeepAlivePolicy >= 0) {
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
	            if(gSnoopSSIDList[i][0]=='\0') 
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

#ifdef WAN_FAILOVER_SUPPORTED

STATIC void HotspotTunnelEventHandler(
    rbusHandle_t handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;
    const char* eventName = event->name;
    rbusValue_t valBuff;

    CcspTraceWarning(("HotspotTunnelEvent : Entering function %s\n", __FUNCTION__));
    valBuff = rbusObject_GetValue(event->data, NULL );
    if(!valBuff)
    {
        CcspTraceWarning(("HotspotTunnelEvent : FAILED , value is NULL\n"));
    }
    else
    {
        const char* newValue = rbusValue_GetString(valBuff, NULL);
        if ( strcmp(eventName,"Device.X_RDK_WanManager.CurrentActiveInterface") == 0 )
        {
            CcspTraceWarning(("HotspotTunnelEvent : New value of CurrentActiveInterface is = %s\n",newValue));
            //hotspot_check_wan_failover_status((char *)newValue);
        }
    }
}
#endif

#ifdef WAN_FAILOVER_SUPPORTED
void  *handle_rbusSubscribe() {
    int   ret   = 0;
    bool retry_again = true;
    int retry_count = 0;

    while (retry_again == true && retry_count < 10) {
        ret = rbusEvent_Subscribe(handle, "Device.X_RDK_WanManager.CurrentActiveInterface", HotspotTunnelEventHandler, NULL, 0);
        if(ret != RBUS_ERROR_SUCCESS)
        {
          CcspTraceError(("HotspotTunnelEvent: rbusEvent_Subscribe failed: %d. Retrying for 10 times...\n", ret));
          retry_count++;
          retry_again = true;
        } else {
          CcspTraceInfo(("HotspotTunnelEvent: rbusEvent_Subscribe success: %d\n", ret));
          retry_again = false;
        }
    }
    if (retry_count >= 10) {
        CcspTraceError(("HotspotTunnelEvent: rbusEvent_Subscribe failed: %d. Returning from %s\n", ret, __FUNCTION__));
        return NULL;
    }
    return NULL;
}
#endif

void hotspot_start()
{
    unsigned int keepAliveThreshold = 0;
    unsigned int secondaryKeepAlives = 0;
	time_t secondaryEndPointstartTime;
	time_t currentTime ;
	unsigned int timeElapsed;
        int   ret   = 0; 

	gKeepAliveEnable = true;
    bool switchedFromSecondary = false;
    char telemetry_buf[128] = {'\0'};
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

    v_secure_system("touch /tmp/hotspotfd_up");
    hotspotfd_log();

#ifdef WAN_FAILOVER_SUPPORTED

    ret = rbus_open(&handle, "HotspotTunnelEvent");
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("HotspotTunnelEvent : rbus_open failed: %d\n", ret));
        return;
    }
    pthread_create(&rbus_tid, NULL, handle_rbusSubscribe, NULL);

#endif

    if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, kHotspotfd_tunnelEP, kDefault_DummyEP, 0))
    {
        CcspTraceError(("sysevent set %s failed for %s\n", kHotspotfd_tunnelEP, kDefault_DummyEP));
    }
    keep_it_alive:

    while ((gKeepAliveEnable == true) && (wanFailover == false)) {
Try_primary:
        while (gPrimaryIsActive && (gKeepAliveEnable == true) && (wanFailover == false)) {

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

                    if(ssid_reset_mask != 0) 
                    {
                       if(TRUE == set_validatessid())
                       {
                          CcspTraceInfo(("SSID's updated before creating tunnels. \n"));
                       }
                       else
                       {
                          CcspTraceInfo(("SSID's are not updated before creating tunnels. \n"));
                       }
                    } 

		    CcspTraceInfo(("Create Primary GRE Tunnel with endpoint:%s\n", gpPrimaryEP));
		    t2_event_d("SYS_INFO_Create_GRE_Tunnel", 1);
                    memset(telemetry_buf, 0, sizeof(telemetry_buf));
                    snprintf(telemetry_buf, sizeof(telemetry_buf), "%s-Primary", gpPrimaryEP);
                    t2_event_s("XWIFI_Active_Tunnel", telemetry_buf);


                    if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, 
                                     kHotspotfd_tunnelEP, gpPrimaryEP, 0)) {

                        CcspTraceError(("sysevent set %s failed on primary\n", kHotspotfd_tunnelEP));
                    }
                    notify_tunnel_status("Up");
                    if (false == gWebConfTun){ 
		        ret = CcspBaseIf_SendSignal_WithData(bus_handle, "TunnelStatus" , "TUNNEL_UP");
                        if ( ret != CCSP_SUCCESS )
                        {
                             CcspTraceError(("%s : TunnelStatus send data failed,  ret value is %d\n",__FUNCTION__ ,ret));
                        }
                        gWebConfTun = true;
                    }
                    #if (defined (_COSA_BCM_ARM_) && !defined(_XB6_PRODUCT_REQ_))
                    hotspotfd_syncMultinet();
		    #endif
		    gTunnelIsUp=true;
					
                    pthread_mutex_lock(&keep_alive_mutex);
                    gbFirstPrimarySignal = false;
                    pthread_mutex_unlock(&keep_alive_mutex);
                    CcspTraceInfo(("Primary GRE flag set to %d\n", gbFirstPrimarySignal));
                    if(switchedFromSecondary)
                    {
                        gSwitchedBackToPrimary++;
                        switchedFromSecondary = false;
                    }
                }

				if (gKeepAliveEnable == false) continue;
				hotspotfd_sleep(((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure), true); //Tunnel Alive case
                if (gKeepAliveEnable == false) continue;

            } else {

                gPrimaryIsAlive = false;
                keepAliveThreshold++;
                CcspTraceInfo(("keepAliveThreshold value %d \n", keepAliveThreshold));
				//if (gKeepAliveEnable == false) continue;
				//hotspotfd_sleep(((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure), false); //Tunnel not Alive case
                //if (gKeepAliveEnable == false) continue;

                if (keepAliveThreshold < gKeepAliveThreshold) {
					if (gKeepAliveEnable == false) continue;
					hotspotfd_sleep(((gTunnelIsUp||gbFirstPrimarySignal)?gKeepAliveInterval:gKeepAliveIntervalFailure), false); //Tunnel not Alive case
                    continue;
                } else {
                    gPrimaryIsActive = false;
                    gSecondaryIsActive = true;
				
                    pthread_mutex_lock(&keep_alive_mutex);
                    gbFirstPrimarySignal = true;
                    pthread_mutex_unlock(&keep_alive_mutex);

		    CcspTraceInfo(("Primary GRE flag set to %d in else\n", gbFirstPrimarySignal));				
	//ARRISXB3-2770 When there is switch in tunnel , existing tunnel should be destroyed and created with new reachable tunnel as GW.
                       /* Coverity FiX CID: 140440 MISSING_LOCK */  
                       pthread_mutex_lock(&keep_alive_mutex);
                        gbFirstSecondarySignal = true;
                    pthread_mutex_unlock(&keep_alive_mutex);
					//fix ends
                    keepAliveThreshold = 0;
                    gPriStateIsDown = true;

					CcspTraceInfo(("Primary GRE Tunnel Endpoint :%s is not alive Switching to Secondary Endpoint :%s\n", gpPrimaryEP,gpSecondaryEP));
                    memset(telemetry_buf, 0, sizeof(telemetry_buf));
                    snprintf(telemetry_buf, sizeof(telemetry_buf), "%s-Secondary", gpSecondaryEP);
                    t2_event_s("XWIFI_Active_Tunnel", telemetry_buf);

                    if(ssid_reset_mask == 0)
                    {
                         if(TRUE == get_validate_ssid())
                         {
                             CcspTraceInfo(("SSID values are updated successfully \n"));
                         }
                         else
                         {
                             CcspTraceInfo(("SSID values not are updated successfully \n"));
                         }
                    }
                    if (gSecStateIsDown && gPriStateIsDown && gBothDnFirstSignal) {

                        gBothDnFirstSignal = false;

                        if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, 
                                         kHotspotfd_tunnelEP, "", 0)) {

                            CcspTraceError(("sysevent set %s failed on secondary\n", kHotspotfd_tunnelEP));
                        }
						gTunnelIsUp=false;
                        notify_tunnel_status("Down");
                    }
                    time(&secondaryEndPointstartTime);  
                }
            }
        }
Try_secondary:
        while (gSecondaryIsActive && (gKeepAliveEnable == true) && (wanFailover == false)) {

            gKeepAlivesSent++;

            if (gKeepAliveLogEnable) {
                hotspotfd_log();
            }
            if((0 == strcmp(gpSecondaryEP, "")) || (0 == strcmp(gpSecondaryEP, " ")) || (0 == strcmp(gpSecondaryEP, "0.0.0.0"))){
                   CcspTraceInfo(("Secondary endpoint ip is invalid, Using primary EP IP \n"));
                   strncpy(gpSecondaryEP, gpPrimaryEP, 40);
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
                //if (secondaryKeepAlives > gSecondaryMaxTime/60)

				if( timeElapsed > gSecondaryMaxTime ) {

                    gPrimaryIsActive = true;
					//ARRISXB3-2770 When there is switch in tunnel , existing tunnel should be destroyed and created with new reachable tunnel as GW.
                    /* Coverity Fix CID:140439 MISSING_LOCK */
                        pthread_mutex_lock(&keep_alive_mutex);
                         gbFirstPrimarySignal = true;
                    pthread_mutex_unlock(&keep_alive_mutex);
		CcspTraceInfo((" GRE flag set to %d in try secondary\n", gbFirstPrimarySignal));				
					// fix ends
                    gSecondaryIsActive = false;
                    keepAliveThreshold = 0;
                    secondaryKeepAlives = 0;
					CcspTraceInfo(("Max. Secondary EP time:%d exceeded. Switching to Primary EP\n", gSecondaryMaxTime));
                    memset(telemetry_buf, 0, sizeof(telemetry_buf));
                    snprintf(telemetry_buf, sizeof(telemetry_buf), "%s-Primary", gpPrimaryEP);
                    t2_event_s("XWIFI_Active_Tunnel", telemetry_buf);

                    // TODO: Do we just destroy this tunnel and move over
                    // to the primary? What if the Primary is down then we switched
                    // for no reason?
                    // TODO: Need to try the Primary once before switching.
                    switchedFromSecondary = true;
                    if(ssid_reset_mask == 0)
                    {
                         if(TRUE == get_validate_ssid())
                         {
                             CcspTraceInfo(("SSID values are updated successfully before Switching to Primary EP\n"));
                         }
                         else
                         {
                             CcspTraceInfo(("SSID values not are updated successfully Switching to Primary EP\n"));
                         }
                    }
                    break;
                }
                if(ssid_reset_mask != 0) {
                     if(TRUE == set_validatessid()) {
                           CcspTraceInfo(("SSID's updated secondary tunnel deletion. \n"));
                     }    
                     else {
                                   CcspTraceInfo(("SSID's are not updated after tunnel deletion. \n"));
                          }    
                }    

                if (gbFirstSecondarySignal) {
                    CcspTraceInfo(("Create Secondary GRE tunnel with endpoint:%s\n", gpSecondaryEP));

                    if (sysevent_set(sysevent_fd_gs, sysevent_token_gs, 
                                     kHotspotfd_tunnelEP, gpSecondaryEP, 0)) {

                        CcspTraceError(("sysevent set %s failed on secondary\n", kHotspotfd_tunnelEP)); 
                    }
                    notify_tunnel_status("Up");
                    gWebConfTun = false;
		    ret = CcspBaseIf_SendSignal_WithData(bus_handle, "TunnelStatus" , "TUNNEL_UP");
                    if ( ret != CCSP_SUCCESS )
                    {
                          CcspTraceError(("%s : TunnelStatus send data failed,  ret value is %d\n",__FUNCTION__ ,ret));
                    }
                    #if (defined (_COSA_BCM_ARM_) && !defined(_XB6_PRODUCT_REQ_))
                    hotspotfd_syncMultinet();
		    #endif
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
				CcspTraceInfo(("Secondary GRE Tunnel Endpoint:%s is not alive\n", gpSecondaryEP));
                gSecondaryIsAlive = false;
                   
                if(ssid_reset_mask == 0)
                { 
                     if(TRUE == get_validate_ssid())
                     {
                         CcspTraceInfo(("SSID values are updated successfully \n"));
                     }
                     else
                     {
                         CcspTraceInfo(("SSID values not are updated successfully \n"));    
                     }
                }

                pthread_mutex_lock(&keep_alive_mutex);
                gbFirstSecondarySignal = true;
                pthread_mutex_unlock(&keep_alive_mutex);

                keepAliveThreshold++;
                CcspTraceInfo(("Secondary keepAliveThreshold value %d \n", keepAliveThreshold));
				//if (gKeepAliveEnable == false) continue;
				//hotspotfd_sleep(((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure), false); //Tunnel not Alive case
                //if (gKeepAliveEnable == false) continue;
                if (keepAliveThreshold < gKeepAliveThreshold) {
					if (gKeepAliveEnable == false) continue;
					hotspotfd_sleep(((gTunnelIsUp||gbFirstSecondarySignal)?gKeepAliveInterval:gKeepAliveIntervalFailure), false); //Tunnel not Alive case
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
                                         kHotspotfd_tunnelEP, "", 0)) {

                            CcspTraceError(("sysevent set %s failed on secondary\n", kHotspotfd_tunnelEP));
                        }
                        t2_event_s("XWIFI_Active_Tunnel", "No Tunnel");

			/*Signal wifi module for tunnel down */
                        notify_tunnel_status("Down");
			ret = CcspBaseIf_SendSignal_WithData(bus_handle, "TunnelStatus", "TUNNEL_DOWN");
                        if ( ret != CCSP_SUCCESS )
                        {
                              CcspTraceError(("%s : TunnelStatus send data failed,  ret value is %d\n",__FUNCTION__ ,ret));
                        }
			gTunnelIsUp=false;
			break;
                    }
                }
            }
        }

        //gTunnelIsUp==false;
        while (gKeepAliveEnable == true && wanFailover == false) {
            gKeepAlivesSent++;
            if (hotspotfd_ping(gpPrimaryEP, gTunnelIsUp) == STATUS_SUCCESS) {
                gPrimaryIsActive = true;
                gSecondaryIsActive = false;
                goto Try_primary;
            }
            if (hotspotfd_ping(gpSecondaryEP, gTunnelIsUp) == STATUS_SUCCESS) {
                gPrimaryIsActive = false;
                gSecondaryIsActive = true;
                time(&secondaryEndPointstartTime);
                goto Try_secondary;
            }
            if(gVapIsUp)
            {
                notify_tunnel_status("Down");
            }
            hotspotfd_sleep((gTunnelIsUp)?gKeepAliveInterval:gKeepAliveIntervalFailure, false);
        }
    }

    while (gKeepAliveEnable == false || wanFailover == true) {
        sleep(1);
    }

    goto keep_it_alive;
}
