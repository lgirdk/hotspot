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

#include <netinet/in.h>
#include "libHotspot.h"
#include "libHotspotApi.h"
#include "webconfig_framework.h"
#include "ccsp_psm_helper.h"
#include "ansc_platform.h"
#include "safec_lib_common.h"

#include <telemetry_busmessage_sender.h>

/**************************************************************************/
/*      GLOBAL and STATIC  VARIABLES                                      */
/**************************************************************************/
extern  ANSC_HANDLE             bus_handle;
extern char                 g_Subsystem[32];
int gSyseventfd;
token_t gSysevent_token;
char     vapBitMask = 0x00;
char     gPriEndptIP[SIZE_OF_IP] = {0};
char     gSecEndptIP[SIZE_OF_IP] = {0};
bool     gXfinityEnable = false;
int      vlanIdList[MAX_VAP];

static pErr execRetVal = NULL;
extern vlanSyncData_s gVlanSyncData[];
callbackHotspot gCallbackSync = NULL;

tunnel_params oldTunnelData = {
    .isFirst = true,
    .gre_enable = false,
    .primaryEP = {0},
    .secondaryEP = {0},
    .Vlans = {0}
};

tunneldoc_t     *tempTunnelData = NULL;

/**************************************************************************/
/**************************************************************************/
/*      Functions                                                          */
/**************************************************************************/


bool tunnel_param_synchronize() {
    int itr;
    CcspTraceInfo(("HOTSPOT_LIB : Entering %s....\n", __FUNCTION__));
    tunnelSet_t *tunnelSet = NULL;

    tunnelSet = (tunnelSet_t *)malloc(sizeof(tunnelSet_t));
 
    if (tunnelSet == NULL ){
          CcspTraceError(("HOTSPOT_LIB : Malloc failed in %s \n", __FUNCTION__));
          return FALSE;
    }

    memset(tunnelSet,0,sizeof(tunnelSet_t));
    strncpy(tunnelSet->set_primary_endpoint, gPriEndptIP, SIZE_OF_IP - 1);
    strncpy(tunnelSet->set_sec_endpoint, gSecEndptIP, SIZE_OF_IP - 1);
    tunnelSet->set_gre_enable = gXfinityEnable;
    for(itr=0; itr<MAX_VAP; itr++)
    {
        tunnelSet->vlan_id_list[itr] = vlanIdList[itr];
    }
    if(gCallbackSync != NULL)
    {
      gCallbackSync(tunnelSet);
    }
    else
    {
       CcspTraceInfo(("HOTSPOT_LIB : call back not registered %s....\n", __FUNCTION__));
    }
#if 0
    CCSP_MESSAGE_BUS_INFO *bus_info = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
    parameterValStruct_t  param_val[4];
    char  component[64]  = "eRT.com.cisco.spvtg.ccsp.pam";
    char dstPath[64]="/com/cisco/spvtg/ccsp/pam";
    const char priEndpoint[256] = "Device.X_COMCAST-COM_GRE.Tunnel.1.PrimaryRemoteEndpoint"; 
    const char secEndpoint[256] = "Device.X_COMCAST-COM_GRE.Tunnel.1.SecondaryRemoteEndpoint";
    const char xfinityenable[256] = "Device.DeviceInfo.X_COMCAST_COM_xfinitywifiEnable";
    char buff[20] = {0};
    char* faultParam      = NULL;
    int   ret             = 0;

    CcspTraceInfo(("HOTSPOT_LIB : Entering function %s....\n", __FUNCTION__));
    
    param_val[0].parameterName = (char *)priEndpoint;
    //strcpy(param_val[0].parameterValue, gPriEndptIP);
    param_val[0].parameterValue = gPriEndptIP;
    param_val[0].type = ccsp_string;

    param_val[1].parameterName = (char *)secEndpoint;
    //strcpy(param_val[1].parameterValue, gSecEndptIP);
    param_val[1].parameterValue = gSecEndptIP;
    param_val[1].type = ccsp_string;
    (true == gXfinityEnable) ?
       strcpy(buff, "true"):
       strcpy(buff,"false");
    param_val[2].parameterName = (char *)xfinityenable;
    param_val[2].parameterValue = buff;
    param_val[2].type = ccsp_boolean;
    CcspTraceInfo(("HOTSPOT_LIB : sync params...\n"));
     
    ret = CcspBaseIf_setParameterValues(
            bus_handle,
            component,
            dstPath,
            0,
            0x0,
            param_val,
            3,
            TRUE,
            &faultParam
            );
    if( ( ret != CCSP_SUCCESS ) && ( faultParam!=NULL )) {
            CcspTraceError((" tunnel set bus failed = %s\n"));
            bus_info->freefunc( faultParam );
            return FALSE;
    }
#endif
    return TRUE;
}


static void sys_execute_cmd(char *cmd){

    CcspTraceInfo(("HOTSPOT_LIB : Entering  %s\n", __FUNCTION__));
    system(cmd);
    return;
}

int gre_sysevent_syscfg_init()
{
    gSyseventfd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION,
                                               "hotspot_service", &gSysevent_token);

    if (gSyseventfd < 0)
    {
         CcspTraceError(("HOTSPOT_LIB : sysevent_open failed in %s \n", __FUNCTION__));
         return 1;
    }
    return 0;
}

int update_bridge_config(int index) {
    int retVal = 0;
    char rule[1024]={0}, query[500]={0}, param[500]={0};
#if defined(_COSA_INTEL_XB3_ARM_)
    char liveNetBuf[300]={0};
    char outBuf[300]={0};
    int len = 0;
#endif

    CcspTraceInfo(("HOTSPOT_LIB : Entering function %s to set sysevent parameters Index=%d\n",
        __FUNCTION__, index));

    if (index >= 0) {
        memset(rule,'\0',sizeof(rule));
        memset(query,'\0',sizeof(query));
        memset(param, '\0', sizeof (param));
        snprintf(rule, sizeof(rule),"-A FORWARD -o %s -p udp --dport=67:68 -j NFQUEUE --queue-bypass --queue-num %d",
                gVlanSyncData[index].bridgeName, gVlanSyncData[index].queue_num );
        snprintf(param, sizeof(param), "gre_1_%s_snoop_rule", gVlanSyncData[index].bridgeName);
        sysevent_set_unique(gSyseventfd, gSysevent_token, "GeneralPurposeFirewallRule", rule, query, sizeof(query));
        sysevent_set(gSyseventfd, gSysevent_token, param, query, 0);

#if defined(_COSA_INTEL_XB3_ARM_)
        sysevent_get(gSyseventfd, gSysevent_token, "multinet-instances", liveNetBuf, sizeof(liveNetBuf));
        CcspTraceInfo(("HOTSPOT_LIB :  %s - sysevent live buff =%s\n", __FUNCTION__, liveNetBuf));
        strcpy(outBuf, liveNetBuf);
        len = strlen(outBuf);
        snprintf(outBuf + len, sizeof(outBuf) - len, "%s%d", len ? " " : "", gVlanSyncData[index].instance);
        CcspTraceInfo(("HOTSPOT_LIB :  %s - sysevent parameter Index=%s\n", __FUNCTION__, outBuf));
        sysevent_set(gSyseventfd, gSysevent_token, "multinet-instances", outBuf,0);
        memset(param, '\0', sizeof (param));
        snprintf(param, sizeof(param), "multinet_%d-localready", gVlanSyncData[index].instance);
        CcspTraceInfo(("HOTSPOT_LIB :  %s - multinet local ready =%s\n", __FUNCTION__, param));
        sysevent_set(gSyseventfd, gSysevent_token, param, "1", 0);
        memset(param, '\0', sizeof (param));
        snprintf(param, sizeof(param), "multinet_%d-name", gVlanSyncData[index].instance);
        CcspTraceInfo(("HOTSPOT_LIB :  %s - multinet name =%s\n", __FUNCTION__, param));
        sysevent_set(gSyseventfd, gSysevent_token, param, gVlanSyncData[index].bridgeName, 0);
#endif

    } else {
      CcspTraceError(("HOTSPOT_LIB : %s Invalid Index=%d\n", __FUNCTION__, index));
      retVal = -1;
    }
    return retVal;
}

void firewall_restart() {
    sysevent_set(gSyseventfd, gSysevent_token, "firewall-restart", NULL, 0);
}

static int hotspot_sysevent_disable_param(){

    sysevent_get(gSyseventfd, gSysevent_token, "hotspot_1-status", 
                                                 NULL, 0);
    return 0;
}

#if defined (_XER5_PRODUCT_REQ_)
static int is_wan_started(){
  
   char wan_status_Value[256] = {0};
   if ( 0 == sysevent_get(gSyseventfd, gSysevent_token, "wan-status", wan_status_Value, sizeof(wan_status_Value)) && '\0' != wan_status_Value[0])
   {
        if (0 == strncmp(wan_status_Value, "started", strlen("started")))
        {
          return 1;
        }
   }
   return 0;
}

static char *get_local_ipv4_address (char *buf, size_t len)
{
    

    CcspTraceInfo(("HOTSPOT_LIB : Entering get_local_ipv4_address\n"));

    if (len == 0)
        return NULL;
    if ( 0 == sysevent_get(gSyseventfd, gSysevent_token, "current_wan_ipaddr", buf, len) && '\0' != buf[0])
    {
       CcspTraceInfo(("HOTSPOT_LIB : Local ipv4 address = %s \n", buf));
       return buf;
    }
    else 
    {
        CcspTraceWarning(("HOTSPOT_LIB : local wan interface has no Global IPv4 address\n"));
        return NULL;
    }

    return NULL;
}
#endif

static char *get_local_ipv6_address (char *buf, size_t len)
{
    FILE *fp;

    CcspTraceInfo(("HOTSPOT_LIB : Entering get_local_ipv6_address\n"));

    if (len == 0)
        return NULL;

    /*
       Output may contain multiple addresses. We rely on the single fgets()
       call below to extract the first one.
    */
    if ((fp = popen("ip addr show erouter0 | grep -w global | awk '/inet6/ {print $2}' | cut -d/ -f1", "r")) == NULL) {
        CcspTraceError(("HOTSPOT_LIB : Popen Error\n"));
        return NULL;
    }

    if (fgets(buf, len, fp) != NULL) {
        len = strlen(buf);
        if ((len > 0) && (buf[len - 1] == '\n'))
            buf[len - 1] = '\0';
    }
    else {
        buf[0] = 0;
    }

    pclose(fp);

    if (buf[0]) {
        CcspTraceInfo(("HOTSPOT_LIB : Local ipv6 address = %s \n", buf));
    }
    else {
        CcspTraceWarning(("HOTSPOT_LIB : local wan interface has no Global IPv6 address\n"));
    }

    return buf;
}

int ipAddress_version(char *ipAddress){
    unsigned char buf[sizeof(struct in6_addr)] = {0};
    if (inet_pton(AF_INET, ipAddress, buf))
        return 4;
    else if (inet_pton(AF_INET6, ipAddress, buf))
        return 6;
    CcspTraceError(("HOTSPOT_LIB : %s Invalid IP Address\n", __FUNCTION__));
    return -1;
}

int create_tunnel(char *gre_primary_endpoint){

   char   cmdBuf[1024] = {0};
   int    offset = 0;
   int    retValue = 0;
   int    ip_version = -1;

   
         memset(cmdBuf, '\0', sizeof(cmdBuf));

         CcspTraceInfo(("HOTSPOT_LIB : Entering %s ...gSyseventfd = %d \n", __FUNCTION__, gSyseventfd));
         if (0 == gSyseventfd){
             retValue =  gre_sysevent_syscfg_init();
             if(1 == retValue){
                   CcspTraceError(("HOTSPOT_LIB : Sysevent failed in create_tunnel\n"));
                   return retValue;
             }
         }
         CcspTraceInfo(("HOTSPOT_LIB : Rename the default gretap0 interface present in yocto\n"));
         offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "%s dev %s name %s; ", IP_SET, GRE_IFNAME, GRE_IFNAME_DUMMY);
         sys_execute_cmd(cmdBuf);
         memset(cmdBuf, '\0', sizeof(cmdBuf));
         offset = 0;
         ip_version = ipAddress_version(gre_primary_endpoint);
         CcspTraceInfo(("HOTSPOT_LIB : Creating IPv%d GRE tunnel\n", ip_version));
         if (ip_version == 4){
#if defined (_XER5_PRODUCT_REQ_)
            // XER5-1049 
            // Qualcomm only support adding tunnel with local IP
            char local_Ipv4Address[INET_ADDRSTRLEN] = {0};
            int timeOut = 60;
	    while(!is_wan_started() && timeOut > 0)
            {
              CcspTraceWarning(("HOTSPOT_LIB : Waiting %dsec for wan to start\n",timeOut));
              sleep(1);
              timeOut--;
            }
            if (get_local_ipv4_address(local_Ipv4Address, sizeof(local_Ipv4Address)) != NULL)
            {
                offset += snprintf(cmdBuf+offset,
                              sizeof(cmdBuf) - offset,
                              "%s %s type gretap local %s remote %s dev erouter0  dsfield b0 nopmtudisc;",
                              IP_ADD, GRE_IFNAME, local_Ipv4Address, gre_primary_endpoint);
            }
            else
            {
                CcspTraceWarning(("HOTSPOT_LIB : Unable to create gretap0 interface since erouter0 doen't have global IPv4\n"));
                 return -1;
            }
#else

             offset += snprintf(cmdBuf+offset,
                              sizeof(cmdBuf) - offset,
                              "%s %s type gretap remote %s dev erouter0  dsfield b0 nopmtudisc;",
                              IP_ADD, GRE_IFNAME, gre_primary_endpoint);
#endif
         }else if (ip_version == 6){
             char local_Ipv6Address[INET6_ADDRSTRLEN];
             if (get_local_ipv6_address(local_Ipv6Address, sizeof(local_Ipv6Address)) != NULL)
             {
                 offset += snprintf(cmdBuf+offset,
                              sizeof(cmdBuf) - offset,
                              "%s name %s type ip6gretap local %s remote %s encaplimit none;",
                              IP_ADD, GRE_IFNAME, local_Ipv6Address, gre_primary_endpoint);
             }
             else
             {
                 CcspTraceWarning(("HOTSPOT_LIB : Unable to create gretap0 interface\n"));
                 return -1;
             }
         }

         #if defined (_ARRIS_XB6_PRODUCT_REQ_) || defined (INTEL_PUMA7)
         offset += snprintf(cmdBuf+offset,
                               sizeof(cmdBuf) - offset,
                               "%s %s txqueuelen 1000 mtu 1500;", IP_SET, GRE_IFNAME);
         #endif
	 CcspTraceInfo(("HOTSPOT_LIB : Adding gretap0 to the Flowmgr \n"));
	 offset += snprintf(cmdBuf+offset, sizeof(cmdBuf) - offset,"echo addif %s wan > /proc/driver/flowmgr/cmd;",GRE_IFNAME);

         CcspTraceInfo(("HOTSPOT_LIB : ROLLBACK Buffer 1 gre add = %s %d\n", cmdBuf, offset));
         if (offset)
             sys_execute_cmd(cmdBuf);
	 return 0;
}

static int deleteVaps(){

     char   cmdBuf[1024];
     int    offset = 0;
     int    index = 0;

     CcspTraceInfo(("HOTSPOT_LIB : Entering %s\n", __FUNCTION__));

     for(index = 0; index < MAX_VAP; index++){
            offset = 0;
            memset(cmdBuf, '\0', sizeof(cmdBuf));
#if !defined(_COSA_INTEL_XB3_ARM_) && !defined(RDK_ONEWIFI)
            offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "%s %s ; ",
                                  IP_DEL, gVlanSyncData[index].vapInterface);
#endif
            offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "%s %s ; ", IP_DEL, gVlanSyncData[index].bridgeName);
            offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "%s %s ;", IP_DEL, GRE_IFNAME);

            CcspTraceInfo(("HOTSPOT_LIB : Buffer 3 gre add = %s %d\n", cmdBuf, offset));
            if (offset)
               sys_execute_cmd(cmdBuf);
      }
      memset(cmdBuf, '\0', sizeof(cmdBuf));
      CcspTraceInfo(("HOTSPOT_LIB : Stopping Hotspot...\n"));
      strncpy(cmdBuf, "killall CcspHotspot", SIZE_CMD);
      sys_execute_cmd(cmdBuf);


      memset(cmdBuf, '\0', sizeof(cmdBuf));
      CcspTraceInfo(("HOTSPOT_LIB : Stopping Hotspot arpd...\n"));
      strncpy(cmdBuf, "killall hotspot_arpd", SIZE_CMD);
      sys_execute_cmd(cmdBuf);
      return 0;
}

static void hotspot_async_reg()
{
    char cmdBuff[300] = {0};
    CcspTraceInfo(("HOTSPOT_LIB : configuring sysevent async....\n"));
    snprintf(cmdBuff, sizeof(cmdBuff), "%s %s", GRE_ASYNC_HOT_EP, GRE_PATH);
    CcspTraceInfo(("HOTSPOT_LIB : sysevent content %s\n", cmdBuff));
    sys_execute_cmd(cmdBuff);

    memset(cmdBuff, '\0', sizeof(cmdBuff));
    FILE* file = fopen(GRE_FILE, "r");
    if(file)
    {
        int len=20;
        char name[30]={0};
        if (fgets(name, len, file) != NULL)
        {
           CcspTraceInfo(("HOTSPOT_LIB : gre ep sync event %s\n", name));
           sysevent_set(gSyseventfd, gSysevent_token, GRE_EP_ASYNC, name, 0);
        }
        if( file!= NULL)
        {
           fclose(file);
        }
    }
}

int hotspot_sysevent_enable_param(){

    char cmdBuff[100] = {0};

    CcspTraceInfo(("HOTSPOT_LIB : Entering function %s to set sysevent parameters gSyseventfd = %d\n",__FUNCTION__, gSyseventfd));
    sysevent_set(gSyseventfd, gSysevent_token, "snooper-circuit-enable", "1", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "snooper-remote-enable", "1", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-primary", gPriEndptIP, 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-secondary", gSecEndptIP, 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-threshold", "3", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-keep-alive", "60", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-max-secondary", "43200", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-policy", "1", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-count", "3", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-dead-interval", "300", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-enable", "1", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "hotspotfd-log-enable", "1", 0);
    sysevent_set(gSyseventfd, gSysevent_token, "gre_current_endpoint", gPriEndptIP, 0);
    if((ipAddress_version(gPriEndptIP) == 6) || (ipAddress_version(gSecEndptIP) == 6))
    {
        CcspTraceInfo(("HOTSPOT_LIB : Add firewall rule to accept IPv6 GRE packets\n"));
        sysevent_set(gSyseventfd, gSysevent_token, "gre_ipv6_fw_rule", " -A INPUT -i erouter0 -p gre -j ACCEPT", 0);
    }
    else
    {
        sysevent_set(gSyseventfd, gSysevent_token, "gre_ipv6_fw_rule", "", 0);
    }
    if((ipAddress_version(gPriEndptIP) == 4) || (ipAddress_version(gSecEndptIP) == 4))
    {
        CcspTraceInfo(("HOTSPOT_LIB :  Add firewall rule to accept IPv4 GRE packets\n"));
        sysevent_set(gSyseventfd, gSysevent_token, "gre_ipv4_fw_rule", " -A INPUT -i erouter0 -p gre -j ACCEPT", 0);
    }
    else
    {
        sysevent_set(gSyseventfd, gSysevent_token, "gre_ipv4_fw_rule", "", 0);
    }
    /*sysevent_get(gSyseventfd, gSysevent_token, "gre_current_endpoint", 
                                                 currentTunIP, sizeof(currentTunIP)); 

      sysevent_get(gSyseventfd, gSysevent_token, "hotspot_1-status", 
                                                 hotspotStatus, sizeof(hotspotStatus)); 
    */
    //TODO: This will be moved to CcspHotspot and new API in library to reverse
    //the tunnel
    if( access(GRE_FILE, F_OK) == 0 )
    {
        CcspTraceInfo(("HOTSPOT_LIB : sysevent async for handle_gre.sh is already configured\n"));
    }
    else
    {
        hotspot_async_reg();
    }
    memset(cmdBuff, '\0', sizeof(cmdBuff));
    CcspTraceInfo(("HOTSPOT_LIB : Stopping existing Hotspot...\n"));
    strncpy(cmdBuff, "killall CcspHotspot", SIZE_CMD);
    sys_execute_cmd(cmdBuff);

    memset(cmdBuff, '\0', sizeof(cmdBuff));
    CcspTraceInfo(("HOTSPOT_LIB : Starting Hotspot...\n"));
    strncpy(cmdBuff, "/usr/bin/CcspHotspot -subsys eRT.", SIZE_CMD);
    sys_execute_cmd(cmdBuff);


    memset(cmdBuff, '\0', sizeof(cmdBuff));
    CcspTraceInfo(("HOTSPOT_LIB : Starting Hotspot arpd...\n"));
    strncpy(cmdBuff, "/usr/bin/hotspot_arpd -q 0", SIZE_CMD);
    sys_execute_cmd(cmdBuff);

    return 0;
}


static void addBrideAndVlan(int vlanIndex, int wan_vlan){
     char   cmdBuf[1024] = {0};
     int    offset = 0;

     if( -1 == vlanIndex) {
         CcspTraceInfo(("HOTSPOT_LIB : %s Invalid Index for the  vlan id: %d\n",
             __FUNCTION__, wan_vlan));
         return;
     }

     CcspTraceInfo(("HOTSPOT_LIB : Adding Bride and vlan configuration: vlan id: %d vlanIndex: %d\n",
             wan_vlan, vlanIndex));
     memset(cmdBuf, '\0', sizeof(cmdBuf));
     offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "brctl addbr %s; ", gVlanSyncData[vlanIndex].bridgeName);    
     offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "ifconfig %s up; ", gVlanSyncData[vlanIndex].bridgeName);    

     if((oldTunnelData.Vlans[vlanIndex] !=0) && (oldTunnelData.Vlans[vlanIndex] != wan_vlan)){
         CcspTraceInfo(("HOTSPOT_LIB : Deleting Vlan interface gretap0.%d ...\n",oldTunnelData.Vlans[vlanIndex]));
         offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "ip link del gretap0.%d; ", oldTunnelData.Vlans[vlanIndex]);
         #if defined (_ARRIS_XB6_PRODUCT_REQ_)
         CcspTraceInfo(("HOTSPOT_LIB : Deleting Vlan interface nmoca0.%d ...\n",oldTunnelData.Vlans[vlanIndex]));
         offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "ip link del nmoca0.%d; ", oldTunnelData.Vlans[vlanIndex]);
         #endif
     }

     offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "vconfig add %s %d; ",GRE_IFNAME, wan_vlan);  
     offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "brctl addif %s %s.%d; ", gVlanSyncData[vlanIndex].bridgeName, GRE_IFNAME, wan_vlan);    
     offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "ifconfig %s up; ",GRE_IFNAME);    
     offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "ifconfig %s.%d up; ",GRE_IFNAME, wan_vlan);    
     /* Add platform specific flag */
     #if defined (_ARRIS_XB6_PRODUCT_REQ_)
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "vconfig add %s %d; ",NMOCA_IFNAME, wan_vlan);
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "brctl addif %s %s.%d; ",gVlanSyncData[vlanIndex].bridgeName,NMOCA_IFNAME, wan_vlan);
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "ifconfig %s up; ", NMOCA_IFNAME);                                                                               
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "ifconfig %s.%d up; ", NMOCA_IFNAME, wan_vlan); 
     #endif
     #if defined(_COSA_INTEL_XB3_ARM_)
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "vconfig add %s %d; ",L2SD0_IFNAME, wan_vlan);
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "brctl addif %s %s.%d; ",gVlanSyncData[vlanIndex].bridgeName, L2SD0_IFNAME, wan_vlan);
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "ifconfig %s up; ", L2SD0_IFNAME);
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "ifconfig %s.%d up; ",L2SD0_IFNAME, wan_vlan);
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "swctl -c 16 -p 7 -v %d -m 2 -q 1; ", wan_vlan);
     offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "swctl -c 16 -p 0 -v %d -m 2 -q 1; ", wan_vlan);
     #endif

     CcspTraceInfo(("HOTSPOT_LIB : Buffer 2 gre add = %s %d\n", cmdBuf, offset));
     if (offset)
        sys_execute_cmd(cmdBuf);

     if(vlanIndex == VLAN_INDEX_1){
         t2_event_d("XWIFI_VLANID_6_split", wan_vlan);
     }
     if(vlanIndex == VLAN_INDEX_3){
         t2_event_d("XWIFI_VLANID_10_split", wan_vlan);
     }
     if(vlanIndex == VLAN_INDEX_4){
         t2_event_d("XWIFI_VLANID_19_split", wan_vlan);
     }
     if(vlanIndex == VLAN_INDEX_5){
         t2_event_d("XWIFI_VLANID_21_split", wan_vlan);
     }
}

int getHotspotVapIndex(char *vapName) {
     CcspTraceInfo(("HOTSPOT_LIB : Vapname received for brige config:%s \n", vapName));


     if (strcmp(vapName, VAP_NAME_4)==0){
          return VLAN_INDEX_0;
     }
     else if (strcmp(vapName, VAP_NAME_5)==0){
          return VLAN_INDEX_1;
     }
     else if (strcmp(vapName, VAP_NAME_8)==0){
          return VLAN_INDEX_2;
     }
     else if (strcmp(vapName, VAP_NAME_9)==0){
          return VLAN_INDEX_3;
     }
#if defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
     else if (strcmp(vapName, VAP_NAME_11)==0){
          return VLAN_INDEX_4;
     }
     else if (strcmp(vapName, VAP_NAME_12)==0){
          return VLAN_INDEX_5;
     }
#endif
     else{
        CcspTraceInfo(("HOTSPOT_LIB : %s Vap name not matched \n", __FUNCTION__));
        return -1;
     }
}

void configHotspotBridgeVlan(char *vapName, int wan_vlan){
     CcspTraceInfo(("HOTSPOT_LIB : Vapname received for brige config:%s \n", vapName));
     addBrideAndVlan( getHotspotVapIndex( vapName), wan_vlan);
}

int  validateIpAddress(char *ipAddress){
    int result = -1;
    unsigned char buf[sizeof(struct in6_addr)] = {0};
    CcspTraceInfo(("HOTSPOT_LIB : Entering %s function....... \n", __FUNCTION__));
    result = inet_pton(AF_INET, ipAddress, buf);
    if(result == 1){
         if((0 == strcmp(ipAddress, "255.255.255.255")) ||
                 (0 == strcmp(ipAddress, "0.0.0.0"))){
           CcspTraceInfo(("HOTSPOT_LIB :  %s IP is either 0.0.0.0 or 255.255.255.255....... \n", __FUNCTION__));
           result = 0;
         }
    } else if (inet_pton(AF_INET6, ipAddress, buf)) {
        result = 1;
    }
    return result;

}

bool get_ssid_enable(int ssidIdx)
{
    int ret = ANSC_STATUS_FAILURE;
    parameterValStruct_t    **valStructs = NULL;
    char dstComponent[64]="eRT.com.cisco.spvtg.ccsp.wifi";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";
    const char ap[128]={0};
    char *paramNames[]={(char *)ap};
    int  valNum = 0;
    bool retVal = false;

    snprintf ( (char *)ap, sizeof(ap), "Device.WiFi.SSID.%d.Enable", ssidIdx);
 

    ret = CcspBaseIf_getParameterValues(
            bus_handle,
            dstComponent,
            dstPath,
            paramNames,
            1,
            &valNum,
            &valStructs);
    
    if(CCSP_Message_Bus_OK != ret){
         CcspTraceError(("%s hotspot_getParameterValues %s error %d\n", __FUNCTION__,paramNames[0],ret));
    }    
    

    if(valStructs)
    {    
          CcspTraceInfo(("Retrieving ssid info for ssid %d = %s\n", ssidIdx, valStructs[0]->parameterValue));
          retVal = (strcmp( valStructs[0]->parameterValue, "true") == 0) ? true : false;
    }
    free_parameterValStruct_t(bus_handle, valNum, valStructs);
    return retVal;
}

int
PsmGet(const char *param, char *value, int size)
{
    char *val = NULL;

    if (PSM_Get_Record_Value2(bus_handle, g_Subsystem,
                (char *)param, NULL, &val) != CCSP_SUCCESS)
        return -1;

    if(val) {
        snprintf(value, size, "%s", val);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(val);
    }
    else return -1;

    return 0;
}

int 
PsmSet(const char *param, const char *value)
{
    if (PSM_Set_Record_Value2(bus_handle, g_Subsystem,
                (char *)param, ccsp_string, (char *)value) != CCSP_SUCCESS){
        CcspTraceError(("HOTSPOT_LIB : PSM set is unsuccessful \n"));
        return -1;
    }
    CcspTraceInfo(("HOTSPOT_LIB : PSM Set for %s with value %s is successful \n", param, value));
    return 0;
}

int prepareFirstRollback(){
    CcspTraceInfo(("HOTSPOT_LIB : Entering %s function....... \n", __FUNCTION__));
    int ret = 0;

    ret  = jansson_store_tunnel_info(NULL);
    CcspTraceInfo(("HOTSPOT_LIB : %s Ret status.......%d \n", __FUNCTION__, ret));

    if(ret > 0){
       if(ret == 2){
           return ret;
       }
       return ret;
    }else{
       return ret;    
    }
//TODO: Find the delta and then store if needed
}

bool prevalidateHotspotBlob(tunneldoc_t *pGreTunnelData)
{
    int index = 0;
    int vlanid = 0;
    if((validateIpAddress(pGreTunnelData->entries->gre_primary_endpoint) != 1))
    {
        CcspTraceError(("HOTSPOT_LIB : Invalid Primary Endpoint IP\n"));
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg,"Invalid Primary Endpoint IP",sizeof(execRetVal->ErrorMsg)-1);
        return false;
    }
    if(pGreTunnelData->entries->table_param->entries_count > MAX_VAP)
    {
        CcspTraceError(("HOTSPOT_LIB : Invalid VAP count\n"));
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg,"Invalid VAP count",sizeof(execRetVal->ErrorMsg)-1);
        return false;
    }
    for(index = 0; index < pGreTunnelData->entries->table_param->entries_count; index++)
    {
        vlanid = pGreTunnelData->entries->table_param->entries[index].wan_vlan;
        if(!((vlanid >= 102) && (vlanid <= 4094)))
        {
            CcspTraceError(("HOTSPOT_LIB : Vlan ID is out of range for index %d\n", index));
            execRetVal->ErrorCode = VALIDATION_FALIED;
            strncpy(execRetVal->ErrorMsg,"Vlan ID is out of range",sizeof(execRetVal->ErrorMsg)-1);
            return false;
        }
        if(getHotspotVapIndex(pGreTunnelData->entries->table_param->entries[index].vap_name) == -1)
        {
            CcspTraceError(("HOTSPOT_LIB : Vap Name incorrect for index %d\n ", index));
            execRetVal->ErrorCode = VALIDATION_FALIED;
            strncpy(execRetVal->ErrorMsg,"Incorrect VAP name",sizeof(execRetVal->ErrorMsg)-1);
            return false;
        }
    }
    CcspTraceInfo(("HOTSPOT_LIB : Pre-validation done successfully\n"));
    return true;
}

int compareTunnelConfig(){

    CcspTraceInfo(("HOTSPOT_LIB : Entering  %s\n", __FUNCTION__));
    int return_status = 0;
    int ind = -1;
    errno_t rc = -1;

    if(oldTunnelData.isFirst == true){
       CcspTraceInfo(("HOTSPOT_LIB : All the parameters are considered as changed, as this the first time.\n"));
#if defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
       return_status = PRIMARY_EP_CHANGED | SECONDARY_EP_CHANGED | VLAN_CHANGE_1 | VLAN_CHANGE_2 | VLAN_CHANGE_3 | VLAN_CHANGE_4 | VLAN_CHANGE_5 | VLAN_CHANGE_6;
       return return_status;
#else
       return_status = PRIMARY_EP_CHANGED | SECONDARY_EP_CHANGED | VLAN_CHANGE_1 | VLAN_CHANGE_2 | VLAN_CHANGE_3 | VLAN_CHANGE_4;
       return return_status;
#endif
    }

    if (oldTunnelData.gre_enable != tempTunnelData->entries->gre_enable) {
        return_status |= GRE_ENABLE_CHANGE;
        CcspTraceInfo(("HOTSPOT_LIB : gre_enable changed: %d -> %d\n", oldTunnelData.gre_enable, tempTunnelData->entries->gre_enable));
    }

    rc = strcmp_s(oldTunnelData.primaryEP, sizeof(oldTunnelData.primaryEP), tempTunnelData->entries->gre_primary_endpoint, &ind);
    ERR_CHK(rc);
    if ((ind != 0) && (rc == EOK)) {
        return_status |= PRIMARY_EP_CHANGED;
        CcspTraceInfo(("HOTSPOT_LIB : gre_primary_endpoint changed: %s -> %s\n", oldTunnelData.primaryEP, tempTunnelData->entries->gre_primary_endpoint));
    }

    rc = strcmp_s(oldTunnelData.secondaryEP, sizeof(oldTunnelData.secondaryEP), tempTunnelData->entries->gre_sec_endpoint, &ind);
    ERR_CHK(rc);
    if ((ind != 0) && (rc == EOK)) {
        return_status |= SECONDARY_EP_CHANGED;
        CcspTraceInfo(("HOTSPOT_LIB : gre_sec_endpoint changed: %s -> %s\n", oldTunnelData.secondaryEP, tempTunnelData->entries->gre_sec_endpoint));
    }
    for (int i = 0; i < tempTunnelData->entries->table_param->entries_count; i++){
        if (oldTunnelData.Vlans[i] != tempTunnelData->entries->table_param->entries[i].wan_vlan) {
            return_status |= VLAN_CHANGE_BASE << (i + 1);
            CcspTraceInfo(("HOTSPOT_LIB : vlan_interface_%d changed: %d -> %d\n", i+1, oldTunnelData.Vlans[i], tempTunnelData->entries->table_param->entries[i].wan_vlan));
    }
    }
    return return_status;

}

pErr setHotspot(void* const network){

     //greTunnelData_s *pGreTunnelData = NULL;
     tunneldoc_t     *pGreTunnelData = NULL;
     int    retValue = 0;
     int    index = 0;
     int    vlanid = 0;
     char   cmdBuf[1024] = {0};
     int   status = 0;
     int   file_status = 0;
     char val[16] = {0};
     bool secTunInvalid = false;
     bool epChanged = false;
     int paramsChanged;
//Check if this is the very first webconfig on this device and if legacy 
//hotspot was enabled , if so store the previous configuration for the rollback 
//Check with Wifi team also , if they woudl be able to rollback to previous

     CcspTraceInfo(("HOTSPOT_LIB : Entering %s function....... \n", __FUNCTION__));
     execRetVal = (pErr) malloc (sizeof(Err));
     if (execRetVal == NULL ){
          CcspTraceError(("HOTSPOT_LIB : Malloc failed in %s \n", __FUNCTION__));
          return execRetVal;
     }

     memset((char *)execRetVal,0,sizeof(Err));

     memset(cmdBuf, '\0', sizeof(cmdBuf));

     if(NULL == network){
          execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
          return execRetVal;
     }

     pGreTunnelData = (tunneldoc_t *)network;
     tempTunnelData = (tunneldoc_t *)malloc(sizeof(tunneldoc_t));
     memcpy(tempTunnelData, pGreTunnelData, sizeof(tunneldoc_t));
 
     PsmGet(PSM_HOTSPOT_ENABLE, val, sizeof(val));
     file_status = access(N_HOTSPOT_JSON, F_OK);
     CcspTraceInfo(("HOTSPOT_LIB : %s Existing Xfinity settings: enabled == %s jsone file_status = %d....... \n", __FUNCTION__, val, file_status));
     if((file_status != 0) && (atoi(val) == TRUE)){
           CcspTraceInfo(("HOTSPOT_LIB : Very first blob and existing hotspot exists, prepare the rollback %s \n", __FUNCTION__));
           status  =  prepareFirstRollback();

           if(1 == status){
               CcspTraceInfo(("HOTSPOT_LIB : Legacy config Stored...  %s \n", __FUNCTION__));
           }else {
                 if(2 == status){
                     CcspTraceInfo(("HOTSPOT_LIB : Invalid IP address in exist legacy config...  %s \n", __FUNCTION__));
                 }
           }
   
     }
     else {
          if(file_status == 0){
           CcspTraceInfo(("HOTSPOT_LIB : hotspot.json file available in nvram.  %s \n", __FUNCTION__));
          } else{
     
            CcspTraceInfo(("HOTSPOT_LIB : Previously Xfinity was disabled, no need to prepare rollback data  %s \n", __FUNCTION__));
          }
     }
     paramsChanged = compareTunnelConfig();
     CcspTraceInfo(("HOTSPOT_LIB : return status of the params changed...  %d \n", paramsChanged));

     if(paramsChanged == 0){
         CcspTraceInfo(("HOTSPOT_LIB : Nothing is changed from tunnel side, No need to recreate...\n"));
         jansson_store_tunnel_info(pGreTunnelData);
         gXfinityEnable = oldTunnelData.gre_enable;
         memset(cmdBuf, '\0', sizeof(cmdBuf));
         CcspTraceInfo(("HOTSPOT_LIB : Creating /tmp/.hotspot_blob_inprogress\n"));
         strncpy(cmdBuf, "touch /tmp/.hotspot_blob_inprogress", SIZE_CMD);
         sys_execute_cmd(cmdBuf);
         execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
         return execRetVal;
     }

     if(true == pGreTunnelData->entries->gre_enable){
 
         if (0 == gSyseventfd){
             retValue =  gre_sysevent_syscfg_init();
             if(1 == retValue){
                   CcspTraceError(("HOTSPOT_LIB : Sysevent failed in set Hotspot \n"));
                   execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
                   return execRetVal;
             }
         }
         if(!prevalidateHotspotBlob(pGreTunnelData))
         {
             CcspTraceError(("HOTSPOT_LIB : Invalid Blob. Not applying the new settings.\n"));
             return execRetVal;
         }
         if((validateIpAddress(pGreTunnelData->entries->gre_sec_endpoint) != 1))
         {
             CcspTraceInfo(("HOTSPOT_LIB : Invalid Secondary Endpoint IP\n"));
             secTunInvalid = true;
         }
         memset(gPriEndptIP, '\0', sizeof(gPriEndptIP));
         memset(gSecEndptIP, '\0', sizeof(gSecEndptIP));
         strncpy(gPriEndptIP, pGreTunnelData->entries->gre_primary_endpoint,SIZE_OF_IP - 1);
         if(secTunInvalid)
         {
             CcspTraceInfo(("HOTSPOT_LIB : Secondary endpoint ip is invalid, Using primary EP IP \n"));
             strncpy(gSecEndptIP, gPriEndptIP, SIZE_OF_IP - 1);
         }
         else
         {
             strncpy(gSecEndptIP, pGreTunnelData->entries->gre_sec_endpoint,SIZE_OF_IP - 1);
         }
         gXfinityEnable = true;
         memset(cmdBuf, '\0', sizeof(cmdBuf));
         CcspTraceInfo(("HOTSPOT_LIB : Creating /tmp/.hotspot_blob_inprogress\n"));
         strncpy(cmdBuf, "touch /tmp/.hotspot_blob_inprogress", SIZE_CMD);
         sys_execute_cmd(cmdBuf);
    /* Deleting existing Tunnels*/
         //deleteVaps();
         if ((paramsChanged & PRIMARY_EP_CHANGED) || (paramsChanged & SECONDARY_EP_CHANGED) || (paramsChanged & GRE_ENABLE_CHANGE)){
             epChanged = true;
             if((oldTunnelData.isFirst == false) && (oldTunnelData.gre_enable == true)){
                 memset(cmdBuf, '\0', sizeof(cmdBuf));
                 CcspTraceInfo(("HOTSPOT_LIB : deleting the gre tunnel...\n"));
                 strncpy(cmdBuf, "ip link del gretap0", SIZE_CMD);
                 sys_execute_cmd(cmdBuf);
             }
             create_tunnel( pGreTunnelData->entries->gre_primary_endpoint);
         }
         CcspTraceInfo(("HOTSPOT_LIB : Number of VAP received in blob: %zu \n", pGreTunnelData->entries->table_param->entries_count));
         memset(vlanIdList, '\0', sizeof(vlanIdList));

         for(index = 0; index < pGreTunnelData->entries->table_param->entries_count; index++){
              if(true == pGreTunnelData->entries->table_param->entries[index].enable){
                       vapBitMask |=  gVlanSyncData[index].bitVal;

                       vlanid = pGreTunnelData->entries->table_param->entries[index].wan_vlan;
//For now keeping it as 200 similar to AC. but this needs to be tweaked or 
//after discussing since l2sd0.xxx may get created in XB3 overlapping the 112,113,1060 vlans
//for the pods.
//check for the return , if some bridges fails, we must return failure
//else wifi will proceed with creating the vap but actually bridges doesnt 
//exists
                       vlanIdList[index] = vlanid;
                   if ((paramsChanged & (VLAN_CHANGE_BASE << (index + 1))) || (epChanged)){
                       configHotspotBridgeVlan(pGreTunnelData->entries->table_param->entries[index].vap_name, vlanid);
                       retValue = update_bridge_config( getHotspotVapIndex(pGreTunnelData->entries->table_param->entries[index].vap_name));
                   }
                   else{
                       continue;
                   }
              }
         }
         jansson_store_tunnel_info(pGreTunnelData);
     }
     else{
         CcspTraceInfo(("HOTSPOT_LIB : Gre is not enabled. Deleting tunnel info \n"));
         deleteVaps();
         hotspot_sysevent_disable_param();
         memset(vlanIdList, '\0', sizeof(vlanIdList));
         memset(gPriEndptIP, '\0', sizeof(gPriEndptIP));
         memset(gSecEndptIP, '\0', sizeof(gSecEndptIP));
         strncpy(gPriEndptIP, "0.0.0.0", SIZE_OF_IP);
         strncpy(gSecEndptIP, "0.0.0.0", SIZE_OF_IP);
         gXfinityEnable = false;
         PsmSet(PSM_HOTSPOT_ENABLE, "0");
         tunnel_param_synchronize();
         vapBitMask = 0x00;
         jansson_store_tunnel_info(pGreTunnelData);
     }
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    return execRetVal;
}

int deleteHotspot(){
     char   cmdBuf[1024];
#if !defined(_COSA_INTEL_XB3_ARM_) && !defined(RDK_ONEWIFI)
     int    offset = 0;
     int    index = 0;
#endif
     bool   ret = FALSE;
     deleteVaps();
     vapBitMask = 0x00;
     CcspTraceInfo(("HOTSPOT_LIB : Entering 'deleteHotspot'\n"));
     // rollback to previous setting ... Read the value from previous legacy hotspot....
     ret = jansson_rollback_tunnel_info();
     if(TRUE == ret){
         CcspTraceInfo(("HOTSPOT_LIB : 'deleteHotspot' rollback success...\n"));
         if(gXfinityEnable == true)
         {
#if !defined(_COSA_INTEL_XB3_ARM_) && !defined(RDK_ONEWIFI)
             for(index = 0; index < MAX_VAP; index++){
                 if (gVlanSyncData[index].bitVal & vapBitMask){
                      memset(cmdBuf, '\0', sizeof(cmdBuf));
                      offset = 0;
                      offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "brctl addif %s %s; ", gVlanSyncData[index].bridgeName, gVlanSyncData[index].vapInterface);
                      CcspTraceInfo(("HOTSPOT_LIB : Buffer 4 gre confirm vap = %s %d\n", cmdBuf, offset));
                      if (offset)
                         sys_execute_cmd(cmdBuf);
                  }
              }
#endif

             vapBitMask = 0x00;
             hotspot_sysevent_enable_param();
             firewall_restart();
             tunnel_param_synchronize();

#if defined(_CBR_PRODUCT_REQ_)
             memset(cmdBuf, '\0', sizeof(cmdBuf));
             sleep(5);
             strncpy(cmdBuf, "killall -q -9 eapd 2>/dev/null", sizeof(cmdBuf)-1);
             sys_execute_cmd(cmdBuf);
             sleep(5);
             CcspTraceInfo(("[%s] [%d]Restarting EAPD.. Buf : [%s]\n", __func__, __LINE__, cmdBuf));
             sys_execute_cmd("eapd");
#endif
         }
         else
         {
             CcspTraceInfo(("HOTSPOT_LIB : Hotspot is Disabled in the rollback setting\n"));
         }
         memset(cmdBuf, '\0', sizeof(cmdBuf));
         CcspTraceInfo(("HOTSPOT_LIB : Removing /tmp/.hotspot_blob_inprogress\n"));
         strncpy(cmdBuf, "rm /tmp/.hotspot_blob_inprogress", SIZE_CMD);
         sys_execute_cmd(cmdBuf);
         free(tempTunnelData);
         tempTunnelData = NULL;

         return ROLLBACK_SUCCESS;
       }
       else{
             vapBitMask = 0x00;
             CcspTraceInfo(("HOTSPOT_LIB : 'deleteHotspot' rollbaack ptr null...\n"));
             memset(cmdBuf, '\0', sizeof(cmdBuf));
             CcspTraceInfo(("HOTSPOT_LIB : Removing /tmp/.hotspot_blob_inprogress\n"));
             strncpy(cmdBuf, "rm /tmp/.hotspot_blob_inprogress", SIZE_CMD);
             sys_execute_cmd(cmdBuf);
             free(tempTunnelData);
             tempTunnelData = NULL;
             return BLOB_EXEC_FAILURE;
       }
}

void populate_old_params_to_structure(){
    CcspTraceInfo(("HOTSPOT_LIB : Entering  %s\n", __FUNCTION__));
    oldTunnelData.gre_enable = tempTunnelData->entries->gre_enable;
    strncpy(oldTunnelData.primaryEP, tempTunnelData->entries->gre_primary_endpoint, sizeof(oldTunnelData.primaryEP)-1);
    oldTunnelData.primaryEP[sizeof(oldTunnelData.primaryEP)-1] = '\0';
    strncpy(oldTunnelData.secondaryEP, tempTunnelData->entries->gre_sec_endpoint, sizeof(oldTunnelData.secondaryEP)-1);
    oldTunnelData.secondaryEP[sizeof(oldTunnelData.secondaryEP)-1] = '\0';
    for(int i =0; i<MAX_VAP; i++){
        oldTunnelData.Vlans[i] = tempTunnelData->entries->table_param->entries[i].wan_vlan;
    }
    oldTunnelData.isFirst = false;
}

int checkGreInterface_Exist(int vlan_ID, char *bridge_name)
{
	FILE *fp = NULL;
	int ret =0;
	char *token = NULL;
    char   gre_Interface[24] = {0};
    memset(gre_Interface, '\0', sizeof(gre_Interface));
    snprintf(gre_Interface, sizeof(gre_Interface), "%s.%d", GRE_IFNAME, vlan_ID);
    char syscmd[1024] = {'\0'};
	char if_list[IFLIST_SIZE] = {'\0'};
        memset(syscmd, 0, sizeof(syscmd));
        snprintf(syscmd, sizeof(syscmd), "brctl show %s | sed '1d' | awk '{print $NF}' | grep %s | tr '\n' ' ' ",bridge_name, gre_Interface);
	fp = popen(syscmd, "r");

	if ( fp != NULL )
	{
		fgets(if_list,IFLIST_SIZE-1,fp);
		if_list[strlen(if_list)-1] = '\0';
		ret = pclose(fp);
		if(ret !=0)
		{
				CcspTraceError(("HOTSPOT_LIB : Error in closing pipe ret val [%d] \n",ret));
		}
	}
	if(strlen(if_list) > 1)
	{
		token = strtok(if_list, " ");
		while(token != NULL)
		{
			if(strcmp(token, gre_Interface) == 0)
			{
				CcspTraceInfo(("HOTSPOT_LIB : %s is attached to %s\n",gre_Interface, bridge_name));
				return INTERFACE_EXIST;
			}
		}
	}
	CcspTraceError(("HOTSPOT_LIB : %s is not attached to %s\n",gre_Interface, bridge_name));
	return INTERFACE_NOT_EXIST;
}

int confirmVap(){
    char   Buf[200] = {0};
#if !defined(_COSA_INTEL_XB3_ARM_)
    char   cmdBuf[1024] = {0};
    int    offset = 0;
    int    index = 0;
#endif
    int    file_status = 0;
 
 
    CcspTraceInfo(("HOTSPOT_LIB : Entering %s \n",__FUNCTION__));
//Test if one vap disabled and another enabled through blob works well with the
//bitmask
//Hows l2sd0.xxx created for the XB3s ?

#if !defined(_COSA_INTEL_XB3_ARM_)
    if(gXfinityEnable) {
        for(int i=0; i<MAX_VAP; i++){
            if(checkGreInterface_Exist(vlanIdList[i], gVlanSyncData[i].bridgeName)){
                CcspTraceError(("HOTSPOT_LIB : %s bridge doesn't have gre_Interface\n", gVlanSyncData[i].bridgeName));
            }
            CcspTraceInfo(("HOTSPOT_LIB : %s have gre_Interface\n", gVlanSyncData[i].bridgeName));
        }
        for(index = 0; index < MAX_VAP; index++){
            if (gVlanSyncData[index].bitVal & vapBitMask){

                memset(cmdBuf, '\0', sizeof(cmdBuf));
                offset = 0;
#if !defined(RDK_ONEWIFI)
                offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "brctl addif %s %s; ", gVlanSyncData[index].bridgeName, gVlanSyncData[index].vapInterface);
#endif
                offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "echo 1 > /sys/class/net/%s/bridge/nf_call_iptables;", gVlanSyncData[index].bridgeName);

                CcspTraceInfo(("HOTSPOT_LIB : Buffer 4 gre confirm vap = %s %d\n", cmdBuf, offset));
                if (offset)
                   sys_execute_cmd(cmdBuf);
            }
        }
     }
#endif
     file_status = access(T_HOTSPOT_JSON, F_OK);

     if(file_status != 0){
           CcspTraceError(("HOTSPOT_LIB : hotspot.json file not available in tmp  %s \n", __FUNCTION__));
           memset(Buf, '\0', sizeof(Buf));
           CcspTraceInfo(("HOTSPOT_LIB : Removing /tmp/.hotspot_blob_inprogress\n"));
           strncpy(Buf, "rm /tmp/.hotspot_blob_inprogress", SIZE_CMD);
           sys_execute_cmd(Buf);
           memset((char *)execRetVal,0,sizeof(Err));
           execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
           return (intptr_t)execRetVal;
     }
     memset(Buf, '\0', sizeof(Buf));
//Lock /nvram/hotspot.json before copying 
     snprintf(Buf, sizeof(Buf), "cp /tmp/hotspot.json  /nvram/hotspot.json");
     sys_execute_cmd(Buf);
  
     memset(Buf, '\0', sizeof(Buf));
     snprintf(Buf, sizeof(Buf), "rm /tmp/hotspot.json");
     sys_execute_cmd(Buf);

     gXfinityEnable ? PsmSet(PSM_HOTSPOT_ENABLE, "1") : PsmSet(PSM_HOTSPOT_ENABLE, "0");
     vapBitMask = 0x00;
     if(gXfinityEnable) {
         hotspot_sysevent_enable_param();
         firewall_restart();
         tunnel_param_synchronize();
         memset(Buf, 0, sizeof(Buf));
         snprintf(Buf, sizeof(Buf), "%d", vlanIdList[0]);
         PsmSet(PSM_VLAN_OPEN_2G, Buf);
         memset(Buf, 0, sizeof(Buf));
         snprintf(Buf, sizeof(Buf), "%d", vlanIdList[1]);
         PsmSet(PSM_VLAN_OPEN_5G, Buf);
         memset(Buf, 0, sizeof(Buf));
         snprintf(Buf, sizeof(Buf), "%d", vlanIdList[2]);
         PsmSet(PSM_VLAN_SECURE_2G, Buf);
         memset(Buf, 0, sizeof(Buf));
         snprintf(Buf, sizeof(Buf), "%d", vlanIdList[3]);
         PsmSet(PSM_VLAN_SECURE_5G, Buf);
#if defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
         memset(Buf, 0, sizeof(Buf));
         snprintf(Buf, sizeof(Buf), "%d", vlanIdList[4]);
         PsmSet(PSM_VLAN_OPEN_6G, Buf);
         memset(Buf, 0, sizeof(Buf));
         snprintf(Buf, sizeof(Buf), "%d", vlanIdList[5]);
         PsmSet(PSM_VLAN_SECURE_6G, Buf);
#endif
#if defined (_CBR_PRODUCT_REQ_)
         memset(Buf, 0, sizeof(Buf));
         snprintf(Buf, sizeof(Buf), "%d", vlanIdList[4]);
         PsmSet(PSM_VLAN_PUBLIC, Buf);
#endif
#if defined(_CBR_PRODUCT_REQ_)
         memset(Buf, '\0', sizeof(Buf));
         sleep(5);
         strncpy(Buf, "killall -q -9 eapd 2>/dev/null", sizeof(Buf)-1);
         sys_execute_cmd(Buf);
         sleep(5);
         CcspTraceInfo(("[%s] [%d]Restarting EAPD.. Buf : [%s]\n", __func__, __LINE__, Buf));
         sys_execute_cmd("eapd");
#endif
     }
     memset(Buf, '\0', sizeof(Buf));
     CcspTraceInfo(("HOTSPOT_LIB : Removing /tmp/.hotspot_blob_inprogress\n"));
     strncpy(Buf, "rm /tmp/.hotspot_blob_inprogress", SIZE_CMD);
     sys_execute_cmd(Buf);
/* Adding flag for pandm to avoid sending multiple blobs */
     memset(Buf, '\0', sizeof(Buf));
     snprintf(Buf, sizeof(Buf), "touch /tmp/.hotspot_blob_executed");
     sys_execute_cmd(Buf);
     populate_old_params_to_structure();
     free(tempTunnelData);
     tempTunnelData = NULL;
     return 0;
}

size_t calculateTimeout(size_t numOfEntries){
    UNREFERENCED_PARAMETER(numOfEntries);
    CcspTraceInfo(("HOTSPOT_LIB : calling calculateTimeout\n"));
    return 30;
}

void register_callbackHotspot(callbackHotspot ptr_reg_callback){

    CcspTraceInfo(("HOTSPOT_LIB : Entering %s....\n", __FUNCTION__));
    gCallbackSync = ptr_reg_callback;
}

static int wanfailover_handleTunnel(bool create)
{

    char   cmdBuf[1024];
    int    offset = 0;
    int    index = 0;

    if(!create) {
        CcspTraceInfo(("HOTSPOT_LIB : %s Bringing down the Hotspot N/W\n", __FUNCTION__));
        for(index = 0; index < MAX_VAP; index++){
            offset = 0;
            memset(cmdBuf, '\0', sizeof(cmdBuf));
#if !defined(_COSA_INTEL_XB3_ARM_) && !defined(RDK_ONEWIFI)
            offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "%s %s ; ",
                                IP_DEL, gVlanSyncData[index].vapInterface);
#endif
            offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "%s %s ; ", IP_DEL, gVlanSyncData[index].bridgeName);
            offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "%s %s ;", IP_DEL, GRE_IFNAME);
            //CcspTraceInfo(("HOTSPOT_LIB : Buffer 3 gre add = %s %d\n", cmdBuf, offset));
            if (offset)
                sys_execute_cmd(cmdBuf);
            CcspTraceInfo(("HOTSPOT_LIB : %s Hotspot bridge %s and ports are down\n", __FUNCTION__, 
                                gVlanSyncData[index].bridgeName));
        }
    } else {
        //Bringup Interface . Below function will either restore from nvram or from the
        //tmp hotspot json.
        CcspTraceInfo(("HOTSPOT_LIB : %s Bringing up the Hotspot N/W\n", __FUNCTION__));
        jansson_rollback_tunnel_info();
    }
    return 0;
}


int hotspot_wan_failover(bool remote_wan_enabled){

    char Buf[200] = {0};
    char rec[200] = {0};
    char val[16] = {0};

    //CcspTraceInfo(("HOTSPOT_LIB : Entering %s ....%d\n", __FUNCTION__, remote_wan_enabled));

    if(remote_wan_enabled) {

        //Delete the existing tunnel, Before deleting make sure we have a valid json file
        //in nvram, if not then we need to prepare the json and store in the /tmp/hotspot_wanfailover.json
        CcspTraceInfo(("HOTSPOT_LIB : Remote WAN enabled, Bringing down tunnels \n"));
        if(0 != access(N_HOTSPOT_JSON, F_OK)) {
             CcspTraceInfo(("HOTSPOT_LIB : %s Preparing backup json for re-creation later\n", __FUNCTION__));
             //Prepare the json using the psm and prepare the /tmp/hotspot_wanfailover.json
             //it will create hotspot.json in nvram
             jansson_store_tunnel_info(NULL);

             memset(Buf, '\0', sizeof(Buf));
             snprintf(Buf, sizeof(Buf), "cp /nvram/hotspot.json /tmp/hotspot_wanfailover.json");
             sys_execute_cmd(Buf);

             snprintf(rec, sizeof(rec), "%s",  WEB_CONF_ENABLE);
             //If webconfig is disabled and if hostpot blob was never sent, remove the unecessary
             //copy from nvram
             if((PsmGet(rec, val, sizeof(val)) == 0 && atoi(val) == FALSE) && (0 != access(HOTSPOT_BLOB, F_OK))){
                CcspTraceInfo(("HOTSPOT_LIB : %s Remove the nvram copy of json\n", __FUNCTION__));
                memset(Buf, '\0', sizeof(Buf));
                snprintf(Buf, sizeof(Buf), "rm -rf /nvram/hotspot.json");
                sys_execute_cmd(Buf);
             }
        }

        wanfailover_handleTunnel(false);
    }
    else{

        CcspTraceInfo(("HOTSPOT_LIB : Remote WAN disabled, Bringing up tunnels \n"));

        wanfailover_handleTunnel(true);
        snprintf(rec, sizeof(rec), "%s",  WEB_CONF_ENABLE);
        //If webconfig enabled and nvram copy of json was missing , take this chance to restore
        if((0 != access(N_HOTSPOT_JSON, F_OK)) && (PsmGet(rec, val, sizeof(val)) == 0 && atoi(val) == TRUE) && (0 == access(HOTSPOT_BLOB, F_OK))){
           CcspTraceInfo(("HOTSPOT_LIB :  This may be case of lost nvram, take oppurtunity and restore in nvram\n"));
           memset(Buf, '\0', sizeof(Buf));
           snprintf(Buf, sizeof(Buf), "cp /tmp/hotspot_wanfailover.json /nvram/hotspot.json");
           sys_execute_cmd(Buf);
        }
        memset(Buf, '\0', sizeof(Buf));
        snprintf(Buf, sizeof(Buf), "rm -rf /tmp/hotspot_wanfailover.json");
        sys_execute_cmd(Buf);
    }
    return 0;
}

void recreate_tunnel(){
    char   cmdBuf[1024];
    int    offset = 0;
    offset += snprintf(cmdBuf+offset, sizeof(cmdBuf) - offset, "%s %s ;", IP_DEL, GRE_IFNAME);
    CcspTraceInfo(("HOTSPOT_LIB : Buffer for deleting gre tunnel = %s %d\n", cmdBuf, offset));
    if (offset){
        sys_execute_cmd(cmdBuf);
    }
    jansson_rollback_tunnel_info();
}
