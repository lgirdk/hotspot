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

#include "libHotspot.h"
#include "libHotspotApi.h"
#include "webconfig_framework.h"
#include "ccsp_psm_helper.h"
#include "ansc_platform.h"

/**************************************************************************/
/*      GLOBAL and STATIC  VARIABLES                                      */
/**************************************************************************/
extern  ANSC_HANDLE             bus_handle;
extern char                 g_Subsystem[32];
int gSyseventfd;
token_t gSysevent_token;
char     vapBitMask = 0x00;
char     gPriEndptIP[32] = {0};
char     gSecEndptIP[32] = {0};
bool     gXfinityEnable = false;

static pErr execRetVal = NULL;
extern vlanSyncData_s gVlanSyncData[];
callbackHotspot gCallbackSync = NULL;

/**************************************************************************/
/**************************************************************************/
/*      Functions                                                          */
/**************************************************************************/


bool tunnel_param_synchronize() {

    CcspTraceInfo(("HOTSPOT_LIB : Entering %s....\n", __FUNCTION__));
    tunnelSet_t *tunnelSet = NULL;

    tunnelSet = (tunnelSet_t *)malloc(sizeof(tunnelSet_t));
 
    if (tunnelSet == NULL ){
          CcspTraceError(("HOTSPOT_LIB : Malloc failed in %s \n", __FUNCTION__));
          return FALSE;
    }
   
    strncpy(tunnelSet->set_primary_endpoint, gPriEndptIP, SIZE_OF_IP);
    strncpy(tunnelSet->set_sec_endpoint, gSecEndptIP, SIZE_OF_IP);
    tunnelSet->set_gre_enable = gXfinityEnable;
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
                gVlanSyncData[index].bridgeName, index+1 );
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

int create_tunnel(char *gre_primary_endpoint){

   char   cmdBuf[1024] = {0};
   int    offset = 0;
   int    retValue = 0;

   
         memset(cmdBuf, '\0', sizeof(cmdBuf));

         CcspTraceInfo(("HOTSPOT_LIB : Entering %s ...gSyseventfd = %d \n", __FUNCTION__, gSyseventfd));
         if (0 == gSyseventfd){
             retValue =  gre_sysevent_syscfg_init();
             if(1 == retValue){
                   CcspTraceError(("HOTSPOT_LIB : Sysevent failed in create_tunnel\n"));
                   return retValue;
             }
         }
         offset += snprintf(cmdBuf+offset,
                                sizeof(cmdBuf) - offset,
                                "%s dev %s name %s; ", IP_SET, GRE_IFNAME, GRE_IFNAME_DUMMY);
         offset += snprintf(cmdBuf+offset,
                               sizeof(cmdBuf) - offset,
                               "%s %s type gretap remote %s dev erouter0  dsfield b0 nopmtudisc;",
                                 IP_ADD, GRE_IFNAME, gre_primary_endpoint);
         #if defined (_ARRIS_XB6_PRODUCT_REQ_)
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
#if !defined(_COSA_INTEL_XB3_ARM_)
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

    /*sysevent_get(gSyseventfd, gSysevent_token, "gre_current_endpoint", 
                                                 currentTunIP, sizeof(currentTunIP)); 

      sysevent_get(gSyseventfd, gSysevent_token, "hotspot_1-status", 
                                                 hotspotStatus, sizeof(hotspotStatus)); 
    */
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
    struct sockaddr_in sa; 

    CcspTraceInfo(("HOTSPOT_LIB : Entering %s function....... \n", __FUNCTION__));
    result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
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
          CcspTraceInfo(("Retrieving ssid info ssid idx= ssidIdx val = %s\n",valStructs[0]->parameterValue));
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
                (char *)param, ccsp_string, (char *)value) != CCSP_SUCCESS)
        return -1; 
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
//Prash TODO: Find the delta and then store if needed
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
//PRASH: Check if this is the very first webconfig on this device and if legacy 
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

     if(true == pGreTunnelData->entries->gre_enable){
 
         if (0 == gSyseventfd){
             retValue =  gre_sysevent_syscfg_init();
             if(1 == retValue){
                   CcspTraceError(("HOTSPOT_LIB : Sysevent failed in set Hotspot \n"));
                   execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
                   return execRetVal;
             }
         }
         if((validateIpAddress(pGreTunnelData->entries->gre_primary_endpoint) != 1))
         {
             CcspTraceError(("HOTSPOT_LIB : Invalid Primary Endpoint IP\n"));
             execRetVal->ErrorCode = VALIDATION_FALIED;
             strncpy(execRetVal->ErrorMsg,"Invalid Primary Endpoint IP",sizeof(execRetVal->ErrorMsg)-1);
             return execRetVal;
         }
         if((validateIpAddress(pGreTunnelData->entries->gre_sec_endpoint) != 1))
         {
             CcspTraceError(("HOTSPOT_LIB : Invalid Secondary Endpoint IP\n"));
             execRetVal->ErrorCode = VALIDATION_FALIED;
             strncpy(execRetVal->ErrorMsg,"Invalid Secondary Endpoint IP",sizeof(execRetVal->ErrorMsg)-1);
             return execRetVal;
         }
         memset(gPriEndptIP, '\0', sizeof(gPriEndptIP));
         memset(gSecEndptIP, '\0', sizeof(gSecEndptIP));
         strncpy(gPriEndptIP, pGreTunnelData->entries->gre_primary_endpoint,SIZE_OF_IP);
         strncpy(gSecEndptIP, pGreTunnelData->entries->gre_sec_endpoint,SIZE_OF_IP);

         if((0 == strcmp(gSecEndptIP, "")) || (0 == strcmp(gSecEndptIP, " ")) || (0 == strcmp(gSecEndptIP, "0.0.0.0"))){
               CcspTraceInfo(("HOTSPOT_LIB : Secondary endpoint ip is invalid, Using primary EP IP \n"));
               strncpy(gSecEndptIP, gPriEndptIP, SIZE_OF_IP);
         }
         gXfinityEnable = true;
         /* Deleting existing Tunnels*/
         deleteVaps();

         create_tunnel( pGreTunnelData->entries->gre_primary_endpoint); 

         CcspTraceInfo(("HOTSPOT_LIB : Number of VAP received in blob: %zu \n", pGreTunnelData->entries->table_param->entries_count));

         for(index = 0; index < pGreTunnelData->entries->table_param->entries_count; index++){
              if(true == pGreTunnelData->entries->table_param->entries[index].enable){

                   vapBitMask |=  gVlanSyncData[index].bitVal;

                   vlanid = pGreTunnelData->entries->table_param->entries[index].wan_vlan;
//PRASH: For now keeping it as 200 similar to AC. but this needs to be tweaked or 
//after discussing since l2sd0.xxx may get created in XB3 overlapping the 112,113,1060 vlans
//for the pods.
                   if(!((vlanid >= 102) && (vlanid <= 4094))){
                        CcspTraceError(("HOTSPOT_LIB : Vlan ID is out of range \n "));
                        execRetVal->ErrorCode = VALIDATION_FALIED;
                        strncpy(execRetVal->ErrorMsg,"Vlan ID is out of range",sizeof(execRetVal->ErrorMsg)-1);
                        return execRetVal;
                   }
//PRASH: check for the return , if some bridges fails, we must return failure
//else wifi will proceed with creating the vap but actually bridges doesnt 
//exists
                   configHotspotBridgeVlan(pGreTunnelData->entries->table_param->entries[index].vap_name, vlanid);
                   retValue = update_bridge_config( getHotspotVapIndex(pGreTunnelData->entries->table_param->entries[index].vap_name));
                   if(-1 == retValue){
                        CcspTraceError(("HOTSPOT_LIB : Vap Name incorrect \n "));
                        execRetVal->ErrorCode = VALIDATION_FALIED;
                        strncpy(execRetVal->ErrorMsg,"Incorrect VAP name",sizeof(execRetVal->ErrorMsg)-1);
                        return execRetVal;
                   }
              }
         }
         jansson_store_tunnel_info(pGreTunnelData);
     }
     else{
         CcspTraceInfo(("HOTSPOT_LIB : Gre is not enabled. Deleting tunnel info \n"));
         deleteVaps();
         hotspot_sysevent_disable_param();
         memset(gPriEndptIP, '\0', sizeof(gPriEndptIP));
         memset(gSecEndptIP, '\0', sizeof(gSecEndptIP));
         strncpy(gPriEndptIP, "0.0.0.0", SIZE_OF_IP);
         strncpy(gSecEndptIP, "0.0.0.0", SIZE_OF_IP);
         gXfinityEnable = false;
         PsmSet(PSM_HOTSPOT_ENABLE, "0");
         tunnel_param_synchronize();
     }
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    return execRetVal;
}

int deleteHotspot(){
#if !defined(_COSA_INTEL_XB3_ARM_)
     char   cmdBuf[1024];
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
#if !defined(_COSA_INTEL_XB3_ARM_)
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
             return ROLLBACK_SUCCESS;
       }
       else{
             vapBitMask = 0x00;
             CcspTraceInfo(("HOTSPOT_LIB : 'deleteHotspot' rollbaack ptr null...\n"));
             return BLOB_EXEC_FAILURE;
       }
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
//PRASH: Test if one vap disabled and another enabled through blob works well with the
//bitmask
//Hows l2sd0.xxx created for the XB3s ?

#if !defined(_COSA_INTEL_XB3_ARM_)
    for(index = 0; index < MAX_VAP; index++){
            if (gVlanSyncData[index].bitVal & vapBitMask){

                memset(cmdBuf, '\0', sizeof(cmdBuf));
                offset = 0;
                offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "brctl addif %s %s; ", gVlanSyncData[index].bridgeName, gVlanSyncData[index].vapInterface);
                offset += snprintf(cmdBuf+offset, 
                                sizeof(cmdBuf) - offset,
                                "echo 1 > /sys/class/net/%s/bridge/nf_call_iptables;", gVlanSyncData[index].bridgeName);

                CcspTraceInfo(("HOTSPOT_LIB : Buffer 4 gre confirm vap = %s %d\n", cmdBuf, offset));
                if (offset)
                   sys_execute_cmd(cmdBuf);
        }
    }
#endif
     file_status = access(T_HOTSPOT_JSON, F_OK);

     if(file_status != 0){
           CcspTraceError(("HOTSPOT_LIB : hotspot.json file not available in tmp  %s \n", __FUNCTION__));
           memset((char *)execRetVal,0,sizeof(Err));
           execRetVal->ErrorCode = BLOB_EXEC_FAILURE;
           return (intptr_t)execRetVal;
     }
     memset(Buf, '\0', sizeof(Buf));
//PRASH: Lock /nvram/hotspot.json before copying 
     snprintf(Buf, sizeof(Buf), "cp /tmp/hotspot.json  /nvram/hotspot.json");
     sys_execute_cmd(Buf);
  
     memset(Buf, '\0', sizeof(Buf));
     snprintf(Buf, sizeof(Buf), "rm /tmp/hotspot.json");
     sys_execute_cmd(Buf);

     gXfinityEnable ? PsmSet(PSM_HOTSPOT_ENABLE, "1") : PsmSet(PSM_HOTSPOT_ENABLE, "0");
     vapBitMask = 0x00;
     hotspot_sysevent_enable_param();
     firewall_restart();
     tunnel_param_synchronize();
/* Adding flag for pandm to avoid sending multiple blobs */
     memset(Buf, '\0', sizeof(Buf));
     snprintf(Buf, sizeof(Buf), "touch /tmp/.hotspot_blob_executed");
     sys_execute_cmd(Buf);

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

