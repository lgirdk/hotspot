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
#include "ccsp_trace.h"
#include <jansson.h>
/**************************************************************************/
/*      GLOBAL and STATIC  VARIABLES                                      */
/**************************************************************************/
extern vlanSyncData_s gVlanSyncData[];
extern char     vapBitMask;
extern char     gPriEndptIP[SIZE_OF_IP];
extern char     gSecEndptIP[SIZE_OF_IP];
extern bool     gXfinityEnable;
/**************************************************************************/

int PsmGet(const char *param, char *value, int size);

static void rollback_vapBridge(char const *vap_name, int wan_vlan){
   CcspTraceInfo(("HOTSPOT_LIB : Entering %s...\n", __FUNCTION__));
   configHotspotBridgeVlan((char *)vap_name,  wan_vlan);
   update_bridge_config(getHotspotVapIndex((char *)vap_name));
}


bool checking_recovery_janson(json_t *json_tun_root) {


    char secEndIp[SIZE_OF_IP] = {0};
    char dscp[10] = {0};
    bool change = 0;

    CcspTraceInfo(("HOTSPOT_LIB : Entering in Function ...%s\n", __FUNCTION__));
    if (!json_tun_root) {
        CcspTraceInfo(("HOTSPOT_LIB : json_tun_root null in hotspot json...%s\n", __FUNCTION__));
        return 1;
    }
    json_t *jsecEndpoint = json_object_get(json_tun_root, J_GRE_WRONG_SEC_EP_NAME);
    json_t *jsecEndpnt = json_object_get(json_tun_root, J_GRE_SEC_EP_NAME);
    if ((jsecEndpoint && json_is_string(jsecEndpoint)) && !(jsecEndpnt)){
        strncpy(secEndIp,
                json_string_value(jsecEndpoint), SIZE_OF_IP - 1);
        CcspTraceInfo(("HOTSPOT_LIB : Recovered secondary EP IP...%s\n", secEndIp));
        json_object_set_new( json_tun_root, J_GRE_SEC_EP_NAME, json_string(secEndIp));
        change = 1;
    }
    json_t *jdscp = json_object_get(json_tun_root, J_GRE_DSCP);
    if (jdscp && json_is_string(jdscp)){
        strncpy(dscp, json_string_value(jdscp),sizeof(dscp)-1);
        json_object_set_new( json_tun_root, J_GRE_DSCP, json_integer(atoi(dscp)));
        CcspTraceInfo(("HOTSPOT_LIB : Recovered dscp value...%s\n", dscp));
        change = 1;
    }
    if(change == 1){
       json_dump_file(json_tun_root, "/nvram/hotspot.json", JSON_INDENT(1));
    }
    else{
        CcspTraceInfo(("HOTSPOT_LIB : No need Recovery for dscp and IP...\n"));
    }
    return 1;
}

bool jansson_rollback_tunnel_info() {

    char priEndIp[SIZE_OF_IP] = {0};
    char secEndIp[SIZE_OF_IP] = {0};
    int count = 0;
    int dscp = 0;
    int i = 0;
    bool gre_enable = false;


    json_t *json_tun_root = json_load_file(N_HOTSPOT_JSON, 0, NULL);
    if (!json_tun_root) {
        //Next see if this is the case of missing nvram json and if we have prepared the wan 
        //failover json
        json_tun_root = json_load_file(WAN_FAILOVER_JSON, 0, NULL);
        if (!json_tun_root) {
        CcspTraceInfo(("HOTSPOT_LIB : Unable to load hotspot json...%s\n", __FUNCTION__));
        return 1;
        } else {
        CcspTraceInfo(("HOTSPOT_LIB : load Wan failover json hotspot json...%s\n", __FUNCTION__));
        }
    }

    checking_recovery_janson(json_tun_root);

    json_t *ecount = json_object_get(json_tun_root, J_GRE_ENT_COUNT);
    if (ecount && json_is_integer(ecount)){

       count = json_integer_value(ecount);
    }
    CcspTraceInfo(("HOTSPOT_LIB : file load hotspot json entries_count...%d\n", count));

    json_t *jpriEndpoint = json_object_get(json_tun_root, J_GRE_PRI_EP_NAME);
    if (jpriEndpoint && json_is_string(jpriEndpoint)){
        strncpy(priEndIp,
                json_string_value(jpriEndpoint), SIZE_OF_IP - 1);
    }
    memset(gPriEndptIP, '\0', sizeof(gPriEndptIP));
    strncpy(gPriEndptIP, priEndIp, SIZE_OF_IP);
    CcspTraceInfo(("HOTSPOT_LIB : file load hotspot json pri end ip...%s\n", priEndIp));

    json_t *jsecEndpoint = json_object_get(json_tun_root, J_GRE_SEC_EP_NAME);
    if (jsecEndpoint && json_is_string(jsecEndpoint)){
        strncpy(secEndIp,
                json_string_value(jsecEndpoint), SIZE_OF_IP - 1);
    }
    memset(gSecEndptIP, '\0', sizeof(gSecEndptIP));
    CcspTraceInfo(("HOTSPOT_LIB : Secondary endpoint ip secEndIp = %s len of sec = %zu \n", secEndIp, strlen(secEndIp)));

    if((0 == strcmp(secEndIp, "")) || (0 == strcmp(secEndIp, " ")) || (0 == strcmp(secEndIp, "0.0.0.0"))){
        CcspTraceInfo(("HOTSPOT_LIB : Secondary endpoint ip is invalid, Using primary EP IP \n"));
        strncpy(gSecEndptIP, gPriEndptIP, SIZE_OF_IP);
    }
    else{
        strncpy(gSecEndptIP, secEndIp, SIZE_OF_IP);
    }
    CcspTraceInfo(("HOTSPOT_LIB : file load hotspot json sec end ip...%s \n", gSecEndptIP));

    json_t *jdscp = json_object_get(json_tun_root, J_GRE_DSCP);
    if (jdscp && json_is_integer(jdscp)){
        dscp = json_integer_value(jdscp);
    }
    CcspTraceInfo(("HOTSPOT_LIB : file load hotspot json dscp...%d\n", dscp));
    //CcspTraceInfo(("HOTSPOT_LIB : file load hotspot json dscp...%d\n", rNetwork->entries->gre_dscp));

    json_t *jgre_enable = json_object_get(json_tun_root, J_GRE_ENABLE);
    if (jgre_enable && json_is_boolean(jgre_enable)){

        gre_enable = json_boolean_value(jgre_enable);
    }
    CcspTraceInfo(("HOTSPOT_LIB : file load hotspot gre_enable...%d \n", gre_enable));
    if(gre_enable){
        create_tunnel(priEndIp);
        gXfinityEnable = true;
    }
    else
    {
        gXfinityEnable = false;
    }

    json_t *json_tun = json_object_get(json_tun_root, J_GRE_TUNNEL_NET);
    json_t *json_vap_name = json_object_get(json_tun, J_GRE_VAP_NAME);
    json_t *json_wan_vlan = json_object_get(json_tun, J_GRE_WAN_VLAN);
    json_t *json_vap_enable = json_object_get(json_tun, J_GRE_VAP_ENABLE);

    json_t *jsonVapName = NULL;
    json_t *jsonVapenable = NULL;
    json_t *jsonVapID = NULL;

    if(json_is_array(json_vap_name) && json_is_array(json_wan_vlan) && json_is_array(json_vap_enable)){
        CcspTraceInfo(("HOTSPOT_LIB : file load EP in array json \n"));
        for(i = 0; i < count; i++){
             jsonVapName = json_array_get(json_vap_name, i);
             const char *name = json_string_value(jsonVapName);

             jsonVapenable = json_array_get(json_vap_enable, i);
             if (json_boolean_value(jsonVapenable) == 1) {
                  CcspTraceInfo(("HOTSPOT_LIB : file load EP in array json enable === %s \n", name));
                  vapBitMask |=  gVlanSyncData[i].bitVal;
                  jsonVapID = json_array_get(json_wan_vlan, i);
                  rollback_vapBridge(name, json_integer_value(jsonVapID));
             }
         }
         //hotspot_sysevent_enable_param();
         //firewall_restart();
     }
     json_decref(jsonVapID);
     json_decref(jsonVapenable);
     json_decref(jsonVapName);
     json_decref(json_vap_enable);
     json_decref(json_wan_vlan);
     json_decref(json_vap_name);
     json_decref(json_tun);
     json_decref(jgre_enable);
     json_decref(jdscp);
     json_decref(jsecEndpoint);
     json_decref(jpriEndpoint);
     json_decref(ecount);
     json_decref(json_tun_root);
     CcspTraceInfo(("HOTSPOT_LIB : Exit file load json \n"));
     return true;
}


int jansson_store_tunnel_info(tunneldoc_t *pTunnelVap) {

    char* s = NULL;
    int i = 0, count = 0;
    char psm_val[128] = {0};
    char vlan_val[128] = {0};

    CcspTraceInfo(("HOTSPOT_LIB : JSON OUTPUT...%s\n", __FUNCTION__));
    json_t *root = json_object();
    json_t *json_tun = json_object();

    json_t *json_arr_vap_name = json_array();
    json_t *json_arr_vlan_id = json_array();
    json_t *json_arr_vap_enable = json_array();

    if( pTunnelVap != NULL) {
        json_object_set_new( root, J_GRE_PRI_EP_NAME, json_string(pTunnelVap->entries->gre_primary_endpoint));
        json_object_set_new( root, J_GRE_SEC_EP_NAME, json_string(pTunnelVap->entries->gre_sec_endpoint));
        json_object_set_new( root, J_GRE_DSCP, json_integer(pTunnelVap->entries->gre_dscp));
        json_object_set_new( root, J_GRE_ENABLE, json_boolean(pTunnelVap->entries->gre_enable));
        json_object_set_new( root, J_GRE_ENT_COUNT, json_integer(pTunnelVap->entries->table_param->entries_count));
        json_object_set_new( root, J_GRE_TUNNEL_NET, json_tun );
        json_object_set_new( json_tun, J_GRE_VAP_NAME, json_arr_vap_name);
        json_object_set_new( json_tun, J_GRE_WAN_VLAN, json_arr_vlan_id);
        json_object_set_new( json_tun, J_GRE_VAP_ENABLE, json_arr_vap_enable);


        json_array_append(json_tun, json_arr_vap_name);
        json_array_append(json_tun, json_arr_vlan_id);
        json_array_append(json_tun, json_arr_vap_enable);
        CcspTraceInfo(("HOTSPOT_LIB :set EP in array json \n"));
        count = pTunnelVap->entries->table_param->entries_count;
        for(i = 0; i < count; i++){
            json_array_append_new( json_arr_vap_name, json_string(pTunnelVap->entries->table_param->entries[i].vap_name) );
            json_array_append( json_arr_vlan_id, json_integer(pTunnelVap->entries->table_param->entries[i].wan_vlan ) );
            json_array_append( json_arr_vap_enable, json_boolean(pTunnelVap->entries->table_param->entries[i].enable) );
        }

        s = json_dumps(root, 0);
        CcspTraceInfo(("HOTSPOT_LIB : JSON OUTPUT...%s\n", s));
   
        int outt = 0;
        outt = json_dump_file(root, "/tmp/hotspot.json", 0);
        CcspTraceInfo(("HOTSPOT_LIB : JSON file ret...%d\n", outt));

        json_decref(json_arr_vlan_id);
        json_decref(json_arr_vap_enable);
        json_decref(json_arr_vap_name);
        json_decref(json_tun);
        json_decref(root);

        return 0;
    } else
    {
        CcspTraceInfo(("HOTSPOT_LIB : %s Just storing existing Xfinity setting in rollback\n",__FUNCTION__));
        PsmGet(PSM_PRI_IP, psm_val, sizeof(psm_val));
        CcspTraceInfo(("HOTSPOT_LIB : PSM rollback pri ip...%s\n", psm_val));
        if((validateIpAddress(psm_val) != 1)){
           CcspTraceError(("HOTSPOT_LIB : Invalid Primary Endpoint IP in json store\n"));
           return 2;
        }
        json_object_set_new( root, J_GRE_PRI_EP_NAME, json_string(psm_val));
        memset(psm_val, 0, sizeof(psm_val));
        PsmGet(PSM_SEC_IP, psm_val, sizeof(psm_val));
        CcspTraceInfo(("HOTSPOT_LIB : PSM rollback sec ip...%s\n", psm_val));
        if((validateIpAddress(psm_val) != 1)){
           CcspTraceError(("HOTSPOT_LIB : Invalid Secondary Endpoint IP in json store\n"));
           return 2;
        }
        json_object_set_new( root, J_GRE_SEC_EP_NAME, json_string(psm_val));
        memset(psm_val, 0, sizeof(psm_val));
        PsmGet(PSM_DSCP_MARK, psm_val, sizeof(psm_val));
        json_object_set_new( root, J_GRE_DSCP, json_integer(atoi(psm_val)));
        CcspTraceInfo(("HOTSPOT_LIB : PSM rollback dscp...%s\n", psm_val));
        memset(psm_val, 0, sizeof(psm_val));
        PsmGet(PSM_HOTSPOT_ENABLE, psm_val, sizeof(psm_val));
        CcspTraceInfo(("HOTSPOT_LIB : PSM rollback hotspot enable...%s\n", psm_val));
        json_object_set_new( root, J_GRE_ENABLE, json_boolean(atoi(psm_val) ? true:false));
        memset(psm_val, 0, sizeof(psm_val));

        json_object_set_new( root, J_GRE_TUNNEL_NET, json_tun );
        json_object_set_new( json_tun, J_GRE_VAP_NAME, json_arr_vap_name);
        json_object_set_new( json_tun, J_GRE_WAN_VLAN, json_arr_vlan_id);
        json_object_set_new( json_tun, J_GRE_VAP_ENABLE, json_arr_vap_enable);

        for(i = 0; i < MAX_VAP; i++) {
            json_array_append_new( json_arr_vap_name, json_string(gVlanSyncData[i].vapName) );
            memset(vlan_val, 0, sizeof(vlan_val));
            snprintf(vlan_val, sizeof(vlan_val), PSM_VLANID, i+1);
            PsmGet(vlan_val, psm_val, sizeof(psm_val));
            CcspTraceInfo(("HOTSPOT_LIB : PSM rollback vap enable...%s index...%d\n", psm_val,  i));
            json_array_append( json_arr_vlan_id, json_integer(atoi(psm_val)));
            json_array_append( json_arr_vap_enable, json_boolean(get_ssid_enable(gVlanSyncData[i].ssidIdx)));
        }
        json_object_set_new( root, J_GRE_ENT_COUNT, json_integer(i));

        s = json_dumps(root, 0);
        CcspTraceInfo(("HOTSPOT_LIB : JSON OUTPUT...%s\n", s));
        int outt = 0;
        outt = json_dump_file(root, "/nvram/hotspot.json", 0);
        CcspTraceInfo(("HOTSPOT_LIB : JSON file ret...%d\n", outt));

        json_decref(json_arr_vlan_id);
        json_decref(json_arr_vap_enable);
        json_decref(json_arr_vap_name);
        json_decref(json_tun);
        json_decref(root);

        return 1;
    } 
}
