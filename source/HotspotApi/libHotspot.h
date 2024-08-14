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
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIB_HOTSPOT_H
#define LIB_HOTSPOT_H

#include <stdio.h>
#include <stddef.h>
#include <strings.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>
#include <arpa/inet.h>
#include <jansson.h>

#include "libHotspotApi.h"

#define GRE_IFNAME        "gretap0"
#define GRE_IFNAME_DUMMY  "gretap_0"
#define WAN_IF            "erouter0"
#define IP_SET            "ip link set"
#define IP_ADD            "ip link add"
#define IP_DEL            "ip link del"
#define NMOCA_IFNAME      "nmoca0"
#define L2SD0_IFNAME      "l2sd0"
#define PARAM_COUNT   3
#define SIZE_OF_IP    40
#define SIZE_CMD      48
#define IFLIST_SIZE          256
#define INTERFACE_EXIST      0
#define INTERFACE_NOT_EXIST  1


#define VAP_NAME_4             "hotspot_open_2g"
#define VAP_NAME_5             "hotspot_open_5g"
#define VAP_NAME_8             "hotspot_secure_2g"
#define VAP_NAME_9             "hotspot_secure_5g"
#define VAP_NAME_10            "new_hotspot_open_2g"
#if defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
#define VAP_NAME_11             "hotspot_open_6g"
#define VAP_NAME_12             "hotspot_secure_6g"
#endif
//PSM objects for Xfinity Hotspot
#define PSM_HOTSPOT_ENABLE     "dmsb.hotspot.enable"
#define PSM_VLANID             "dmsb.hotspot.tunnel.1.interface.%d.VLANID"
#define PSM_PRI_IP             "dmsb.hotspot.tunnel.1.PrimaryRemoteEndpoint"       
#define PSM_SEC_IP             "dmsb.hotspot.tunnel.1.SecondaryRemoteEndpoint"
#define PSM_DSCP_MARK          "dmsb.hotspot.gre.1.DSCPMarkPolicy"

#define PSM_VLAN_OPEN_2G       "dmsb.l2net.3.Vid"
#define PSM_VLAN_OPEN_5G       "dmsb.l2net.4.Vid"
#define PSM_VLAN_SECURE_2G     "dmsb.l2net.7.Vid"
#define PSM_VLAN_SECURE_5G     "dmsb.l2net.8.Vid"

#if defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
#define PSM_VLAN_OPEN_6G       "dmsb.l2net.15.Vid"
#define PSM_VLAN_SECURE_6G     "dmsb.l2net.16.Vid"
#endif

#define WEB_CONF_ENABLE         "eRT.com.cisco.spvtg.ccsp.webpa.WebConfigRfcEnable"
     
#define END_POINT_IP 40
#if defined (_CBR_PRODUCT_REQ_)
   #define MAX_VAP      5
   #define PSM_VLAN_PUBLIC        "dmsb.l2net.11.Vid"
#elif defined (_XB8_PRODUCT_REQ_) && defined(RDK_ONEWIFI)
   #define MAX_VAP      6
#else
   #define MAX_VAP      4
#endif
#define VAP_NAME     30

#define N_HOTSPOT_JSON      "/nvram/hotspot.json"
#define T_HOTSPOT_JSON      "/tmp/hotspot.json"
#define WAN_FAILOVER_JSON   "/tmp/hotspot_wanfailover.json"
#define HOTSPOT_BLOB        "/nvram/hotspot_blob"
/** Janson Key string **/

#define J_GRE_PRI_EP_NAME  "gre_primary_endpoint"
#define J_GRE_SEC_EP_NAME  "gre_sec_endpoint"
#define J_GRE_ENABLE       "gre_enable"
#define J_GRE_WRONG_SEC_EP_NAME "gre_secondary_endpoint"
#define J_GRE_ENT_COUNT    "entries_count"
#define J_GRE_TUNNEL_NET   "tunnel_network"
#define J_GRE_VAP_NAME     "vap_name"
#define J_GRE_DSCP         "gre_dscp"
#define J_GRE_WAN_VLAN     "wan_vlan"
#define J_GRE_VAP_ENABLE   "enable"


#define GRE_PATH "/etc/utopia/service.d/service_multinet/handle_gre.sh > /tmp/.hotspot_path"
#define GRE_ASYNC_HOT_EP "sysevent async hotspotfd-tunnelEP"  
#define GRE_EP_ASYNC   "gre_ep_async"
#define GRE_FILE "/tmp/.hotspot_path"

/* Structure for Sync vlan and brdige interface */
typedef enum {
      VLAN_INDEX_0 = 0,
      VLAN_INDEX_1,
      VLAN_INDEX_2,
      VLAN_INDEX_3,
      VLAN_INDEX_4,
      VLAN_INDEX_5
}eVlanID;

typedef struct{
      //eVlanID      mVlanID;
      char         *vapName;       //e.g. xfinity
      char         *vapInterface;       //e.g. ath4
      char         *bridgeName;         //e.g. brlan2
      char         bitVal;
      int          ssidIdx;
#if defined(_COSA_INTEL_XB3_ARM_)
      int          instance;
#endif
      int          queue_num;
}vlanSyncData_s;

typedef struct {
    bool isFirst;
    bool gre_enable;
    char primaryEP[SIZE_OF_IP];
    char secondaryEP[SIZE_OF_IP];
    int Vlans[MAX_VAP];
} tunnel_params;

typedef enum {
      GRE_ENABLE_CHANGE = 1 << 0,
      PRIMARY_EP_CHANGED = 1 << 1,
      SECONDARY_EP_CHANGED = 1 << 2,
      VLAN_CHANGE_BASE = 1 << 3,
      VLAN_CHANGE_1 = VLAN_CHANGE_BASE << 1,
      VLAN_CHANGE_2 = VLAN_CHANGE_BASE << 2,
      VLAN_CHANGE_3 = VLAN_CHANGE_BASE << 3,
      VLAN_CHANGE_4 = VLAN_CHANGE_BASE << 4,
      VLAN_CHANGE_5 = VLAN_CHANGE_BASE << 5,
      VLAN_CHANGE_6 = VLAN_CHANGE_BASE << 6
}eTunnel_Params_Changed;

/**/
void firewall_restart();
bool jansson_rollback_tunnel_info();
int jansson_store_tunnel_info(tunneldoc_t *);
bool checking_recovery_janson(json_t *json_tun_root);

int gre_sysevent_syscfg_init();
void configHotspotBridgeVlan(char *vapName, int wan_vlan);
int  update_bridge_config (int index);
int getHotspotVapIndex(char *vapName);
char* getIpv6Address();
int create_tunnel(char *gre_primary_endpoint);
int hotspot_sysevent_enable_param();
bool get_ssid_enable(int ssidIdx);
int checkGreInterface_Exist(int vlan_ID, char *bridge_name);
bool prevalidateHotspotBlob(tunneldoc_t *pGreTunnelData);
int  validateIpAddress(char *ipAddress);
int ipAddress_version(char *ipAddress);
int prepareFirstRollback();
int compareTunnelConfig();
int PsmGet(const char *param, char *value, int size);
int PsmSet(const char *param, const char *value);
#endif
