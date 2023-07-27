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

#ifndef LIB_HOTSPOT_API_H
#define LIB_HOTSPOT_API_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "webconfig_framework.h"

typedef struct
{
    size_t    entries_count;	   
} wifi_doc_t;

typedef struct
{
    char *        vap_name;
    unsigned int  wan_vlan;
    bool          enable;
} tunnel_t;

typedef struct
{
    tunnel_t * entries;
    size_t    entries_count;	   
} tunnelTable_t;


typedef struct {
    char *        gre_primary_endpoint;
    char *        gre_sec_endpoint;
    int           gre_dscp;
    bool          gre_enable;
    tunnelTable_t * table_param;
} tdoc_t;

typedef struct
{
    tdoc_t * entries;
    size_t    entries_count;	   
} tunneldoc_t;

typedef struct
{
    char *name;
    char *value;
    uint32_t   value_size;
    uint16_t type;
} hparam_t;

typedef struct {
    hparam_t   *entries;
    size_t      entries_count;
    char *        subdoc_name;
    uint32_t      version;
    uint16_t      transaction_id;
} hotspotparam_t;

typedef struct {
    char         set_primary_endpoint[40];
    char         set_sec_endpoint[40];
    bool         set_gre_enable;
    int          vlan_id_list[5];
} tunnelSet_t;

typedef void (*callbackHotspot)(tunnelSet_t *tunnelSet);	

void register_callbackHotspot(callbackHotspot ptr_reg_callback);
void callbackWCConfirmVap(tunnelSet_t  *tunnelSet);

pErr setHotspot( void* const network);
int deleteHotspot();
int confirmVap();
size_t calculateTimeout(size_t numOfEntries);
int hotspot_wan_failover(bool isRemoteWANEnabled);
void recreate_tunnel();
#endif
