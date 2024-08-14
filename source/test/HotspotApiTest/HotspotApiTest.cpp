/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <experimental/filesystem>
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include <mocks/mock_sysevent.h>
#include <mocks/mock_util.h>
#include <mocks/mock_base_api.h>
#include <mocks/mock_usertime.h>
#include <mocks/mock_ansc_wrapper_api.h>
#include <mocks/mock_trace.h>
#include <mocks/mock_safec_lib.h>
#include <mocks/mock_psm.h>
#include <mocks/mock_telemetry.h>
#include <mocks/mock_jansson.h>
#include <mocks/mock_file_io.h>

extern "C" {
#include "libHotspot.h"
}

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::DoAll;

SyseventMock * g_syseventMock = nullptr;
UtilMock * g_utilMock = nullptr;
BaseAPIMock * g_baseapiMock = nullptr;
UserTimeMock * g_usertimeMock = nullptr;
AnscWrapperApiMock * g_anscWrapperApiMock = nullptr;
TraceMock * g_traceMock = nullptr;
SafecLibMock* g_safecLibMock = nullptr;
PsmMock * g_psmMock = nullptr;
telemetryMock * g_telemetryMock = nullptr;
JanssonMock * g_janssonMock = nullptr;
FileIOMock * g_fileIOMock = nullptr;

char g_Subsystem[32] = {0};
extern int gSyseventfd;
extern token_t gSysevent_token;
extern vlanSyncData_s gVlanSyncData[];
extern tunnel_params oldTunnelData;
extern tunneldoc_t *tempTunnelData;
extern bool gXfinityEnable;
extern int vlanIdList[MAX_VAP];
typedef void* ANSC_HANDLE;
ANSC_HANDLE bus_handle;
CCSP_MESSAGE_BUS_INFO busInfo;
pErr execRetVal;
FILE *file;

class HotspotApiTestFixture : public ::testing::Test {
    protected:
        SyseventMock mockedSysevent;
        UtilMock mockedUtil;
        BaseAPIMock mockedbaseapi;
        UserTimeMock mockedUsertime;
        AnscWrapperApiMock mockedAnscWrapperApi;
        TraceMock mockedTrace;
        SafecLibMock mockedSafecLib;
        PsmMock mockedPsm;
        telemetryMock mockedTelemetry;
        JanssonMock mockedJansson;
        FileIOMock mockedFileIO;

        HotspotApiTestFixture()
        {
            execRetVal = (pErr) malloc (sizeof(Err));
            busInfo.freefunc = free;
            bus_handle = &busInfo;

            g_syseventMock = &mockedSysevent;
            g_utilMock = &mockedUtil;
            g_baseapiMock = &mockedbaseapi;
            g_usertimeMock = &mockedUsertime;
            g_anscWrapperApiMock = &mockedAnscWrapperApi;
            g_traceMock = &mockedTrace;
            g_safecLibMock = &mockedSafecLib;
            g_psmMock = &mockedPsm;
            g_telemetryMock = &mockedTelemetry;
            g_janssonMock = &mockedJansson;
            g_fileIOMock = &mockedFileIO;
        }
        virtual ~HotspotApiTestFixture()
        {
            free(execRetVal);
            g_syseventMock = nullptr;
            g_utilMock = nullptr;
            g_baseapiMock = nullptr;
            g_usertimeMock = nullptr;
            g_anscWrapperApiMock = nullptr;
            g_traceMock = nullptr;
            g_safecLibMock = nullptr;
            g_psmMock = nullptr;
            g_telemetryMock = nullptr;
            g_janssonMock = nullptr;
            g_fileIOMock = nullptr;
        }

        virtual void SetUp()
        {
            printf("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }

        virtual void TearDown()
        {
            printf("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }

        static void SetUpTestCase()
        {
            printf("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());
        }

        static void TearDownTestCase()
        {
            printf("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());
        }
};

void createFile(const char* fname) {
    if ((file = fopen(fname, "r"))) {
        fclose(file);
    }
    else {
        file = fopen(fname, "w");
        fclose(file);
    }
}

void removeFile(const char* fname) {
    remove(fname);
}

//TestCases for HotspotApi.c
TEST_F(HotspotApiTestFixture, gre_sysevent_syscfg_init_success) {
    int result;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("hotspot_service"), _)).Times(1).WillOnce(Return(0));
    result = gre_sysevent_syscfg_init();

    EXPECT_EQ(0, result);
}

TEST_F(HotspotApiTestFixture, gre_sysevent_syscfg_init_fail) {
    int result;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("hotspot_service"), _)).Times(1).WillOnce(Return(-1));
    result = gre_sysevent_syscfg_init();

    EXPECT_EQ(1, result);
}

TEST_F(HotspotApiTestFixture, update_bridge_config_pass) {
    int index = 1;
    int retval;

    EXPECT_CALL(*g_syseventMock, sysevent_set_unique(_, _, StrEq("GeneralPurposeFirewallRule"), _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).Times(1).WillOnce(Return(0));

    retval = update_bridge_config(index);
    EXPECT_EQ(0, retval);
}

TEST_F(HotspotApiTestFixture, update_bridge_config_fail) {
    int index = -1;
    int retval;

    retval = update_bridge_config(index);
    EXPECT_EQ(-1, retval);
}

TEST_F(HotspotApiTestFixture, ipAddress_version_ipv4Addr) {
    char ipAddress[] = "96.109.150.129";

    int result = ipAddress_version(ipAddress);
    EXPECT_EQ(4, result);
}

TEST_F(HotspotApiTestFixture, ipAddress_version_ipv6Addr) {
    char ipAddress[] = "2001:0558:4030:0008:dcb4:5b90:399e:9a17";

    int result = ipAddress_version(ipAddress);
    EXPECT_EQ(6, result);
}

TEST_F(HotspotApiTestFixture, ipAddress_version_invalid) {
    char ipAddress[] = "127.0.0.258";

    int result = ipAddress_version(ipAddress);
    EXPECT_EQ(-1, result);
}

TEST_F(HotspotApiTestFixture, create_tunnel) {
    int result;
    char ipAddress[] = "96.109.150.141";
    gSyseventfd = 0;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("hotspot_service"), _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));

    result = create_tunnel(ipAddress);
    EXPECT_EQ(0, result);
}

TEST_F(HotspotApiTestFixture, create_tunnel_ipv6) {
    int result;
    char ipAddress[] = "2001:0558:4030:0008:dcb4:5b90:399e:9a17";
    FILE* fp = nullptr;
    gSyseventfd = 0;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("hotspot_service"), _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq("ip addr show erouter0 | grep -w global | awk '/inet6/ {print $2}' | cut -d/ -f1"), _))
    .Times(1).WillOnce(Return(fp));
    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));

    result = create_tunnel(ipAddress);
    EXPECT_EQ(-1, result);
}

TEST_F(HotspotApiTestFixture, create_tunnel_sysevent_fail) {
    int result;
    char ipAddress[] = "96.109.150.141";
    gSyseventfd = 0;

    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("hotspot_service"), _)).Times(1).WillOnce(Return(-1));

    result = create_tunnel(ipAddress);
    EXPECT_EQ(1, result);
}

TEST_F(HotspotApiTestFixture, hotspot_sysevent_enable_param_filePresent) {
    int result;
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, access(StrEq(GRE_FILE), _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));

    result = hotspot_sysevent_enable_param();
    EXPECT_EQ(0, result);
}

TEST_F(HotspotApiTestFixture, hotspot_sysevent_enable_param_fileNotPresent) {
    int result;
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, access(StrEq(GRE_FILE), _)).WillRepeatedly(Return(1));
    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));

    result = hotspot_sysevent_enable_param();
    EXPECT_EQ(0, result);
}

TEST_F(HotspotApiTestFixture, getHotspotVapIndex_VAP_NAME_4) {
    int result;
    char vapName[] = "hotspot_open_2g";

    result = getHotspotVapIndex(vapName);
    EXPECT_EQ(0, result);
}

TEST_F(HotspotApiTestFixture, getHotspotVapIndex_VAP_NAME_5) {
    int result;
    char vapName[] = "hotspot_open_5g";

    result = getHotspotVapIndex(vapName);
    EXPECT_EQ(1, result);
}

TEST_F(HotspotApiTestFixture, getHotspotVapIndex_VAP_NAME_8) {
    int result;
    char vapName[] = "hotspot_secure_2g";

    result = getHotspotVapIndex(vapName);
    EXPECT_EQ(2, result);
}

TEST_F(HotspotApiTestFixture, getHotspotVapIndex_VAP_NAME_9) {
    int result;
    char vapName[] = "hotspot_secure_5g";

    result = getHotspotVapIndex(vapName);
    EXPECT_EQ(3, result);
}

TEST_F(HotspotApiTestFixture, getHotspotVapIndex_INVALID_VAP_NAME) {
    int result;
    char vapName[] = "secure_5g";

    result = getHotspotVapIndex(vapName);
    EXPECT_EQ(-1, result);
}

TEST_F(HotspotApiTestFixture, validateIpAddress_ipv4_pass) {
    int result;
    char ipAddress[] = "96.109.150.141";

    result = validateIpAddress(ipAddress);
    EXPECT_EQ(1, result);
}

TEST_F(HotspotApiTestFixture, validateIpAddress_ipv4_fail) {
    int result;
    char ipAddress[] = "255.255.255.255";

    result = validateIpAddress(ipAddress);
    EXPECT_EQ(0, result);
}

TEST_F(HotspotApiTestFixture, validateIpAddress_ipv6_pass) {
    int result;
    char ipAddress[] = "2001:0558:4030:0008:dcb4:5b90:399e:9a17";

    result = validateIpAddress(ipAddress);
    EXPECT_EQ(1, result);
}

TEST_F(HotspotApiTestFixture, get_ssid_enable) {
    int ssidIdx = 1;
    bool retVal = false;

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _))
        .WillOnce(Return(CCSP_Message_Bus_OK));

    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_, _, _))
        .Times(1);

    retVal = get_ssid_enable(ssidIdx);

    EXPECT_FALSE(retVal);
}

TEST_F(HotspotApiTestFixture, get_ssid_enable_false) {
    int ssidIdx = 1;
    bool retVal = false;

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _))
        .WillOnce(Return(1));

    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_, _, _))
        .Times(1);

    retVal = get_ssid_enable(ssidIdx);

    EXPECT_FALSE(retVal);
}

ACTION_P(SetPsmValueArg4, value)
{
    *static_cast<char**>(arg4) = strdup(*value);
}

TEST_F(HotspotApiTestFixture, PsmGet_success) {
    char param[25] = {0};
    char val[16] = {0};
    int result;
    char mockValue[] = "true";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&mockValue),
            ::testing::Return(CCSP_SUCCESS)
        ));

    result = PsmGet(param, val, sizeof(val));
    EXPECT_EQ(0, result);
}

TEST_F(HotspotApiTestFixture, PsmGet_fail) {
    const char param[] = "dmsb.hotspot.enable";
    char val[16] = {0};
    int result;

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(1)
        .WillOnce(Return(CCSP_FAILURE));

    result = PsmGet(param, val, sizeof(val));
    EXPECT_EQ(-1, result);
}

TEST_F(HotspotApiTestFixture, PsmSet_fail) {
    int result;
    const char param[] = "dmsb.hotspot.enable";
    const char val[] = "true";

    EXPECT_CALL(*g_psmMock, PSM_Set_Record_Value2(_, _, _, _, _))
        .Times(1)
        .WillOnce(Return(CCSP_FAILURE));

    result = PsmSet(param, val);
    EXPECT_EQ(-1, result);
}

TEST_F(HotspotApiTestFixture, prepareFirstRollback) {
    int result;
    json_t* nullObj = nullptr;

    EXPECT_CALL(*g_janssonMock, json_object()).Times(2).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_array()).Times(3).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _)).Times(1).WillOnce(Return(CCSP_SUCCESS));

    result = prepareFirstRollback();
    EXPECT_EQ(2, result);
}

TEST_F(HotspotApiTestFixture, prevalidateHotspotBlob_valid) {
    tunneldoc_t greTunnelData;
    greTunnelData.entries = new tdoc_t;
    greTunnelData.entries->gre_primary_endpoint = strdup("96.109.150.141");
    greTunnelData.entries->table_param = new tunnelTable_t;
    greTunnelData.entries->table_param->entries_count = 2;
    greTunnelData.entries->table_param->entries = new tunnel_t[2];
    greTunnelData.entries->table_param->entries[0].wan_vlan = 102;
    greTunnelData.entries->table_param->entries[0].vap_name = strdup("hotspot_open_2g");
    greTunnelData.entries->table_param->entries[1].wan_vlan = 103;
    greTunnelData.entries->table_param->entries[1].vap_name = strdup("hotspot_open_5g");

    bool result = prevalidateHotspotBlob(&greTunnelData);
    EXPECT_TRUE(result);

    for (int i = 0; i < greTunnelData.entries->table_param->entries_count; ++i) {
        free(greTunnelData.entries->table_param->entries[i].vap_name);
    }
    delete[] greTunnelData.entries->table_param->entries;
    delete greTunnelData.entries->table_param;
    free(greTunnelData.entries->gre_primary_endpoint);
    delete greTunnelData.entries;
}

TEST_F(HotspotApiTestFixture, compareTunnelConfig_isFirst_True) {
    int result;

    result = compareTunnelConfig();
    EXPECT_EQ(PRIMARY_EP_CHANGED | SECONDARY_EP_CHANGED | VLAN_CHANGE_1 | VLAN_CHANGE_2 | VLAN_CHANGE_3 | VLAN_CHANGE_4, result);
}

TEST_F(HotspotApiTestFixture, compareTunnelConfig_ChangeInConfig) {
    int ind = -1;
    oldTunnelData.isFirst = false;
    oldTunnelData.gre_enable = false;
    strncpy(oldTunnelData.primaryEP, "96.109.150.129", sizeof(oldTunnelData.primaryEP));
    strncpy(oldTunnelData.secondaryEP, "96.109.150.114", sizeof(oldTunnelData.secondaryEP));
    oldTunnelData.Vlans[0] = 102;
    oldTunnelData.Vlans[1] = 103;

    tempTunnelData = new tunneldoc_t;
    tempTunnelData->entries = new tdoc_t;
    tempTunnelData->entries->gre_enable = true;
    tempTunnelData->entries->gre_primary_endpoint = strdup("96.109.150.114");
    tempTunnelData->entries->gre_sec_endpoint = strdup("96.109.150.129");
    tempTunnelData->entries->table_param = new tunnelTable_t;
    tempTunnelData->entries->table_param->entries_count = 2;
    tempTunnelData->entries->table_param->entries = new tunnel_t[2];
    tempTunnelData->entries->table_param->entries[0].wan_vlan = 103;
    tempTunnelData->entries->table_param->entries[1].wan_vlan = 104;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq(oldTunnelData.primaryEP), _, _, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq(oldTunnelData.secondaryEP), _, _, _, _, _)).Times(1).WillOnce(Return(0));

    int result = compareTunnelConfig();
    EXPECT_EQ(GRE_ENABLE_CHANGE | PRIMARY_EP_CHANGED | SECONDARY_EP_CHANGED | VLAN_CHANGE_1 | VLAN_CHANGE_2, result);

    free(tempTunnelData->entries->gre_primary_endpoint);
    free(tempTunnelData->entries->gre_sec_endpoint);
    delete[] tempTunnelData->entries->table_param->entries;
    delete tempTunnelData->entries->table_param;
    delete tempTunnelData->entries;
    delete tempTunnelData;
}

TEST_F(HotspotApiTestFixture, compareTunnelConfig_noChange) {
    int ind = -1;
    oldTunnelData.isFirst = false;
    oldTunnelData.gre_enable = false;
    strncpy(oldTunnelData.primaryEP, "96.109.150.114", sizeof(oldTunnelData.primaryEP));
    strncpy(oldTunnelData.secondaryEP, "96.109.150.129", sizeof(oldTunnelData.secondaryEP));
    oldTunnelData.Vlans[0] = 102;
    oldTunnelData.Vlans[1] = 103;

    tempTunnelData = new tunneldoc_t;
    tempTunnelData->entries = new tdoc_t;
    tempTunnelData->entries->gre_enable = false;
    tempTunnelData->entries->gre_primary_endpoint = strdup("96.109.150.114");
    tempTunnelData->entries->gre_sec_endpoint = strdup("96.109.150.129");
    tempTunnelData->entries->table_param = new tunnelTable_t;
    tempTunnelData->entries->table_param->entries_count = 2;
    tempTunnelData->entries->table_param->entries = new tunnel_t[2];
    tempTunnelData->entries->table_param->entries[0].wan_vlan = 102;
    tempTunnelData->entries->table_param->entries[1].wan_vlan = 103;

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _)).Times(2).WillOnce(Return(1))
                                                                          .WillOnce(Return(1));

    int result = compareTunnelConfig();
    EXPECT_EQ(0, result);

    free(tempTunnelData->entries->gre_primary_endpoint);
    free(tempTunnelData->entries->gre_sec_endpoint);
    delete[] tempTunnelData->entries->table_param->entries;
    delete tempTunnelData->entries->table_param;
    delete tempTunnelData->entries;
    delete tempTunnelData;
}

TEST_F(HotspotApiTestFixture, setHotspot_SUCCESS_CASE_1) {
    pErr res;
    json_t *nullObj = nullptr;
    char *retVal = nullptr;
    tunneldoc_t* pGreTunnelData;
    pGreTunnelData = new tunneldoc_t;
    pGreTunnelData->entries = new tdoc_t;
    pGreTunnelData->entries->gre_enable = false;
    pGreTunnelData->entries->gre_primary_endpoint = strdup("96.109.150.114");
    pGreTunnelData->entries->gre_sec_endpoint = strdup("96.109.150.129");
    pGreTunnelData->entries->table_param = new tunnelTable_t;
    pGreTunnelData->entries->table_param->entries_count = 2;
    pGreTunnelData->entries->table_param->entries = new tunnel_t[2];
    pGreTunnelData->entries->table_param->entries[0].wan_vlan = 103;
    pGreTunnelData->entries->table_param->entries[1].wan_vlan = 104;

    createFile(N_HOTSPOT_JSON);

    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("hotspot_1-status"), _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _)).Times(2).WillOnce(Return(0))
                                                                          .WillOnce(Return(0));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .WillRepeatedly(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_psmMock, PSM_Set_Record_Value2(_, _, _, _, _)).Times(1).WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_janssonMock, json_object()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_array()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_string(_)).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_object_set_new(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_janssonMock, json_integer(_)).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_false()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_true()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_array_append_new(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_janssonMock, json_dumps(_, _)).WillOnce(Return(retVal));
    EXPECT_CALL(*g_janssonMock, json_dump_file(_, StrEq("/tmp/hotspot.json"), _)).Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, access(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillRepeatedly(Return(0));

    res = setHotspot((void*)pGreTunnelData);

    EXPECT_EQ(BLOB_EXEC_SUCCESS, res->ErrorCode);
    removeFile(N_HOTSPOT_JSON);

    free(pGreTunnelData->entries->gre_primary_endpoint);
    free(pGreTunnelData->entries->gre_sec_endpoint);
    delete[] pGreTunnelData->entries->table_param->entries;
    delete pGreTunnelData->entries->table_param;
    delete pGreTunnelData->entries;
    delete pGreTunnelData;
}

TEST_F(HotspotApiTestFixture, setHotspot_SUCCESS_CASE_2) {
    pErr res;
    gSyseventfd = 0;
    json_t *nullObj = nullptr;
    char *retVal = nullptr;
    tunneldoc_t* pGreTunnelData;

    oldTunnelData.isFirst = false;
    oldTunnelData.gre_enable = false;
    strncpy(oldTunnelData.primaryEP, "96.109.150.141", sizeof(oldTunnelData.primaryEP));
    strncpy(oldTunnelData.secondaryEP, "96.109.150.129", sizeof(oldTunnelData.secondaryEP));
    oldTunnelData.Vlans[0] = 102;
    oldTunnelData.Vlans[1] = 103;

    pGreTunnelData = new tunneldoc_t;
    pGreTunnelData->entries = new tdoc_t;
    pGreTunnelData->entries->gre_enable = false;
    pGreTunnelData->entries->gre_primary_endpoint = strdup("96.109.150.141");
    pGreTunnelData->entries->gre_sec_endpoint = strdup("96.109.150.129");
    pGreTunnelData->entries->table_param = new tunnelTable_t;
    pGreTunnelData->entries->table_param->entries_count = 2;
    pGreTunnelData->entries->table_param->entries = new tunnel_t[2];
    pGreTunnelData->entries->table_param->entries[0].enable = true;
    pGreTunnelData->entries->table_param->entries[0].vap_name = strdup("hotspot_open_2g");
    pGreTunnelData->entries->table_param->entries[0].wan_vlan = 102;
    pGreTunnelData->entries->table_param->entries[1].vap_name = strdup("hotspot_open_5g");
    pGreTunnelData->entries->table_param->entries[1].wan_vlan = 103;

    createFile(N_HOTSPOT_JSON);

    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("hotspot_1-status"), _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .WillRepeatedly(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_psmMock, PSM_Set_Record_Value2(_, _, _, _, _)).Times(1).WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _)).Times(2).WillOnce(Return(0))
                                                                          .WillOnce(Return(0));
    EXPECT_CALL(*g_janssonMock, json_object()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_array()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_string(_)).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_object_set_new(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_janssonMock, json_integer(_)).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_true()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_false()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_array_append_new(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_janssonMock, json_dumps(_, _)).WillOnce(Return(retVal));
    EXPECT_CALL(*g_janssonMock, json_dump_file(_, StrEq("/tmp/hotspot.json"), _)).Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_fileIOMock, access(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).WillRepeatedly(Return(0));

    res = setHotspot((void*)pGreTunnelData);

    EXPECT_EQ(BLOB_EXEC_SUCCESS, res->ErrorCode);
    removeFile(N_HOTSPOT_JSON);

    free(pGreTunnelData->entries->gre_primary_endpoint);
    free(pGreTunnelData->entries->gre_sec_endpoint);
    free(pGreTunnelData->entries->table_param->entries[0].vap_name);
    free(pGreTunnelData->entries->table_param->entries[1].vap_name);
    delete[] pGreTunnelData->entries->table_param->entries;
    delete pGreTunnelData->entries->table_param;
    delete pGreTunnelData->entries;
    delete pGreTunnelData;
}

TEST_F(HotspotApiTestFixture, setHotspot_FAIL_1) {
    pErr res;

    res = setHotspot(nullptr);

    EXPECT_EQ(BLOB_EXEC_FAILURE, res->ErrorCode);
}

TEST_F(HotspotApiTestFixture, setHotspot_FAIL_2) {
    pErr res;
    tunneldoc_t* pGreTunnelData;
    pGreTunnelData = new tunneldoc_t;
    pGreTunnelData->entries = new tdoc_t;
    pGreTunnelData->entries->gre_enable = true;
    pGreTunnelData->entries->gre_primary_endpoint = strdup("96.109.150.114");
    pGreTunnelData->entries->gre_sec_endpoint = strdup("96.109.150.129");
    pGreTunnelData->entries->table_param = new tunnelTable_t;
    pGreTunnelData->entries->table_param->entries_count = 2;
    pGreTunnelData->entries->table_param->entries = new tunnel_t[2];
    pGreTunnelData->entries->table_param->entries[0].wan_vlan = 103;
    pGreTunnelData->entries->table_param->entries[1].wan_vlan = 1104;

    createFile(N_HOTSPOT_JSON);

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, _, _, _))
        .Times(1)
        .WillOnce(Return(CCSP_FAILURE));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(_, _, _, _, _, _)).Times(2).WillOnce(Return(0))
                                                                          .WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, access(_, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_fileIOMock, fclose(_)).Times(testing::AnyNumber());
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, StrEq("hotspot_service"), _)).Times(1).WillOnce(Return(0));

    res = setHotspot((void*)pGreTunnelData);

    EXPECT_EQ(VALIDATION_FALIED, res->ErrorCode);
    removeFile(N_HOTSPOT_JSON);

    free(pGreTunnelData->entries->gre_primary_endpoint);
    free(pGreTunnelData->entries->gre_sec_endpoint);
    delete[] pGreTunnelData->entries->table_param->entries;
    delete pGreTunnelData->entries->table_param;
    delete pGreTunnelData->entries;
    delete pGreTunnelData;
}

TEST_F(HotspotApiTestFixture, deleteHotspot) {
    int result;
    json_t *nullObj = nullptr;

    EXPECT_CALL(*g_janssonMock, json_load_file(StrEq(N_HOTSPOT_JSON), _, _)).Times(1).WillOnce(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_load_file(StrEq(WAN_FAILOVER_JSON), _, _)).Times(1).WillOnce(Return(nullObj));
    EXPECT_CALL(*g_utilMock, system(StrEq("ip link del NULL ; ip link del NULL ; ip link del gretap0 ;"))).Times(4).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_utilMock, system(StrEq("killall CcspHotspot"))).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_utilMock, system(StrEq("killall hotspot_arpd"))).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_utilMock, system(StrEq("rm /tmp/.hotspot_blob_inprogress"))).Times(1).WillOnce(Return(0));

    result = deleteHotspot();
    EXPECT_EQ(ROLLBACK_SUCCESS, result);
}

TEST_F(HotspotApiTestFixture, checkGreInterface_Exist) {
    int result;
    int vlan_id = 101;
    char bridgeName[] = "brlan0";

    FILE *expectedFd = (FILE *)0xffffffff;
    char expectedIfList[] = "gretap0.101 ";
    char   gre_Interface[24] = {0};
    char expectedCmd[128] = {0};

    memset(gre_Interface, '\0', sizeof(gre_Interface));
    snprintf(gre_Interface, sizeof(gre_Interface), "%s.%d", GRE_IFNAME, vlan_id);

    memset(expectedCmd, '\0', sizeof(expectedCmd));
    snprintf(expectedCmd, sizeof(expectedCmd), "brctl show %s | sed '1d' | awk '{print $NF}' | grep %s | tr '\n' ' ' ", bridgeName, gre_Interface);

    EXPECT_CALL(*g_fileIOMock, popen(_, StrEq("r"))).Times(1).WillOnce(Return(expectedFd));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, _))
        .Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<0>(expectedIfList, expectedIfList + strlen(expectedIfList) + 1),
            Return(static_cast<char*>(expectedIfList))
        ));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd)).Times(1).WillOnce(Return(0));

    result = checkGreInterface_Exist(vlan_id, bridgeName);

    EXPECT_EQ(INTERFACE_EXIST, result);
}

TEST_F(HotspotApiTestFixture, checkGreInterface_failure) {
    int result;
    int vlan_id = 102;
    char bridgeName[] = "brlan0";

    FILE *expectedFd = nullptr;
    char   gre_Interface[24] = {0};
    char expectedCmd[128] = {0};

    memset(gre_Interface, '\0', sizeof(gre_Interface));
    snprintf(gre_Interface, sizeof(gre_Interface), "%s.%d", GRE_IFNAME, vlan_id);

    memset(expectedCmd, '\0', sizeof(expectedCmd));
    snprintf(expectedCmd, sizeof(expectedCmd), "brctl show %s | sed '1d' | awk '{print $NF}' | grep %s | tr '\n' ' ' ", bridgeName, gre_Interface);

    EXPECT_CALL(*g_fileIOMock, popen(_, StrEq("r"))).Times(1).WillOnce(Return(expectedFd));

    result = checkGreInterface_Exist(vlan_id, bridgeName);

    EXPECT_EQ(INTERFACE_NOT_EXIST, result);
}

TEST_F(HotspotApiTestFixture, confirmVap_failure) {
    int result;
    FILE *fp = nullptr;
    gXfinityEnable = true;

    EXPECT_CALL(*g_fileIOMock, popen(_, StrEq("r"))).WillRepeatedly(Return(fp));
    EXPECT_CALL(*g_fileIOMock, access(StrEq(T_HOTSPOT_JSON), _)).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*g_utilMock, system(StrEq("rm /tmp/.hotspot_blob_inprogress"))).Times(1).WillOnce(Return(0));

    result = confirmVap();

    //On failure, this function return (intptr_t)execRetVal, Expect any integer value as Result
    EXPECT_THAT(result, testing::AnyOf(testing::Lt(INT_MAX), testing::Gt(INT_MIN)));
}

TEST_F(HotspotApiTestFixture, confirmVap_success) {
    int result;
    FILE *fp = nullptr;
    char Buf[200] = {0};
    gXfinityEnable = true;
    vlanIdList[0] = 101;
    vlanIdList[1] = 102;
    vlanIdList[2] = 105;
    vlanIdList[3] = 106;

    oldTunnelData.isFirst = false;
    oldTunnelData.gre_enable = false;
    strncpy(oldTunnelData.primaryEP, "96.109.150.129", sizeof(oldTunnelData.primaryEP));
    strncpy(oldTunnelData.secondaryEP, "96.109.150.114", sizeof(oldTunnelData.secondaryEP));
    oldTunnelData.Vlans[0] = 102;
    oldTunnelData.Vlans[1] = 103;

    tempTunnelData = new tunneldoc_t;
    tempTunnelData->entries = new tdoc_t;
    tempTunnelData->entries->gre_enable = true;
    tempTunnelData->entries->gre_primary_endpoint = strdup("96.109.150.114");
    tempTunnelData->entries->gre_sec_endpoint = strdup("96.109.150.129");
    tempTunnelData->entries->table_param = new tunnelTable_t;
    tempTunnelData->entries->table_param->entries_count = 2;
    tempTunnelData->entries->table_param->entries = new tunnel_t[2];
    tempTunnelData->entries->table_param->entries[0].wan_vlan = 103;
    tempTunnelData->entries->table_param->entries[1].wan_vlan = 104;

    EXPECT_CALL(*g_fileIOMock, popen(_, StrEq("r"))).WillRepeatedly(Return(fp));
    EXPECT_CALL(*g_fileIOMock, access(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_psmMock, PSM_Set_Record_Value2(_, _, _, _, _)).WillRepeatedly(Return(CCSP_SUCCESS));

    result = confirmVap();
    EXPECT_EQ(0, result);
}


TEST_F(HotspotApiTestFixture, calculateTimeout) {
    size_t result;

    result = calculateTimeout(10);
    EXPECT_EQ(30, result);
}

TEST_F(HotspotApiTestFixture, hotspot_wan_failover_1) {
    int result;
    int remote_wan_enabled = false;
    json_t* obj = nullptr;
    char mockValue[] = "1";

    EXPECT_CALL(*g_janssonMock, json_load_file(_, _, _)).Times(2).WillOnce(Return(obj)).WillOnce(Return(obj));
    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, access(StrEq(N_HOTSPOT_JSON), _)).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(WEB_CONF_ENABLE), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&mockValue),
            ::testing::Return(CCSP_SUCCESS)
        ));
    EXPECT_CALL(*g_fileIOMock, access(StrEq(HOTSPOT_BLOB), _)).Times(1).WillOnce(Return(0));

    result = hotspot_wan_failover(remote_wan_enabled);
    EXPECT_EQ(0, result);
}

TEST_F(HotspotApiTestFixture, hotspot_wan_failover_2) {
    int result;
    int remote_wan_enabled = true;
    json_t* obj = nullptr;
    char mockValue[] = "0";

    EXPECT_CALL(*g_janssonMock, json_object()).Times(2).WillRepeatedly(Return(obj));
    EXPECT_CALL(*g_janssonMock, json_array()).Times(3).WillRepeatedly(Return(obj));
    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_fileIOMock, access(StrEq(N_HOTSPOT_JSON), _)).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(PSM_PRI_IP), _, _))
        .Times(1)
        .WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(WEB_CONF_ENABLE), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&mockValue),
            ::testing::Return(CCSP_SUCCESS)
        ));
    EXPECT_CALL(*g_fileIOMock, access(StrEq(HOTSPOT_BLOB), _)).Times(1).WillOnce(Return(1));

    result = hotspot_wan_failover(remote_wan_enabled);
    EXPECT_EQ(0, result);
}

TEST_F(HotspotApiTestFixture, configHotspotBridgeVlan_valid) {
    char vap_name[] = "hotspot_secure_5g";
    int vlan_id = 101;

    EXPECT_CALL(*g_utilMock, system(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(StrEq("XWIFI_VLANID_10_split"), _)).Times(1).WillOnce(Return(T2ERROR_SUCCESS));

    configHotspotBridgeVlan(vap_name, vlan_id);
}

TEST_F(HotspotApiTestFixture, configHotspotBridgeVlan_invalid) {
    char vap_name[] = "invalid_vap";
    int vlan_id = 199;

    configHotspotBridgeVlan(vap_name, vlan_id);
}

TEST_F(HotspotApiTestFixture, recreate_tunnel_valid) {
    json_t *nullObj = nullptr;

    EXPECT_CALL(*g_utilMock, system(StrEq("ip link del gretap0 ;"))).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_janssonMock, json_load_file(StrEq(N_HOTSPOT_JSON), _, _)).Times(1).WillOnce(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_load_file(StrEq(WAN_FAILOVER_JSON), _, _)).Times(1).WillOnce(Return(nullObj));

    recreate_tunnel();
}

TEST_F(HotspotApiTestFixture, prevalidateHotspotBlob_invalidPrimaryEndpoint) {
    tunneldoc_t greTunnelData;
    char errorMsg[] = "Invalid Primary Endpoint IP";

    memset(execRetVal, 0, sizeof(Err));

    greTunnelData.entries = new tdoc_t;
    greTunnelData.entries->gre_primary_endpoint = strdup("255.255.255.255");
    greTunnelData.entries->table_param = new tunnelTable_t;
    greTunnelData.entries->table_param->entries_count = 2;
    greTunnelData.entries->table_param->entries = new tunnel_t[2];
    greTunnelData.entries->table_param->entries[0].wan_vlan = 102;
    greTunnelData.entries->table_param->entries[0].vap_name = strdup("hotspot_open_2g");
    greTunnelData.entries->table_param->entries[1].wan_vlan = 103;
    greTunnelData.entries->table_param->entries[1].vap_name = strdup("hotspot_open_5g");

    bool result = prevalidateHotspotBlob(&greTunnelData);

    EXPECT_FALSE(result);

    free(greTunnelData.entries->gre_primary_endpoint);
    free(greTunnelData.entries->table_param->entries[0].vap_name);
    free(greTunnelData.entries->table_param->entries[1].vap_name);
    delete[] greTunnelData.entries->table_param->entries;
    delete greTunnelData.entries->table_param;
    delete greTunnelData.entries;
}

TEST_F(HotspotApiTestFixture, prevalidateHotspotBlob_invalidVapCount) {
    tunneldoc_t greTunnelData;
    greTunnelData.entries = new tdoc_t;
    greTunnelData.entries->gre_primary_endpoint = strdup("96.109.150.141");
    greTunnelData.entries->table_param = new tunnelTable_t;
    greTunnelData.entries->table_param->entries_count = 5;
    greTunnelData.entries->table_param->entries = new tunnel_t[5];

    greTunnelData.entries->table_param->entries[0].wan_vlan = 102;
    greTunnelData.entries->table_param->entries[0].vap_name = strdup("hotspot_open_2g");
    greTunnelData.entries->table_param->entries[1].wan_vlan = 103;
    greTunnelData.entries->table_param->entries[1].vap_name = strdup("hotspot_open_5g");
    greTunnelData.entries->table_param->entries[2].wan_vlan = 104;
    greTunnelData.entries->table_param->entries[2].vap_name = strdup("hotspot_secure_2g");
    greTunnelData.entries->table_param->entries[3].wan_vlan = 105;
    greTunnelData.entries->table_param->entries[3].vap_name = strdup("hotspot_secure_5g");
    greTunnelData.entries->table_param->entries[4].wan_vlan = 106;
    greTunnelData.entries->table_param->entries[4].vap_name = strdup("hotspot_guest");

    bool result = prevalidateHotspotBlob(&greTunnelData);

    EXPECT_FALSE(result);

    free(greTunnelData.entries->gre_primary_endpoint);
    for (int i = 0; i < greTunnelData.entries->table_param->entries_count; ++i) {
        free(greTunnelData.entries->table_param->entries[i].vap_name);
    }
    delete[] greTunnelData.entries->table_param->entries;
    delete greTunnelData.entries->table_param;
    delete greTunnelData.entries;
}

TEST_F(HotspotApiTestFixture, prevalidateHotspotBlob_invalidVlanId) {
    tunneldoc_t greTunnelData;
    greTunnelData.entries = new tdoc_t;
    greTunnelData.entries->gre_primary_endpoint = strdup("96.109.150.141");
    greTunnelData.entries->table_param = new tunnelTable_t;
    greTunnelData.entries->table_param->entries_count = 2;
    greTunnelData.entries->table_param->entries = new tunnel_t[2];
    greTunnelData.entries->table_param->entries[0].wan_vlan = 101;
    greTunnelData.entries->table_param->entries[0].vap_name = strdup("hotspot_open_2g");
    greTunnelData.entries->table_param->entries[1].wan_vlan = 4095;
    greTunnelData.entries->table_param->entries[1].vap_name = strdup("hotspot_open_5g");

    bool result = prevalidateHotspotBlob(&greTunnelData);

    EXPECT_FALSE(result);

    free(greTunnelData.entries->gre_primary_endpoint);
    for (int i = 0; i < greTunnelData.entries->table_param->entries_count; ++i) {
        free(greTunnelData.entries->table_param->entries[i].vap_name);
    }
    delete[] greTunnelData.entries->table_param->entries;
    delete greTunnelData.entries->table_param;
    delete greTunnelData.entries;
}

TEST_F(HotspotApiTestFixture, prevalidateHotspotBlob_invalidVapName) {
    tunneldoc_t greTunnelData;
    greTunnelData.entries = new tdoc_t;
    greTunnelData.entries->gre_primary_endpoint = strdup("96.109.150.141");
    greTunnelData.entries->table_param = new tunnelTable_t;
    greTunnelData.entries->table_param->entries_count = 2;
    greTunnelData.entries->table_param->entries = new tunnel_t[2];
    greTunnelData.entries->table_param->entries[0].wan_vlan = 102;
    greTunnelData.entries->table_param->entries[0].vap_name = strdup("hotspot_open_2g");
    greTunnelData.entries->table_param->entries[1].wan_vlan = 103;
    greTunnelData.entries->table_param->entries[1].vap_name = strdup("invalid_vap_name");

    bool result = prevalidateHotspotBlob(&greTunnelData);

    EXPECT_FALSE(result);

    free(greTunnelData.entries->gre_primary_endpoint);
    for (int i = 0; i < greTunnelData.entries->table_param->entries_count; ++i) {
        free(greTunnelData.entries->table_param->entries[i].vap_name);
    }
    delete[] greTunnelData.entries->table_param->entries;
    delete greTunnelData.entries->table_param;
    delete greTunnelData.entries;
}

//TestCases for HotspotJansson.c
TEST_F(HotspotApiTestFixture, checking_recovery_janson_fail) {
    json_t* obj = nullptr;
    int result;

    result = checking_recovery_janson(obj);
    EXPECT_EQ(1, result);
}

TEST_F(HotspotApiTestFixture, checking_recovery_janson_invalid) {
    int result;
    json_t* mock_json_tun_root = (json_t*)0x12345678;
    json_t* nullObj = nullptr;

    EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_WRONG_SEC_EP_NAME)))
        .Times(1).WillOnce(Return(nullObj));

    EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_SEC_EP_NAME)))
        .Times(1).WillOnce(Return(nullObj));

    EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_DSCP)))
        .Times(1).WillOnce(Return(nullObj));

    result = checking_recovery_janson(mock_json_tun_root);
    EXPECT_EQ(1, result);
}

TEST_F(HotspotApiTestFixture, checking_recovery_janson_valid) {
    int result;
    json_t* mock_json_tun_root = (json_t*)0x12345678;
    json_t* nullObj = nullptr;
    json_t* obj1 = new json_t;
    obj1->type = JSON_STRING;

    json_t* obj2 = new json_t;
    obj2->type = JSON_STRING;

    json_t* jsonInt = new json_t;
    jsonInt->type = JSON_INTEGER;

    EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_WRONG_SEC_EP_NAME)))
        .Times(1).WillOnce(Return(obj1));

    EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_SEC_EP_NAME)))
        .Times(1).WillOnce(Return(nullObj));

    EXPECT_CALL(*g_janssonMock, json_string_value(obj1)).Times(1).WillOnce(Return("96.109.150.129"));

    EXPECT_CALL(*g_janssonMock, json_string(StrEq("96.109.150.129"))).Times(1).WillOnce(Return(obj1));

    EXPECT_CALL(*g_janssonMock, json_object_set_new(mock_json_tun_root, StrEq(J_GRE_SEC_EP_NAME), obj1))
        .Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_DSCP)))
        .Times(1).WillOnce(Return(obj2));

    EXPECT_CALL(*g_janssonMock, json_string_value(obj2)).Times(1).WillOnce(Return("101"));

    EXPECT_CALL(*g_janssonMock, json_integer(101)).Times(1).WillOnce(Return(jsonInt));

    EXPECT_CALL(*g_janssonMock, json_object_set_new(mock_json_tun_root, StrEq(J_GRE_DSCP), jsonInt))
        .Times(1).WillOnce(Return(0));

    EXPECT_CALL(*g_janssonMock, json_dump_file(mock_json_tun_root, StrEq("/nvram/hotspot.json"), _))
        .Times(1).WillOnce(Return(0));

    result = checking_recovery_janson(mock_json_tun_root);
    EXPECT_EQ(1, result);

    delete obj1;
    delete obj2;
    delete jsonInt;
}

TEST_F(HotspotApiTestFixture, jansson_rollback_tunnel_info) {
    json_t* nullObj = nullptr;
    json_t* mock_json_tun_root = new json_t;
    json_t* ecount = new json_t;
    json_t* jpriEndpoint = new json_t;
    json_t* jsecEndpoint = new json_t;
    json_t* jdscp = new json_t;
    json_t* jgre_enable = new json_t;
    json_t* json_tun = new json_t;
    json_t* json_vap_name = new json_t;
    json_t* json_wan_vlan = new json_t;
    json_t* json_vap_enable = new json_t;
    json_t* jsonVapName = new json_t;
    json_t* jsonVapenable = new json_t;
    json_t* jsonVapID = new json_t;

    ecount->type = JSON_INTEGER;
    jpriEndpoint->type = JSON_STRING;
    jsecEndpoint->type = JSON_STRING;
    jdscp->type = JSON_INTEGER;
    jgre_enable->type = JSON_TRUE;
    json_tun->type = JSON_OBJECT;
    json_vap_name->type = JSON_ARRAY;
    json_wan_vlan->type = JSON_ARRAY;
    json_vap_enable->type = JSON_ARRAY;
    jsonVapName->type = JSON_STRING;
    jsonVapenable->type = JSON_TRUE;
    jsonVapID->type = JSON_INTEGER;

    mock_json_tun_root->refcount = 1;
    ecount->refcount = 1;
    jpriEndpoint->refcount = 1;
    jsecEndpoint->refcount = 1;
    jdscp->refcount = 1;
    jgre_enable->refcount = 1;
    json_tun->refcount = 1;
    json_vap_name->refcount = 1;
    json_wan_vlan->refcount = 1;
    json_vap_enable->refcount = 1;
    jsonVapName->refcount = 1;
    jsonVapenable->refcount = 1;
    jsonVapID->refcount = 1;

    {
        testing::InSequence s;

        EXPECT_CALL(*g_janssonMock, json_load_file(StrEq(N_HOTSPOT_JSON), 0, _))
            .Times(1).WillOnce(Return(mock_json_tun_root));

        EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_WRONG_SEC_EP_NAME)))
            .Times(1).WillOnce(Return(nullObj));

        EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_SEC_EP_NAME)))
            .Times(1).WillOnce(Return(nullObj));

        EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_DSCP)))
            .Times(1).WillOnce(Return(nullObj));

        EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_ENT_COUNT)))
            .Times(1).WillOnce(Return(ecount));

        EXPECT_CALL(*g_janssonMock, json_integer_value(ecount)).Times(1).WillOnce(Return(1));

        EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_PRI_EP_NAME)))
            .Times(1).WillOnce(Return(jpriEndpoint));

        EXPECT_CALL(*g_janssonMock, json_string_value(jpriEndpoint)).Times(1).WillOnce(Return("192.168.1.1"));

        EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_SEC_EP_NAME)))
            .Times(1).WillOnce(Return(jsecEndpoint));

        EXPECT_CALL(*g_janssonMock, json_string_value(jsecEndpoint)).Times(1).WillOnce(Return("0.0.0.0"));

        EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_DSCP)))
            .Times(1).WillOnce(Return(jdscp));

        EXPECT_CALL(*g_janssonMock, json_integer_value(jdscp)).Times(1).WillOnce(Return(10));

        EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_ENABLE)))
            .Times(1).WillOnce(Return(jgre_enable));

        EXPECT_CALL(*g_janssonMock, json_object_get(mock_json_tun_root, StrEq(J_GRE_TUNNEL_NET)))
            .Times(1).WillOnce(Return(json_tun));

        EXPECT_CALL(*g_janssonMock, json_object_get(json_tun, StrEq(J_GRE_VAP_NAME)))
            .Times(1).WillOnce(Return(json_vap_name));

        EXPECT_CALL(*g_janssonMock, json_object_get(json_tun, StrEq(J_GRE_WAN_VLAN)))
            .Times(1).WillOnce(Return(json_wan_vlan));

        EXPECT_CALL(*g_janssonMock, json_object_get(json_tun, StrEq(J_GRE_VAP_ENABLE)))
            .Times(1).WillOnce(Return(json_vap_enable));

        EXPECT_CALL(*g_janssonMock, json_array_get(json_vap_name, 0)).Times(1).WillOnce(Return(jsonVapName));
        EXPECT_CALL(*g_janssonMock, json_string_value(jsonVapName)).Times(1).WillOnce(Return("vap0"));
        EXPECT_CALL(*g_janssonMock, json_array_get(json_vap_enable, 0)).Times(1).WillOnce(Return(jsonVapenable));
        EXPECT_CALL(*g_janssonMock, json_array_get(json_wan_vlan, 0)).Times(1).WillOnce(Return(jsonVapID));
        EXPECT_CALL(*g_janssonMock, json_integer_value(jsonVapID)).Times(1).WillOnce(Return(1));
        EXPECT_CALL(*g_janssonMock, json_delete(_)).Times(testing::AnyNumber());
    }

    EXPECT_CALL(*g_utilMock, system(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_syseventMock, sysevent_open(_, _, _, _, _)).Times(1).WillOnce(Return(0));

    bool result = jansson_rollback_tunnel_info();

    EXPECT_TRUE(result);

    delete ecount;
    delete jpriEndpoint;
    delete jsecEndpoint;
    delete jdscp;
    delete jgre_enable;
    delete json_tun;
    delete json_vap_name;
    delete json_wan_vlan;
    delete json_vap_enable;
    delete jsonVapName;
    delete jsonVapenable;
    delete jsonVapID;
}

TEST_F(HotspotApiTestFixture, jansson_store_tunnel_info_CASE_1) {
    int result;
    json_t* nullObj = nullptr;
    tunneldoc_t* pGreTunnelData = new tunneldoc_t;
    pGreTunnelData->entries = new tdoc_t;
    pGreTunnelData->entries->gre_enable = false;
    pGreTunnelData->entries->gre_primary_endpoint = strdup("96.109.150.114");
    pGreTunnelData->entries->gre_sec_endpoint = strdup("96.109.150.129");
    pGreTunnelData->entries->table_param = new tunnelTable_t;
    pGreTunnelData->entries->table_param->entries_count = 2;
    pGreTunnelData->entries->table_param->entries = new tunnel_t[2];
    pGreTunnelData->entries->table_param->entries[0].wan_vlan = 103;
    pGreTunnelData->entries->table_param->entries[1].wan_vlan = 104;

    EXPECT_CALL(*g_janssonMock, json_object()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_array()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_string(_)).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_integer(_)).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_false()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_true()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_object_set_new(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_janssonMock, json_array_append_new(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_janssonMock, json_dumps(_, _)).WillOnce(Return((char*)nullptr));
    EXPECT_CALL(*g_janssonMock, json_dump_file(_, _, _)).WillOnce(Return(0));

    result = jansson_store_tunnel_info(pGreTunnelData);
    EXPECT_EQ(0, result);

    free(pGreTunnelData->entries->gre_primary_endpoint);
    free(pGreTunnelData->entries->gre_sec_endpoint);
    delete[] pGreTunnelData->entries->table_param->entries;
    delete pGreTunnelData->entries->table_param;
    delete pGreTunnelData->entries;
    delete pGreTunnelData;
}

TEST_F(HotspotApiTestFixture, jansson_store_tunnel_info_CASE_2) {
    int result;
    json_t* nullObj = nullptr;
    tunneldoc_t* pGreTunnelData = nullptr;

    EXPECT_CALL(*g_janssonMock, json_object()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_array()).WillRepeatedly(Return(nullObj));

    char mockPriIP[] = "96.109.150.114";
    char mockSecIP[] = "96.109.150.129";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(PSM_PRI_IP), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&mockPriIP),
            ::testing::Return(CCSP_SUCCESS)
        ));
    EXPECT_CALL(*g_janssonMock, json_object_set_new(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(PSM_SEC_IP), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&mockSecIP),
            ::testing::Return(CCSP_SUCCESS)
        ));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(PSM_DSCP_MARK), _, _))
        .Times(1)
        .WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(PSM_HOTSPOT_ENABLE), _, _))
        .Times(1)
        .WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.hotspot.tunnel.1.interface.1.VLANID"), _, _))
        .Times(1)
        .WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.hotspot.tunnel.1.interface.2.VLANID"), _, _))
        .Times(1)
        .WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.hotspot.tunnel.1.interface.3.VLANID"), _, _))
        .Times(1)
        .WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq("dmsb.hotspot.tunnel.1.interface.4.VLANID"), _, _))
        .Times(1)
        .WillOnce(Return(CCSP_SUCCESS));
    EXPECT_CALL(*g_janssonMock, json_string(_)).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_integer(_)).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_false()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_true()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_array_append_new(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, _, _, _, _, _))
        .WillRepeatedly(Return(CCSP_Message_Bus_OK));

    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_, _, _))
        .Times(4);
    EXPECT_CALL(*g_janssonMock, json_dumps(_, _)).WillOnce(Return((char*)nullptr));
    EXPECT_CALL(*g_janssonMock, json_dump_file(_, _, _)).WillOnce(Return(0));

    result = jansson_store_tunnel_info(pGreTunnelData);
    EXPECT_EQ(1, result);
}

TEST_F(HotspotApiTestFixture, jansson_store_tunnel_info_FAIL) {
    int result;
    json_t* nullObj = nullptr;
    tunneldoc_t* pGreTunnelData = nullptr;

    EXPECT_CALL(*g_janssonMock, json_object()).WillRepeatedly(Return(nullObj));
    EXPECT_CALL(*g_janssonMock, json_array()).WillRepeatedly(Return(nullObj));

    char mockPriIP[] = "96.109.150.114";
    char mockSecIP[] = "0.0.0.0";

    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(PSM_PRI_IP), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&mockPriIP),
            ::testing::Return(CCSP_SUCCESS)
        ));
    EXPECT_CALL(*g_janssonMock, json_object_set_new(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_janssonMock, json_string(_)).Times(1).WillOnce(Return(nullObj));
    EXPECT_CALL(*g_psmMock, PSM_Get_Record_Value2(_, _, StrEq(PSM_SEC_IP), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetPsmValueArg4(&mockSecIP),
            ::testing::Return(CCSP_SUCCESS)
        ));

    result = jansson_store_tunnel_info(pGreTunnelData);
    EXPECT_EQ(2, result);
}