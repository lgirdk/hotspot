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
#include <sys/shm.h>
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
#include <mocks/mock_telemetry.h>
#include <mocks/mock_file_io.h>
#include <mocks/mock_securewrapper.h>
#include <mocks/mock_nfqueue.h>
#include <mocks/mock_socket.h>
#include "test/mocks/mock_hotspotApi.h"

extern "C" {
#include "cosa_hotspot_dml.h"
#include "dhcp.h"
#include "debug.h"
#include "dhcpsnooper.h"
#include "hotspotfd.h"
#include "test/mocks/hotspotfd_internal_mock.h"
}

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::DoAll;
using ::testing::SetArgPointee;

SyseventMock * g_syseventMock = nullptr;
UtilMock * g_utilMock = nullptr;
BaseAPIMock * g_baseapiMock = nullptr;
UserTimeMock * g_usertimeMock = nullptr;
AnscWrapperApiMock * g_anscWrapperApiMock = nullptr;
TraceMock * g_traceMock = nullptr;
SafecLibMock* g_safecLibMock = nullptr;
telemetryMock * g_telemetryMock = nullptr;
FileIOMock * g_fileIOMock = nullptr;
SecureWrapperMock * g_securewrapperMock = nullptr;
HotspotApiMock * g_hotspotApiMock = nullptr;
NfQueueMock * g_nfQueueMock = nullptr;
SocketMock * g_socketMock = nullptr;

class HotspotFdTestFixture : public ::testing::Test {
    protected:
        SyseventMock mockedSysevent;
        UtilMock mockedUtil;
        BaseAPIMock mockedbaseapi;
        UserTimeMock mockedUsertime;
        AnscWrapperApiMock mockedAnscWrapperApi;
        TraceMock mockedTrace;
        SafecLibMock mockedSafecLib;
        telemetryMock mockedTelemetry;
        FileIOMock mockedFileIO;
        SecureWrapperMock mockedSecureWrapper;
        HotspotApiMock mockedHotspotApi;
        NfQueueMock mockedNfQueue;
        SocketMock mockedSocket;

        HotspotFdTestFixture()
        {
            busInfo.freefunc = free;
            bus_handle = &busInfo;

            g_syseventMock = &mockedSysevent;
            g_utilMock = &mockedUtil;
            g_baseapiMock = &mockedbaseapi;
            g_usertimeMock = &mockedUsertime;
            g_anscWrapperApiMock = &mockedAnscWrapperApi;
            g_traceMock = &mockedTrace;
            g_safecLibMock = &mockedSafecLib;
            g_telemetryMock = &mockedTelemetry;
            g_fileIOMock = &mockedFileIO;
            g_securewrapperMock = &mockedSecureWrapper;
            g_hotspotApiMock = &mockedHotspotApi;
            g_nfQueueMock = &mockedNfQueue;
            g_socketMock = &mockedSocket;
        }
        virtual ~HotspotFdTestFixture()
        {
            g_syseventMock = nullptr;
            g_utilMock = nullptr;
            g_baseapiMock = nullptr;
            g_usertimeMock = nullptr;
            g_anscWrapperApiMock = nullptr;
            g_traceMock = nullptr;
            g_safecLibMock = nullptr;
            g_telemetryMock = nullptr;
            g_fileIOMock = nullptr;
            g_securewrapperMock = nullptr;
            g_hotspotApiMock = nullptr;
            g_nfQueueMock = nullptr;
            g_socketMock = nullptr;
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

static inline void mylist_add(struct mylist_head *nn, struct mylist_head *h)
{
        h->n->p = nn;
        nn->n = h->n;
        nn->p = h;
        h->n = nn;
}

static inline void mylist_del(struct mylist_head *e)
{
    e->n->p = e->p;
    e->p->n = e->n;

    e->n = 0;
    e->p = 0;
}

//Testcases for cosa_hotspot_dml.c
TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_GetParamStringValue_SUCCESS) {
    ULONG result;
    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char pValue[100];
    ULONG ulSize = sizeof(pValue);

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    result = HotspotConnectedDevice_GetParamStringValue(hInsContext, ParamName, pValue, &ulSize);
    EXPECT_EQ(0, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_GetParamStringValue_FAIL) {
    ULONG result;
    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientNotChange";
    char pValue[100];
    ULONG ulSize = sizeof(pValue);

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(-1),
            Return(1)
        ));
    result = HotspotConnectedDevice_GetParamStringValue(hInsContext, ParamName, pValue, &ulSize);
    EXPECT_EQ(1, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_SUCCESS_1) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char strValue[] = "1|3| -65|01:23:45:67:89:AB";
    char macAddr[18] = "01:23:45:67:89:AB";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    EXPECT_CALL(*g_safecLibMock, sscanf_s(StrEq(strValue), _, _, _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<2>(1),
            testing::SetArgPointee<3>(3),
            testing::SetArgPointee<4>(-65),
            testing::SetArrayArgument<5>(macAddr, macAddr + strlen(macAddr) + 1),
            Return(4)
        ));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(StrEq("WIFI_INFO_Hotspot_client_connected"), 1)).Times(1).WillOnce(Return(T2ERROR_SUCCESS));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(TRUE, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_SUCCESS_2) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char strValue[] = "0|1|75|AB:CD:EF:01:23:45";
    char macAddr[18] = "AB:CD:EF:01:23:45";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    EXPECT_CALL(*g_safecLibMock, sscanf_s(StrEq(strValue), _, _, _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<2>(0),
            testing::SetArgPointee<3>(1),
            testing::SetArgPointee<4>(75),
            testing::SetArrayArgument<5>(macAddr, macAddr + strlen(macAddr) + 1),
            Return(4)
        ));
    EXPECT_CALL(*g_telemetryMock, t2_event_d(StrEq("WIFI_INFO_Hotspot_client_disconnected"), 1)).Times(1).WillOnce(Return(T2ERROR_SUCCESS));

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(TRUE, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_FAIL_1) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char *strValue = nullptr;

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(FALSE, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_FAIL_2) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char strValue[] = "0|1|75|AB:CD:EF:01:23:45:15";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(FALSE, result);
}

TEST_F(HotspotFdTestFixture, HotspotConnectedDevice_SetParamStringValue_FAIL_3) {
    BOOL result;

    ANSC_HANDLE hInsContext = nullptr;
    char ParamName[] = "ClientChange";
    char strValue[] = "0|1|75|AB:CD:EF:01:23:45";
    char macAddr[18] = "AB:CD:EF:01:23:45";

    EXPECT_CALL(*g_safecLibMock, _memset_s_chk(_, _, _, _, _)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq("ClientChange"), _, StrEq(ParamName), _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    EXPECT_CALL(*g_safecLibMock, sscanf_s(StrEq(strValue), _, _, _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<2>(0),
            testing::SetArgPointee<3>(1),
            testing::SetArgPointee<4>(75),
            testing::SetArrayArgument<5>(macAddr, macAddr + strlen(macAddr) + 1),
            Return(EOF)
        ));

    result = HotspotConnectedDevice_SetParamStringValue(hInsContext, ParamName, strValue);
    EXPECT_EQ(FALSE, result);
}

//Testcases for dhcp_snooper.c
TEST_F(HotspotFdTestFixture, snoop_ipChecksum) {
    struct iphdr mockHeader;
    mockHeader.check = 0x0;
    mockHeader.version = 4;
    mockHeader.ihl = 5;
    mockHeader.tos = 0x10;
    mockHeader.tot_len = 20;
    mockHeader.id = 0x1234;
    mockHeader.frag_off = 0x4000;
    mockHeader.ttl = 64;
    mockHeader.protocol = 6;
    mockHeader.saddr = inet_addr("192.168.0.1");
    mockHeader.daddr = inet_addr("192.168.0.2");

    // calculate expected checksum
    unsigned int nbytes = sizeof(struct iphdr);
    unsigned short *buf = (unsigned short *)&mockHeader;
    unsigned int sum = 0;
    for (; nbytes > 1; nbytes -= 2) {
        sum += *buf++;
    }
    if (nbytes == 1) {
        sum += *(unsigned char*) buf;
    }
    sum  = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    unsigned short expectedChecksum = ~sum;

    unsigned short actualChecksum = snoop_ipChecksum(&mockHeader);

    EXPECT_EQ(expectedChecksum, actualChecksum);
}

TEST_F(HotspotFdTestFixture, snoop_log_SUCCESS) {
    createFile(SNOOP_LOG_PATH);
    int gShm_snoop_fd;
    gShm_snoop_fd = shmget(kSnooper_Statistics, kSnooper_SharedMemSize, IPC_CREAT | 0666);
    gpSnoop_Stats = (snooper_statistics_s *)shmat(gShm_snoop_fd, NULL, 0);

    EXPECT_CALL(*g_fileIOMock, fclose(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _memcpy_s_chk(_, _, _, _, _, _)).Times(1).WillOnce(Return(0));
    snoop_log();

    removeFile(SNOOP_LOG_PATH);
}

TEST_F(HotspotFdTestFixture, snoop_log_FAIL) {
    createFile(SNOOP_LOG_PATH);
    int gShm_snoop_fd;
    gShm_snoop_fd = shmget(kSnooper_Statistics, kSnooper_SharedMemSize, IPC_CREAT | 0666);
    gpSnoop_Stats = (snooper_statistics_s *)shmat(gShm_snoop_fd, NULL, 0);

    EXPECT_CALL(*g_fileIOMock, fclose(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _memcpy_s_chk(_, _, _, _, _, _)).Times(1).WillOnce(Return(1));
    snoop_log();

    removeFile(SNOOP_LOG_PATH);
}

//Testcases of hotspotfd.c
TEST_F(HotspotFdTestFixture, Get_HotspotfdType) {
    HotspotfdType result;
    char name[] = "hotspotfd-primary";

    EXPECT_CALL(*g_safecLibMock, _strcmp_s_chk(StrEq(name), _, _, _, _, _))
        .WillOnce(DoAll(
            testing::SetArgPointee<3>(0),
            Return(0)
        ));
    result = Get_HotspotfdType(name);
    EXPECT_EQ(HOTSPOTFD_PRIMARY, result);
}

TEST_F(HotspotFdTestFixture, deleteSharedMem_CASE_1) {
    bool result;

    result = deleteSharedMem(865889, true);
    EXPECT_EQ(true, result);
}

TEST_F(HotspotFdTestFixture, deleteSharedMem_CASE_2) {
    bool result;

    result = deleteSharedMem(865889, false);
    EXPECT_EQ(true, result);
}

TEST_F(HotspotFdTestFixture, set_tunnelstatus) {
    bool result;
    char status[] = "Up";
    char mockFaultParam[] = "TRUE";

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(status)).Times(1).WillOnce(Return(status));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_, _, _, _, _, _, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::WithArg<8>([&](char** faultParam){
        *faultParam = mockFaultParam;
        }),
    Return(CCSP_SUCCESS)));

    result = set_tunnelstatus(status);
    EXPECT_EQ(true, result);
}

TEST_F(HotspotFdTestFixture, notify_tunnel_status_UP) {
    char status[] = "Up";
    char mockFaultParam[] = "TRUE";

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(status)).Times(1).WillOnce(Return(status));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_, _, _, _, _, _, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::WithArg<8>([&](char** faultParam){
        *faultParam = mockFaultParam;
        }),
    Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_SendSignal_WithData(_, StrEq("Device.X_COMCAST-COM_GRE.Tunnel.1.TunnelStatus"), _))
    .Times(1).WillOnce(Return(CCSP_SUCCESS));

    notify_tunnel_status(status);
}

TEST_F(HotspotFdTestFixture, notify_tunnel_status_DOWN) {
    char status[] = "Down";
    char mockFaultParam[] = "False";

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(status)).Times(1).WillOnce(Return(status));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_, _, _, _, _, _, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::WithArg<8>([&](char** faultParam){
        *faultParam = mockFaultParam;
        }),
    Return(CCSP_SUCCESS)));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_SendSignal_WithData(_, StrEq("Device.X_COMCAST-COM_GRE.Tunnel.1.TunnelStatus"), _))
    .Times(1).WillOnce(Return(CCSP_SUCCESS));

    notify_tunnel_status(status);
}

TEST_F(HotspotFdTestFixture, set_validatessid_CASE1) {
    bool result;
    char mockValue[] = "false";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";

    ssid_reset_mask = 0x0;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("false"))).Times(4).WillRepeatedly(Return(mockValue));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_, _, StrEq(dstPath), _, _, _, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::WithArg<8>([&](char** faultParam){
        *faultParam = mockValue;
        }),
    Return(CCSP_SUCCESS)));

    result = set_validatessid();

    EXPECT_EQ(true, result);
}

TEST_F(HotspotFdTestFixture, set_validatessid_CASE2) {
    bool result;
    char mockValue[] = "true";
    char dstPath[64]="/com/cisco/spvtg/ccsp/wifi";

    ssid_reset_mask = 0xf;

    EXPECT_CALL(*g_anscWrapperApiMock, AnscCloneString(StrEq("true"))).Times(4).WillRepeatedly(Return(mockValue));
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_setParameterValues(_, _, StrEq(dstPath), _, _, _, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::WithArg<8>([&](char** faultParam){
        *faultParam = mockValue;
        }),
    Return(CCSP_SUCCESS)));

    result = set_validatessid();

    EXPECT_EQ(true, result);
}

void SetOutValStructs(parameterValStruct_t** outValStructs, parameterValStruct_t** valStructs) {
    *outValStructs = *valStructs;
}
TEST_F(HotspotFdTestFixture, get_validate_ssid_SUCCESS) {
    bool result;
    char dstPath[64] = "/com/cisco/spvtg/ccsp/wifi";
    ssid_reset_mask = 0x0;

    //Allocate memory and assign mock values for valStructs
    const char *paramNames[] = {"ap5", "ap6", "ap9", "ap10"};
    int numParams = sizeof(paramNames) / sizeof(paramNames[0]);

    parameterValStruct_t **valStructs = (parameterValStruct_t **)malloc(numParams * sizeof(parameterValStruct_t *));
    if (valStructs == NULL) {
        printf("Memory allocation failed for valStructs array\n");
        return;
    }

    for (int i = 0; i < numParams; i++) {
        valStructs[i] = (parameterValStruct_t *)malloc(sizeof(parameterValStruct_t));
        if (valStructs[i] == NULL) {
            printf("Memory allocation failed for valStructs[%d]\n", i);
            goto cleanup;
        }

        valStructs[i]->parameterName = strdup(paramNames[i]);
        if (valStructs[i]->parameterName == NULL) {
            printf("Memory allocation failed for parameterName\n");
            goto cleanup;
        }

        valStructs[i]->parameterValue = strdup("true");
        if (valStructs[i]->parameterValue == NULL) {
            printf("Memory allocation failed for parameterValue\n");
            goto cleanup;
        }
        valStructs[i]->type = ccsp_string;
    }

    // Set expectations
    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, StrEq(dstPath), _, _, _, _))
    .Times(1)
    .WillOnce(testing::DoAll(
        testing::Invoke([&](void*, const char*, char*, char**, int, int*, parameterValStruct_t*** outValStructs) {
            *outValStructs = valStructs;
        }),
        Return(CCSP_Message_Bus_OK)
    ));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_, _, _)).Times(1);

    result = get_validate_ssid();
    EXPECT_EQ(true, result);

cleanup:
    for (int i = 0; i < numParams; i++) {
        if (valStructs[i]) {
            free(valStructs[i]->parameterName);
            free(valStructs[i]->parameterValue);
            free(valStructs[i]);
        }
    }
    free(valStructs);
}

TEST_F(HotspotFdTestFixture, get_validate_ssid_FAIL) {
    bool result;
    char dstPath[64] = "/com/cisco/spvtg/ccsp/wifi";

    EXPECT_CALL(*g_baseapiMock, CcspBaseIf_getParameterValues(_, _, StrEq(dstPath), _, _, _, _))
    .Times(1)
    .WillOnce(Return(1));
    EXPECT_CALL(*g_baseapiMock, free_parameterValStruct_t(_, _, _)).Times(1);

    result = get_validate_ssid();
    EXPECT_EQ(false, result);
}

TEST_F(HotspotFdTestFixture, hotspotfd_isClientAttached_SUCCESS) {
    bool result;
    bool mockpNew;
    gSnoopNumberOfClients = 2;

    result = hotspotfd_isClientAttached(&mockpNew);
    EXPECT_EQ(true, result);
    EXPECT_EQ(true, mockpNew);
}

TEST_F(HotspotFdTestFixture, hotspotfd_isClientAttached_FAIL) {
    bool result;
    bool mockpNew;
    gSnoopNumberOfClients = 0;

    result = hotspotfd_isClientAttached(&mockpNew);
    EXPECT_EQ(false, result);
}

TEST_F(HotspotFdTestFixture, hotspotfd_checksum) {
    struct packet pckt;

    // Initialize ICMP header
    pckt.hdr.type = 8;
    pckt.hdr.code = 0;
    pckt.hdr.un.echo.id = htons(1234);
    pckt.hdr.un.echo.sequence = htons(1);
    pckt.hdr.checksum = 0;
    strcpy(pckt.msg, "Sample ICMP packet data");

    unsigned short expected_checksum = hotspotfd_checksum(&pckt, sizeof(pckt));

    EXPECT_TRUE(std::isfinite(expected_checksum));
}

TEST_F(HotspotFdTestFixture, hotspotfd_log) {
    createFile(HOTSPOTFD_STATS_PATH);

    // Attach the shared memory and check for errors
    gShm_fd = shmget(kKeepAlive_Statistics, kKeepAlive_SharedMemSize, IPC_CREAT | 0666);
    ASSERT_NE(gShm_fd, -1) << "Failed to create shared memory segment";
    gpStats = (hotspotfd_statistics_s *)shmat(gShm_fd, NULL, 0);
    ASSERT_NE(gpStats, (void *)-1) << "Failed to attach shared memory";

    // Initialize global variables
    gKeepAliveEnable = true;
    gPrimaryIsActive = true;
    gPrimaryIsAlive = true;
    gSecondaryIsActive = false;
    gSecondaryIsAlive = false;
    gKeepAlivesSent = 0;
    gKeepAlivesReceived = 0;
    gKeepAliveInterval = 30;
    gKeepAliveCount = 3;
    gKeepAliveThreshold = 15;
    gSecondaryMaxTime = 0;
    gSwitchedBackToPrimary = false;
    gPriStateIsDown = false;
    gSecStateIsDown = false;
    gBothDnFirstSignal = true;
    gKeepAliveChecksumCnt = 0;
    gKeepAliveSequenceCnt = 0;
    gDeadInterval = 30;
    strcpy(gpPrimaryEP, "96.109.150.114");
    strcpy(gpSecondaryEP, "96.109.150.120");
    strcpy(gKeepAliveInterface, "erouter0");

    EXPECT_CALL(*g_fileIOMock, fclose(_)).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).Times(2).WillRepeatedly(Return(0));

    hotspotfd_log();

    // Clean up
    removeFile(HOTSPOTFD_STATS_PATH);
    if (gpStats != (void *)-1) {
        shmdt(gpStats);
    }
    if (gShm_fd != -1) {
        shmctl(gShm_fd, IPC_RMID, NULL);
    }
}

TEST_F(HotspotFdTestFixture, hotspotfd_isValidIpAddress) {
    bool result;
    char ipAddr[] = "96.109.150.114";

    result = hotspotfd_isValidIpAddress(ipAddr);
    EXPECT_EQ(true, result);
}

TEST_F(HotspotFdTestFixture, hotspotfd_setupSharedMemory) {
    int status;

    gShm_fd = shmget(kKeepAlive_Statistics, kKeepAlive_SharedMemSize, IPC_CREAT | 0666);
    ASSERT_NE(gShm_fd, -1) << "Failed to create shared memory segment";
    gpStats = (hotspotfd_statistics_s *)shmat(gShm_fd, NULL, 0);
    ASSERT_NE(gpStats, (void *)-1) << "Failed to attach shared memory";
    gShm_snoop_fd = shmget(kSnooper_Statistics, kSnooper_SharedMemSize, IPC_CREAT | 0666);
    ASSERT_NE(gShm_snoop_fd, -1) << "Failed to create shared memory segment";
    gpSnoop_Stats = (snooper_statistics_s *)shmat(gShm_snoop_fd, NULL, 0);
    ASSERT_NE(gpSnoop_Stats, (void *)-1) << "Failed to attach shared memory";

    status = hotspotfd_setupSharedMemory();
    EXPECT_EQ(STATUS_SUCCESS, status);

    if (gpStats != (void *)-1) {
        shmdt(gpStats);
    }
    if (gShm_fd != -1) {
        shmctl(gShm_fd, IPC_RMID, NULL);
    }
    if (gpSnoop_Stats != (void *)-1) {
        shmdt(gpSnoop_Stats);
    }
    if (gShm_snoop_fd != -1) {
        shmctl(gShm_snoop_fd, IPC_RMID, NULL);
    }
}

TEST_F(HotspotFdTestFixture, hotspotfd_getStartupParameters) {
    int result;
    char mockIP[] = "96.109.150.114";
    char mockIPv6[] = "2001:db8:85a3:8d3:1319:8a2e:370:7348";
    char mockIntervalValue[] = "30";
    char emptyString[] = "";

    {
        testing::InSequence s;

        // Mock the calls to sysevent_get with expected values
        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kHotspotfd_primary), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIP, mockIP + strlen(mockIP) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_secondary), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIP, mockIP + strlen(mockIP) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("old_wan_ipv4addr"), StrEq(emptyString), _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(emptyString, emptyString + strlen(emptyString) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("current_wan_ipaddr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIP, mockIP + strlen(mockIP) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("old_wan_ipv4addr"), _, _)).Times(1)
        .WillOnce(Return(0));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("old_wan_ipv4addr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIP, mockIP + strlen(mockIP) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("old_wan_ipv6addr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(emptyString, emptyString + strlen(emptyString) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("wan6_ipaddr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIPv6, mockIPv6 + strlen(mockIPv6) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_set(_, _, StrEq("old_wan_ipv6addr"), _, _)).Times(1)
        .WillOnce(Return(0));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq("old_wan_ipv6addr"), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIPv6, mockIPv6 + strlen(mockIPv6) + 1),
        Return(0)));

        // Mock the rest of the sysevent_get calls with generic mockIntervalValue
        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_keep_alive), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_keep_alive_threshold), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_max_secondary), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_keep_alive_policy), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(khotspotfd_keep_alive_count), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id1), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id2), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id3), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id4), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_id5), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(ksnooper_circuit_id6), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index1), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index2), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index3), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index4), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_ssid_index5), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(ksnooper_ssid_index6), _, _)).Times(1)
        .WillOnce(testing::DoAll(
        testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
        Return(0)));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_circuit_enable), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_remote_enable), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));

        EXPECT_CALL(*g_syseventMock, sysevent_get(_, _, StrEq(kSnooper_max_clients), _, _)).Times(1)
        .WillOnce(testing::DoAll(
            testing::SetArrayArgument<3>(mockIntervalValue, mockIntervalValue + strlen(mockIntervalValue) + 1),
            Return(0)
        ));
    }

    EXPECT_CALL(*g_safecLibMock, _strcpy_s_chk(_, _, _, _)).WillRepeatedly(Return(0));

    result = hotspotfd_getStartupParameters();
    EXPECT_EQ(STATUS_SUCCESS, result);
}
