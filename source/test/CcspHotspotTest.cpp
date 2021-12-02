/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
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

#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include "test/mocks/mock_sysevent.h"

extern "C" {
#include "libHotspot.h"
}

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

SyseventMock * g_syseventMock = NULL;

char g_Subsystem[32] = {0};
extern int gSyseventfd;
extern token_t gSysevent_token;
extern vlanSyncData_s gVlanSyncData[];

class HotspotTestFixture : public ::testing::Test {
    protected:
        SyseventMock mockedSysevent;

        HotspotTestFixture()
        {
            g_syseventMock = &mockedSysevent;
        }
        virtual ~HotspotTestFixture()
        {
            g_syseventMock = NULL;
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

TEST_F(HotspotTestFixture, hotspot_update_bridge_config_iptables_rules)
{
    int index = 0;
    char rule[1024]={0};
    char param[500]={0};

    gSyseventfd = 100;
    gSysevent_token = 1000;

    for (index=0; index < 4; index++)
    {
        snprintf(rule, sizeof(rule),
            "-A FORWARD -o %s -p udp --dport=67:68 -j NFQUEUE --queue-bypass --queue-num %d",
            gVlanSyncData[index].bridgeName, index+1);
        snprintf(param, sizeof(param), "gre_1_%s_snoop_rule",
            gVlanSyncData[index].bridgeName);

        EXPECT_CALL(*g_syseventMock, sysevent_set_unique(gSyseventfd, gSysevent_token,
                StrEq("GeneralPurposeFirewallRule"), StrEq(rule), _, _))
            .Times(1)
            .WillOnce(Return(0));

        EXPECT_CALL(*g_syseventMock, sysevent_set(gSyseventfd, gSysevent_token,
            StrEq(param), _, _))
            .Times(1)
            .WillOnce(Return(0));

        EXPECT_EQ(0, update_bridge_config(index));
    }
}
