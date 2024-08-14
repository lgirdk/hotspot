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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

class HotspotApiInterface {
public:
    virtual ~HotspotApiInterface() {}
    virtual int ipAddress_version(char*) = 0;
    virtual void recreate_tunnel() = 0;
};

class HotspotApiMock: public HotspotApiInterface {
public:
    virtual ~HotspotApiMock() {}
    MOCK_METHOD1(ipAddress_version, int(char*));
    MOCK_METHOD0(recreate_tunnel, void());
};