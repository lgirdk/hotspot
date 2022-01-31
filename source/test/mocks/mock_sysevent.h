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


#ifndef MOCK_SYSEVENT_H
#define MOCK_SYSEVENT_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>

typedef unsigned int token_t; // from sysevent.h

class SyseventInterface {
public:
    virtual ~SyseventInterface() {}
    virtual int sysevent_set_unique(const int fd, const token_t token, const char *name, const char *value, char *outbuf, int outbytes) = 0;
    virtual int sysevent_set(const int fd, const token_t token, const char *name, const char *value, int conf_req) = 0;
};

class SyseventMock : public SyseventInterface {
public:
    virtual ~SyseventMock() {}
    MOCK_METHOD6(sysevent_set_unique, int(const int fd, const token_t token, const char *name, const char *value, char *outbuf, int outbytes));
    MOCK_METHOD5(sysevent_set, int(const int fd, const token_t token, const char *name, const char *value, int conf_req));
};

#endif
