/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#ifndef __DEBUG_H__   
#define __DEBUG_H__

#define  STATUS_SUCCESS     0
#define  STATUS_FAILURE     0xFFFFFFFF

enum
{
   LOG_ERR      = 1,
   LOG_INFO     = 2,
   LOG_NOISE    = 3
};

extern unsigned int glog_level;

#define msg_debug(fmt...) {    \
        if (LOG_NOISE <= glog_level ) {\
        printf("%s:%d> ", __FUNCTION__, __LINE__); printf(fmt); }}

#define msg_info(fmt...) {    \
        if (LOG_INFO <= glog_level ) {\
        printf("%s:%d> ", __FUNCTION__, __LINE__); printf(fmt); }}

#define msg_err(fmt...) {    \
        if (LOG_ERR <= glog_level ) {\
        printf("%s:%d> ", __FUNCTION__, __LINE__); printf(fmt); }}


#endif
