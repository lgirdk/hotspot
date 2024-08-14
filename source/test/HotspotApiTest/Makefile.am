##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2024 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#####################################S#####################################
AM_CFLAGS =

AM_CXXFLAGS = -std=c++11

AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = HotspotApi_gtest.bin

HotspotApi_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest \
                                 -I${top_srcdir}/source \
                                 -I${top_srcdir}/source/include \
                                 -I${top_srcdir}/source/util \
                                 -I${top_srcdir}/source/HotspotApi \
                                 -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/ccsp
HotspotApi_gtest_bin_SOURCES = ${top_builddir}/source/HotspotApi/HotspotApi.c \
                                ${top_builddir}/source/HotspotApi/HotspotLib.c \
                                ${top_builddir}/source/HotspotApi/HotspotJansson.c \
                                HotspotApiTest.cpp \
                                gtest_main.cpp

HotspotApi_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -lpthread

HotspotApi_gtest_bin_LDADD = $(HOME)/usr/local/lib/libmock_ccsp_common.la \
                              $(HOME)/usr/local/lib/libmock_sysevent.la \
                              $(HOME)/usr/local/lib/libmock_psm.la \
                              $(HOME)/usr/local/lib/libmock_util.la \
                              $(HOME)/usr/local/lib/libmock_safec_lib.la \
                              $(HOME)/usr/local/lib/libmock_telemetry.la \
                              $(HOME)/usr/local/lib/libmock_jansson.la \
                              $(HOME)/usr/local/lib/libmock_file_io.la

#Code Coverage Flags
AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage
HotspotApi_gtest_bin_LDFLAGS += --coverage