##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
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
##########################################################################
#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#

AC_PREREQ([2.65])
AC_INIT([hotspot], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
LT_INIT

AC_ARG_ENABLE([unitTestDockerSupport],
             AS_HELP_STRING([--enable-unitTestDockerSupport],[enable Docker support for unit testing (default is no)]),
             [
              case "${enableval}" in
                yes)
                  UNIT_TEST_DOCKER_SUPPORT=true
                  m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile source/test/HotspotApiTest/Makefile source/test/HotspotFdTest/Makefile])])
                  ;;
                no)
                  UNIT_TEST_DOCKER_SUPPORT=false
                  AC_MSG_WARN([Docker support is disabled])
                  ;;
                *)
                  AC_MSG_ERROR([bad value ${enableval} for --enable-unitTestDockerSupport])
                  ;;
              esac
             ],
             [AC_MSG_WARN([Docker support is disabled])])

AM_CONDITIONAL([UNIT_TEST_DOCKER_SUPPORT], [test x$UNIT_TEST_DOCKER_SUPPORT = xtrue])

FEATURE_WAN_FAIL_OVER=no
AC_ARG_ENABLE([wanfailover],
        AS_HELP_STRING([--enable-wanfailover],[enable wanfailover]),
        [
          case "${enableval}" in
           yes) FEATURE_WAN_FAIL_OVER=yes ;;
           no) AC_MSG_ERROR([wanfailover is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-wanfailover ]) ;;
           esac
           ],
         [echo "wanfailover is disabled."])

AM_CONDITIONAL([FEATURE_WAN_FAIL_OVER], [test $FEATURE_WAN_FAIL_OVER = yes])

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

PKG_CHECK_MODULES([DBUS],[dbus-1 >= 1.6.18])

AC_CONFIG_FILES(
    source/hotspotfd/Makefile
    source/XfinityTestAgent/Makefile
    source/arp_solicitation/Makefile
    source/HotspotApi/Makefile
    source/Makefile
    Makefile
)

AC_SUBST(UNIT_TEST_DOCKER_SUPPORT)
AC_OUTPUT
