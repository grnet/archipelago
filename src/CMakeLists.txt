# Copyright 2014 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.

cmake_minimum_required(VERSION 2.8)

project (archipelago_peers)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(DUMMY_SRC dummy.c peer.c)
add_executable(archip-dummy ${DUMMY_SRC})
target_link_libraries(archip-dummy xseg pthread)
set_target_properties(archip-dummy
	PROPERTIES
	COMPILE_DEFINITIONS "MT"
	)

set(RADOS_SRC mt-sosd.c peer.c hash.c)
add_executable(archip-radosd ${RADOS_SRC})
target_link_libraries(archip-radosd xseg pthread rados crypto)
set_target_properties(archip-radosd
	PROPERTIES
	COMPILE_DEFINITIONS "MT"
	)

set(BENCH_SRC bench-xseg.c peer.c bench-lfsr.c bench-timer.c bench-utils.c
	bench-report.c bench-verify.c)
add_executable(archip-bench ${BENCH_SRC})
target_link_libraries(archip-bench xseg pthread m)

add_executable(archip-benchfd ${BENCH_SRC})
target_link_libraries(archip-benchfd xseg pthread m)
set_target_properties(archip-benchfd
	PROPERTIES
	COMPILE_DEFINITIONS "FD"
	)


set(FILED_SRC filed.c peer.c hash.c)
add_executable(archip-filed ${FILED_SRC})
target_link_libraries(archip-filed xseg pthread crypto)
set_target_properties(archip-filed
	PROPERTIES
	COMPILE_DEFINITIONS "MT"
	)

set(VLMCD_SRC mt-vlmcd.c peer.c)
add_executable(archip-vlmcd ${VLMCD_SRC})
target_link_libraries(archip-vlmcd xseg)

set(MAPPERD_SRC mapper.c peer.c hash.c mapper-handling.c 
	mapper-version0.c mapper-version1.c mapper-version2.c)
add_executable(archip-mapperd ${MAPPERD_SRC})
target_link_libraries(archip-mapperd xseg st crypto)
set_target_properties(archip-mapperd
	PROPERTIES
	COMPILE_DEFINITIONS "ST_THREADS"
	)

INSTALL_TARGETS(/bin archip-filed archip-radosd archip-vlmcd archip-mapperd
	archip-bench archip-dummy archip-benchfd)
