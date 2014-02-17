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

project(archipelago_python)

set(VERSIONCMD ${CMAKE_CURRENT_SOURCE_DIR}/version.sh
	${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

ADD_CUSTOM_COMMAND (OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/archipelago/version.py
		    COMMAND ${VERSIONCMD}
		    #DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/xseg/version.py"
		   )
ADD_CUSTOM_TARGET (pyversion DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/archipelago/version.py)

SET(SETUP_PY_IN ${CMAKE_CURRENT_SOURCE_DIR}/setup.py)
SET(SETUP_PY ${CMAKE_CURRENT_BINARY_DIR}/setup.py)
SET(SETUP_PY_BUILD_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/build)

SET(DISTSETUP_PY_IN ${CMAKE_CURRENT_SOURCE_DIR}/distribute_setup.py)
SET(DISTSETUP_PY ${CMAKE_CURRENT_BINARY_DIR}/distribute_setup.py)
configure_file(${SETUP_PY_IN} ${SETUP_PY})
configure_file(${DISTSETUP_PY_IN} ${DISTSETUP_PY})

ADD_CUSTOM_COMMAND( OUTPUT ${SETUP_PY_BUILD_OUTPUT} ${CMAKE_CURRENT_BINARY_DIR}/archipelago ${CMAKE_CURRENT_BINARY_DIR}/archipelago.egg-info
		    COMMAND python ${SETUP_PY} build

		    COMMENT "Building python")

ADD_CUSTOM_TARGET(python ALL DEPENDS ${SETUP_PY_BUILD_OUTPUT} )
ADD_DEPENDENCIES(python pyversion)

install(CODE "execute_process(COMMAND python ${SETUP_PY} install --install-layout=deb --root=$DESTDIR)")


