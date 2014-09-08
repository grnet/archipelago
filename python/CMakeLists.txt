# Copyright (C) 2010-2014 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
	            COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/archipelago
		    COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/archipelago/__init__.py

		    COMMAND python ${SETUP_PY} build

		    COMMENT "Building python")

ADD_CUSTOM_TARGET(python ALL DEPENDS ${SETUP_PY_BUILD_OUTPUT} )
ADD_DEPENDENCIES(python pyversion)

install(CODE "execute_process(COMMAND python ${SETUP_PY} install --install-layout=deb --root=$DESTDIR)")


