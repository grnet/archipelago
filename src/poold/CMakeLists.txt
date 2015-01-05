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

set(poold_definitions
    POOLD_SOCKET_PATH="/var/run/archipelago/poold.socket"
    POOLD_PIDFILE="/var/run/archipelago/poold.pid")
set(POOLD_SRC poold.cc system.cc socket.cc epoll.cc sighandler.cc)
add_executable(archip-poold ${POOLD_SRC})
target_link_libraries(archip-poold log4cplus pthread)
set_target_properties(
    archip-poold
    PROPERTIES
    COMPILE_DEFINITIONS "${poold_definitions}"
    )

INSTALL_TARGETS(/bin archip-poold)
