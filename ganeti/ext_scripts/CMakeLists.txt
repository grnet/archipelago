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

project (archipelago_extscripts)

SET(EXTDIR /usr/share/ganeti/extstorage/archipelago)

INSTALL(FILES parameters.list DESTINATION ${EXTDIR})
INSTALL(PROGRAMS vlmc_wrapper.py DESTINATION ${EXTDIR})

install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E
	create_symlink  vlmc_wrapper.py
		 	\$ENV{DESTDIR}/${EXTDIR}/attach)")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E
	create_symlink  vlmc_wrapper.py
		 	\$ENV{DESTDIR}/${EXTDIR}/create)")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E
	create_symlink  vlmc_wrapper.py
		 	\$ENV{DESTDIR}/${EXTDIR}/detach)")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E
	create_symlink  vlmc_wrapper.py
		 	\$ENV{DESTDIR}/${EXTDIR}/setinfo)")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E
	create_symlink  vlmc_wrapper.py
		 	\$ENV{DESTDIR}/${EXTDIR}/snapshot)")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E
	create_symlink  vlmc_wrapper.py
		 	\$ENV{DESTDIR}/${EXTDIR}/verify)")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E
	create_symlink  vlmc_wrapper.py
		 	\$ENV{DESTDIR}/${EXTDIR}/remove)")
install(CODE "EXECUTE_PROCESS(COMMAND ${CMAKE_COMMAND} -E
	create_symlink  vlmc_wrapper.py
		 	\$ENV{DESTDIR}/${EXTDIR}/grow)")
install(CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}/var/log/ganeti/extstorage)")
