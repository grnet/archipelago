Archipelago
===========

Overview
--------

Archipelago is a distributed storage layer that decouples Volume and File
operations/logic from the actual underlying storage technology, used to store
data. It provides a unified way to provision, handle and present Volumes and
Files independently of the storage backend. It also implements thin clones,
snapshots, and deduplication, and has pluggable drivers for different backend
storage technologies. It was primarily designed to solve problems that arise on
large scale cloud environments. Archipelago's end goal is to:

* Decouple storage logic from the actual data store
* Provide logic for thin cloning and snapshotting
* Provide logic for deduplication
* Provide different endpoint drivers to access Volumes and Files
* Provide backend drivers for different storage technologies

It has been designed to help with the further commoditization of storage and in
the same time ease the integration and/or migration between different backend
storage technologies, without changing the way Volumes and Files are accessed.

Project Page
------------

Please see the [official Synnefo site](http://www.synnefo.org) and the [latest
Archipelago docs](http://www.synnefo.org/docs/archipelago/latest/index.html)
for more information.


Copyright and license
=====================

Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

