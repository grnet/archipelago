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

Copyright (C) 2011-2014 GRNET S.A. All rights reserved.

Redistribution and use in source and binary forms, with or
without modification, are permitted provided that the following
conditions are met:

  1. Redistributions of source code must retain the above
     copyright notice, this list of conditions and the following
     disclaimer.

  2. Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials
     provided with the distribution.

THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A. OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and
documentation are those of the authors and should not be
interpreted as representing official policies, either expressed
or implied, of GRNET S.A.

