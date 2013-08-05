.. _archipelago:

Volume Service (archipelago)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Problem Overview
================

In an IaaS cloud, VM provisioning and destroying happens thousands times in a
day. It should be fast and efficient. Copying data between nodes requires time
and bandwidth which can be a bottleneck. More over it takes up extra space for
the copied data. So fast VM provisioning with zero data movement and
deduplicated data is a huge deal. Furthermore support for VM snapshots, to be
used as VM backups or to create new VMs with the changes made in the original
VM, is an asset with regard to functionality and productivity.

However all this functionality should not interfere with the ability to migrate
the VMs between hardware nodes or having redundancy on the actual data, in case
of hardware failures.

Archipelago tackles this problem, by creating a storage layer that adds the
necessary logic, between the client that uses the volume and the actual storage.
As an added benefit, the actual storage used is not relative provided that the
appropriate storage driver is used.

Archipelago Overview
====================

Archipelago, as mentioned before, is a distributed storage layer that provides
volumes with the ability to snapshot them and clone them to create new ones,
independently from the actual storage. Archipelago software stack is deployed on
each node where the volume will be used, acting as disks for VMs for example.
Then each volume is exposed as an independent block device and accessed as such.
The data of each volume can reside on any supported storage type. The software
stack will take care any coordination or concurrency control needed between
other nodes running archipelago

Archipelago main asset is that it decouples the
composition/snapshot/cloning/deduplicating logic from the storage backend used.
It provides a software stack where the aforementioned logic and volume handling
is implemented and through plugable storage drivers, it can operate over
different storage types. So, Archipelago greatly reduces the need of each
individual storage manufacturer or developer, to develop the same set of
features for their storage solution.

Archipelago Architecture
========================

.. image:: images/archipelago-architecture.png
    :target: _images/archipelago-architecture.png


Archipelago consists of several components, both userspace and kernelspace,
which communicate through a custom-built shared memory segment communication
mechanism. This mechanism, which is called XSEG, also defines a common
communication protocol between these components and is provided by the library
``libxseg``.  Each Archipelago component, which can be a kernelspace block
driver or a userspace process, is an *xseg peer*.  The segment provides *ports*,
where each peer binds. The peer then uses the port to communicate with the other
peers on the same segment. The communication consists of *requests* that are
submitted to the receiver port, and are responded to the submitter port.

This form of communication, allows us to develop distinct components for each
operation of Archipelago, while being able to communicate with exactly
the same protocol between these components, independently from their domain
(userspace or kernelspace).

Archipelago components
**********************

Each Archipelago component serves a distinct purpose and coordinates with the
other components to provide the final service.

These components are described below.

Volume composer (vlmcd)
#######################
Volume composer is responsible for the volume composition. Xsegbd devices direct
I/O requests on the volume, to the volume composer. Volume composer then
consults the mapper, to get the actual objects on which it will perform the
appropriate I/O. It then directs I/O requests for each individual object to the
blocker and wait for their completion. In the end, it composes the individual
responses, to respond to the original volume request from the xsegbd.

Mapper (mapperd)
################
Mapper is responsible for keeping and updating the mappings from volume
offsets to individual objects which actually hold the data. It is also
responsible for creating new volumes, snapshotting existing ones and create new
volume based on a previously captured snapshot (clones). It stores the mappings
to the storage backend, from which it reads and/or updates them, keeping them
cached when appropriate. It also ensure that each action on the volumes, does
not happen unless the necessary volume locks are acquired.

File blocker (filed)
####################
File blocker is responsible for storing each object as a single file in a
specified directory. It servers the requests for each objects as they come from
the volume composer and the mapper components.

Rados blocker (sosd)
####################
Rados blocker is another form of blocker which stores each objects as a single
object in a RADOS pool. It can be used instead of the file blocker, to create
and use disks over RADOS storage.

Block devices (xsegbd)
######################
Each volume on Archipelago is exposed as a block device in the system /dev
directory. These special devices are nothing more than just another peer, which
forwards the requests through the shared memory segment, to the volume composer
for completion.


In a nutshell, in archipelago, each xsegbd device communicates through the
shared memory segment with the volume composer. Then the volume composer
requests the objects on which it should perform the I/O from the mapper. The
mapper takes into account all the necessary logic (taking locks etc) and
retrieves the mappings from the storage, by requesting the appropriate objects
from the blocker responsible to hold the maps. It then performs any copy on
write operations needed and returns the mapping to the volume composer. The
volume composer then communicates with the blocker responsible for holding the
objects where the actual data reside and composes the responses, to respond to
the original request.

Archipelago APIs
================

Archipelago allows users to manage and access volume backed by various storage
types. In order to do that, archipelago provides multiple endpoints for the user
to interact (block device driver, qemu driver, user provided process, command
line tool, etc).

Archipelago Integration with synnefo and ganeti
===============================================

How everything ties together in a real world awesome cloud infra.

