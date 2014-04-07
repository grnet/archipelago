.. _archipelago:

Archipelago
^^^^^^^^^^^


Problem Overview
================

In an IaaS cloud, VM provisioning and destroying happens continiously and it
should be fast and efficient. In the same time, VMs should be live-migratable
across physical nodes to achieve persistency. So the question boils down to:

How can I deploy VMs from image files in seconds, while in the same time being
able to live-migrate them and do that in a large-scale and stable manner?

As far as we know, no one seems to have completely solved the above problem, at
least not in the open source world. There are some solutions either proprietary
or open source that try to tackle the problem, but all of them seem to have
limitations regarding different aspects of the problems.

Proprietary SAN/NAS solutions
-----------------------------

Proprietary SAN/NAS solutions support live-migration out-of-the-box since the
storage is shared across all physical nodes where VMs live. The most advanced
ones also support thin cloning and snapshotting, meaning they also solve the
'fast' provisioning part. However they have some major problems:

| 1. They are not open
| 2. They are expensive
| 3. They do not scale
| 4. They cause vendor lock-in

Over the network RAID-1: DRBD
-----------------------------

DRBD is a great technology. It is open source, proven, mature and if you
combine it with a sophisticated virtualization manager that can handle it (such
as Google Ganeti) you can also support live VM migrations out-of-the-box, even
in geographically distinct locations. DRBD is also very scalable since it is
completely decentralized. However it has two big problems:

| 1. It does not support thin clones and snapshots
| 2. It cannot be used as a centralized store for files and images

The above mean that it cannot cater for the 'fast' provisioning part and cannot
be easily integrated to act as a backend for files, images or objects.

Open source distributed filesystems
-----------------------------------

Open source distributed filesystems seem to be the way to go in the cloud and
are highly appreciated and praised by many promiment members of the cloud
community. Solutions like Ceph, GlusterFS, MooseFS, ZFS and others are potential
candidates when it comes to backing a large scale cloud service. A distributed
filesystem is visible by all physical nodes hosting VMs, so live-migration is
supported and they can also be used to store files and images. However, such
solutions seem to have problems too, when it comes to deploying in a large
scale critical environmet. The major ones are:

| 1. Stability
| 2. Scalability

Our experience also indicates that a cloud platform doesn't really need
filesystem semantics, but rather block and object interfaces. Thus, a
distributed filesystem adds complexity and overhead to the picture. The Ceph
project seems to be doing a good job towards this direction, but it is still
very early to point it as the possible solution.

Multiple storage technologies
-----------------------------

Since there is no single solution to fit the cloud case, one even more important
problem arises. What happens with legacy hardware, how does one maintain,
upgrade, move from one technology to the other, or even integrate different
storage technologies to cater for different needs in a unified way? And why does
a reliable, redundant, scalable data store has to interfere with cloud
semantics, clones, snapshots, deduplication, block and file interfaces?

The above problems, which were the ones we also bumped on and tried to solve on
our own real-world use case, led us to the design and implementation of
Archipelago.
