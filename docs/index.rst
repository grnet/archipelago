Archipelago
^^^^^^^^^^^


Overview
========

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

Archipelago is written in C.

The following documentation describes the exact problem, the idea behind
Archipelago, the Archipelago architecture and internals, and the different
drivers for endpoints and backend storage. Furthermore, we describe how to
install, configure and use Archipelago:

.. toctree::
   :maxdepth: 2
   :numbered:
   :glob:

   archipelago
   archipelago_deploy
