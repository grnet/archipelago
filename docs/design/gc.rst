.. _design_xseg_wait:

Design doc for garbage collection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This document describes the current state of garbage collection mechanism in
Archipelago and proposes a new design.

Current State
=============

Currently, Archipelago is not in great need of garbage collection. Since
Archipelago does not yet support snapshot and hashing, there was no great need
to keep unreferenced objects in the storage. When a volume was removed, every
archipelago object could be deleted. But when snapshots came into the picture,
there are shared Archipelago objects that should be reference counted to know
whether to delete them or not, or left stale and get garbage collected later.

Currently there are data objects, map objects, lock objects and new version
introduces precomputed hash objects.


Proposed changes
================

Introduce unique Archipelago object names
-----------------------------------------

Archipelago should create unique object names. To this direction we introduce
epoch number on each map, which is increased on every volume modification (such
as snapshot, deletion, creation, etc)

Archipelago could create new object with unique names with the following scheme:

``volumename_epoch_objectid``

Obviously, each volume name should be unique for Archipelago. As an extention,
the tuple (volumename, objectid) should be unique, on a given Archipelago
storage, if we assume that there are no stale objects. To lift the last
restriction and allow stale objects, we introduce epoch on the maps. With epoch
we can tell the state of the map, that is if it has been changed with a snapshot
or with a deletion/creation action. Exporting this information on the object
name, we get unique object names that correspond to the version of the map that
created them.

Avoid reference counting on objects
-----------------------------------

When a snapshot is created, it originally points to the same objects as the
parent. When a clone is created, it follows the same pattern.
Lets assume that we remove one of theses entities. How can we be sure on what
objects to delete. We need a reference count on them, which should be updated on
every action that (de)references the object. This can get expensive. So another
way to go, is to just leave the objects in place, and later invoke a garbage
collection mechanism to clean them up.

So we propose to not delete the entity objects on removal. Moreover, in order to
keep the epoch number intact when we remove a volume and create a new one with
the same name, we should not delete the map file rather marking it as deleted,
keeping the basic metadata in place. Later, if keeping small metadata for every
entity that is ever created proves to be a problem, we can offload this from the
storage to another system (such as a DB) or even invoking deeper garbage
collection to reset the epoch number.

Garbage collection
------------------

A basic algorithm for garbage collection is as follows:

Get all data objects, candidates for removal.

1) Get a set of objects at the start of the process
2) Scan all map files and insert all reachable objects to a set (possible
   optimization: use bloom filters)
3) Scan all objects, and those that are not found in the set, can be safely
   removed.

This algorithm, provided that we use unique name for each object, can be run on
a live system without any pause or downtime. Having unique name for each new
object, ensures that when references to an object are found zero, they can never
increase.

The above algorithm, needs one clarification. As the object count increases, the
size of object set will get too big to handle using in-memory (volatile or
permanent) structures. One alternative, is to split objects in gc epoches and
then on step (3), scan all objects that existed before the current gc epoch.

Implementation details
======================

For a first approach, we propose the following implementation.

The vlmc tool will initiate a gc. For this purpose, it will access the storage
directly and locate the map files. It will then extract the mapping from them
and create the referenced set of objects.

Then the tool will compare this set with all the objects and remove the
symmetric difference of the two sets.

This approach has several problems to address:
The basic one, is how to ensure that we wont get garbage when reading a mapfile
that is in use, and in general how we handle the case.

To implement gc epoches, the blockers should accompany each newly created object
with the current gc epoch. The current gc epoch will be stored in storage and
cached on each node. When a new garbage collection is started, it should
invalidate/update the current gc epoch of all nodes before proceeding with the
garbage collection.
