Archipelago
^^^^^^^^^^^

Archipelago is a distributed software defined storage solution that decouples
cloning and snapshotting logic from the actual storage used.

Every Volume inside a VM can be thought of as a linearly addressable set of
fixed-size blocks. The storage of the actual blocks is orthogonal to the task of
exposing a single block device for use by each VM. Bridging the gap between the
VMs performing random access to Volumes and the storage of actual blocks is
Archipelago: a custom storage handling layer which handled volumes as set of
distinct blocks in the backend, a process we call volume composition.

For the actual storage of blocks, Archipelago is agnostic to the storage backend
used. Through plugable storage drivers, Archipelago can support multiple storage
backends to suit the needs of each deployment. We currently provide two storage
drivers. One for simple files, where each object is stored as a single file on the
(shared) filesystem, and one for objects backed by RADOS. RADOS is the
distributed object store which supports the Ceph parallel filesystem. With RADOS,
we can solve the problem of reliable, fault-tolerant object storage through
replication on multiple storage nodes.

As mentioned before, Archipelago composes the volume through individual blocks.
This is accomplished by maintaining a map for each volume, to map offset in a
volume with a single object. The exact offset inside the object, is calculated
statically from the fixed object size and the offset in the volume. But having
this map and the composition subsystems, allow us to do much more than simple
volume composition.  Archipelago offers Copy-On-Write snapshotable volumes.
Furthermore, each snapshot can be hashed, to allow deduplication to play its
part, reducing the storage cost of each hashed object. Further more, Archipelago
can integrate with Pithos, and use Pithos images to provision a volume with
Copy-On-Write semantics (i.e. a clone). Since Pithos images are already hashed,
we can store Archipelago hashed volumes, which are indistinguishable from a Pithos
image, along with the Pithos images, to enable further deduplication, or even
registering an archipelago hashed snapshot as Pithos image file.

Having stated all that, Archipelago is used by Cyclades and Ganeti for fast VM
provisioning based on CoW volumes. Moreover, it enables live migration of
thinly-provisioned VMs with no physically shared storage.


Contents:
*********

.. toctree::
   :maxdepth: 2
   :numbered:
   :glob:

   archipelago
   archipelago_deploy
