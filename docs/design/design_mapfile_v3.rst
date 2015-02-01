.. _design_mapfile_v3:

:Author: Chrysostomos Nanakos
:Contact: cnanakos@grnet.gr
:Revision: 1
:Date: 1/2/2015

Design doc for the new v3 mapfile
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Objective
=========

The current mapfile (v2) structure cannot provide Petabyte-scale volumes
and in parallel support thin provisioning, thin cloning and thin snapshotting.
Besides that, it makes impossible to realize the need for reference counting
garbage collection in realtime.

The new proposed mapfile (v3) structure will:

#. Provide larger volumes (16x) with the same mapdata size.
#. Provide the necessary infrastructure to support realtime in-line reference
   counting garbage collection.
#. Provide Gigabyte-scale volumes with in-line deduplication.
#. Provide faster thin provisioning, thin cloning and thin snapshotting.

Detailed Design
===============

Current state
-------------

Currently the v2 mapfile holds the following information in two basic data
structures that are splitted in two different data files:

#. The header file which includes the signature, the version, the volume size,
   the volume blocksize, the epoch and finally a flags field. The size of the
   header file spans 512 bytes.

#. The mapdata file which includes the object names accompanied with the
   name length and a flags field used to denote if the object is writable or
   not. Each object data structure spans 128 bytes on disk.

New v3 mapfile
--------------

The new mapfile will be consisted from three different data structures and
each one will span one data file.

#. The header file will include the signature, the version, the volume size,
   the volume blocksize, the epoch, the flags field and finally a new flag
   called sgc that denotes if the volume has been garbage collected and will be
   used during the migration from v2 to v3 and later on for bootstrapping
   reasons.

#. The metadata file is a new file introduced in v3 and will include the
   the current volume index, the volume array length, the content addressable
   array length, the content addressable array, the volume array and finally
   the size in bytes of the unhexlified content addressable object placed in
   the relevant array.

#. The mapdata file has a new form in v3 and it will include the epoch, the
   volume index, the type that denotes if the object is content addressable or
   not and finally a flag field that denotes if the object is writable. Each
   object data structure spans 8 bytes on disk instead of 128 with the
   previous format.

The data structures for each file of the above follows below:

.. code-block:: c

    #define V3_OBJECT_TYPE_ARCHIP 1
    #define V3_OBJECT_TYPE_CAS 0
    #define V3_OBJECT_READONLY 1
    #define V3_OBJECT_WRITABLE 0
    #define V3_OBJECT_ZERO_EPOCH (2 << 32 -1)
    #define V3_OBJECT_V1_EPOCH (2 << 32 -2)

    #define V3_META_HEADER_SIZE 512

    struct v3_meta_hdr {
        /* size of each cas name (unhexlified) */
        uint32_t cas_size;
        /* total length in bytes of the cas_array */
        uint64_t cas_array_len;
        /* total length in bytes of the vol_array */
        uint64_t vol_array_len;
        /* Volume name index of the current volume */
        uint32_t cur_vol_idx;
    } __attribute__ ((packed));

    struct v3_object {
        uint32_t epoch;
        unsigned name_idx:30;
        unsigned type:1;
        unsigned ro:1;
    };

    static struct v3_object v3_zero_object = {
        V3_OBJECT_ZERO_EPOCH,
        0,
        V3_OBJECT_TYPE_CAS,
        V3_OBJECT_READONLY
    };

    static struct v3_object v3_v1_object = {
        V3_OBJECT_V1_EPOCH,
        <name_idx>,
        V3_OBJECT_TYPE_ARCHIP,
        <ro>
    };


Today with the v2 mapfile for a 4MB map object we can build 128GB volumes.
With the new v3 mapfile for the same 4MB map object we can have 2TB volumes.

Respectively with the v3 mapfile a 128TB volume needs only 256MB map object
and a 1PB costs only 2GB mapfile. This means ultra fast provisioning, cloning
and finally snapshotting.

With the current v2 mapfile a 1PB volume costs 32GB mapdata which makes it
impossible for provisioning, cloning or snapshotting.
