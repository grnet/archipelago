.. _design_entities:

Archipelago logical entities and commands
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


Current state
=============

Currently, Archipelago has a number of peers around Xseg, either userspace or
kernelspace. Peers are layed out in a flat topology and although they do
completely different operations, that doesn't reflect to the way they are
called and handled by the management commands. Also, it is difficult for the
user to easily understand the flow of the requests inside Archipelago. Since,
new peers with added functionality are coming in the future, things will get
even more complicated.


Objective
=========

This design doc has the following objectives:

#. Define the northbound and southbound interfaces of Archipelago and describe how
   it interacts with a cloud platform and the underlying storage technology.
#. Describe which peer falls into which category.
#. Identify the different logical entities and name them.
#. Rename management commands to reflect the above entities.


Archipelago topology
====================

We will divide Archipelago in three layers:

* The northbound interface
* The Archipelago core
* The southbound interface

Northbound interface
--------------------

The northbound interface is where Archipelago interacts with the cloud
platform. In other words, it is the `endpoints` that Archipelago provides for
use by the upper layers to access Archipelago resources [volumes or files].
Currently, these are:

* block endpoints
* qemu endpoints
* http endpoints

Each type of endpoint is served by the corresponding `endpoint driver`:

* block driver (the ``blktap`` peer)
* qemu driver (resides inside the ``vlmc`` tool)
* http driver (the ``pithos`` peer)

Core
----

The Archipelago core implements the actual composition, mapping and
deduplication logic. It consists of the following peers:

* the ``vlmc`` peer
* the ``mapper`` peer

The core stands in the middle in the Archipelago topology. It talks to the
upper layers (cloud platform) through the northbound interface and to the lower
layers (actual storage) through the southbound interface.

Southbound interface
--------------------

The southbound interface is where Archipelago interacts with the underlying
storage technology. It is the different `backends` that Archipelago can
initiate to talk with the storage and store the actual data. Each backend
handles a separate underlying storage entity of a specific type and multiple
backends can be enabled simultaneously. Each backend uses a corresponding
`backend driver` according to the type of storage it wants to communicate with.
Currently, there are two backend drivers for two types of underlying storage:

* shared file driver (the ``filed`` peer)
* RADOS driver (the ``sosd`` peer)

The shared file driver is used by backends that store data on a shared
filesystem such as NFS, OCFS2, GPFS, CephFS or GlusterFS. The RADOS driver is
used by backends that store data on a Ceph/RADOS cluster directly with
``librados``.


Logical entities
================

From the above, we identify the following entities:

#. **Volume**: a linear storage space we are operating on, defined by an
   Archipelago `map`. That `map` could be also describing a File but we will
   assume everything is a Volume in Archipelago-terms.
#. **Endpoint**: an access endpoint that can be used by upper layers to access
   a specific volume.
#. **Endpoint driver**: a driver which is used to create and manage an endpoint.
#. **Backend**: the entity that communicates with a specific underlying storage
   solution.
#. **Backend driver**: a driver used by a backend, to communicate with the
   underlying storage.


Volume operations
=================

A **Volume** can be either read-only (also called a 'snapshot') or read-write
(also called a 'clone'). There are three operations on Volumes:

#. **Create**: Create a new empty Volume of specific size, with a specific name.
#. **Clone**: Create a read-write Volume (clone) from an existing Volume.
   The source Volume can be either read-only (clone) or read-write (snapshot).
   The new Volume may have a different size if specified so, as long as it is
   larger than the source.
#. **Snapshot**: Create a read-only Volume (snapshot) from an existing Volume.
   The source Volume can be either read-only (clone) or read-write (snapshot).
   The new Volume may have a different size if specified so, as long as it is
   larger than the source.


Management commands
===================

After identifying the logical entities and operations we should provide the
corresponding commands to manage them:

.. code-block:: console

   # archip volume-list
   # archip volume-info <volume-name>
   # archip volume-clone <volume-name> [--name=<clone-name>] [--size <size>]
   # archip volume-create --name=<volume-name> --size <size> [--backend=<backend-name>]
   # archip volume-snapshot <volume-name> [--name <snapshot-name>] [--size <size>]
   # archip volume-present <volume-name> --endpoint-driver <endpoint-driver>
   # archip volume-unpresent <volume-name> | <endpoint>
   # archip volume-remove <volume-name>
   # archip volume-move <volume-name> --from=<backend-name> --to=<backend-name>
   # archip volume-open <volume-name>
   # archip volume-close <volume-name>
   # archip volume-lock <volume-name>
   # archip volume-unlock [-f] <volume-name>
   # archip volume-showpresented [--filter-by:endpoint-driver=<endpoint-driver>,
                                              backend-driver=<backend-driver>]
                                 [<volume-name>]

   # archip endpoint-list [--show-volumes]

   # archip backend-list
   # archip backend-info
   # archip backend-create <backend-name> --driver <backend-driver>
   # archip backend-remove <backend-name>
   # archip backend-sync --origin=<backend-name> --target=<backend-name>

   # archip driver-list [--endpoint] | [--backend]


.. note::

        driver-list could also be split to:
        # edriver-list    #for endpoint-driver
        # bdriver-list    #for backend-driver
        to have a 1:1 mapping from entities to commands.
