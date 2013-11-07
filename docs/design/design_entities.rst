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

#. Define the north and south bound of Archipelago and describe how it
   interacts with a cloud platform and the underlying storage technology.
#. Describe which peer falls into which category.
#. Identify the different logical entities and name them.
#. Rename management commands to reflect the above entities.


Archipelago topology
====================

We will divide Archipelago in three layers:

* The north bound
* The Archipelago core
* The south bound

North bound
-----------

The north bound is where Archipelago interfaces with the cloud platform. In
other words, it is the `endpoints` that Archipelago provides for use by the
upper layers to access Archipelago resources [volumes or files]. Currently,
these are:

* block endpoints (via the ``xsegbd`` peer)
* qemu endpoints (via the ``vlmc`` tool)
* http endpoints (via the ``pithos`` peer)

Each type of endpoint is served by the corresponding `endpoint driver`:

* block driver (the ``xsegbd`` peer)
* qemu driver (resides inside the ``vlmc`` tool)
* http driver (the ``pithos`` peer)

Core
----

The Archipelago core implements the actual composition, mapping and
deduplication logic. It consists of the following peers:

* the ``vlmc`` peer
* the ``mapper`` peer

The core stands in the middle in the Archipelago topology. It talks to the
upper layers (cloud platform) through the north bound and to the lower layers
(actual storage) through the south bound.

South bound
-----------

The south bound is where Archipelago interfaces with the underlying storage
technology. It is the different `backends` that Archipelago can initiate to
talk with the storage and store the actual data. Each backend handles a
separate underlying storage entity of a specific type and multiple backends can
be enabled simultaneously. Each backend uses a corresponding `backend driver`
according to the type of storage it wants to communicate with. Currently, there
are two backend drivers for two types of underlying storage:

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


Management commands
===================

After identifying the logical entities we should provide the corresponding
commands to manage them:

.. code-block:: console

   # archip volume-list [--show-endpoint] [--show-backend]
   # archip volume-info
   # archip volume-create <volume-name> [--origin <volume-name>] [--size <size>]
   # archip volume-snapshot <volume-name> --origin <volume-name>
   # archip volume-present <volume-name> --endpoint-driver <endpoint-driver>
   # archip volume-unpresent <volume-name> | <endpoint>
   # archip volume-remove <volume-name>
   # archip volume-move --from=<backend-name> --to=<backend-name>
   # archip volume-open <volume-name>
   # archip volume-close <volume-name>
   # archip volume-lock <volume-name>
   # archip volume-unlock [-f] <volume-name>
   # archip volume-showpresented [--filter-by:endpoint-driver=<endpoint-driver>,
                                            backend-driver=<backend-driver>]
                               [<volume-name>]

   # archip enpoint-list [--show-volumes]

   # archip backend-list
   # archip backend-info
   # archip backend-create <backend-name> --driver <backend-driver>
   # archip backend-remove <backend-name>
   # archip backend-sync --origin=<backend-name> --target=<backend-name>

   # archip driver-list [--endpoint] | [--backend]


.. note::

        driver-list could also be split to:
        # edriver-list # for endpoint-driver
        # bdriver-list # for backend-driver
        to have a 1:1 mapping from entities to commands.
