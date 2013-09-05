Archipelago management
======================

This section describes basic Archipelago management and configuration.

Archipelago installation
************************

Archipelago consists of the following packages:

* ``libxseg0``: libxseg used to communicate over shared memory segments
* ``python-xseg``: python bindings for libxseg
* ``archipelago-kernel-dkms``: contains archipelago kernel modules to provide
  block devices to be used as vm disks
* ``archipleago-modules-source``: contains archipelago kernel modules source, to
  build deb packages with the help of module assistant
* ``python-archipelago``: archipelago python module. Includes archipelago and
  vlmc functionality.
* ``archipelago``: user space tools and peers for the archipelago management and
  volume composition
* ``archipelago-rados``: user space storage driver to enable RADOS support
* ``archipelago-ganeti``: ganeti ext storage scripts, that enable ganeti to
  provision VMs over archipelago



Installing ``archipelago-ganeti`` from the apt repository should fetch all the
necessary dependencies, based on the dkms infrastructure. Install also
``archipelago-rados`` to enable RADOS storage backend.


.. code-block:: console

    $ apt-get install archipelago-ganeti archipelago-rados

.. tip:: Archipelago does not start automatically after installation. Please
         review the configuration file, make any appropriate changes to the
         default configuration (e.g. default max segment size) and start it
         manually.

If a dkms based install is not desired, build your own archipelago-modules
package by installing archipelago-modules-source and performing:

.. code-block:: console

    $ m-a build --text-mode --kvers-list "target kernel to build" archipelago-modules

.. note:: Kernel modules need linux-kernel >= 3.2

.. warning:: Archipelago currently supports only x86_64 architecture.

Archipelago configuration
*************************

Archipelago configuration file is located to :
``/etc/archipelago/archipelago.conf``


``SEGMENT_PORTS``
    **Description** : Max number of ports in the segment.

``SEGMENT_SIZE``
    **Description** : Shared memory size, used for IPC.

``XSEGBD_START``
    **Description** : Start port of xsegbd peers

``XSEGBD_END``
    **Description** : End port of xsegbd peers

``VTOOL_START``
    **Description** : Start port of vlmc tool.

``VTOOL_END``
    **Description** : End port of vlmc tool.

``roles``
    **Description** : A list of (role_name, role_type) tuples, which is used to
    deploy the archipelago user space peers. Order matters.

``role_name { 'setting': value }``
    **Description** : A python dictionary which holds the parameters of they
    userspace peers.

Common peer options:
 * ``portno_start``: Start port of the peer.
 * ``portno_end``: End port of the peer.
 * ``log_level``: Loggging lever for the peer. Available logging levers 0-3.
 * ``nr_ops``: Number of ops, each peer can have flying.

.. * ``logfile``:
.. * ``pidfile``:

Filed specific options:
 * ``nr_threads``: Number of I/O threads to server requests.
 * ``archip_dir``: Directory where the files will reside.
 * ``fdcache``: Number of file descriptors to be kept open.

Rados specific options:
 * ``nr_threads``: Number of threads to server requests.
 * ``pool``: RADOS pool where the objects will be stored.

Mapper specified options:
 * ``blockerb_port``: Port for communication with the blocker responsible for
   the data blocks.
 * ``blockerm_port``: Port for communication with the blocker responsible for
   the maps.

Vlmc specific options:
 * ``blocker_port``: Port for communication with the blocker responsible for the
   data blocks.
 * ``mapper_port``: Port for communication with the mapper.

Archipelago commands
********************

``archipelago`` provides basic functionality for archipelago.

Usage:

.. code-block:: console

  $ archipelago [-u] command


Currently it supports the following commands:

* ``start [role]``
  Starts archipelago or the specified peer.
* ``stop [role]``
  Stops archipelago or the specified peer.
* ``restart [role]``
  Restarts archipelago or the specified peer.
* ``status``
  Show the status of archipelago.

``role`` is one of the roles defined on the configuration file.


``start``, ``stop``, ``restart`` can be combined with the ``-u / --user`` option
to affect only the userspace peers supporting archipelago.

Archipelago advanced commands
*****************************

The ``vlmc`` tool provides a way to interact with archipelago volumes

Usage:

.. code-block:: console

  $ vlmc command [args]

Available commands:

* **map**: maps the volume to a xsegbd device

  Usage: ``$ vlmc map <volumename>``

* **unmap**: unmaps the specified device from the system.

  Usage: ``vlmc unmap </dev/xsegbd[1-..]>``

* **create**: creates a new volume with an optional specified size from an optional
  specified snapshot

  Usage: ``vlmc create <volumename> --snap <snapname> --size <size>``

  Usage: ``vlmc create <volumename> --snap <snapname>``

  Usage: ``vlmc create <volumename> --size <size>``

  The ``--snap`` and ``--size`` are both optional, but at least one of them is
  mandatory. If snap is not specified, then a blank volume with the specified
  size is created. If size is not specified, the new volume inherits the size
  from the snapshot.

* **snapshot**: create a snapshot with the given name from the specified volume.

  Usage: ``vlmc snapshot <volumename> <snapshotname>``

* **remove**: removes the volume.

  Usage: ``vlmc remove <volumename>``

  This does not actually delete the blocks, just make the volume inaccessible
  for usage. The actual blocks are removed later, when a garbage collection is
  invoked.

* **list**: Provides a list of archipelago volume currently found on storage

  Usage: ``vlmc list``

* **info**: shows volume information. Currently returns only the volume size.

  Usage: ``vlmc info <volumename>``

* **open**: opens an archipelago volume. That is, taking all the necessary locks
  and also make the rest of the infrastructure aware of the operation.

  Usage: ``vlmc open <volumename>``

  This operation succeeds if the volume is alread opened by the current host.

* **close**: closes an archipelago volume. That is, performing all the necessary
  functions in the insfrastrure to successfully release the volume. Also
  releases all the acquired locks.

  Usage: ``vlmc close <volumename>``

  A explicit ``close`` command should be invoked an explicit ``open``, to
  release the volume, unless another action triggered an implicit ``close``.

* **lock**: locks a volume. This step allow the administrator to lock an
  archipelago volume, independently from the rest of the infrastructure.

  Usage: ``vlmc lock <volumename>``

  The locks are idempotent for the current owner of the lock. That is, a lock
  operation will succeed when the volume is already locked by the same blocker.

* **unlock**: unlocks a volume. This allow the administrator to unlock a volume,
  independently from the rest of the infrastructure.

  Usage: ``vlmc unlock [-f] <volumename>``

  The unlock option can be performed only by the blocker that acquired the lock
  in the first place. To unlock a volume from another blocker, ``-f`` option
  must be used to break the lock.

Archipelago volume locking system
*********************************

Archipelago uses volume storage based locks, to get exclusive access to volumes.
Since a volume can be active in only one VM, locks are used to ensure that
restriction. But since locks are storage based, they are permanent and
independent from the process or subsystem that acquired them. So, if a process, 
an archipelago deployment on a node misbehaves or crashes, or even a hypervisor
management software (e.g. ganeti) fails to perform a migration, there might be an
inconsistency. Knowledge of locking behavior in archipelago is necessary in
order to surpass these problems.

#TODO FILL ME

locking is cached on mapper

Persistent locks. held if a process/blocker stops/fails/crashes

lock is acquired with best effort mode:

* reads: try to get it, but do not fail if not able to. just don't cache anything
* writes: try to get it, and wait until the owner free it.
* snapshot/remove/create etc: Try to get it. Fail if not able to.

during migrations: blah blah
