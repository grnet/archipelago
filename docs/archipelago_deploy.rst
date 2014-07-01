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

To be able to download all Archipelago components you need to add the following
lines in your ``/etc/apt/sources.list`` file:

.. code-block:: console

   deb http://apt.dev.grnet.gr unstable/
   deb-src http://apt.dev.grnet.gr unstable/

and import the our repository's GPG key:

.. code-block:: console

   curl https://dev.grnet.gr/files/apt-grnetdev.pub | apt-key add -

Then install the Archipelago packages. Installing ``archipelago-ganeti`` from
the apt repository should fetch all the necessary dependencies, based on the
dkms infrastructure. Install also ``archipelago-rados`` if you want to enable
the RADOS backend driver:

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

The Archipelago configuration file is:
``/etc/archipelago/archipelago.conf``

If your machine features < 6GB of RAM you need to set the ``SEGMENT_SIZE``
accordingly to a lower value. (e.g., for a machine with 2GB of RAM, you can set
it to 1GB). You should also create the two directories to store maps and blocks
and define them accordingly inside the ``blockerb`` and ``blockerm`` settings
of the configuration file (these are needed for the File backend driver to
work). These are the minimum settings you need to change before starting
Archipelago.

Below is a list of all configuration settings:

``SEGMENT_PORTS``
    **Description** : Max number of ports in the segment.

``SEGMENT_SIZE``
    **Description** : Shared memory size, used for IPC.

``USER``
    **Description** : Switch peer processes to run as this user.

``GROUP``
    **Description** : Switch peer processes to run as this group.

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

Once you configure Archipelago, you are then ready to start it.

The ``archipelago`` tool provides the basic commands to control Archipelago.

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

``start``, ``stop``, ``restart`` can be combined with the ``-u / --user``
option to affect only the userspace peers supporting Archipelago.

Archipelago volume commands
***************************

The ``vlmc`` tool provides a way to interact with Archipelago volumes

Usage:

.. code-block:: console

  $ vlmc command [args]

Available commands:

* **showmapped**: Shows the mapped volumes and the archipelago devices on that
  node.

  Usage: ``$ vlmc showmapped``

* **map**: maps the volume to a blktap device

  Usage: ``$ vlmc map <volumename>``

* **unmap**: unmaps the specified device from the system.

  Usage: ``$ vlmc unmap </dev/xen/blktap-2/tapdev[0-..]>``

* **create**: creates a new volume with an optional specified size from an optional
  specified snapshot

  Usage: ``$ vlmc create <volumename> --snap <snapname> --size <size>``

  Usage: ``$ vlmc create <volumename> --snap <snapname>``

  Usage: ``$ vlmc create <volumename> --size <size>``

  The ``--snap`` and ``--size`` are both optional, but at least one of them is
  mandatory. If snap is not specified, then a blank volume with the specified
  size is created. If size is not specified, the new volume inherits the size
  from the snapshot.

* **snapshot**: create a snapshot with the given name from the specified volume.

  Usage: ``$ vlmc snapshot <volumename> <snapshotname>``

* **remove**: removes the volume.

  Usage: ``$ vlmc remove <volumename>``

  This does not actually delete the blocks, just make the volume inaccessible
  for usage. The actual blocks are removed later, when a garbage collection is
  invoked.

* **info**: shows volume information. Currently returns only the volume size.

  Usage: ``$ vlmc info <volumename>``

* **open**: opens an archipelago volume. That is, taking all the necessary locks
  and also make the rest of the infrastructure aware of the operation.

  Usage: ``$ vlmc open <volumename>``

  This operation succeeds if the volume is alread opened by the current host.

* **close**: closes an archipelago volume. That is, performing all the necessary
  functions in the insfrastrure to successfully release the volume. Also
  releases all the acquired locks.

  Usage: ``$ vlmc close <volumename>``

  A explicit ``close`` command should be invoked an explicit ``open``, to
  release the volume, unless another action triggered an implicit ``close``.

* **lock**: locks a volume. This step allow the administrator to lock an
  archipelago volume, independently from the rest of the infrastructure.

  Usage: ``$ vlmc lock <volumename>``

  The locks are idempotent for the current owner of the lock. That is, a lock
  operation will succeed when the volume is already locked by the same blocker.

* **unlock**: unlocks a volume. This allow the administrator to unlock a volume,
  independently from the rest of the infrastructure.

  Usage: ``$ vlmc unlock [-f] <volumename>``

  The unlock option can be performed only by the blocker that acquired the lock
  in the first place. To unlock a volume from another blocker, ``-f`` option
  must be used to break the lock.

