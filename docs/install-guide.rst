Installation guide
==================

Package installation
********************

Archipelago consists of the following packages:

* ``archipelago``: user space tools and peers for the archipelago management and
  volume composition. This package depends on:

  * ``libxseg0``: libxseg used to communicate over shared memory segments
  * ``python-xseg``: python bindings for libxseg
  * ``python-archipelago``: archipelago python module. Includes archipelago and
    vlmc python modules.

* ``archipelago-rados``: user space storage driver to enable RADOS support
* ``archipelago-ganeti``: ganeti ext storage scripts, that enable ganeti to
  provision VMs over archipelago
* ``blktap-archipelago-utils``: blktap utilities to support presenting an Archipelago
  resource as a blktap block device. Currently this package is custom patched to
  support archipelago and it is provided by the Synnefo Apt repository.
* ``xseg-tools``: xseg utility that is used to dig into the shared memory
  segment communication mechanism.

To be able to download all Archipelago components you need to add the following
lines in your ``/etc/apt/sources.list`` file:

.. code-block:: console

   deb http://apt.dev.grnet.gr wheezy/
   deb-src http://apt.dev.grnet.gr wheezy/

and import our repository's GPG key:

.. code-block:: console

   curl https://dev.grnet.gr/files/apt-grnetdev.pub | apt-key add -

Then install the Archipelago packages. Installing ``archipelago`` and
``archipelago-ganeti`` packages from the APT repository should fetch all the
necessary dependencies.  Install also ``archipelago-rados`` if you want to
install the RADOS backend driver. Bare in mind that archipelago-rados package
requires ceph packages which can be found on the wheezy-backports or the ceph's
provided repository.

.. code-block:: console

    $ apt-get install archipelago archipelago-ganeti archipelago-rados

To present Archipelago resources as block devices, the
``blktap-archipelago-utils`` and ``blktap-dkms`` packages are required. Please
note that you need to install the latest version of ``blktap-archipelago-utils``
from the aforementioned GRNet repo, since it contains extra patches to support
Archipelago. You should use your distro provided ``blktap-dkms`` package.

.. code-block:: console

    # apt-get install blktap-archipelago-utils blktap-dkms

.. tip:: Archipelago does not start automatically after installation. Please
         review the configuration file, make any appropriate changes to the
         default configuration (e.g. default max segment size) and start it
         manually.

.. tip:: For those users who do not wish to install all the dependencies of
         blktap-dkms package the Synnefo apt repository provides a patched
         version of the dkms package that is able to provide a binary kernel
         module. The patched dkms aims to facilitate the process of building
         kernel modules from source. It uses source code from apt repositories
         and produces binary .deb packages.

         After installing the patched version of dkms from Synnefo apt repository
         to the build machine, the process of producing a binary .deb package
         from blktap-dkms is really simple:

         .. code-block:: console

             # apt-get install blktap-dkms
             # dkms mkbmdeb blktap/2.0.91

         The last command produces the final binary package under the directory
         ``/var/lib/dkms/blktap/2.0.91/bmdeb/`` which can be
         installed without installing the blktap-dkms dependencies.

         With backports kernel a newer blktap-dkms package should be
         fetched from unstable/SID. The version option used in dkms that denotes
         the blktap-dkms version should change accordingly.

.. warning:: Archipelago currently does not provide any garbage collection
             functionality. Make sure your storage capacity can meet your data
             needs when using Archipelago.


Setup data storage
******************

Archipelago over RADOS
~~~~~~~~~~~~~~~~~~~~~~

If you plan to run Archipelago over RADOS, you need to create two RADOS pools to
host Archipelago data. One pool is meant to host the Archipelago map files (e.g.
the ``maps`` pool) and the other one is used to host the actual data (e.g. the
``blocks`` pool).

Archipelago over NFS
~~~~~~~~~~~~~~~~~~~~

If you plan to run Archipelago over NFS, you need to create an NFS share and
mount it on all nodes that run Archipelago. Three subdirectories are needed. A
subdirectory where Archipelago mapfiles will be placed (e.g. ``maps``), a
subdirectory where Archipelago data files will be stored (e.g. ``blocks``), and
a separate directory where Archipelago places lock files (e.g. ``locks``).

Archipelago by default creates an ``archipelago`` user and group and the default
configuration executes Archipelago with these permissions. Make sure that the
Archipelago user and group have the same permissions on the NFS share accross
all nodes. That means for example that ``archipelago`` UID and GID are
consistent across all Archipelago nodes for NFSv3 or there is a proper name
mapping for NFSv4.


.. code-block:: console

   # mkdir /srv/archip/
   # cd /srv/archip/
   # mkdir -p {maps,blocks,locks}
   # chown archipelago:archipelago {maps,blocks,locks}
   # chmod 770 {maps,blocks,locks}
   # chmod g+s {maps,blocks,locks}


.. warning:: Each subdirectory of the /srv/archip/ (i.e. maps, blocks, locks)
             must be a single filesystem and contain no mountpoints or symbolic
             links to other filesystems.


Basic Archipelago configuration
*******************************

The Archipelago configuration file is:
``/etc/archipelago/archipelago.conf``

If your machine features < 6GB of RAM you need to set the ``SEGMENT_SIZE``
accordingly to a lower value. (e.g., for a machine with 2GB of RAM, you can set
it to 1GB).

For a ``filed`` based setup, you should adjust the ``blockerm`` and ``blockerb``
settings to point to the directories exported by the NFS server. More
specifically:
* Adjust the ``archip_dir`` of ``blockerb`` to point to the
  ``/srv/archip/blocks`` directory.
* Adjust the ``archip_dir`` of ``blockerm`` to point to the ``/srv/archip/maps``
  directory.
* Set the ``lock_dir`` of ``blockerm`` to point to the ``/srv/archip/locks``
  directory.


If you wish to start with a RADOS setup, a default archipelago-rados
configuration file ships with the package. You can use it as your base
configuration file.  The basic thing you need to adjust to your setup are the
pools of ``blockerm`` and ``blockerb`` where the map and data objects will be
stored.

You might also want to setup the ``cephx_id`` option, to point to your client
keyring.

:ref:`archip_config` section contains a full list of the configuration settings.
