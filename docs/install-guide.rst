Installation guide
==================

Archipelago installation
************************

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
requires ceph packages which can be found on the wheeze-backports or the ceph's
provided repository.

.. code-block:: console

    $ apt-get install archipelago archipelago-ganeti archipelago-rados

To present Archipelago resources as block devices, the ``blktap-archipelago-utils`` and
``blktap-dkms`` packages are required. Please note that you need to install the
latest version of ``blktap-archipelago-utils`` from the aforementioned GRNet repo, since it
contains extra patches to support Archipelago. You should use your distro
provided ``blktap-dkms`` package.

.. code-block:: console

    # apt-get install blktap-archipelago-utils blktap-dkms

.. tip:: Archipelago does not start automatically after installation. Please
         review the configuration file, make any appropriate changes to the
         default configuration (e.g. default max segment size) and start it
         manually.

.. warning:: Archipelago currently does not provide any garbage collection
             functionality. Make sure your storage capacity can meet your data
             needs when using Archipelago.

Basic Archipelago configuration
*******************************

The Archipelago configuration file is:
``/etc/archipelago/archipelago.conf``

If your machine features < 6GB of RAM you need to set the ``SEGMENT_SIZE``
accordingly to a lower value. (e.g., for a machine with 2GB of RAM, you can set
it to 1GB). You should also create the two directories to store maps and blocks
and define them accordingly inside the ``blockerb`` and ``blockerm`` settings
of the configuration file (these are needed for the File backend driver to
work). These are the minimum settings you need to change before starting
Archipelago.

If you wish to start with a RADOS setup, a default archipelago-rados
configuration file ships with the package. You can use it as your base config.
The basic thing you need to adjust to your setup are the pools of ``blockerm``
and ``blockerb`` where the map and data objects will be stored.

:ref:`archip_config` section contains a full list of the configuration settings.
