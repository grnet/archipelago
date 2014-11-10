Upgrade to Archipelago v0.4rc2
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Upgrade Steps
=============

This guide assumes an upgrade from the previous v0.4rc1 version of Archipelago.
This guide does not support upgrading from an intermediate snapshot version of
Archipelago.

If you plan to integrate Archipelago with Pithos, all Archipelago nodes must be
upgraded first.

The following steps must be applied to each node that gets upgraded.

0. Prerequisites

1. Prepare the node.

2. Evacuate the node.

3. Stop Archipelago

4. Install the Archipelago v0.4 packages

5. Adjust the new config file.

6. Start Archipelago


0. Prerequisites
~~~~~~~~~~~~~~~~

Archipelago v0.4rc2 relies on having group read/write permissions on certain
files for the components to communicate with each other. Since snf-image is one
of these components, if you are using it, you must upgrade snf-image on all
nodes to v0.16.3 which can properly handle file creation permissions.

1. Prepare the node
~~~~~~~~~~~~~~~~~~~

Each node that will be updated must be idle with respect to Archipelago. To
achieve the above the administrator must make sure that neither him nor the
upper service layers perform any kind of Archipelago action on the node.

In order to do so, the administrator can manually set each node to be upgraded
as drained using the following command on the ganeti master:

.. code-block:: console

        # gnt-node modify --drained=True <node>

or set the whole cluster to drained using the following snf-manage command from
the Cyclades service node:

.. code-block:: console

        # snf-manage backend-modify --drained=True <backend_id>


2. Evacuate the node
~~~~~~~~~~~~~~~~~~~~

For each node to be upgraded, the administrator must evacuate it from
Archipelago VMs, by either live-migrating them or failing them over to an
already upgrade node. Of course, there is an exception on the first node to be
upgraded.

3. Stop Archipelago
~~~~~~~~~~~~~~~~~~~

Archipelago must be fully stopped before upgrading. Perform the following
command to achieve it:

.. code-block:: console

        # archipelago stop

4. Install the Archipelago v0.4 packages
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Archipelago consists of the following packages:

* ``libxseg0``: libxseg used to communicate over shared memory segments
* ``python-xseg``: python bindings for libxseg
* ``python-archipelago``: archipelago python module that includes archipelago
  and vlmc functionality.
* ``archipelago``: user space tools and peers for the archipelago management and
  volume composition.
* ``archipelago-ganeti``: ganeti ext storage scripts, that enable ganeti to
  provision VMs over archipelago.

You can install them by installing archipelago archipelago-ganeti.

.. code-block:: console

        # apt-get install archipelago archipelago-ganeti

Optionally if you want RADOS support for archipelago, you should install
archipelago-rados package.

.. code-block:: console

        # apt-get install archipelago-rados

and also xseg-tools package in case you need to dig into the shared memory
segment

.. code-block:: console

        # apt-get install xseg-tools

On the nodes that will host VMs, blktap-archipelago-utils from GRNET and the
distro-provided blktap-dkms package must also be installed.

.. code-block:: console

        # apt-get install blktap-archipelago-utils blktap-dkms

5. Adjust the config file
~~~~~~~~~~~~~~~~~~~~~~~~~

The Archipelago config file is located on ``/etc/archipelago/archipelago.conf``.
You can choose to keep your configuration file from rc1 or use the one shipped
with rc2. In the first case, you must make sure to add the new configuration
settings introduced in rc2. In the latter case, you should reconfigure
Archipelago to match your installation.

New config option that were introduced in rc2 is:

* ``UMASK``: This setting on the ``[[Archipelago]]`` section controls the umask
  of Archipelago processes and external tools (e.g.  ganeti external storage
  script). Peers have a seperate ``umask`` option on their section. These
  settings should be configured to 007.

.. tip::

    You should also make sure that you have upgraded your snf-image to v0.16.3.

Archipelago v0.4rc2 also creates a new system user and group called ``archipelago``.
By default the configuration file shipped with Archipelago is set up to run as
those users. If you choose to use your previous configuration file, make sure
you switch the ``USER`` and ``GROUP`` settings to ``archipelago`` (with one
exception noted below).

If your are using Archipelago with ``filed`` special care is needed:

* You must change the corresponding ``USER`` and ``GROUP`` values of the
  configuration file to ``root``, and follow the supplementary procedure on the
  end of this upgrade guide.

* You must make sure that the ``archipelago`` user and group have the same
  permissions on the NFS share accross all nodes. This means for example that
  ``archipelago`` UID and GID are consistent across all Archipelago nodes for
  NFSv3 or there is a proper name mapping for NFSv4.

6. Start Archipelago
~~~~~~~~~~~~~~~~~~~~

After successfully configuring the new/upgraded Archipelago installation, start
it.

.. code-block:: console

        # archipelago start

After a successfull start, you can undrain the node:

.. code-block:: console

        # gnt-cluster modify --drained=False <node>

If you have drained the whole cluster and successfully upgraded all the nodes,
you can undrain it using the snf-manage command:

.. code-block:: console

        # snf-manage backend-modify --drained=False <backend_id>



Finalizing upgrade
==================
After upgrading all Archipelago nodes, you have to take certain steps to
finalize the upgrade.

Adjust NFS shares permissions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As already mentioned, Archipelago v0.4 creates the new ``archipelago`` system
user and group. In this section, we describe how to adjust the permissions of
the directories and files on the NFS shares that Archipelago is using in order
to run Archipelago as ``archipelago:archipelago``. If you are not using
Archipelago over NFS, skip this section.

We will refer to the Archipelago data directory as the directory that holds the
Archipelago data. On new installations this would probably be ``/srv/archip``.

.. warning::

 If you are integrating with a previous Synnefo installation, you must make sure
 that both Archipelago and Pithos have access to Archipelago data. You should
 skip this section, and perform the steps that are described in the
 `Synnefo upgrade notes
 <https://www.synnefo.org/docs/synnefo/latest/upgrade/upgrade-0.16.html>`_.

1. Change Archipelago data group permissions
--------------------------------------------

  Ensure that every file and folder under the Archipelago data directory has
  correct permissions.

  .. code-block:: console

      # find /srv/archip/ -type d -exec chmod g+rwxs '{}' \;
      # find /srv/archip/ -type f -exec chmod g+rw '{}' \;


2. Change the Archipelago data group owner
------------------------------------------

  Make ``archipelago`` group the group owner of every file under the Archipelago
  data directory.

  .. code-block:: console

      # chgrp archipelago /srv/archip/
      # find /srv/archip/ -type d -exec chgrp archipelago '{}' \;
      # find /srv/archip/ -type f -exec chgrp archipelago '{}' \;

  From now on, every file or directory created under the Archipelago data
  directory will belong to the ``archipelago`` group because of the directory
  sticky bit that we set on the previous step. Plus the ``archipelago`` group
  will have full read/write access because of the SET_GUID bit.


3. Change Archipelago user and group
------------------------------------

  Now we can change the Archipelago configuration on all Archipelago nodes, to
  run as ``archipelago``:``archipelago`` user and group, since it no longer
  requires root priviledges.

  For each Archipelago node:

  * Stop Archipelago

    .. code-block:: console

      # archipelago stop

  * Change the ``USER`` and ``GROUP`` configuration option to ``archipelago``
    user. The configuration file is located under
    ``/etc/archipelago/archipelago.conf``


  * Start Archipelago

    .. code-block:: console

      # archipelago start


Change ``Filed`` lock files location
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If your installation does not rely on ``filed`` skip this section.

In previous Archipelago versions, lock files were placed along with the data
files of blockerm. In Archipelago version 0.4 we set a distinct lock file
directory for easier lock lookup.

0. Prerequisites
----------------

Make sure you have a common directory shared with all Archipelago nodes (e.g.
/srv/archip/locks). The directory must be owned by the user and group
Archipelago run as (default ``archipelago``:``archipelago``) and both the user
and the group must have read and write permissions.

1. Stop all Archipelago instances
---------------------------------

On every node that runs Archipelago, perform the following:

.. code-block:: console

  # archipelago stop

Use the ``-f`` option if there are mapped volumes. Have in mind that during the
time Archipelago is stopped, the VMs will appear frozen whenever they attempt to
perform any disk I/O.


2. Set lock directory
---------------------

Set the lock directory for all ``blockerm`` peers on all nodes.
Add the following line ``lock_dir=/srv/archip/lock`` where ``/srv/archip/locks``
is the shared directory created on step 0.

3. Start all Archipelago instances
----------------------------------

On every node that runs Archipelago, perform the following:

.. code-block:: console

  # archipelago start


Pithos integration when using ``Filed``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you haven't executed this proccedure while installing Archipelago v0.4rc1 it
is recommended to perform it now. Otherwise skip this section.

If you are using Pithos backed by Archipelago with ``filed``, after having
upgraded all Archipelago nodes and successfully installed the upgraded Pithos
version, the following steps must also be followed.


1. Stop all Archipelago instances
---------------------------------

On every node that runs Archipelago, perform the following:

.. code-block:: console

  # archipelago stop

Use the ``-f`` option if there are mapped volumes. Have in mind that during the
time Archipelago is stopped, the VMs will appear frozen whenever they attempt to
perform any disk I/O.


2. Enable Pithos object migration
---------------------------------

Enable the ``pithos_migrate`` setting for all ``blockerm`` and ``blockerb``
peers on all nodes. Add the following line ``pithos_migrate=True`` on the
``blockerm`` and ``blockerb`` section of the configuration files.


3. Start all Archipelago instances
----------------------------------

On every node that runs Archipelago, perform the following:

.. code-block:: console

  # archipelago start


Convert all volume mapfiles
~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you haven't executed this proccedure while installing Archipelago v0.4rc1 it
is recommended to perform it now. Otherwise skip this section.

Archipelago lazily upgrades the mapfiles to the latest version, when they are
accessed. To make sure that all mapfiles have been upgraded to the latest
version, the provided migration tool must be executed. The tool is located in
``/usr/share/archipelago/tools/finalize_upgrade_0.4``.
You can run it from any node with access to Archipelago. Make sure that it
completes successfully.

It is advised, in order to avoid false alarms (e.g. a mapfile that failed to
upgrade), to be idle wrt to Archipelago control operations.
