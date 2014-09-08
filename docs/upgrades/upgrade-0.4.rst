Upgrade to Archipelago v0.4
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Upgrade Steps
=============

This guide assumes an upgrade from the previous (v0.3.x) version of Archipelago.
This guide does not support upgrading from an intermediate snapshot version of
Archipelago.

If you plan to integrate Archipelago with Pithos, all Archipelago nodes must be
upgraded first.

The following steps must be applied to each node that gets upgraded.

1. Prepare the node.

2. Evacuate the node.

3. Stop Archipelago

4. Install the Archipelago v0.4 packages

5. Adjust the new config file.

6. Remove the old config file

7. Start Archipelago


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

If upgrading from Archipelago version less that 0.3.5, the administrator must
make sure that each mapped volume on the node is opened. An oneliner like the
following should do the trick:

.. code-block:: console

        # for i in $(vlmc showmapped|grep -v image|awk '{print $2}'); do vlmc open $i ; done ;

Make sure that no errors are raised. If so, the administrator must resolve them
manually.

2. Evacuate the node
~~~~~~~~~~~~~~~~~~~~

For each node to be upgraded, the administrator must evacuate it from
Archipelago VMs, by either live-migrating them or failing them over to an
already updated node. Of course, there is an exception on the first node to be
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

On the nodes that will host VMs, blktap-archipelago-utils from grnet and the distro-provided
blktap-dkms package must also be installed.

.. code-block:: console

        # apt-get install blktap-archipelago-utils blktap-dkms

5. Adjust the new config file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Adjust the new config file to the deployment needs. The new config file is
located on ``/etc/archipelago/archipelago.conf``.

Notable new config options that should be configured are:

* ``BLKTAP_ENABLED``: Whether or not the blktap module should be used. Must be set
  to true for nodes that will host VMs.
* ``USER``: The user that archipelago will run as.
* ``GROUP``: The group that archipelago will run as.

Currently on the nodes that serve as VM containers, theses settings must be set
to ``root``.

If your are using Archipelago with ``filed`` and Pithos, make sure the selected
``USER`` and ``GROUP`` settings are compatible with those on your Pithos
configuration. Since Archipelago and Pithos operate on the same files, they
must have the same access regarding permissions.

6. Remove the old config file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After migrating your setting from the old config to the new one, you can safely
remove it from your system.

.. code-block:: console

        # rm /etc/default/archipelago


7. Start Archipelago
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



Pithos integration when using ``Filed``
=======================================

If you are using Pithos backed by Archipelago with ``filed``, after having
upgraded all Archipelago nodes and successfully installed the upgraded Pithos
version, the following steps must also be followed.


1. Stop all Archipelago instances
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On every node that runs Archipelago, perform the following:

.. code-block:: console

  # archipelago stop

Use the ``-f`` option if there are mapped volumes. Have in mind that during the
time Archipelago is stopped, the VMs will appear frozen whenever they attempt to
perform any disk I/O.


2. Enable Pithos object migration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enable the ``pithos_migrate`` setting for all ``blockerm`` and ``blockerb``
peers on all nodes. Add the following line ``pithos_migrate=True`` on the
``blockerm`` and ``blockerb`` section of the configuration files.


3. Start all Archipelago instances
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On every node that runs Archipelago, perform the following:

.. code-block:: console

  # archipelago start

Finalizing upgrade
==================

After all nodes are upgraded, from one node with access to archipelago run the
provided script to make sure all old resources have been migrated to the new
Archipelago. It is advised, in order to avoid false alarms (e.g. a mapfile that
failed to upgrade), to be idle wrt to
Archipelago control operations.


