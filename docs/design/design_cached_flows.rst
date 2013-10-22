.. _design_cached_flows:

Design doc for flow support in cached
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Current state
==============

There are currently no flows in Archipelago. However, since we expect to
support them shortly, cached should decide on how it will handle them.

The introduction of flows is essential for the correct management of volumes by
cached. More specifically, cached has currently no way of knowing the objects
of a volume, so that it can flush them in case of a flush request. However, if
there was a flow or a family of flows associated with each volume, this problem
would be trivial to solve.

Objectives
==========

The objectives for our implementation are:

#. Index the cached objects of volumes and flows.
#. Create a cache that has a **global** size limit in object data (buckets) and
   index (size of hash table, cache entries etc.) **per namespace**.
#. Support custom **flow** limits and policies.
   Typically:

   * Size limit for index and object data.
   * Different cache write policies for each flow.

Moreover, a design goal is to build around these objectives but make our design
extensible enough in order to be prepared for the full introduction of flows with
minimal refactoring.

.. note::

        We don't want to introduce the concept of volumes in cached. Instead,
        we will use the more generic term "resource". Thus, the cached objects
        of a resource will be considered as cached objects of a flow or family
        of flows that originate from the same resource.

.. note::

        Having a limit for index data and object data is awkward. Ideally,
        there should be a unified limit for both the index and object data and
        if that limit is hit, free entries from the index or buckets
        accordingly.  We acknowledge this issue, but it is not severe and can
        be addressed in another design doc.

Flows
=====

Although flows will be better explained in the appropriate design doc, we will
present in this section a basic explanation of them to understand what we
expect to handle.

First of all, we define as **minor flow** a tagged series of requests that
follow the same I/O path and have the same policies and limitations. For
example, a flow of writes for a volume's blocks can be considered as a minor
flow.

Moreover, we define as **major flow** a collective of minor flows that *may*
share the same path, policies and limitations, but **strictly** refer to the
same resource (commonly a volume). For example, a major flow can be a  collective
of minor flows for read/write operations on the maps/blocks of a volume, since
they have originated from the same resource.

Furthermore, we expect to provide a different I/O path and policies for
different namespaces of a resource, e.g. we may want to cache a volume's maps
in write-through mode and its blocks in write-back. This example shows that it
would be more natural if different namespaces of a resource were tagged as
separate **minor flows** too.

Design overview
================

The design that we propose for cached is the following:

|cached-design|

We separate cached in 4 levels:

#. Top level: In this level, we keep an **index** of the major/minor flows for
   which we have cached objects, as well as global statistics of allocated
   buckets, index size etc.
#. Flow level: In this level, we **cache** the objects that belong in a **minor flow** (called "flow
   objects" from now on).
   Moreover, we point to the flow-specific policies and limits.
#. Object level: In this level, we keep an **index** of the original objects as they exist
   in Archipelago. The objects remain indexed as long as a flow object
   has a reference on them.
#. Bucket level: In this level, we keep an **index** of the buckets that an object has claimed.

Design of components
======================

Major flows/minor flows
-----------------------

We have explained in the `Flows`_ section what are the minor/major flows. What
we want to clarify in this section is the way we will index these.

When cached receives an xseg request, two of the fields that it will check is
the minor and major flow id of the request. Using these, it can
populate the flow index.

First, we will keep the major flows in an xindex (more about `xindex` in the
respective design doc). We expect that for the first iteration, the minor flows
of a major flow will be very few (probably less than 5) so we can keep them in a
list.

Also, for the first iteration, we expect that the number of major/minor flows
at any time will be manageable (not more than a 1000) so we can delegate the
task of unindexing/evicting an active flow in the future. However, inactive
flows, i.e.  flows with no cached objects must be removed.

To sum up, a major flow is considered active as long as it indexes at least one
minor flow. A minor flow is considered active as long as it has at least one
cached object. In all other cases, the flow will be removed.

In the design diagram, the minor flows are the purple lines and the major flows are
the posts that keep them together. Moreover, the flow index is the red index at
the top of the diagram.

Flow objects
------------

Flow objects have been created because we need a way to cache the target object
of a request, but also be able to share it with other flows (e.g. due to CoW).

Thus, we need support for multiple flows to point reliably to the same object.
Also, we need a way to know how many buckets has a flow allocated for an object, as well as
to make sure that this shared object is not evicted for as long as it is cached
by a flow. So, our solution is not to index the original object but the "flow object", a
reference to the object from the viewpoint of a flow.

The flow object has the same name as the original object and holds a reference
to it.  Also, it has statistics that refer solely to the buckets that the flow
has allocated. However, since it is merely a reference, it does not cache the
data. Instead, it provides a pointer to the original object that holds the
data.

In the design diagram, the flow objects correspond to the purple labels that
hang from a flow.

Original objects
------------------

In contrast to the original implementation of cached, we do not keep the original
objects in an xcache. The reason we do so is because the flow objects are responsible
for the correct handling and data propagation of objects.

Thus, we keep the original objects in an xindex. They retain their xworkqs and
xwaitqs but they are no longer referenced by the xseg requests. Instead, they are
referenced by the flow objects.

In the design diagram, the original objects are the blue circles that are
referenced by the flow objects.

Buckets
-------

The only change that is introduced for buckets is that we need to know which bucket
has been allocated for a flow object. We keep track of this information by adding
an extra field in the bucket index, the id of the flow object.

.. note::

        This information could be kept in a special index of a flow object.
        However, consider the case where a bucket that has been allocated by flow1
        is dirtied by flow2. In this scenario we need to notify instantly flow1 for this
        change, thus this solution makes this much easier.

Cached operations
=======================

Read/Write
-----------

Let's see step by step the handling of a new read/write request:

#. We read the **major flow** field of the request. We give this to the top
   level index to check if the major flow is indexed.

   * If it is **not indexed**, we initialize a new major flow entry and index
     it. Also, we update the refcount of the major flow.

#. We read the **minor flow** field of the request. We check if the indexed
   major flow also indexes this minor flow

   * If it is **not indexed**, we initialize a new minor flow entry and insert
     it in the list. Also, we do all the necessary initializations (e.g.
     initialization of xcache) and update the refcount of the minor flow.

#. We check if the **flow object** is cached by the minor flow.

   * If it is **not cached**, we create a new flow object entry and insert it
     in the xcache. Also, we update its refcount and do all the necessary
     initializations.
   * If it is **cached**, we update its refcount, store its handler in the
     request and proceed

#. We check if the **flow object** has a pointer/handler to the **original object**.

   * If it does not have any, e.g. because we have just inserted the flow object
     in the xcache, we proceed to the next step.
   * If it does, we can skip the next step.

#. We check if the **original object** is indexed.

   * If it is **indexed**, we update its reference count and store its handler to the
     flow object
   * If it is **not indexed**, we initialize an original object entry and
     insert it in the xindex for the **respective namespace**. Then, we do the
     necessary initializations, update its refcount and store its handler in
     the flow object

#. We enqueue our work in the **workq** of the **original object**.
#. Once we enter the **workq** we can read/modify the data of the **original object**. There are
   the following two scenarios:

   * The request range includes unallocated portions of the object's data:

     #. We claim the necessary number of buckets,
     #. update the bucket index of the original object and then
     #. store the flow object handler in these buckets.

   * If the bucket exists, the request can freely read or write to it.
   * In **either case**, **any update** to the original object's buckets must
     update the statistics of four different entities:

     #. The object,
     #. the flow object **that has allocated the bucket**,
     #. the minor flow and
     #. cached.

     Fortunately, this is an operation that can
     be done with atomic gets/puts, so we can proceed without a lock.

#. After the **request** has been **completed**, we put the **flow object
   handler** that is stored in the request.


Snapshot
--------------

In order to get a snapshot of a resource, we need a way to
flush its dirty data. The data may have been dirtied by one or more flows, but
we are certain that these flows will belong in the same major flow.

This means that we can check the major flow id of the flush/snapshot request and
send a flush request to all the minor flows.

.. note::

        The flush request may be tagged with the flow id of the snapshot
        request, but for now it will be tagged with the flow id of the flow
        objects.

ENOSPC scenarios
-----------------

For every flow, we will try to flush its dirty data once its dirty threshold
exceeds a specified level. This preemptive measure however is not enough. There
are two cases when we can run out of space:

#. When we run out of global space for the index/object data, according to the
   limits of the namespace.
#. When we run out of space for the flow index/data, according to the flow
   policy.

In the first case, we can send a flush request to a random flow. This flush
request should attempt to get the necessary buckets to replenish the bucket
pool. The second case is a subset of the first case and is handled accordingly,
i.e.  we sent a flush request for that specific flow.

.. |cached-design| image:: /images/cached-design.svg

