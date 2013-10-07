.. _design_cached_flows:

Design doc for flow support in cached
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Current state
==============

There is currently no flow support in Archipelago whatsoever. However, since we
expect to support it shortly, cached can provide some preliminary support.

Moreover, cached has currently no way of knowing the objects of a volume,
so that we can flush them in case of a flush request. This is an urgent feature
and since the first flow implementation will probably refer to a unique volume,
this means that by indexing which objects belong to each flow, we will
essentially know the objects of a volume.

Design overview
================

XSEG requests should have a flow ID in them. We can feed this ID to a
special-purpose index (xhash) that will track the flows for which we have
objects cached. To be compliant with namespaces, there should be one such index
for each namespace.

For each flow, we will keep its cached objects on a list and when we want to
operate on all the objects of the flow, we will simply traverse this list.

Flow policies
===============

This design doc also paves the way for policies per flow. The contribution of
this doc to this subject is the following:

For every flow, we maintain an LRU list of its objects. Also, we keep a policy
struct (black box for now) in each flow so that cached can consult it in the
future.

Implementation details
======================

To begin with, we want to index all flows and since any object can belong to a
unique flow, we will create an xhash called `flow_index`. This index should
hold the same number of entries as the original xcache struct, which will be
renamed to `obj_cache`.

Moreover, each flow will need an xworkq for safe operations on its objects. We
propose the following flow struct for each flow:

.. code-block:: c

        struct cached_flow {
                struct xworkq workq;
                xlock lock;
                object_list;
                flow_policies;
        }

Moreover, we introduce the following struct for each object that will be
associated with a flow:

.. code-block:: c

        struct cached_flow_entry {
                flow_id;
                lru_list;
                uint32_t status;
                xcache handler h;
        }

The status of `cached_flow_entry` (`fe` for short) has the following possible
values:

* **FE_FREE**, which indicates that the `fe` is not allocated.
* **FE_ALLOCATED**, which indicates that the `fe` is allocated but not indexed.
* **FE_READY**, which indicates that the `fe` has been indexed and can be used.
* **FE_ERROR**, which indicates that the `fe` has encountered an error.

Furthermore, we present another structure, similar to `cio` (which will be
renamed to `oio` (`obj_io`)) but for flow operations. It is called `fio` and is
the following:

.. code-block:: c

        struct flow_io {
                uint32_t state;
                flow id;
                uint32_t pending_reqs;
                struct work work;
        };

This struct will be stored in the `peer_request` struct and will be used when the
peer wants to enqueue a job in the flow workq. Also, the `fio` states will be the following:

* **FIO_READY**, which indicates that the `fio` does not currently do any job.
* **FIO_BUSY**, which indicates that the `fio` is busy with a job.
* **FIO_ERROR**, which indicates that the `fio` has encountered an error.

The integration with the existing `oio`  will be done with the help of a
wrapper struct, the `cached_custom_ios` which can be seen below:

.. code-block:: c

        struct cached_io {
                struct flow_io fio;
                struct obj_io oio;
                struct xwaitq waitq;
                struct work;


This wrapper struct does not contain only the `fio` and `cio`, but also a waitq
that can be used to execute jobs that wait until the `fio` and `cio` have no
`pending_reqs` left.

In a nutshell, the synchronization between the `flow_cache` and `obj_cache` has
to tackle two challenging issues:

#. Coherency: there is bound to be a window frame that an object will be in one
   of the two caches. Make this frame as small as possible and guarantee that
   probes to these tables will result in something coherent.
#. Locking: we don't want two different xcaches to share locks, which means
   that synchronization will be difficult.

We now present how we will handle each operation on flows. Keep in mind that
for each operation there are two stages: a) getting access to the flow and
b) getting access to the requested object(s).
There are the following operations:

* `Insertion`_
* `Update`_
* `Flushing`_
* `Deletion`_

Insertion
----------

The insertion operation aims to index a {flow, object} tuple. This tuple is
represented by the `fe`; the flow id stands for the flow while the xcache
handler for the object.

This struct is allocated in the `on_init` handler of cached, which is use to
initialize a `ce`. If the initialized `ce` is not inserted, then likewise our
initialized struct is not inserted too and it can be safely freed. This way, we
know for sure that we will index only new insertions and not reinsertions.

At this point, we have to index the initialized flow entry. Before we do so, we
must ensure that the associated flow id has been indexed in the xhash. If not,
we must insert it before we proceed.

After we have verified that the flow id has been inserted, we can insert the
object in the `cached_flow` object list. Before we do so, we update the
object's refcount, since we will operate on it, and create an insertion job
using `fio`. Also, we increment its `pending_reqs` and mark it as **FIO_BUSY**.
Then, we enqueue this insertion job for the initialized `fe` in the flow workq.

The insertion job will do the following:

.. code-block:: c

        append the object to the list
        mark its status as FE_READY
        put the ce
        decrement fio->pending_reqs
        signal the waitq of cached_io

While this job is pending to be executed, cached can process the request for
the object. Once it has finished however, it must ensure that the object has
been inserted before it completes the request. This can be done safely as so:

.. code-block:: c

        if fio or cio have pending reqs
                enqueue cached_complete in the waitq of cached_io

All we have to do then is to make sure that when we decrement the pending_reqs
of either `fio` or `oio` and they reach zero, we will signal this waitq. This
is a feature that was wrongfully missing from the cached logic and its
implementation has been long due.

Update
-------

We update an `fe` in all the other cases besides insertion, i.e. when we simply
update the reference of a `cache_entry`. Updates refer to the position of the
object in the LRU list of a flow.

Similar to insertions, updates can be issued asynchronously. The difference is
that in our case, we update
the refcount of the ce and issue the following job:

.. code-block:: c

        update the position of the object in the LRU
        put the ce
        decrement fio->pending_reqs
        signal the waitq of cached_io

Flushing
---------

When a flow asks to flush its cached objects, we must first enqueue the
following job to the flow workq:

.. code-block:: c

        for each object of the list
                check if object is still cached
                enqueue flush work to the object workq


Deletion
---------

We delete objects from the `flow index` when we no longer keep them in the
object cache. To do so, we can enqueue the following job in the on_put function
of `obj_cache`:

.. code-block:: c

        remove object from list
        free allocated resources

We can safely do so since the stale flow entries that may be encountered by
a flushing operation will be handled correctly.

Notes
======
1) The `lru_list` will be a list similar to the O(1) lru used in xcache, which
means that this lru must move from the xcache code and become an xtype of its
own.

2) It would be handy if xcache could be used to index the flows. This way, the
allocation of flows will become very easy as it's already implemented.

