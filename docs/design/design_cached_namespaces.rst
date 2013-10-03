.. _design_cached_namespaces:

Design doc for namespaces in cached
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Current state
=============

Currently, cached has been created to index only objects. However, there are
more entities in Archipelago:

* volume locks
* volume hashes
* maps
* volumes

The functionality this design doc proposes has three parts:

#. The identification support for these namespaces
#. The ability to cache objects that belong in different
   namespaces in a generic manner.
#. The enforcing of different policies (e.g. cache size, cache write policy
   etc.) for each namespace.

Design overview
===============

We propose the addition of a logic layer in cached, that will allow different
namespaces to co-exist. This layer should provide each namespace with the
following:

* A place where cached-specific policies will be stored
* A place where the control functions (xworkq, xwaitq), indexes (xcache) and data
  (buckets) will be stored.

Moreover, we do not want to add to cached any extra logic for the handling of
objects that belongs in different namespaces, since that would result in a
messy code. Instead, cached should treat each namespace object as any other
object, which means that `struct ce` should cover equally maps, objects and
volumes.

The question arises then, what will cached use namespaces for?

It will use them for two things:

* Propagate the namespace of an object to the other peers, since all
  Archipelago will operate with namespaces.
* Apply different policies for each namespace. For example, the administrator
  may want to commission 16MB for maps, 1G for objects and 128G for volumes.
  Also, he/she may want maps to have a writethrough policy whereas objects and
  volumes a writeback policy.

Besides the above, for all indents and purposes everything is an object for
cached.

Advanced design issues
=======================

Bucket indexing
----------------

As philipgian has observed, a static bucket array will not scale for objects
such as volumes for the following reason:

Consider that we index a 200GB volume. If we partition it to 4k buckets, we
potentially have to track over 50 million buckets. A static array that at least
tracks these buckets (64-bit pointer) will take over 400MB of space. And that's
just for a single volume.

To this end, we need an index mechanism with the following characteristics:

#. Fast insertion, lookups and removal of indexed objects (miracle-making
   capabilities preferred but optional)
#. Sorting of the indexes, so that we can write to, claim and free bucket
   ranges fast.

The above requirements  adumbrate a B+ tree index. This is not final however
and we are in the process of looking for an alternative solution.

Finally, since objects that belong in the same namespace can have arbitrary
size, the index mechanism should be able to grow without an upper bound.

Implementation details
======================

Namespace arguments
--------------------

To instruct cached to cache a specific namespace, we will have the following
arguments::

  -{lock, hash, object, volume}

that will accept a series of tokens::

   $nr_entries:$cache_size:[$bucket_size]:[$write_cache_policy]

This renders previous arguments such as -mo (max objects), -cs (cache size),
-bs (bucket size) invalid and will be incorporated into the `-{lock, hash,
object, volume}` arguments that we presented.

Cached struct refactoring
--------------------------

Currently, cached struct holds object specific statistics and counters as well
as xworkqs and xwaitqs that are related to xcache and object buckets.

The introduction of namespaces means that this:

.. code-block:: c

        struct cached {
                struct xcache * cache;
                uint64_t total_size;
                uint64_t max_objects; 
                uint64_t max_req_size;
                uint32_t object_size;  
                uint32_t bucket_size; 
                uint32_t buckets_per_object;
                uint64_t total_buckets; 
                xport bportno;
                int write_policy;
                struct xworkq workq;
                struct xworkq bucket_workq;
                struct xwaitq pending_waitq;
                struct xwaitq bucket_waitq;
                struct xwaitq req_waitq;
                unsigned char * bucket_data;
                struct xq bucket_indexes;
                struct xlock bucket_lock;
                //scheduler
                uint64_t * bucket_alloc_status_counters;
                uint64_t * bucket_data_status_counters;
                double threshold;
        };

should turn to this

.. code-block:: c

        struct cached {
                xport bportno;
                struct xworkq workq;
                struct xwaitq req_waitq; // this is probably generic
                struct cached_namespace cns[MAX_NAMESPACES]
        };

The entry point for everything that cached needs for a namespace is the
following:

.. code-block:: c

        struct cached_namespace {
                struct xcache * cache;
                uint64_t total_size;
                uint64_t max_objects; 
                uint64_t max_req_size;
                uint32_t object_size;           // this can go
                uint32_t bucket_size; 
                uint32_t buckets_per_object;
                uint64_t total_buckets; 
                xport bportno;
                int write_policy;
                struct xworkq workq;
                struct xworkq bucket_workq;
                struct xwaitq pending_waitq;
                struct xwaitq bucket_waitq;
                unsigned char * bucket_data;
                struct xq bucket_indexes;       //this should be handled differently
                struct xlock bucket_lock;
                //scheduler
                uint64_t * bucket_alloc_status_counters;
                uint64_t * bucket_data_status_counters;
                double threshold;
                struct cached * cached;
        }

The memory overhead of having an uninitialized struct as the above for 4-5 namespaces
should be very small.

Note that we have to refactor all our code to get the correct `struct
cached_namespace` instead of the generic `struct cached` that we have now.

Policies per namespace
-----------------------

For the time-being, the only policies that we have is the cache write policy
and the number of entries and cache size that we index. For now, these can be
scattered in the above struct and our code will consult the respective
namespace struct for its policies.


