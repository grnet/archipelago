.. _design_cached_flows:

Design doc for xindex
^^^^^^^^^^^^^^^^^^^^^

Current situation
==================

Using xcache, we currently have a way to cache any entity we want. By caching,
we mean that once an entity is inserted in the xcache, it will be referenced by
it and will leave only when our policy dictates us so.

However, it has arisen as a necessity to also have a simple and
lightweight way to to index entries for as long as a request (and not a cache)
references them. This is a subset of the xcache capabilities, which is why we will
create xindex, an indexing mechanism integrated with a refcount mechanism that
will index entries strictly for as long as a request references them.

Design overview
================

Xindex will use the following components:

* One hash table for indexing
* Α refcount mechanism for each entry
* Event hooks

Basically, its an stripped-down xcache without rm_entries, lru queues and
evictions.  As a result, we expect that the locking scheme will be much
simpler.

Moreover, we have queued to rewrite xcache in order to be based on xindex.

Implementation details
======================

The current list of functions (some of them do not show which of their
arguments are pointers and will be updated later on).

Also, further updates to xindex will be added in this design doc.

Xindex functions
-----------------

**Init/close functions**

.. code-block:: c

        int xindex_init(struct xindex index, uint32_t xindex_size,
                        struct xindex_ops ops, uint32_t flags, void priv);
        void xindex_close(struct xindex index);
        void xindex_free(struct xindex index);


**Allocation functions**

.. code-block:: c

        xindex_handler xindex_alloc_init(struct xindex index, char name);
        void xindex_free_entry(struct xindex index, xindex_handler h);

**Indexing functions**

.. code-block:: c

        xindex_handler xindex_lookup(struct xindex index, char name);
        xindex_handler xindex_insert(struct xindex index, xindex_handler h);

**Refcount functions**

.. code-block:: c

        void xindex_put(struct xindex index, xindex_handler h);
        void xindex_get(struct xindex index, xindex_handler h);

**Misc functions**

.. code-block:: c

        void *xindex_get_entry(struct xindex index, xindex_handler h);


Event hooks
-----------------

.. code-block:: c

        int (on_init)(void index_data, void user_data);
        void (on_put)(void index_data, void user_data);
        void (on_free)(void index_data, void user_data);
        void (on_node_init)(void index_data);
