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

Entry states
------------

An entry during its lifetime will pass from the following states:

#. XINDEX_NODE_FREE, when the node is unclaimed.
#. XINDEX_NODE_CLAIMED, when the node is claimed, initialized and is pending
   insertion.
#. XINDEX_NODE_ACTIVE, when the entry is inserted in the hash table.
#. XINDEX_NODE_REMOVED, when the entry is removed from the hash table (but is
   still claimed).

After an entry is removed, its next state is XINDEX_NODE_FREE and the cycle
starts again. We name this cycle an `epoch`, and we define that a new entry
epoch begins once it is removed from xindex.

Xindex handler
---------------

The new xindex handler is a step forward from the xcache handler, which was a
typedef of xqindex and pointed directly to the internal node.

In this iteration, we have separated the bits of the xindex_hanlder in two
fields:

#. The rightmost bits are used to store the xqindex of the entry. These bits
   will be at most 32, since the index size is a uint32_t.
#. The rest leftmost bits are used to keep the epoch of the handler.

The handler's epoch is not always the same as the entry's epoch. It is a
snapshot of the entry's epoch when the handler was claimed by the user.
Effectively, this means that if an entry gets removed, all previous handlers
become invalid.

Epoch overflow
~~~~~~~~~~~~~~~~~~~~~~~~

On a long enough time line, the epoch of every entry drops to zero. The soonest
this will happen is after 2^32 (or 4 billion) insertion/removal pairs. The side effect of this
is that a handler that was previously invalid may become valid again.

This may sound severe, but should only affect peers that:

a. keep a copy of an xindex handler somewhere without updating the entry's
   refcount and
b. may consult that handler only after the entry has been inserted and removed at least
   4 billion times.

Probably, there is no such peer but if there is, it can plug a function
on the `on_recycle_handler` hook, so that it can get notified and resort to
the appropriate actions.

Xindex entry contents
----------------------

The entry contents are kept in a priv pointer in the xindex_entry struct.  The
only way a peer can access the contents is through the xindex handler. Note
that if the entry has changed epoch, previous handlers become invalid.

This way, we can find bugs more easily, since early removal of an entry is now
detected if later on someone tries to get the entry's contents.

Implementation details
======================

The current list of functions is the following:

Xindex functions
-----------------

**Init/close functions**

.. code-block:: c

        int xindex_init(struct xindex index, uint32_t xindex_size,
                        struct xindex_ops ops, int type, void priv);
        void xindex_close(struct xindex index);
        void xindex_free(struct xindex index);

.. note::

        In xindex_init, the `type` argument is necessary and is either
        XINDEX_INTEGER or XINDEX_STRING.


**Allocation functions**

.. code-block:: c

        xindex_handler xindex_alloc_init(struct xindex index, char name);

.. note::

        When an entry is allocated, the only way to free it is through xindex_put.
        This means that xindex_free_new is superseded by xindex_put.

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

        void xindex_get_entry(struct xindex index, xindex_handler h);

.. note::

        May return NULL if the handler is invalid.

Event hooks
-----------------

.. code-block:: c

        int (on_init)(void index_data, void user_data);
        void (on_put)(void index_data, void user_data);
        void (on_free)(void index_data, void user_data);
        void (on_node_init)(void index_data);
        void (on_recycle_handler)(void index_data, void user_data);
