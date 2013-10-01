.. _design_cached_namespaces:

Design doc for namespaces in cached
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Current state
=============

Currently, cached has been created to index only objects. However, there are
three more entities in Archipelago:

* volume locks
* volume (?) hashes
* volumes

These entities should also be able to be cached, which means that cached must
add support for them.

Moreover, these categories are differentiated with the use of namespaces, which
cached (and Archipelago by extension), must also support.

Finally, since cached will cache disparate entities, it should be able to
support different policies (e.g. cache size, cache write policy etc.) for each
of them.

Design overview
===============

The handling of each category should be as modular as possible, meaning that
once cached identifies in what category an entity belongs, it should follow a
path that does not affect the rest of the categories.

This means that our design is separated in three parts:

#. `Identification of namespaces`_
#. `Indexing of entities in different namespaces`_
#. `Request handling for different namespaces`_

Identification of namespaces
-----------------------------

Although cached could identify the namespace of an entity by some special
characters in its name, it is better and faster to simply read a "namespace
tag" that can come along with the XSEG request.

This means two things:

#. The peer that issues a request must also tag it with the correct namespace
#. The namespaces must be defined in libxseg.

Moreover, when cached creates its own requests, it must also tag them before it
sends them to the blocker.

Indexing of entities in different namespaces
---------------------------------------------

For each namespace that a cached instantiation is configured to cache, there
will be an xcache that will index its entities.

Furthermore, each xcache must have variable number of entries, defined
by the user, as it happens now. Moreover, besides xcache, the user must be able
to set peripheral parameters such as the number of entries, the cache size etc.

Request handling for different namespaces
------------------------------------------

A new level of indirection is introduced after a request is accepted/received.
Namely, cached will have to identify the namespace for this request and sent it
to the appropriate channels. This should be the only point where at the same
lines of code, the more than one namespaces are referenced.

Implementation details
======================

Before cached can begin identifying namespaces, we must define them globally.
We propose the following tags::

  XSEG_LOCK 0
  XSEG_HASH 1
  XSEG_OBJECT 2
  XSEG_VOLUME 3

Moreover, since objects carry on their name an implied namespace, there is a
need for a namespace seperator::

  XSEG_NAMESPACE_SEPARATOR ':' (or '-')

This requires an Archipelago wide-change to every request issued by a peer.
We will add one more argument to the `xseg_prep_request()` or `xseg_get_request`
function that will be the namespace tag of the request.

As for how cached will know what namespaces will it cache, there will be the
following arguments::

  -{lock, hash, object, volume}

that will accept a series of tokens::

   $nr_entries:$cache_size:[$bucket_size]:[$write_cache_policy]

