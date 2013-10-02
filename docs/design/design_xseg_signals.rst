.. _design_xseg_signals:

Design doc for xseg signaling
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Current State
=============

Peers use the xseg requests to pass data between them and the xseg signaling
mechanisms to signal one another.  The peers are separated in the domain they
operate. Currently there are two domains, kernel and user domain. Each domain
has certain peer types designed for that domain, each with its own peer ops. The
signaling mechanism that will be used to signal a peer, is tight to the peer
operations and in general with the peer type.

In more detail, each port where the peer binds to,  gets a signal descriptor
that will be used to signal the peer. This signal descriptor is provided by the
peer type definition and points to the peer instance data. These data will be
given to the peer-type provided functions, to signal the peer.

This approach has worked so far, but has a major limitation. It tightly couples
the peer type with the signaling mechanism. This does not allow having multiple
signaling mechanisms for the same peer type.

Design overview
===============

This design attempts to introduce separate signal types and to decouple them from the peer types.
This comprises of the following:

1. Introduce signal types to the ``xseg`` mechanism.
2. Modify ``xseg`` to make use of the new signal types, instead of relying to
   the peer-type signaling.


Signal types
------------

Signal types are an xseg way to describe a signaling mechanism. They are used to
wrap the fundamental signaling mechanisms provided by the OS and the expose a
consistent API to signal peers, independently from the peer type or domain.

A peer can use a signal descriptor to inform other interested parties, how to
signal them. The signal descriptor already holds instance specific data that are
used to signal the peer. We extend the signal descriptor to hold the signal type
that should be used.  That way a signal descriptor describes to all interested
parties, how a peer should prepare itself to accept signals or which action and
on which data should be taken to notify a peer.

Each signal type is specified for use with a peer in certain domain, with hooks
to support receiving signals from the other domains.  The signal types are
domain-wise interoperable. That means, that a peer of a domain, can use all the
available signal types specified for that domain.  A peer can use only compatible
signal descriptors, i.e, signal descriptors from the same domain as the peer.

Each peer must allocate and use at least one signal descriptor, to be able to
receive signals.  It must provide each port it binds to, with a signal
descriptor that will be used to notify the peer, when the port is signaled.

Signal type propagation
-----------------------

Each signal type has a unique name. To avoid the expensive string comparison each
time we want to get the signal ops from the signal descriptor, each signal type
is given a unique integer id. To support dynamic signal type loading, it's
impractical to statically assign integer ids. So they should be dynamically
decided and propagated consistently among the peers. The same thing must happen
for the memory location which pools signal-type specific signal descriptor data.

This can be done using the same mechanism that is currently used for peer type
propagation.

Decoupling the signal types from the peer types have the following consequences:

1. Peer types do not need to be synced among the different peers using the
   shared data, and should be replaced by the signal types.
2. The peer data is not needed any more, and can be replaced with xobj_handlers
   that return signal descriptor structs of the specified type.

Reference counting
------------------

Each signal descriptor can be access by possible all peers on the segment. This
means that the peer that allocates the signal descriptor, cannot safely free it,
unless it knows for sure that nobody else is using it. To address this, each
signal descriptor will be reference counted and will be freed only when the
references drop to zero.

More over, each peer cannot safely quit a signal type. If there are active
signal descriptors which have not yet been released, it is not safe to clean up
local signal initializations. So each peer type counts in a peer private manner,
the active signal descriptors. This can be achieved by counting the
initializations and cleanups of the signal descriptors.

Implementation details
======================


Structs
-------

* Signal descriptors

  A generic signal descriptor struct is introduced to hold the signal type and
  the instance specific data of the peer. Each signal type has its own data, so
  the signal descriptor points to memory location in the segment where these
  data reside.

  .. code-block:: c

    /* Generic signal descriptor struct.
     * Contains the type of the signal descriptor and a pointer to the actual struct
     */
    struct signal_desc {
        uint64_t type, /* type of signal_desc */
        xptr sd /* pointer to the signal-type specific descriptor struct */
    }


* Signal types

  A signal type must define its name and provide function on how to perform
  certain operations. 

  .. code-block:: c

    /*
     * Signal descriptor operations
     */
    struct xseg_signal_type {
        {
            int (*init_signal_desc)(struct xseg *xseg, void *sd),
            void (*quit_signal_desc)(struct xseg *xseg, void *sd),
            int (*local_signal_init)(struct xseg *xseg),
            void (*local_signal_quit(struct xseg *xseg),
            int (*remote_signal_init)(void),
            void (*remote_signal_quit)(void),
            int (*prepare_wait)(struct xseg *xseg, void *sd),
            int (*cancel_wait)(struct xseg *xseg, void *sd),
            int (*wait_signal)(struct xseg *xseg, void *sd, uint32_t usec_timeout),
            int (*signal)(struct xseg *xseg, void *sd),
        },
        "signal_type_name"
    }

  These operations are:
  
  - Initialization/cleanup of an individual signal descriptor.

    .. code-block:: c

        int (*init_signal_desc)(struct xseg *xseg, void *sd)
        void (*quit_signal_desc)(struct xseg *xseg, void *sd)
  
  - Initialization/cleanup needed to be able to accept signals of this type.
  
    .. code-block:: c
  
        int (*local_signal_init)(struct xseg *xseg)
        void (*local_signal_quit(struct xseg *xseg)
  
  - Initialization/cleanup needed to be able to send signals of this type.
  
    .. code-block:: c
  
        void (*local_signal_quit(struct xseg *xseg),
        int (*remote_signal_init)(void),
  
  

* Ports

  Xseg ports must me extended to hold a pointer to the signal descriptor of the
  peer that uses the port.

  .. code-block:: c
  
      struct xseg_port {
          ...
          xptr signal_desc /* pointer to struct signal_desc */
          ...
      }

API Calls
---------

Generic library wide structs:

  .. code-block:: c

      static struct xseg_signal_type *__signal_types[XSEG_NR_SIGNAL_TYPES];
      static unsigned int __nr_signals;


New calls:

.. - .. code-block:: c
.. 
..     xseg_alloc_signal_desc(struct xseg *xseg, char *type)
.. 
.. 
..   * **Description**: Allocates a new signal descriptor of the given type.
..   * **Calls**:
..       .. code-block:: c
..   
..           __find_signal_type()
..           __alloc_signal_desc(xseg, signal_type_id)
..           xobj_get()
.. 
.. - .. code-block:: c
.. 
..     xseg_init_signal_desc(struct xseg *xseg, struct signal_desc *sd)
.. 
..   * **Description**: Initialization of a allocated signal descriptor
..   * **Calls**:
..       .. code-block:: c
..   
..           signal_type->init_signal_desc();
.. 
.. 
.. - .. code-block:: c
.. 
..     xseg_quit_signal_desc(struct xseg *xseg, void *sd)
.. 
..   * **Description**: Cleanup of a previously initialized signal descriptor.
..   * **Calls**:
..       .. code-block:: c
..   
..           signal_type->quit_signal_desc()

- .. code-block:: c

    xseg_get_signal_desc(struct xseg *xseg, char *type)

  * **Description**: Allocate and initialize a new signal descriptor of this type.
  * **Calls**:
      .. code-block:: c
 
          __find_signal_type()
          __alloc_signal_desc(xseg, signal_type_id)
          xobj_get()
          signal_type->init_signal_desc()

- .. code-block:: c

    xseg_put_signal_desc(struct xseg *xseg, struct signal_desc *sd)

  * **Description**: Put a signal descriptor. Cleanup and free a previously
    allocated signal descriptor, if the caller is the last user
  * **Calls**:
      .. code-block:: c

          if xobj_put() == 0
                  signal_type->quit_signal_desc()
                  __free_signal_desc(xseg, sd)

  * **Notes**: Putting a signal descriptor means that it cannot be used again.
    It does not mean that the peer will not receive any more signals of this
    signal type. Also, since the signal descriptors are reference counted (see
    other design doc), the cleanup and the deallocation are not guaranteed when
    this calls completes.



Modified calls:

- .. code-block:: c

    xseg_prepare_wait(struct xseg *xseg, void *sd);

  * **Description**: Prepare a signal descriptor for waiting on it.
  * **Calls**:
      .. code-block:: c
  
          signal_desc_type->prepare_wait()

- .. code-block:: c

    xseg_cancel_wait(struct xseg *xseg, void *sd)

  * **Description**: Cancels waiting on a signal descrptor.
  * **Calls**:
      .. code-block:: c
  
          signal_desc_type->cancel_wait()

- .. code-block:: c

    xseg_wait_signal(struct xseg *xseg, void *sd, uint32_t usec_timeout)

  * **Description**: Waits on a signal descriptor for a maximum usec_timeout usecs.
  * **Calls**:
      .. code-block:: c
  
          signal_desc_type->wait_signal()


- .. code-block:: c

    xseg_local_signal_init(struct xseg *xseg, char *signal_type);

  * **Description**: Initializations needed to be able to accept signals from this signal descriptor type.
  * **Calls**:
      .. code-block:: c

          signal_desc_type->local_signal_init(struct xseg *xseg);

- .. code-block:: c

    xseg_local_signal_quit(struct xseg *xseg, char *signal_type);

  * **Description**: Cleanup after initializations.
  * **Calls**:
      .. code-block:: c

          signal_desc_type->local_signal_quit(struct xseg *xseg);

- .. code-block:: c

    xseg_bind_port(struct xseg *xseg, xport pornto, void *sd);

  * **Description**: Bind to the specified portno, and attach the given signal_descriptor to it.
  * **Calls**:



Typical usage scenario
======================

1. Initialize signal receiving for a signal type.
2. Get a new signal descriptor for the signal type (sd).
3. Prepare waiting on the signal descriptor.
4. Accept new request.
5. Cancel waiting on the signal descriptor.
6. Process request.
7. Prepare waiting on the signal descriptor.
8. Wait on the signal descriptor.

...

9. Put the signal descriptor.
10. Quit the signal type.
