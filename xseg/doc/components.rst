Archipelagos Components
=======================

This document intends to document the various components of Archipelagos, the
storage infrastructure behind the Cydlades IaaS cloud software.

xq
**
Fixed-size (power of 2, up to 2^32), double-ended, circular queue of xserial
(unsigned int) elements, which guarantees safe concurrent access (with built-in
locking).

xq is used to safely index and/or split a shared buffer.

xseg
****
The backbone of Archipelagos.

The xseg API (and its implementation) provides access to shared memory segments,
residing either in userspace (posix segments) or in kernel space (segdev
segments), to both user- and kernel-space 'processes/threads' (known as peers,
in the xseg API).

The shared memory segments (referred to as plainly segments in the xseg API) are
formed by a pool of requests (xseg requests), and multiple endpoints (xseg
ports), on which the xseg peers bind. 

The xseg API defines certain operations that can be performed on a segment
(malloc / allocate / map / etc), and ceration operations that can performed by
peers (signal / wait_for_signal / prepare_wait / cancel_wait etc).
