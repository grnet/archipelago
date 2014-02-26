Design docs
^^^^^^^^^^^

Introduction
============

Design docs are used to introduce a new feature to the existing code. They are
created during the design process and strictly before the actual
implementation. Their significance is two-fold:

* They allow members of the same team to understand what is the new feature
  that their team member wants to insert, as well as quickly evaluate its
  design. This means that there is zero communication overhead [#]_ between
  them while remaining in sync. Moreover, it makes it easier for another member
  to provide feedback.
* Adhering to the notion that you only understand something when you have to
  explain it to others, writing down the design of a new feature can have a
  beneficiary `rubber duck effect`_ on the author and thus prevent feature
  design shortcomings that were not foreseen.

Index tree
==========

We present on the list below the design docs so far:

.. toctree::
   :maxdepth: 2
   :numbered:
   :glob:

   design_entities
   design_cached_namespaces
   design_cached_flows
   design_xseg_signals
   design_xindex
   design_gc

.. _rubber duck effect: http://en.wikipedia.org/wiki/Rubber_duck_debugging
.. [#] The overhead of writing the design doc is a whole different story...
