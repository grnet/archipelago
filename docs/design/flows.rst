Ο ορισμός για τα flows είναι πιο μακρυά από εκείνον των network traffic flows
[1] :

"Traffic flow, packet flow or network flow is a sequence of packets from a
source computer to a destination, which may be another host, a multicast group,
or a broadcast domain".

αλλά είναι αρκετά κοντά στον "ορισμό" των flows από το openflow [2]:

"flows are broadly defined, and are limited only by the capabilities of the
particular implementation of the Flow Table. For example, a flow could be a TCP
connection, or all packets from a particular MAC address or IP address, or all
packets with the same VLAN tag, or all packets from the same switch port. For
experiments involving non-IPv4 packets, a flow could be defined as all packets
matching a specific (but non-standard) header".

To IO flow ακολουθεί ένα διαφορετικό approach, αρκετά περιοριστικό (και ποιο
IaaS-cloudικο) κατά τη γνώμη μου [3]:
"Flows are named using a four-tuple comprising human-friendly high-level
identifiers: { VMs, operations, files, shares }. "
.
[1] http://en.wikipedia.org/wiki/Traffic_flow_%28computer_networking%29
[2] OpenFlow: Enabling Innovation in Campus Networks
http://ccr.sigcomm.org/online/files/p69-v38n2n-mckeown.pdf
[3] IOFlow: A Software-Defined Storage Architecture
http://research.microsoft.com/pubs/198941/ioflow-sosp13.pdf

-----------------------------------

Archipelago is consisted of peers. North bound endpoints create requests that
are passed between the peers in a specific way in order to meet the south bound
endpoints, essentially forming flows following a path. This path is not
necessarily the same for all requests, but can be altered dynamically by
applying policies on the requests.

What is a flow and why we need them
-----------------------------------

In general we can define a flow as a set of requests that are related in some
way. In Archipelago we are interested in identifying the requests that form
flows based on relations we desire. Some of the relations can be extracted by
the inherent attributes of the requests (such as type of operation, length of
the request), while for others we need a way to tag the requests and later
identify the requests we are interested in.

Example of relations based on inherent attributes: All the READ requests, all
the 4K I/O requests, all the 4k READ requests, etc.

But we would like to categorize requests and identify flows in other ways too.
We identify four basic relations we would like to categorize requests:

# The resource on which the requests operate.
# The endpoint that originated from.
# The peer that created the request.
# The action that triggered a specific request (e.g. snapshot).

In order to identify the above we propose tagging each request on creation with
the following ids:

- **Resource id** : which is unique for every resource. This can be a
  monotonically increased 64-bit integer, assigned on resource creation.
- **Peer id** : which is unique for every peer type supported by Archipelago.
- **Flow id** : Extra tag to group requests in an arbitrary way.

Having each request tagged with the above ids, we can identify flows by more
complex relations such as: All the requests that belong on the same resource,
all the requests originated from the same endpoint, all the requests specially
tagged, all the requests the mapper created for a specific resource, all the I/O
requests of a specific resource, etc.

By having a way to identify these relationships, we can later get traces on the
parts we are interested, apply policies on certain flows (on certain requests
matching our criteria) and in general change dynamically the path of a request.
