# Copyright 2013 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.

#!/usr/bin/env python2.7
import sys, os, signal, time
from xseg import xseg_api as xseg

mportno = 0
dportno = 2
xconf = xseg.xseg_config()
cb_null_ptrtype = xseg.CFUNCTYPE(None, xseg.POINTER(xseg.xseg), xseg.uint32_t)
nr_requests = 10000
concurrent_reqs = 10

def mapper_loop(ctx):
    nr_submitted = 0
    nr_received = 0
    nr_flying = 0
    xreq = None
    recv = None

    t = time.time()
    while 1:
        xseg.xseg_prepare_wait(ctx, mportno)
        if nr_submitted < nr_requests and nr_flying < concurrent_reqs:
            xreqp = xseg.xseg_get_request(ctx, mportno)
            try:
                xreq = xreqp.contents
                xseg.xseg_cancel_wait(ctx, mportno)
                if xseg.xseg_prep_request(xreq, 2, 4096) < 0:
                    xseg.xseg_put_request(ctx, xreq.portno, xreq)
                    return -1
                nr_flying += 1
                nr_submitted += 1
                xreq.offset = 2
                xreq.size = 4096
                xreq.op = 1

                srl = xseg.xseg_submit(ctx, dportno, xreq)
                xseg.xseg_signal(ctx, dportno)
            except Exception as e:
                pass

        xreqp = xseg.xseg_receive(ctx, mportno)
        try:
            recv = xreqp.contents
            xseg.xseg_cancel_wait(ctx, mportno)
            nr_flying -= 1
            nr_received += 1
            xseg.xseg_put_request(ctx, recv.portno, recv)
        except Exception as e:
            pass

        if recv == None and xreq == None:
            xseg.xseg_wait_signal(ctx, 1000)

        if nr_received >= nr_requests:
            break

    print ("Elapsed: %lf\n", time.time() - t)
    print "submitted %ld, received %ld\n" % (nr_submitted, nr_received)

def mapper_init():
    xseg.xseg_initialize()
    xseg.xseg_parse_spec("segdev:xsegbd:", xconf)
    ctx=xseg.xseg_join(xconf.type, xconf.name, "posix", xseg.cast(0, cb_null_ptrtype))
    xseg.xseg_bind_port(ctx, mportno)

    return ctx

if __name__ == '__main__':
    nr_requests = int(sys.argv[1])
    concurrent_reqs = int(sys.argv[2])
    ctx = mapper_init()
    mapper_loop(ctx)
