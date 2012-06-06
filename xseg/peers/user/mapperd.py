#!/usr/bin/env python2.7
# The *Python* Mapper
import sys, argparse
# FIXME:
sys.path.append("/root/archip/xseg/sys/user/python")
from xseg import xseg_api as xseg
from xseg import xprotocol

cb_null_ptrtype = xseg.CFUNCTYPE(None, xseg.POINTER(xseg.xseg), xseg.uint32_t)

# FIXME: Error handling
def perr(errbuf):
    print >> sys.stderr, errbuf
    sys.exit(-1)

def mapper_loop(port, ctx):
    while True:
        if xseg.xseg_prepare_wait(ctx, port) != 0:
            perr("prepare_wait\n")

        xreqp = xseg.xseg_accept(ctx, port)
        try:
            xreq = xreqp.contents
        except ValueError:
            xseg.xseg_wait_signal(ctx, 1000)
            continue

        xseg.xseg_cancel_wait(ctx, port)

        if xseg.sizeof(xprotocol.xseg_reply_map) + xseg.sizeof(xprotocol.xseg_reply_map_scatterlist) > xreq.datalen:
            perr("datalen\n")
        if xreq.targetlen > xprotocol.XSEG_MAX_TARGETLEN:
            perr("targetlen\n")

        mreplyp = xseg.cast(xreq.data, xseg.POINTER(xprotocol.xseg_reply_map))
        try:
            mreply = mreplyp.contents
        except ValueError:
            perr("mreply\n")

        mreply.cnt = 1
        
        segsp = xseg.cast(mreply.segs, xseg.POINTER(xprotocol.xseg_reply_map_scatterlist))
        try:
            segs = segsp.contents
        except ValueError:
            perr("segs\n")

        segs.offset = xreq.offset
        segs.size = xreq.size
        tmp = xseg.string_at(xreq.target, xreq.targetlen)
        segs.target = tmp
        
        xreq.state |= xseg.XS_SERVED
        if xseg.xseg_respond(ctx, xreq.portno, xreq) == xseg.NoSerial:
            perr("xseg_respond\n")
        
        if xseg.xseg_signal(ctx, xreq.portno) != 0:
            perr("xseg_signal")

def mapper_init(port, spec):
    if xseg.xseg_initialize() < 0:
        perr("xseg_initialize")
    
    xconf = xseg.xseg_config()
    xseg.xseg_parse_spec(spec, xconf)

    ctx = xseg.xseg_join(xconf.type, xconf.name, "posix", xseg.cast(0, cb_null_ptrtype))
    try:
       ctx.contents
    except ValueError:
        xseg.xseg_finalize()
        perr("xseg_join")
    
    xseg.xseg_bind_port(ctx, port)

    return ctx

def parse_cmdline():
    parser = argparse.ArgumentParser(description='mapper')

    parser.add_argument('-p', '--port', type=int, nargs='?', help='mapper port')
    parser.add_argument('-b', '--bport', type=int, nargs='?', help='blocker port')
    parser.add_argument('-g', '--spec', type=str, nargs='?', help='xseg segment spec')

    return parser.parse_args()

def validate_cmdline(args):
    if args.port < 0:
        perr("invalid port specified")
    if args.spec == None:
        perr ("invalid spec")

if __name__ == '__main__':
    args = parse_cmdline()
    validate_cmdline(args)

    ctx = mapper_init(args.port, args.spec)
    
    mapper_loop(args.port, ctx)
