#!/usr/bin/env python2.7
# The *Python* Mapper
import sys, argparse
from xseg.xseg_api import xseg_api as xseg

cb_null_ptrtype = xseg.CFUNCTYPE(None, xseg.POINTER(xseg.xseg), xseg.uint32_t)

def perr(errbuf):
    print >> sys.stderr, errbuf
    sys.exit(-1)

def respond_loop(port, ctx):
    while True:
        xseg.xseg_prepare_wait(ctx, port)

        xreqp = xseg.xseg_accept(ctx, port)
        try:
            xreq = xreqp.contents
        except ValueError:
            xseg.xseg_wait_signal(ctx, 1000)
            continue

        xseg.xseg_cancel_wait(ctx, port)
        
        xreq.state |= xseg.XS_SERVED
        xseg.xseg_respond(ctx, xreq.portno, xreq)
        xseg.xseg_signal(ctx, xreq.portno)

def respond_init(port, spec):
    if xseg.xseg_initialize() < 0:
        perr("xseg_initialize")
    
    xconf = xseg.xseg_config()
    xseg.xseg_parse_spec(spec, xconf)

    ctx = xseg.xseg_join(xconf.type, xconf.name, "posix", xseg.cast(0, cb_null_ptrtype))
    if ctx == None:
        xseg.xseg_finalize()
        perr("xseg_join")
    
    xseg.xseg_bind_port(ctx, port)

    return ctx

def parse_cmdline():
    parser = argparse.ArgumentParser(description='mapper')

    parser.add_argument('-p', '--port', type=int, nargs='?', help='mapper port')
    parser.add_argument('-g', '--spec', type=str, nargs='?', help='xseg segment spec')

    return parser.parse_args()

def validate_cmdline(args):
    if args.port < 0:
        perr("invalid port specified")
    if args.spec == None:
        perr ("invalid spec")

if __name__ == '__main__':
    args = parse_cmdline()
    print args
    validate_cmdline(args)

    ctx = mapper_init(args.port, args.spec)
    
    mapper_loop(args.port, ctx)
