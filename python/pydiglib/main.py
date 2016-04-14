
import os, sys, socket, time
import win_inet_pton

from .common import *
from .options import options, parse_args
from .tsig import Tsig
from .util import *
from .dnsparam import *
from .dnsmsg import *
from .query import *
from .walk import zonewalk


def main(args):
    """ main function"""
    sys.excepthook = excepthook
    tsig = Tsig()                          # instantiate Tsig object

    if len(args) == 1:
        raise UsageError('')

    try:
        qname, qtype, qclass = parse_args(args[1:])
        qtype_val = qt.get_val(qtype)
        qclass_val = qc.get_val(qclass)
    except (ValueError, IndexError, KeyError) as e:
        raise UsageError("Incorrect program usage: %s" % e)

    if options["do_0x20"]:
        qname = randomize_case(qname)
    query = DNSquery(qname, qtype_val, qclass_val)
        
    try:
        server_addr, port, family, socktype = \
                     get_socketparams(options["server"], options["port"],
                                      options["af"], socket.SOCK_DGRAM)
    except socket.gaierror as e:
        raise ErrorMessage("bad server: %s (%s)" % (options["server"], e))
        
    random_init()

    if options["do_zonewalk"]:
        zonewalk(server_addr, port, family, qname, options)
        sys.exit(0)

    txid = mk_id()
    tc = 0
    requestpkt = mk_request(query, txid, options)
    size_query = len(requestpkt)

    if qtype == "AXFR":
        responses = do_axfr(query, requestpkt, server_addr, port, family)
        sys.exit(0)

    # the rest is for non AXFR queries ..

    response = None

    if options["tls"]:
        t1 = time.time()
        responsepkt = send_request_tls(requestpkt, server_addr, 
                                       options["tls_port"], family,
                                       hostname=options["tls_hostname"])
        t2 = time.time()
        if responsepkt:
            size_response = len(responsepkt)
            print(";; TLS response from %s, %d bytes, in %.3f sec" %
                  ( (server_addr, options["tls_port"]), size_response, (t2-t1)))
            response = DNSresponse(family, query, requestpkt, responsepkt, txid)
        else:
            print(";; TLS response failure from %s, %d" %
                  (server_addr, options["tls_port"]))
            if not options["tls_fallback"]:
                return 2

    elif not options["use_tcp"]:
        t1 = time.time()
        (responsepkt, responder_addr) = \
                      send_request_udp(requestpkt, server_addr, port, family,
                                       ITIMEOUT, RETRIES)
        t2 = time.time()
        size_response = len(responsepkt)
        if not responsepkt:
            print("No response from server")
            return
        response = DNSresponse(family, query, requestpkt, responsepkt, txid)
        if not response.tc:
            print(";; UDP response from %s, %d bytes, in %.3f sec" %
                  (responder_addr, size_response, (t2-t1)))
            if server_addr != "0.0.0.0" and responder_addr[0] != server_addr:
                print("WARNING: Response from unexpected address %s" %
                      responder_addr[0])

    if options["use_tcp"] or (response and response.tc) \
       or (options["tls"] and options["tls_fallback"] and not response):
        if (response and response.tc):
            print(";; UDP Response was truncated. Retrying using TCP ...")
        if (options["tls"] and options["tls_fallback"] and not response):
            print(";; TLS fallback to TCP ...")
        t1 = time.time()
        responsepkt = send_request_tcp2(requestpkt, server_addr, port, family)
        t2 = time.time()
        size_response = len(responsepkt)
        print(";; TCP response from %s, %d bytes, in %.3f sec" %
              ( (server_addr, port), size_response, (t2-t1)))
        response = DNSresponse(family, query, requestpkt, responsepkt, txid)

    response.print_preamble(options)
    response.decode_sections()
    dprint(";; Compression pointer dereferences=%d" % count_compression)

    return response.rcode
