import os, sys, socket, base64

from .common import *
from .util import *
from .tsig import Tsig, read_tsig_params
from .windows import get_windows_default_dns


# Global dictionary of options: many options may be overridden or set in
# parse_args() by command line arguments.
options = dict(
    DEBUG=False,
    server=None, 
    port=DEFAULT_PORT, 
    srcip=None, 
    use_tcp=False,
    aa=0, 
    ad=0,
    cd=0, 
    rd=1, 
    use_edns0=False, 
    dnssec_ok=0,
    hexrdata=False, 
    do_zonewalk=False, 
    cookie=False,
    subnet=False,
    chainquery=False,
    do_0x20=False,
    ptr=False, 
    af=socket.AF_UNSPEC, 
    do_tsig=False,
    tsig_sigtime=None, 
    unsigned_messages="", 
    msgid=None,
    tls=False,
    tls_auth=False,
    tls_port=DEFAULT_PORT_TLS,
    tls_fallback=False,
    tls_hostname=None,
)


def set_tls_options(arg):
    """Set TLS options: authentication, fallback, hostname ..
       +tls={auth|noauth}
       +tls_port={N}
       +tls_fallback
       +tls_hostname={hostname}
    """
    if arg.startswith("+tls="):
        options["tls"] = True
        auth = arg[5:]
        if auth == "auth":
            options["tls_auth"] = True
        elif auth == "noauth":
            options["tls_auth"] = False
        else:
            raise ErrorMessage("Unsupported option: %s" % arg)
    elif arg.startswith("+tls_port="):
        options["tls_port"] = int(arg[10:])
    elif arg == "+tls_fallback":
        options["tls_fallback"] = True
    elif arg.startswith("+tls_hostname="):
        options["tls_hostname"] = arg[14:]
    else:
        raise ErrorMessage("Unsupported option: %s" % arg)

    return


def parse_args(arglist):
    """Parse command line arguments. Options must come first."""

    qtype = "A"
    qclass = "IN"
    
    i=0
    tsig = options["tsig"] = Tsig()
    
    for (i, arg) in enumerate(arglist):

        if arg.startswith('@'):
            options["server"] = arg[1:]

        elif arg == "-h":
            raise UsageError()

        elif arg.startswith("-p"):
            options["port"] = int(arg[2:])

        elif arg.startswith("-b"):
            options["srcip"] = arg[2:]

        elif arg == "+tcp":
            options["use_tcp"] = True

        elif arg.startswith("+tls"):
            set_tls_options(arg)

        elif arg == "+aaonly":
            options["aa"] = 1

        elif arg == "+adflag":
            options["ad"] = 1

        elif arg == "+cdflag":
            options["cd"] = 1

        elif arg == "+norecurse":
            options["rd"] = 0

        elif arg == "+edns0":
            options["use_edns0"] = True

        elif arg == "+dnssec":
            options["use_edns0"] = True
            options["dnssec_ok"] = 1; 

        elif arg == "+hex":
            options["hexrdata"] = True

        elif arg == "+walk":
            options["do_zonewalk"] = True

        elif arg == "+cookie":
            options["use_edns0"] = True
            options["cookie"] = True

        elif arg.startswith("+cookie="):
            options["use_edns0"] = True
            options["cookie"] = arg[8:]
            
        elif arg.startswith("+subnet="):
            options["use_edns0"] = True
            options["subnet"] = arg[8:]
            
        elif arg == "+chainquery":
            options["use_edns0"] = True
            options["chainquery"] = True

        elif arg.startswith("+chainquery="):
            options["use_edns0"] = True
            options["chainquery"] = arg[12:]

        elif arg == "+0x20":
            options["do_0x20"] = True

        elif arg == "-4":
            options["af"] = socket.AF_INET

        elif arg == "-6":
            options["af"] = socket.AF_INET6

        elif arg == "-x":
            options["ptr"] = True

        elif arg == "-d":
            options['DEBUG'] = True

        elif arg.startswith("-k"):
            tsig_file = arg[2:]
            name, key = read_tsig_params(tsig_file)
            tsig.setkey(name, key)
            options["do_tsig"] = True

        elif arg.startswith("-i"):
            options["msgid"] = int(arg[2:])

        elif arg.startswith("-y"):
            # -y overrides -k, if both are specified
            alg, name, key = arg[2:].split(":")
            key = base64.decodestring(key.encode())
            tsig.setkey(name, key, alg)
            options["do_tsig"] = True

        else:
            break

    if not options["server"]:         # use 1st server listed in resolv.conf
        if os.name != 'nt':
            for line in open(RESOLV_CONF):
                if line.startswith("nameserver"):
                    options["server"] = line.split()[1]
                    break
            else:
                raise ErrorMessage("Couldn't find a default server in %s" %
                                   RESOLV_CONF)
        else:
            options["server"] = get_windows_default_dns()
            if not options["server"]:
                raise ErrorMessage("Couldn't find a default server")

    qname = arglist[i]

    if not options["do_zonewalk"]:
        if arglist[i+1:]:           qtype = arglist[i+1].upper()
        if arglist[i+2:]:           qclass = arglist[i+2].upper()

    if options["ptr"]:
        qname = ip2ptr(qname); qtype = "PTR"; qclass = "IN"
    elif qtype in ['OPENPGPKEY', 'SMIMEA'] and qname.find('@') != -1:
        qname = uid2ownername(qname, qtype)
    else:
        if not qname.endswith("."): qname += "."

    return (qname, qtype, qclass)

