
import socket, struct, time, string, base64, math

from .options import options
from .common import *
from .dnsparam import *
from .util import *


class DNSquery:
    """DNS Query class"""

    def __init__(self, qname, qtype, qclass, minimize=False):
        self.qname = qname
        self.orig_qname = self.qname
        self.qtype = qtype
        self.qclass = qclass
        self.minimize = minimize

    def __repr__(self):
        return "<DNSquery: %s,%s,%s>" % (self.qname, self.qtype, self.qclass)


class DNSresponse:
    """DNS Response class"""

    id = None
    qr = None
    opcode = None
    aa = None
    tc = None
    rd = None
    ra = None
    z = None
    rcode = None
    ercode = None
    cnt_compression = 0
    # sections: list of tuples of (text name, rrcount)
    sections = [ "QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL" ]
    print_section_bitmap = 0b1111           # default: print all sections
    qdcount = None
    ancount = None
    nscount = None
    arcount = None

    def __init__(self, family, query, requestpkt, pkt, 
                 sent_id, used_tcp=False,  checkid=True):
        self.family = family
        self.query = query
        self.requestpkt = requestpkt
        self.pkt = pkt
        self.used_tcp = used_tcp
        self.decode_header(pkt, sent_id, checkid)
        self.log_file = LOGFILE

    def decode_header(self, pkt, sent_id, checkid=True):
        """Decode a DNS protocol header"""
        self.id, answerflags, self.qdcount, self.ancount, \
            self.nscount, self.arcount = struct.unpack('!HHHHHH', pkt[:12])
        if checkid and (self.id != sent_id):
            # Should continue listening for a valid response here (ideally)
            raise ErrorMessage("got response with id: %ld (expecting %ld)" % 
                               (self.id, sent_id))
        self.qr = answerflags >> 15
        self.opcode = (answerflags >> 11) & 0xf
        self.aa = (answerflags >> 10) & 0x1
        self.tc = (answerflags >> 9) & 0x1
        self.rd = (answerflags >> 8) & 0x1
        self.ra = (answerflags >> 7) & 0x1
        self.z  = (answerflags >> 6) & 0x1
        self.ad = (answerflags >> 5) & 0x1
        self.cd = (answerflags >> 4) & 0x1
        self.rcode = (answerflags) & 0xf

    def print_ampratio(self):
        """Print packet amplification ratios"""
        size_response = len(self.pkt)
        size_query = len(self.requestpkt)
        if self.family == socket.AF_INET:
            overhead = 42                # Ethernet + IPv4 + UDP header
        elif self.family == socket.AF_INET6:
            overhead = 62                # Ethernet + IPv6 + UDP header
        else:
            overhead = 0                 # shouldn't happen

        # amp1: ratio of only the DNS response payload & query payload
        # amp2: estimated ratio of the full packets assuming Ethernet link
        amp1 = (size_response * 1.0/size_query)
        w_qsize = size_query + overhead
        w_rsize = size_response + \
                  overhead * math.ceil(size_response/(1500.0-overhead))
        amp2 = w_rsize/w_qsize

        print(";; Size query=%d, response=%d, amp1=%.2f amp2=%.2f" %
              (size_query, size_response, amp1, amp2))
    
    def print_preamble(self, options):
        """Print preamble of a DNS response message"""
        if options["do_0x20"]:
            print(";; 0x20-hack qname: %s" % self.query.qname)
        print(";; rcode=%d(%s), id=%d" %
              (self.rcode, rc.get_name(self.rcode), self.id))
        print(";; qr=%d opcode=%d aa=%d tc=%d rd=%d ra=%d z=%d ad=%d cd=%d" %
              (self.qr,
               self.opcode,
               self.aa,
               self.tc,
               self.rd,
               self.ra,
               self.z,
               self.ad,
               self.cd))
        print(";; question=%d, answer=%d, authority=%d, additional=%d" %
              (self.qdcount, self.ancount, self.nscount, self.arcount))
        self.print_ampratio()

    def print_rr(self, rrname, ttl, rrtype, rrclass, rdata, l=0):
        print("%s\t%d\t%s\t%s\t%s" %
              (pdomainname(rrname), ttl,
               qc.get_name(rrclass), qt.get_name(rrtype), rdata))
        if l == 1:
            open(self.log_file, "a").write("%s\t%d\t%s\t%s\t%s\n" %
                  (pdomainname(rrname), ttl,
                   qc.get_name(rrclass), qt.get_name(rrtype), rdata))
        return

    def print_rrs(offset, section_num, section_name, rrcount):
        for i in range(rrcount):
            if section_num == 0:            # Question
                rrname, rrtype, rrclass, offset = \
                        decode_question(self.pkt, offset)
                answer_qname = pdomainname(rrname)
                if self.query.qtype != 252:
                    print("%s\t%s\t%s" % (answer_qname,
                                          qc.get_name(rrclass),
                                          qt.get_name(rrtype)))
            else:
                rrname, rrtype, rrclass, ttl, rdata, offset = \
                    decode_rr(self.pkt, offset, options["hexrdata"])
                print("%s\t%d\t%s\t%s\t%s" %
                      (pdomainname(rrname), ttl,
                       qc.get_name(rrclass), qt.get_name(rrtype), rdata))

        return offset

    def question_matched(self, qname, qtype, qclass):
        if self.rcode in [0, 3]:
            if (not domain_name_match(qname, self.query.qname, 
                                      options["do_0x20"])) \
                or (qtype != self.query.qtype) \
                or (qclass != self.query.qclass):
                print("*** WARNING: Answer didn't match question!\n")
        return

    def decode_sections(self, is_axfr=False):
        offset = 12                     # skip over DNS header
        answer_qname = None

        for (secname, rrcount) in zip(self.sections, 
                     [self.qdcount, self.ancount, self.nscount, self.arcount]):
            if rrcount and (not is_axfr):
                print("\n;; %s SECTION:" % secname)
            if secname == "QUESTION":
                for i in range(rrcount):
                    rrname, rrtype, rrclass, offset = \
                            decode_question(self.pkt, offset)
                    answer_qname = pdomainname(rrname)
                    if (is_axfr):
                        continue
                    print("%s\t%s\t%s" % (answer_qname,
                                          qc.get_name(rrclass), 
                                          qt.get_name(rrtype)))
                    self.question_matched(answer_qname, rrtype, rrclass)
            else:
                l = 0
                for i in range(rrcount):
                    rrname, rrtype, rrclass, ttl, rdata, offset = \
                            decode_rr(self.pkt, offset, options["hexrdata"])
                    if (is_axfr and (secname != "ANSWER")):
                        continue
                    elif rrtype == 41:
                        print_optrr(rrclass, ttl, rdata)
                    else:
                        l += 1
                        self.print_rr(rrname, ttl, rrtype, rrclass, rdata, l)

    def __repr__(self):
        return "<DNSresponse>"


def print_optrr(rrclass, ttl, rdata):
    """decode and print EDNS0 OPT pseudo RR; see RFC 2671"""
    packed_ttl = struct.pack('!I', ttl)
    ercode, version, z = struct.unpack('!BBH', packed_ttl)
    flags = []
    if z & 0x8000: flags.append("do")                  # DNSSEC OK bit
    print(";; OPT: edns_version=%d, udp_payload=%d, flags=%s, ercode=%d(%s)" %
          (version, rrclass, ' '.join(flags), ercode, rc.get_name(ercode)))
    blob = rdata
    while blob:
        ocode, olen = struct.unpack('!HH', blob[:4])
        odesc = edns_opt.get(ocode, "Unknown")
        print(";; OPT code=%d (%s), length=%d" % (ocode, odesc, olen))
        print(";; DATA: %s" % hexdump(blob[4:4+olen]))
        blob = blob[4+olen:]


def decode_question(pkt, offset):
    """decode question section of a DNS message"""
    domainname, offset = get_domainname(pkt, offset)
    rrtype, rrclass = struct.unpack("!HH", pkt[offset:offset+4])
    offset += 4
    return (domainname, rrtype, rrclass, offset)


def generic_rdata_encoding(rdata, rdlen):
    """return generic encoding of rdata for unknown types; see RFC 3597"""
    return "\# %d %s" % (rdlen, hexdump(rdata))

    
def decode_txt_rdata(rdata, rdlen):
    """decode TXT RR rdata into a string of quoted text strings,
    escaping any embedded double quotes"""
    txtstrings = []
    position = 0
    while position < rdlen:
        slen, = struct.unpack('B', rdata[position:position+1])
        s = rdata[position+1:position+1+slen]
        s = '"{}"'.format(s.replace(b'"', b'\\"').decode())
        txtstrings.append(s)
        position += 1 + slen
    return ' '.join(txtstrings)


def decode_soa_rdata(pkt, offset, rdlen):
    """decode SOA rdata: mname, rname, serial, refresh, retry, expire, min"""
    d, offset = get_domainname(pkt, offset)
    mname = pdomainname(d)
    d, offset = get_domainname(pkt, offset)
    rname = pdomainname(d)
    serial, refresh, retry, expire, min = \
            struct.unpack("!IiiiI", pkt[offset:offset+20])
    return "%s %s %d %d %d %d %d" % \
           (mname, rname, serial, refresh, retry, expire, min)
    

def decode_srv_rdata(pkt, offset):
    """decode SRV rdata: priority (2), weight (2), port, target; RFC 2782"""
    priority, weight, port = struct.unpack("!HHH", pkt[offset:offset+6])
    d, offset = get_domainname(pkt, offset+6)
    target = pdomainname(d)
    return "%d %d %d %s" % (priority, weight, port, target)


def decode_sshfp_rdata(pkt, offset, rdlen):
    """decode SSHFP rdata: alg, fp_type, fingerprint; see RFC 4255"""
    alg, fptype = struct.unpack('BB', pkt[offset:offset+2])
    fingerprint = hexdump(pkt[offset+2:offset+rdlen])
    if options['DEBUG']:
        rdata = "%d(%s) %d(%s) %s" % \
                (alg, sshfp_alg.get(alg, "unknown"),
                 fptype, sshfp_fptype.get(fptype, "unknown"), fingerprint)
    else:
        rdata = "%d %d %s" % (alg, fptype, fingerprint)
    return rdata


def decode_naptr_rdata(pkt, offset, rdlen):
    """decode NAPTR: order, pref, flags, svc, regexp, replacement; RFC 2915"""
    param = {}
    order, pref = struct.unpack('!HH', pkt[offset:offset+4])
    position = offset+4
    for name in ["flags", "svc", "regexp"]:
        slen, = struct.unpack('B', pkt[position])
        s = pkt[position+1:position+1+slen]
        param[name] = '"%s"' % s.replace('\\', '\\\\')
        position += (1+slen)
    d, junk = get_domainname(pkt, position)
    replacement = pdomainname(d)
    return "%d %d %s %s %s %s" % (order, pref, param["flags"], param["svc"],
                                  param["regexp"], replacement)


def decode_ipseckey_rdata(pkt, offset, rdlen):
    """decode IPSECKEY rdata; see RFC 4025"""
    prec, gwtype, alg = struct.unpack('BBB', pkt[offset:offset+3])
    position = offset+3
    if gwtype == 0:                            # no gateway present
        gw = "."
    elif gwtype == 1:                          # 4-byte IPv4 gw
        gw = socket.inet_ntop(socket.AF_INET, pkt[position:position+4])
        position += 4
    elif gwtype == 2:                          # 16-byte IPv6 gw
        gw = socket.inet_ntop(socket.AF_INET6, pkt[position:position+16])
        position += 16
    elif gwtype == 3:                          # domainname
        d, position = get_domainname(pkt, position)
        gw = pdomainname(d)
    if alg == 0:                               # no public key
        pubkey = ""
    else:
        pubkeylen = rdlen - (position - offset)
        pubkey = base64.standard_b64encode(pkt[position:position+pubkeylen]).decode('ascii')
    return "{} {} {} {} {}".format(prec, gwtype, alg, gw, pubkey)


def decode_tlsa_rdata(rdata):
    """decode TLSA rdata: usage(1) selector(1) mtype(1) cadata;
       see RFC 6698"""
    usage, selector, mtype = struct.unpack("BBB", rdata[0:3])
    cadata = hexdump(rdata[3:])
    return "%d %d %d %s" % (usage, selector, mtype, cadata)


def decode_openpgpkey_rdata(rdata):
    """decode OPENPGPKEY rdata: base64-string"""
    return "{}".format(base64.standard_b64encode(rdata).decode('ascii'))


def decode_dnskey_rdata(pkt, offset, rdlen):
    """decode DNSKEY rdata: flags, proto, alg, pubkey; see RFC 4034"""
    flags, proto, alg = struct.unpack('!HBB', pkt[offset:offset+4])
    pubkey = pkt[offset+4:offset+rdlen]
    if options['DEBUG']:
        zonekey = (flags >> 8) & 0x1;         # bit 7
        sepkey = flags & 0x1;                 # bit 15
        keytype = None
        if proto == 3:
            if zonekey and sepkey:
                keytype="KSK"
            elif zonekey:
                keytype="ZSK"
        if keytype: comments = "%s, " % keytype
        comments += "proto=%s, alg=%s" % \
                   (dnssec_proto[proto], dnssec_alg[alg])
        if alg in [5, 7, 8, 10]:              # RSA algorithms
            if pubkey[0] == '\x00':   # length field is 3 octets
                elen, = struct.unpack('!H', pubkey[1:3])
                exponent = packed2int(pubkey[1:1+elen])
                modulus_len = len(pubkey[1+elen:]) * 8
            else:                     # length field is 1 octet
                elen, = struct.unpack('B', pubkey[0:1])
                exponent = packed2int(pubkey[1:1+elen])
                modulus_len = len(pubkey[1+elen:]) * 8
            comments = comments + ", e=%d modulus_size=%d" % \
                       (exponent, modulus_len)
        elif alg in [3, 6]:                   # DSA algorithms
            # not decoded yet (not commonly seen?) - see RFC 2536
            pass
        elif alg in [13, 14]:                 # ECDSA algorithms
            # The pubkey is the concatenation of 2 curve points, so
            # for ECDSAP384, the size is 768 bits.
            comments = comments + ", size=%d" % (len(pubkey) * 8)
        result = "{} {} {} {} ; {}".format(
            flags, proto, alg,
            base64.standard_b64encode(pubkey).decode('ascii'), comments)
    else:
        result = "{} {} {} {}".format(
            flags, proto, alg,
            base64.standard_b64encode(pubkey).decode('ascii'))
    return result


def decode_ds_rdata(pkt, offset, rdlen):
    """decode DS rdata: keytag, alg, digesttype, digest; see RFC 4034"""
    keytag, alg, digesttype = struct.unpack('!HBB', pkt[offset:offset+4])
    digest = hexdump(pkt[offset+4:offset+rdlen])
    if options['DEBUG']:
        result = "%d %d(%s) %d(%s) %s" % \
                 (keytag, alg, dnssec_alg[alg], digesttype,
                  dnssec_digest[digesttype], digest)
    else:
        result = "%d %d %d %s" % (keytag, alg, digesttype, digest)
    return result


def decode_rrsig_rdata(pkt, offset, rdlen):
    """decode RRSIG rdata; see RFC 4034"""
    end_rdata = offset + rdlen
    type_covered, alg, labels, orig_ttl, sig_exp, sig_inc, keytag = \
          struct.unpack('!HBBIIIH', pkt[offset:offset+18])
    sig_exp = time.strftime("%Y%m%d%H%M%S", time.gmtime(sig_exp))
    sig_inc = time.strftime("%Y%m%d%H%M%S", time.gmtime(sig_inc))
    d, offset = get_domainname(pkt, offset+18)
    signer_name = pdomainname(d)
    signature = pkt[offset:end_rdata]
    retval = "{} {} {} {} {} {} {} {} {}".format(
        qt.get_name(type_covered), alg, labels, orig_ttl,
        sig_exp, sig_inc, keytag, signer_name,
        base64.standard_b64encode(signature).decode('ascii'))
    if options['DEBUG']:
        retval += " ; sigsize=%d" % (len(signature) * 8)
    return retval


def decode_typebitmap(windownum, bitmap):
    """decode NSEC style type bitmap into list of RR types; see RFC 4034"""
    rrtypelist = []
    for (charpos, c) in enumerate(bitmap):
        if PYVERSION == 2:
            value, = struct.unpack('B', c)
        else:
            value = c
        for i in range(8):
            isset = (value << i) & 0x80
            if isset:
                bitpos = (256 * windownum) + (8 * charpos) + i
                rrtypelist.append(qt.get_name(bitpos))
    return rrtypelist


def decode_nsec_rdata(pkt, offset, rdlen):
    """decode NSEC rdata: nextrr, type-bitmap; see RFC 4034"""
    end_rdata = offset + rdlen
    d, offset = get_domainname(pkt, offset)
    nextrr = pdomainname(d)
    type_bitmap = pkt[offset:end_rdata]
    p = type_bitmap
    rrtypelist = []
    while p:
        windownum, winlen = struct.unpack('BB', p[0:2])
        bitmap = p[2:2+winlen]
        rrtypelist += decode_typebitmap(windownum, bitmap)
        p = p[2+winlen:]
    return "%s %s" % (nextrr, ' '.join(rrtypelist))


def decode_nsec3param_rdata(pkt, offset, rdlen):
    """decode NSEC3PARAM rdata: hash, flags, iterations, salt len, salt;
    see RFC 5155 Section 4.2"""
    
    hashalg, flags, iterations, saltlen = struct.unpack('!BBHB',
                                                        pkt[offset:offset+5])
    salt = hexdump(pkt[offset+5:offset+5+saltlen])
    result = "%d %d %d %s" % (hashalg, flags, iterations, salt)
    return result


def decode_nsec3_rdata(pkt, offset, rdlen):
    """decode NSEC3 rdata; see RFC 5155 Section 3"""

    # Translation table for normal base32 to base32 with extended hex
    # alphabet used by NSEC3 (see RFC 4648, Section 7). This alphabet
    # has the property that encoded data maintains its sort order when
    # compared bitwise.
    if PYVERSION == 2:
        b32_to_ext_hex = string.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                          b'0123456789ABCDEFGHIJKLMNOPQRSTUV')
    else:
        b32_to_ext_hex = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                         b'0123456789ABCDEFGHIJKLMNOPQRSTUV')

    end_rdata = offset + rdlen
    hashalg, flags, iterations, saltlen = struct.unpack('!BBHB',
                                                        pkt[offset:offset+5])
    salt = hexdump(pkt[offset+5:offset+5+saltlen])
    offset += (5 + saltlen)
    hashlen, = struct.unpack('!B', pkt[offset:offset+1])
    offset += 1
    # hashed next owner name, base32 encoded with extended hex alphabet
    hashed_next_owner = base64.b32encode(pkt[offset:offset+hashlen])
    hashed_next_owner = hashed_next_owner.translate(b32_to_ext_hex).decode()
    offset += hashlen
    type_bitmap = pkt[offset:end_rdata]
    p = type_bitmap
    rrtypelist = []
    while p:
        windownum, winlen = struct.unpack('BB', p[0:2])
        bitmap = p[2:2+winlen]
        rrtypelist += decode_typebitmap(windownum, bitmap)
        p = p[2+winlen:]
    rrtypes = ' '.join(rrtypelist)
    result = "%d %d %d %s %s %s" % \
             (hashalg, flags, iterations, salt, hashed_next_owner, rrtypes)
    return result


def decode_caa_rdata(rdata):
    """decode CAAA rdata: TLSA rdata: flags(1), tag-length, tag, value;
       see RFC 6844"""
    flags, taglen = struct.unpack("BB", rdata[0:2])
    tag = rdata[2:2+taglen]
    value = rdata[2+taglen:]
    return "{} {} \"{}\"".format(flags, tag.decode(), value.decode())


def decode_rr(pkt, offset, hexrdata):
    """ Decode a resource record, given DNS packet and offset"""

    orig_offset = offset
    domainname, offset = get_domainname(pkt, offset)
    rrtype, rrclass, ttl, rdlen = \
            struct.unpack("!HHIH", pkt[offset:offset+10])
    offset += 10
    rdata = pkt[offset:offset+rdlen]
    if hexrdata:
        rdata = hexdump(rdata)
    elif rrtype == 1:                                        # A
        rdata = socket.inet_ntop(socket.AF_INET, rdata)
    elif rrtype in [2, 5, 12, 39]:                           # NS, CNAME, PTR
        rdata, junk = get_domainname(pkt, offset)            # DNAME
        rdata = pdomainname(rdata)
    elif rrtype == 6:                                        # SOA
        rdata = decode_soa_rdata(pkt, offset, rdlen)
    elif rrtype == 15:                                       # MX
        mx_pref, = struct.unpack('!H', pkt[offset:offset+2])
        rdata, junk = get_domainname(pkt, offset+2)
        rdata = "%d %s" % (mx_pref, pdomainname(rdata))
    elif rrtype in [16, 99]:                                 # TXT, SPF
        rdata = decode_txt_rdata(rdata, rdlen)
    elif rrtype == 28:                                       # AAAA
        rdata = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rrtype == 33:                                       # SRV
        rdata = decode_srv_rdata(pkt, offset)
    elif rrtype == 41:                                       # OPT
        pass
    elif rrtype in [43, 59, 32769]:                          # [C]DS, DLV
        rdata = decode_ds_rdata(pkt, offset, rdlen)
    elif rrtype == 44:                                       # SSHFP
        rdata = decode_sshfp_rdata(pkt, offset, rdlen)
    elif rrtype == 45:                                       # IPSECKEY
        rdata = decode_ipseckey_rdata(pkt, offset, rdlen)
    elif rrtype in [46, 24]:                                 # RRSIG, SIG
        rdata = decode_rrsig_rdata(pkt, offset, rdlen)
    elif rrtype == 47:                                       # NSEC
        rdata = decode_nsec_rdata(pkt, offset, rdlen)
    elif rrtype in [48, 25, 60]:                             # [C]DNSKEY, KEY
        rdata = decode_dnskey_rdata(pkt, offset, rdlen)
    elif rrtype == 50:                                       # NSEC3
        rdata = decode_nsec3_rdata(pkt, offset, rdlen)
    elif rrtype == 51:                                       # NSEC3PARAM
        rdata = decode_nsec3param_rdata(pkt, offset, rdlen)
    elif rrtype in [52, 53]:                                 # TLSA, SMIMEA
        rdata = decode_tlsa_rdata(rdata)
    elif rrtype == 61:                                       # OPENPGPKEY
        rdata = decode_openpgpkey_rdata(rdata)
    elif rrtype == 257:                                      # CAA
        rdata = decode_caa_rdata(rdata)
    elif rrtype == 250:                                      # TSIG
        tsig_name = pdomainname(domainname)
        tsig = options["tsig"]
        rdata = tsig.decode_tsig_rdata(pkt, offset, rdlen,
                                       tsig_name, orig_offset)
    else:                                                    # use RFC 3597
        rdata = generic_rdata_encoding(rdata, rdlen)
    offset += rdlen
    return (domainname, rrtype, rrclass, ttl, rdata, offset)


def decode_nsec_rr(pkt, offset):
    """ Decode an NSEC resource record; used by zonewalk() routine"""
    
    domainname, offset = get_domainname(pkt, offset)
    rrtype, rrclass, ttl, rdlen = \
            struct.unpack("!HHIH", pkt[offset:offset+10])
    if rrtype != 47:
        raise ErrorMessage("encountered RR type %s, expecting NSEC" % rrtype)
    
    offset += 10
    rdata = pkt[offset:offset+rdlen]

    end_rdata = offset + rdlen
    d, offset = get_domainname(pkt, offset)
    nextrr = pdomainname(d)
    type_bitmap = pkt[offset:end_rdata]
    p = type_bitmap
    rrtypelist = []
    while p:
        windownum, winlen = struct.unpack('BB', p[0:2])
        bitmap = p[2:2+winlen]
        rrtypelist += decode_typebitmap(windownum, bitmap)
        p = p[2+winlen:]
    offset += rdlen
    return (domainname, rrtype, rrclass, ttl, nextrr, rrtypelist, offset)

