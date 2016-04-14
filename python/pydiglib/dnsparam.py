import hashlib
import struct


class DNSparam:
    """Class to encapsulate some DNS parameter types (type, class etc)"""

    def __init__(self, prefix, name2val):
        self.name2val = name2val
        self.val2name = dict([(y,x) for (x,y) in name2val.items()])
        self.prefix = prefix
        self.prefix_offset = len(prefix)
        
    def get_name(self, val):
        """given code (value), return text name of dns parameter"""
        if self.prefix:
            return self.val2name.get(val, "%s%d" % (self.prefix, val))
        else:
            return self.val2name[val]

    def get_val(self, name):
        """given text name, return code (value) of a dns parameter"""
        if self.prefix and name.startswith(self.prefix):
            return int(name[self.prefix_offset:])
        else:
            return self.name2val[name]

# DNS Resource Record Types
DICT_RRTYPE = {
    "A": 1,
    "NS": 2,
    "MD": 3,
    "MF": 4,
    "CNAME": 5,
    "SOA": 6,
    "MB": 7,
    "MG": 8,
    "MR": 9,
    "NULL": 10,
    "WKS": 11,
    "PTR": 12,
    "HINFO": 13,
    "MINFO": 14,
    "MX": 15,
    "TXT": 16,
    "RP": 17,
    "AFSDB": 18,
    "X25": 19,
    "ISDN": 20,
    "RT": 21,
    "NSAP": 22,
    "NSAP-PTR": 23,
    "SIG": 24,
    "KEY": 25,
    "PX": 26,
    "GPOS": 27,
    "AAAA": 28,
    "LOC": 29,
    "NXT": 30,
    "EID": 31,
    "NIMLOC": 32,
    "SRV": 33,
    "ATMA": 34,
    "NAPTR": 35,
    "KX": 36,
    "CERT": 37,
    "A6": 38,
    "DNAME": 39,
    "SINK": 40,
    "OPT": 41,
    "APL": 42,
    "DS": 43,
    "SSHFP": 44,
    "IPSECKEY": 45,
    "RRSIG": 46,
    "NSEC": 47,
    "DNSKEY": 48,
    "DHCID": 49,
    "NSEC3": 50,
    "NSEC3PARAM": 51,
    "TLSA": 52,
    "SMIMEA": 53,
    "HIP": 55,
    "NINFO": 56,
    "RKEY": 57,
    "TALINK": 58,
    "CDS": 59,
    "CDNSKEY": 60,
    "OPENPGPKEY": 61,
    "SPF": 99,
    "UINFO": 100,
    "UID": 101,
    "GID": 102,
    "UNSPEC": 103,
    "NID": 104,
    "L32": 105,
    "L64": 106,
    "LP": 107,
    "EUI48": 108,
    "EUI64": 109,
    "TKEY": 249,
    "TSIG": 250,
    "IXFR": 251,
    "AXFR": 252,
    "MAILB": 253,
    "MAILA": 254,
    "ANY": 255,
    "URI": 256,
    "CAA": 257,
    "TA": 32768,
    "DLV": 32769,
}

DICT_RRCLASS = {
    "IN": 1,
    "CH": 3,
    "HS": 4,
    "ANY": 255,
}

# DNS Response Codes
DICT_RCODE = {
    "NOERROR": 0,
    "FORMERR": 1,
    "SERVFAIL": 2,
    "NXDOMAIN": 3,
    "NOTIMPL": 4,
    "REFUSED": 5,
    "NOTAUTH": 9,
    "BADVERS": 16,
    "BADKEY": 17,
    "BADTIME": 18,
    "BADMODE": 19,
    "BADNAME": 20,
    "BADALG": 21,
    "BADTRUNC": 22,
    "BADCOOKIE": 23,
}

# Instantiate the DNS parameter classes at the module level, since they
# are used by a variety of module routines.
qt = DNSparam("TYPE", DICT_RRTYPE)
qc = DNSparam("CLASS", DICT_RRCLASS)
rc = DNSparam("RCODE", DICT_RCODE)

# DNSSEC Protocol Numbers                
dnssec_proto = { 
    0: "Reserved", 
    1: "TLS", 
    2: "Email", 
    3: "DNSSEC", 
    4: "IPSEC",
}

# DNSSEC Algorithms
dnssec_alg = { 
    0: "Reserved", 
    1: "RSAMD5", 
    2: "DH", 
    3: "DSA", 
    4: "Reserved",
    5: "RSASHA1", 
    6: "DSA-NSEC3-SHA1", 
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256", 
    10: "RSASHA512", 
    12:"ECC-GOST",
    13:"ECDSAP256SHA256", 
    14:"ECDSAP384SHA384",
}

# DNSSEC Digest algorithms (see RFC 4509 and RFC 6605)
dnssec_digest = { 
    1: "SHA-1", 
    2: "SHA-256", 
    4: "SHA-384",
}

# SSH Fingerprint algorithms (see RFC 4255)
sshfp_alg = { 
    1: "RSA", 
    2: "DSA",
    3: "ECDSA",
    4: "ED25519",
}

# SSHFP fingerprint types (see RFC 4255)
sshfp_fptype = { 
    1: "SHA-1",
    2: "SHA-256",
}            

# EDNS Options Codes
edns_opt = {
    0: "Reserved",
    3: "NSID",
    5: "DAU",
    6: "DHU",
    7: "N3U",
    8: "Client Subnet",
    9: "Expire",
    10: "Cookie",
    11: "Keepalive",
    12: "Padding",
    13: "Chain",
}
