import socket, struct, random, hashlib, binascii
from .common import *

class Struct:
    "Container class to emulate C struct or record."
    pass


def random_init():
    random.seed(os.urandom(64))
    return


def hexdump(inputbytes):
    """return a hexadecimal string representation of given byte string"""
    if PYVERSION == 2:
        return ''.join(["%02x" % ord(x) for x in inputbytes])
    else:
        return binascii.hexlify(inputbytes).decode('ascii')


def h2bin(x):
    """turn hex dump string with optional whitespaces into binary string"""
    return x.replace(' ', '').replace('\n', '').decode('hex')


def packed2int(input):
    """convert arbitrary sized bigendian byte-string into an integer"""
    sum = 0
    for (i, x) in enumerate(input[::-1]):
        if PYVERSION == 2:
            sum += ord(x) * 2**(8*i)
        else:
            sum += x * 2**(8*i)
    return sum


def randomize_case(input):
    """randomize case of input string; using the bit 0x20 hack to
    improve input entropy: see draft-vixie-dns-0x20-00"""
    outlist = []
    random.seed()
    for c in input:
        if c.isalpha():
            if random.choice([0,1]):
                outlist.append(chr((ord(c) ^ 0x20)))
                continue
        outlist.append(c)
    return "".join(outlist)


def domain_name_match(s1, s2, case_sensitive=False):
    if case_sensitive:
        return (s1 == s2)
    else:
        return (s1.lower() == s2.lower())
    

def ip2ptr(address):
    """return PTR owner name of an IPv4 or IPv6 address (for -x option)"""
    v4_suffix = '.in-addr.arpa.'
    v6_suffix = '.ip6.arpa.'
    error = False
    try:
        if address.find('.') != -1:                             # IPv4 address
            packed = socket.inet_pton(socket.AF_INET, address)
            if PYVERSION == 2:
                octetlist = ["%d" % ord(x) for x in packed]
            else:
                octetlist = ["%d" % x for x in packed]
            ptrowner = "%s%s" % ('.'.join(octetlist[::-1]), v4_suffix)
        elif address.find(':') != -1:                           # IPv6 address
            packed = socket.inet_pton(socket.AF_INET6, address)
            if PYVERSION == 2:
                hexstring = ''.join(["%02x" % ord(x) for x in packed])
            else:
                hexstring = ''.join(["%02x" % x for x in packed])
            ptrowner = "%s%s" % \
                       ('.'.join([x for x in hexstring[::-1]]), v6_suffix)
        else:
            error = True
    except socket.error:
        error = True
    if error:
        raise ErrorMessage("%s isn't an IPv4 or IPv6 address" % address)
    
    return ptrowner


def get_socketparams(server, port, af, type):
    """Only the first set of parameters is used. Passing af=AF_UNSPEC prefers
    IPv6 if possible."""
    ai = socket.getaddrinfo(server, port, af, type)[0]
    family, socktype, proto, canonname, sockaddr = ai
    server_addr, port = sockaddr[0:2]
    return (server_addr, port, family, socktype)


def sendSocket(s, message):
    """Send message on a connected socket"""
    try:
        octetsSent = 0
        while (octetsSent < len(message)):
            sentn = s.send(message[octetsSent:])
            if sentn == 0:
                raise ErrorMessage("send() returned 0 bytes")
            octetsSent += sentn
    except Exception as e:
        print("DEBUG: Exception: %s" % e)
        return False
    else:
        return True


def recvSocket(s, numOctets):
    """Read and return numOctets of data from a connected socket"""
    response = b""
    octetsRead = 0
    while (octetsRead < numOctets):
        chunk = s.recv(numOctets-octetsRead)
        chunklen = len(chunk)
        if chunklen == 0:
            return b""
        octetsRead += chunklen
        response += chunk
    return response


def xor_string(a, b):
    """bitwise XOR bytes in a and b and return concatenated result"""
    result = b''
    for (x, y) in zip(a, b):
        if PYVERSION == 2:
            result += struct.pack('B', (ord(x) ^ ord(y)))
        else:
            result += struct.pack('B', (x ^ y))
    return result


def hmac(key, data, func):
    """HMAC algorithm; see RFC 2104, 4635"""
    BLOCKSIZE = 64                                  # 64 bytes = 512 bits
    ipad = b'\x36' * BLOCKSIZE
    opad = b'\x5c' * BLOCKSIZE

    key = key + b'\x00' * (BLOCKSIZE - len(key))    # pad to blocksize

    m = func()
    m.update(xor_string(key, ipad) + data)
    r1 = m.digest()

    m = func()
    m.update(xor_string(key, opad) + r1)

    return m.digest()

                                
def txt2domainname(input, canonical_form=False):
    """turn textual representation of a domain name into its wire format"""
    if input == ".":
        d = b'\x00'
    else:
        d = b""
        for label in input.split('.'):
            label = label.encode('ascii')
            if canonical_form:
                label = label.lower()
            length = len(label)
            d += struct.pack('B', length) + label
    return d


def get_domainname(pkt, offset):
    """decode a domainname at the given packet offset; see RFC 1035"""
    global count_compression
    labellist = []               # a domainname is a sequence of labels
    Done = False
    while not Done:
        llen, = struct.unpack('B', pkt[offset:offset+1])
        if (llen >> 6) == 0x3:                 # compression pointer, sec 4.1.4
            count_compression += 1
            c_offset, = struct.unpack('!H', pkt[offset:offset+2])
            c_offset = c_offset & 0x3fff       # last 14 bits
            offset +=2
            rightmostlabels, junk = get_domainname(pkt, c_offset)
            labellist += rightmostlabels
            Done = True
        else:
            offset += 1
            label = pkt[offset:offset+llen]
            offset += llen
            labellist.append(label)
            if llen == 0:
                Done = True
    return (labellist, offset)


def pdomainname(labels):
    """given a sequence of domainname labels, return a quoted printable text
    representation of the domain name"""

    printables = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-*+'
    result_list = []

    for label in labels:
        result = ''
        for c in label:
            if isinstance(c, int):
                c_int, c_chr = c, chr(c)
            else:
                c_int, c_chr = ord(c), c.decode()
            if c in printables:
                result += c_chr
            else:
                result += ("\\%03d" % c_int)
        result_list.append(result)

    if result_list == ['']:
        return "."
    else:
        return ".".join(result_list)


def uid2ownername(uid, qtype):
    """Return OPENPGPKEY/SMIMEA ownername for given uid/email address"""
    if qtype == 'OPENPGPKEY':
        applabel = '_openpgpkey'
    elif qtype == 'SMIMEA':
        applabel = '_smimecert'
    else:
        raise ErrorMessage('Invalid qtype (%s) for uid2owner' % qtype)
    localpart, rhs = uid.split('@')
    h = hashlib.sha256()
    h.update(localpart.encode('utf8'))
    owner = "{}.{}.{}".format(h.hexdigest()[0:56], applabel, rhs)
    if not owner.endswith('.'):
        owner = owner + '.'
    return owner
