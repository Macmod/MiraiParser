import sys
import re
import ctypes as ct
from binascii import unhexlify, hexlify
from struct import unpack

hex_mask = re.compile(r'^[0-9A-Z]{2}$')
BUFSIZE = 8192

# Setup b2a lib
b2a = ct.CDLL('bytes2atk/b2a.so')
b2a.attack_parse.argtypes = (
    ct.c_char_p, ct.c_int, ct.c_char_p, ct.c_char_p
)
b2a.attack_parse.restype = None

# Python wrapper around C parser
def attack_parse(attack):
    global BUFSIZE
    global b2a

    full_cmd = ct.create_string_buffer(attack[2:])
    plain = ct.create_string_buffer(BUFSIZE)
    error = ct.create_string_buffer(BUFSIZE)

    if len(attack) >= 2:
        alen = ct.c_int(unpack('!H', attack[:2])[0])
        b2a.attack_parse(full_cmd, alen, plain, error)

        if plain[0] != '\0':
            return plain.value
    else:
        return None

def get_bytes(fname):
    with open(fname) as infile:
        line = True
        while line:
            line = infile.readline()
            toks = line.split()

            # If raw bytes line
            if len(toks) > 6 and toks[6] == 'bytes:':
                b = ''
                nbytes = int(toks[7][:-1])

                # Get bytes
                for i in range(nbytes/16 + (1 if nbytes % 16 else 0)):
                    bytesline = infile.readline().split()

                    i = 0
                    while i < len(bytesline) and hex_mask.match(bytesline[i]):
                        b += bytesline[i]
                        i += 1

                # Parse attack
                if b != '':
                    date = ' '.join(toks[:3])[:-1]
                    cnc = toks[5][:-1]

                    inbytes = unhexlify(b)
                    if 'PING' in inbytes:
                        continue

                    attack = attack_parse(inbytes)

                    if attack:
                        yield date, cnc, attack

for info in get_bytes(sys.argv[1]):
    print ', '.join(info)
