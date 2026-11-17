"""Pulls every Remote ID message pack (and the messages inside) out of the sample captures."""
import struct, sys

def pcap(path):
    b = open(path, 'rb').read(); off = 24
    while off + 16 <= len(b):
        cl = struct.unpack('<I', b[off + 8:off + 12])[0]; off += 16
        yield b[off:off + cl]; off += cl

def pcapng(path):
    b = open(path, 'rb').read(); off = 0
    while off + 12 <= len(b):
        bt, bl = struct.unpack('<II', b[off:off + 8])
        if bt == 6:
            body = b[off + 8:off + bl - 4]
            cl = struct.unpack('<I', body[12:16])[0]
            yield body[20:20 + cl]
        off += bl

packs = []
for f in ('odid_wifi_bcn_sample.pcap', 'odid_wifi_sample.pcap'):
    for d in pcap('tests/data/' + f):
        k = d.find(bytes.fromhex('fa0bbc0d'))
        if k > 0:
            packs.append(d[k + 5:k + d[k - 1]]); continue
        k = d.find(bytes.fromhex('8869199d9209'))
        if k > 0 and d[k - 3] == 3:
            packs.append(d[k + 11:k + 10 + d[k + 9]])
for d in pcapng('tests/data/odid_bt5_lr_sample.pcapng'):
    k = d.find(bytes.fromhex('16faff0d'))
    if k > 0:
        packs.append(d[k + 5:k + d[k - 1]])
msgs = set()
for p in packs:
    if p[0] >> 4 == 0xF and p[1] == 25 and p[2] <= 9:
        for i in range(p[2]):
            msgs.add(p[3 + 25 * i:28 + 25 * i].hex())
work = sys.argv[1]
open(work + '/msgs.hex', 'w').write('\n'.join(sorted(msgs)) + '\n')
open(work + '/packs.hex', 'w').write('\n'.join(p.hex() for p in packs) + '\n')
