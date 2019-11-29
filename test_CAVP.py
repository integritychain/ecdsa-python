#!/usr/bin/env python

import re
from zipfile import ZipFile
from ecdsa import CurveP256, CurveP384, CurveP521, ECDSA, Point, Coordinate, KeyPair

# Verbiage HERE

params = dict()

with ZipFile('186-3ecdsatestvectors.zip', 'r') as zipFile:

    # Test signature generation
    with zipFile.open('SigGen.txt') as file:
        for index, line in enumerate(file):
            items = re.split("\ +=\ +", line.decode("ascii").strip())
            if items[0].startswith('['): PGO = 0
            if items[0] == '[P-256,SHA-256]':
                PGO = 1; print("Testing P-256 SigGen")
                ecdsa = ECDSA(CurveP256)
            if items[0] == '[P-384,SHA-384]':
                PGO = 1; print("Testing P-384 SigGen")
                ecdsa = ECDSA(CurveP384)
            if items[0] == '[P-521,SHA-512]':
                PGO = 1; print("Testing P-521 SigGen")
                ecdsa = ECDSA(CurveP521)
            if len(items) > 1:
                if len(items[1]) % 2 == 1: items[1] = "0" + items[1]
                params[items[0]] = bytearray.fromhex(items[1])
                if items[0] == 'S' and PGO == 1:
                    print("  -> Test on line {}...".format(index+1), end='')
                    key_pair = ecdsa.generate_keypair(private=int.from_bytes(params['d'], byteorder='big'))
                    if key_pair.public.x.coord != int.from_bytes(params['Qx'], byteorder='big'): raise RuntimeError("Qx does not match")
                    if key_pair.public.y.coord != int.from_bytes(params['Qy'], byteorder='big'): raise RuntimeError("Qy does not match")
                    r, s = ecdsa.sign(params['Msg'], key_pair, k=int.from_bytes(params['k'], byteorder='big'))
                    if r != int.from_bytes(params['R'], byteorder='big'): raise RuntimeError("R does not match")
                    if s != int.from_bytes(params['S'], byteorder='big'): raise RuntimeError("S does not match")
                    print("PASS")

    # Test signature verification
    with zipFile.open('SigVer.rsp') as file:
        for index, line in enumerate(file):
            items = re.split("\s*=\s*", line.decode("ascii").strip())
            if items[0].startswith('['): PGO = 0
            if items[0] == '[P-256,SHA-256]':
                PGO = 1; print("Testing P-256 SigVer")
                ecdsa = ECDSA(CurveP256)
            if items[0] == '[P-384,SHA-384]':
                PGO = 1; print("Testing P-384 SigVer")
                ecdsa = ECDSA(CurveP384)
            if items[0] == '[P-521,SHA-512]':
                PGO = 1; print("Testing P-521 SigVer")
                ecdsa = ECDSA(CurveP521)
            if len(items) > 1:
                if len(items[1]) % 2 == 1 and not items[0].startswith("Res"): items[1] = "0" + items[1]
                if not items[0].startswith("Res"): params[items[0]] = bytearray.fromhex(items[1])
                if items[0] == 'Result' and PGO == 1:
                    print("  -> Test on line {}...".format(index+1), end='')
                    key_pair = KeyPair(public=Point(Coordinate(int.from_bytes(params['Qx'], byteorder='big'), ecdsa.curve.PRIME),
                                                    Coordinate(int.from_bytes(params['Qy'], byteorder='big'), ecdsa.curve.PRIME)), private=None)
                    # if index > 1945:
                    #     print("debug target")
                    res = ecdsa.verify(params['Msg'], key_pair.public, int.from_bytes(params['R'], byteorder='big'), int.from_bytes(params['S'], byteorder='big'))
                    if items[1].startswith("P") and res != True: raise RuntimeError("CAVP Pass, Code Fail")
                    if items[1].startswith("F") and res != False: raise RuntimeError("CAVP Fail, Code Pass")
                    print("PASS")
