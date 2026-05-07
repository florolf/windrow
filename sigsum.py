#!/usr/bin/env python3

import time

from collections import defaultdict
from typing import Optional

import requests

from .utils import sha256

SigsumDoc = dict[str, list[list[str]]]

def parse_ascii(doc: str) -> SigsumDoc:
    out = defaultdict(list)

    for line in doc.splitlines():
        if not line:
            continue

        key, value = line.split('=', 1)
        out[key].append(value.split())

    return out


class SigsumLog:
    def __init__(self, endpoint: str, pubkey: bytes):
        self.endpoint = endpoint
        self.pubkey = pubkey

        self.session = requests.Session()
        self.session.headers['User-Agent'] = f'windrow/v0.1'

    def do_request(self, *args, timeout=60, may_not_found=False) -> Optional[str]:
        url = '/'.join([self.endpoint, *[str(x) for x in args]])

        print(url)
        backoff = 1
        deadline = time.time() + timeout
        while True:
            remaining = max(0, deadline - time.time())

            resp = self.session.get(url, timeout=remaining)
            if resp.status_code == 429:
                if time.time() + backoff < deadline:
                    time.sleep(backoff)
                    backoff *= 2
                    continue

            if may_not_found and resp.status_code == 404:
                return None

            resp.raise_for_status()
            return resp.text

    def get_tree_head(self) -> SigsumDoc:
        return parse_ascii(self.do_request('get-tree-head'))

    def get_inclusion_proof(self, size: int, leaf_hash: bytes) -> Optional[SigsumDoc]:
        _ascii = self.do_request('get-inclusion-proof', size, leaf_hash.hex(), may_not_found=True)
        if _ascii is None:
            return None

        return parse_ascii(_ascii)

    def get_leaves(self, start: int, end: int) -> list[SigsumDoc]:
        ascii_ = self.do_request('get-leaves', start, end)
        data = parse_ascii(ascii_)

        result = []
        for checksum, signature, key_hash in data['leaf']:
            result.append(
                (checksum, signature, key_hash)
            )

        return result

    def add_leaf(self, pubkey: bytes, message: bytes, signature: bytes) -> bytes:
        body = f'message={message.hex()}\nsignature={signature.hex()}\npublic_key={pubkey.hex()}\n'
        while True:
            resp = self.session.post(self.endpoint + '/add-leaf', data=body)
            if resp.status_code == 202:
                time.sleep(1)
                continue

            resp.raise_for_status()
            break

        keyhash = sha256(pubkey)
        checksum = sha256(message)

        leaf = b'\x00' + checksum + signature + keyhash
        return sha256(leaf)

    def get_proof(self, leaf_hash: bytes, timeout: int = 0) -> str:
        proof = [
            'version=2',
            f'log={sha256(self.pubkey).hex()}',
        ]

        deadline = time.time() + timeout
        ip = None
        while timeout == 0 or time.time() < deadline:
            th = self.get_tree_head()
            current_size = int(th['size'][0][0])

            ip = self.get_inclusion_proof(current_size, leaf_hash)
            if ip is not None:
                break

            time.sleep(1)

        if ip is None:
            raise RuntimeError('failed to find leaf')

        leaf_index = int(ip['leaf_index'][0][0])
        leaf = self.get_leaves(leaf_index, leaf_index+1)[0]

        proof.append(f'leaf={leaf[2]} {leaf[1]}')
        proof.append('')

        proof.append(f'size={th['size'][0][0]}')
        proof.append(f'root_hash={th['root_hash'][0][0]}')
        proof.append(f'signature={th['signature'][0][0]}')
        for cs in th['cosignature']:
            proof.append(f'cosignature={' '.join(cs)}')
        proof.append('')

        proof.append(f'leaf_index={leaf_index}')
        for nh in ip['node_hash']:
            proof.append(f'node_hash={nh[0]}')

        return '\n'.join(proof) + '\n'

