import flask
import hashlib
import uuid
import os
import subprocess
import tempfile

from pathlib import Path
from typing import Optional, Tuple

import nacl.signing

from .utils import sha256

def check_sig(pubkey: bytes, checksum: bytes, signature: bytes) -> bool:
    commitment = b'sigsum.org/v1/tree-leaf\0' + checksum

    pk = nacl.signing.VerifyKey(pubkey)
    try:
        pk.verify(commitment, signature)
        return True
    except:
        return False

def sigsum_submit(policy: str, message: bytes, signature: bytes, pubkey: bytes, token: Optional[Tuple[str, str]] = None) -> str:
    with tempfile.TemporaryDirectory() as tmp_path:
        tmp = Path(tmp_path)

        request = f"message={message.hex()}\n"
        request += f"signature={signature.hex()}\n"
        request += f"public_key={pubkey.hex()}\n"
        (tmp / 'request').write_text(request)

        cmd = ['sigsum-submit']

        if policy.startswith('/'):
            cmd += ['-p', policy]
        else:
            cmd += ['-P', policy]

        if token is not None:
            cmd += ['--token-domain', token[0], '--token-signing-key', token[1]]

        cmd += ['request']

        proc = subprocess.run(cmd, cwd=tmp)
        proc.check_returncode()

        return (tmp / 'request.proof').read_text()


def create_app():
    app = flask.Flask(__name__)

    whitelist = set()
    with open(os.environ['WINDROW_WHITELIST']) as f:
        for line in f:
            whitelist.add(bytes.fromhex(line))

    sigsum_policy = os.environ['WINDROW_SIGSUM_POLICY']

    sigsum_token_domain = os.environ.get('WINDROW_SIGSUM_TOKEN_DOMAIN')
    sigsum_token_key_path = os.environ.get('WINDROW_SIGSUM_TOKEN_KEY_FILE')
    if sigsum_token_domain is None and sigsum_token_key_path is None:
        sigsum_token = None
    elif sigsum_token_domain is not None and sigsum_token_key_path is not None:
        sigsum_token = (sigsum_token_domain, sigsum_token_key_path)
    else:
        raise RuntimeError('WINDROW_SIGSUM_TOKEN_DOMAIN and WINDROW_SIGSUM_TOKEN_KEY_FILE must be set together')

    repo = Path(os.environ['WINDROW_REPO'])
    repo.mkdir(parents=True, exist_ok=True)

    (repo / 'tmp').mkdir(exist_ok=True)

    @app.route("/v1/read/<checksum>")
    def v1_read(checksum: str):
        try:
            cs = bytes.fromhex(checksum)
            if len(cs) != 32:
                raise ValueError()
        except:
            return "not a valid hash", 400

        hex_cs = cs.hex()
        path = repo / hex_cs[0:4] / hex_cs

        if not path.exists():
            return 'file not found', 404

        return flask.send_file(path)

    @app.route("/v1/read/<checksum>/proof")
    def v1_read_proof(checksum: str):
        try:
            cs = bytes.fromhex(checksum)
            if len(cs) != 32:
                raise ValueError()
        except:
            return "not a valid hash", 400

        hex_cs = cs.hex()
        path = repo / hex_cs[0:4] / f'{hex_cs}.proof'

        if not path.exists():
            return 'file not found', 404

        return flask.send_file(path)

    @app.route("/v1/upload", methods=['POST'])
    def v1_post():
        request_id = str(uuid.uuid4())

        param = {}
        for key, header in [
            ('public_key', 'X-Windrow-Public-Key'),
            ('signature', 'X-Windrow-Signature'),
            ('hash', 'X-Windrow-Hash'),
        ]:
            value = flask.request.headers.get(header)
            if value is None:
                return f"'{header}' header is missing", 400

            try:
                param[key] = bytes.fromhex(value)
            except:
                return f'malformed {header}', 400

        if param['public_key'] not in whitelist:
            return 'public key not allowed', 403

        checksum = sha256(param['hash'])
        if not check_sig(param['public_key'], checksum, param['signature']):
            return 'invalid signature', 400

        hex_cs = checksum.hex()
        final_path = repo / hex_cs[0:4] / hex_cs
        if final_path.exists():
            proof_path = final_path.with_suffix('.proof')
            old_keyhash = None
            for line in proof_path.read_text().splitlines():
                if line.startswith('leaf='):
                    old_keyhash = bytes.fromhex(line[len('leaf='):].split(' ')[0])
                    break

            while flask.request.stream.read(1024 * 1024):
                pass

            if old_keyhash == sha256(param['public_key']):
                return hex_cs, 200

            return 'artifact already exists', 409

        tmp_path = repo / 'tmp' / request_id
        h = hashlib.sha256()
        with tmp_path.open('wb') as f:
            while chunk := flask.request.stream.read(1024 * 1024):
                h.update(chunk)
                f.write(chunk)

        if h.digest() != param['hash']:
            tmp_path.unlink()
            return 'hash mismatch', 400

        final_path.parent.mkdir(exist_ok=True)

        tmp_path.move(final_path)

        try:
            proof = sigsum_submit(sigsum_policy, param['hash'], param['signature'], param['public_key'], sigsum_token)
        except:
            final_path.unlink()
            return 'sigsum submission failed', 500

        final_path.with_suffix('.proof').write_text(proof)

        return hex_cs, 200

    return app

if __name__ == '__main__':
    app = create_app()
    app.run()
