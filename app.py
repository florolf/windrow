import flask
import uuid
import os

from pathlib import Path

import nacl.signing

from .utils import sha256, sha256_file
from .sigsum import SigsumLog

def check_sig(pubkey: bytes, checksum: bytes, signature: bytes) -> bool:
    commitment = b'sigsum.org/v1/tree-leaf\0' + checksum

    pk = nacl.signing.VerifyKey(pubkey)
    try:
        pk.verify(commitment, signature)
        return True
    except:
        return False


def create_app():
    app = flask.Flask(__name__)

    whitelist = set()
    with open(os.environ['WINDROW_WHITELIST']) as f:
        for line in f:
            whitelist.add(bytes.fromhex(line))

    sigsum_log = SigsumLog(
        os.environ['WINDROW_LOG_ENDPOINT'],
        bytes.fromhex(os.environ['WINDROW_LOG_PUBKEY'])
    )

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

        if len(flask.request.files) != 1:
            return "need exactly one file argument", 400

        if 'public_key' not in flask.request.form:
            return "public_key is missing", 400

        try:
            pubkey = bytes.fromhex(flask.request.form['public_key'])
            if pubkey not in whitelist:
                return 'public key not allowed', 403
        except:
            return 'invalid public key', 400

        if 'signature' not in flask.request.form:
            return "signature is missing", 400

        try:
            signature = bytes.fromhex(flask.request.form['signature'])
        except:
            return 'invalid signature', 400

        (file, ) = flask.request.files.values()
        tmp_path = repo / 'tmp' / request_id
        file.save(tmp_path)

        file_hash = sha256_file(tmp_path)
        checksum = sha256(file_hash)

        if not check_sig(pubkey, checksum, signature):
            tmp_path.unlink()
            return 'invalid signature', 400

        hex_cs = checksum.hex()
        final_path = repo / hex_cs[0:4] / hex_cs
        final_path.parent.mkdir(exist_ok=True)

        tmp_path.move(final_path)

        try:
            leaf_hash = sigsum_log.add_leaf(pubkey, file_hash, signature)
        except:
            tmp_path.unlink()
            return 'sigsum submission failed', 500

        try:
            proof = sigsum_log.get_proof(leaf_hash)
        except:
            tmp_path.unlink()
            return 'sigsum submission failed', 500

        final_path.with_suffix('.proof').write_text(proof)

        return hex_cs, 200

    return app

if __name__ == '__main__':
    app = create_app()
    app.run()
