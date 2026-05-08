import argparse
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

from pathlib import Path


def parse_request(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        k, v = line.split('=')
        out[k] = v
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('url', help='windrow base URL')
    ap.add_argument('key', help='submitter key')
    ap.add_argument('file', help='artifact to upload')
    args = ap.parse_args()

    artifact = Path(args.file)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        staged = tmp / 'artifact'
        staged.symlink_to(artifact.resolve())

        subprocess.run(['sigsum-submit', '-k', args.key, str(staged)], check=True)
        req = parse_request((tmp / 'artifact.req').read_text())

    with artifact.open('rb') as payload:
        request = urllib.request.Request(
            args.url.rstrip('/') + '/v1/upload',
            data=payload,
            method='POST',
            headers={
                'Content-Type': 'application/octet-stream',
                'Content-Length': str(artifact.stat().st_size),
                'X-Windrow-Public-Key': req['public_key'],
                'X-Windrow-Signature': req['signature'],
                'X-Windrow-Hash': req['message'],
            },
        )

        try:
            with urllib.request.urlopen(request) as resp:
                print(resp.read().decode())
        except urllib.error.HTTPError as e:
            print(f'upload failed: {e.code} {e.reason}', file=sys.stderr)
            print(e.read().decode(), file=sys.stderr)
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
