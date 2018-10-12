import sys
from pathlib import Path
import secp256k1



def _main():
    if len(sys.argv) != 4:
        print("usage: {} public data signature".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    data = Path(sys.argv[2]).read_bytes()
    pubkey_compressed = bytes(int(x, 16) for x in Path(sys.argv[1]).read_text().strip().split(",") if x)
    signature_raw = bytes(int(x, 16) for x in Path(sys.argv[3]).read_text().strip().split(",") if x)
    pubkey = secp256k1.PublicKey(pubkey_compressed, raw=True)
    signature = pubkey.ecdsa_deserialize_compact(signature_raw)


    if not pubkey.ecdsa_verify(data, signature):
        print("verification failed", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    _main()
