import sys
from pathlib import Path
import secp256k1



def _main():
    if len(sys.argv) != 4:
        print("usage: {} private data signature".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)


    data = Path(sys.argv[2]).read_bytes()
    private_raw = bytes(int(x, 16) for x in Path(sys.argv[1]).read_text().strip().split(",") if x)
    private = secp256k1.PrivateKey(private_raw, raw=True)

    signature = private.ecdsa_sign(data)
    signature_raw = private.ecdsa_serialize_compact(signature)
    signature_text = ', '.join("0x{:02x}".format(x) for x in signature_raw) + ", \n"
    with Path(sys.argv[3]).open("w") as fd:
        fd.write(signature_text)

if __name__ == "__main__":
    _main()
