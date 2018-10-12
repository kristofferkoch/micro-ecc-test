#! /bin/sh -e
mkdir -p "output"
gcc -Wno-unused-parameter -std=gnu11 -O2 -g3 -Wall -Wextra -fstack-protector-all -I . -I micro-ecc -c micro-ecc/uECC.c -o output/uECC.o
gcc -Wno-unused-parameter -std=gnu11 -O2 -g3 -Wall -Wextra -fstack-protector-all -I . -I micro-ecc -c sha256.c -o output/sha256.o
g++ -std=gnu++17 -O2 -g3 -Wall -Wextra -fstack-protector-all -I . -I micro-ecc -c uecc_genkey.cpp -o output/uecc_genkey.o
g++ -std=gnu++17 -O2 -g3 -Wall -Wextra -fstack-protector-all -I . -I micro-ecc -c uecc_sign.cpp -o output/uecc_sign.o
g++ -std=gnu++17 -O2 -g3 -Wall -Wextra -fstack-protector-all -I . -I micro-ecc -c uecc_verify.cpp -o output/uecc_verify.o
g++ output/uECC.o output/sha256.o output/uecc_sign.o -o output/uecc_sign
g++ output/uECC.o output/sha256.o output/uecc_genkey.o -o output/uecc_genkey
g++ output/uECC.o output/sha256.o output/uecc_verify.o -o output/uecc_verify
