#include "uECC.h"

#include <vector>
#include <cstdio>
#include <cstdint>
#include <cerrno>
#include <cstring>

int main(int argc, char **argv)
{
    if (argc != 3) {
        std::fprintf(stderr, "usage: %s public private\n", argv[0]);
        return 1;
    }

    auto pub_fd = std::fopen(argv[1], "w");
    if (!pub_fd) {
        std::fprintf(stderr, "Could not open public key %s: %s\n",
                     argv[1], std::strerror(errno));
    }
    auto priv_fd = std::fopen(argv[2], "w");
    if (!priv_fd) {
        std::fprintf(stderr, "Could not open private key %s: %s\n",
                     argv[2], std::strerror(errno));
    }
    auto curve = uECC_secp256k1();
    std::vector<std::uint8_t> public_key(uECC_curve_public_key_size(curve));
    std::vector<std::uint8_t> private_key(uECC_curve_private_key_size(curve));

    int ok = uECC_make_key(&public_key[0], &private_key[0], curve);
    if (!ok) {
        std::fprintf(stderr, "Could not make key\n");
        return 1;
    }

    std::vector<std::uint8_t> compressed(uECC_curve_private_key_size(curve) + 1);

    uECC_compress(&public_key[0], &compressed[0], curve);

    for (size_t i = 0; i < compressed.size(); i++) {
        fprintf(pub_fd, "0x%02x, ", compressed[i]);
    }
    fprintf(pub_fd, "\n");

    for (size_t i = 0; i < private_key.size(); i++) {
        fprintf(priv_fd, "0x%02x, ", private_key[i]);
    }
    fprintf(priv_fd, "\n");

    fclose(pub_fd);
    fclose(priv_fd);

    return 0;
}
