#include "uECC.h"

#include <sha256.h>

#include <vector>
#include <cstdint>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <cstdlib>

static std::vector<std::uint8_t> read_data(char const *  filename) {
    auto fd = fopen(filename, "r");
    if (!fd) {
        std::fprintf(stderr, "Could not read public key %s: %s\n",
                     filename, std::strerror(errno));
        std::exit(1);
    }
    std::vector<std::uint8_t> ret;

    for(;;) {
        int e;
        int n = std::fscanf(fd, "0x%x, ", &e);
        if (n != 1) {
            break;
        }
        ret.push_back(e);
    }
    std::fclose(fd);
    return std::move(ret);
}

static std::vector<std::uint8_t> read_pubkey(char const *  filename) {
    auto const compressed = read_data(filename);

    auto curve = uECC_secp256k1();
    size_t const expected = uECC_curve_private_key_size(curve) + 1;

    if (compressed.size() != expected) {
        std::fprintf(stderr, "Expected %zu bytes in compressed pubkey, got %zu\n",
                     expected, compressed.size());
        std::exit(1);
    }

    std::vector<uint8_t> decompressed(uECC_curve_public_key_size(curve));
    uECC_decompress(&compressed[0], &decompressed[0], curve);

    return std::move(decompressed);
}

static std::vector<std::uint8_t> read_signature(char const *  filename) {
    auto ret = read_data(filename);

    auto curve = uECC_secp256k1();
    size_t const expected = 2*uECC_curve_private_key_size(curve);

    if (ret.size() != expected) {
        std::fprintf(stderr, "Expected %zu bytes in signature, got %zu\n",
                     expected, ret.size());
        std::exit(1);
    }


    return std::move(ret);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s public data signature\n", argv[0]);
        return 1;
    }

    auto curve = uECC_secp256k1();
    auto pubkey = read_pubkey(argv[1]);

    auto data_fd = fopen(argv[2], "r");
    std::fseek(data_fd, 0, SEEK_END);
    size_t const fsize = std::ftell(data_fd);
    std::fseek(data_fd, 0, SEEK_SET);
    std::vector<std::uint8_t> data(fsize);
    auto const read_size = std::fread(&data[0], 1, fsize, data_fd);
    if (read_size != fsize) {
        fprintf(stderr, "Could not read data: %s (%zu != %zu)\n", std::strerror(errno), read_size, fsize);
        return 1;
    }
    std::fclose(data_fd);

    auto signature = read_signature(argv[3]);

    context_sha256_t sha256 = {};
    sha256_starts(&sha256);
    sha256_update(&sha256, &data[0], data.size());
    std::vector<std::uint8_t> hash(32);
    sha256_finish(&sha256, &hash[0]);

    int one_if_ok = uECC_verify(&pubkey[0],
                                &hash[0],
                                hash.size(),
                                &signature[0],
                                curve);
    if (one_if_ok != 1) {
        fprintf(stderr, "Signature verification failed\n");
        return 2;
    }
    return 0;
}
