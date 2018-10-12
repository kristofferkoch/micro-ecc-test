#include "uECC.h"

#include <sha256.h>

#include <vector>
#include <cstdint>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <cstdlib>

static std::vector<std::uint8_t> read_privkey(char const *  filename) {
    auto fd = fopen(filename, "r");
    if (!fd) {
        std::fprintf(stderr, "Could not read private key %s: %s\n",
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

    auto curve = uECC_secp256k1();
    size_t const expected = uECC_curve_private_key_size(curve);

    if (ret.size() != expected) {
        std::fprintf(stderr, "Expected %zu bytes, got %zu\n",
                     expected, ret.size());
        std::exit(1);
    }

    return std::move(ret);
}

struct Ctx {
    Ctx()
        : uECC {
            .init_hash = init,
            .update_hash = update,
            .finish_hash = finish,
            .block_size = 64,
            .result_size = 32,
            .tmp = tmp
        }
        , sha256{}
    {

    }
    uECC_HashContext uECC;

private:
    static Ctx & from(const struct uECC_HashContext *base) {
        return *reinterpret_cast<Ctx *>(const_cast<struct uECC_HashContext *>(base));
    }
    static void init(const struct uECC_HashContext *base) {
        auto & ctx = from(base);
        sha256_starts(&ctx.sha256);
    }
    static void update(const struct uECC_HashContext *base,
                              const uint8_t *message,
                              unsigned message_size) {
        auto & ctx = from(base);
        sha256_update(&ctx.sha256, message, message_size);
    }

    static void finish(const struct uECC_HashContext *base,
                       uint8_t *hash_result) {
        auto & ctx = from(base);
        sha256_finish(&ctx.sha256, hash_result);
    }

    uint8_t tmp[128];
    context_sha256_t sha256;
};




int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s private data signature\n", argv[0]);
        return 1;
    }

    auto curve = uECC_secp256k1();
    auto privkey = read_privkey(argv[1]);
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

    auto sign_fd = std::fopen(argv[3], "w");

    context_sha256_t sha256 = {};
    sha256_starts(&sha256);
    sha256_update(&sha256, &data[0], data.size());
    std::vector<std::uint8_t> hash(32);
    sha256_finish(&sha256, &hash[0]);


    std::vector<uint8_t> signature(2*uECC_curve_private_key_size(curve));
    Ctx ctx;
    uECC_sign_deterministic(&privkey[0],
                            &hash[0],
                            hash.size(),
                            &ctx.uECC,
                            &signature[0],
                            curve);

    for (size_t i = 0; i < signature.size(); i++) {
        std::fprintf(sign_fd, "0x%02x, ", signature[i]);
    }
    std::fprintf(sign_fd, "\n");
    std::fclose(sign_fd);

    return 0;
}
