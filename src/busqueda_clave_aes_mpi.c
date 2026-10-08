/* Busqueda de una clave AES con reparto por bloques y Open MPI. */

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define TOTAL_KEYS (UINT64_C(1) << 20)
#define SECRET_KEY UINT64_C(12345)
#define MESSAGE_LEN 16
#define KNOWN_FRAGMENT "Puedes"
#define KNOWN_FRAGMENT_LEN (sizeof(KNOWN_FRAGMENT) - 1)

static const unsigned char message[] = "Puedes lograrlo!";

_Static_assert(sizeof(message) - 1 == MESSAGE_LEN,
               "El mensaje debe tener exactamente 16 bytes.");

static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
}

static void make_key(uint64_t candidate, unsigned char key[16])
{
    memset(key, 0, 16);

    for (int i = 0; i < 8; i++) {
        key[15 - i] = (unsigned char)((candidate >> (8 * i)) & 0xFF);
    }
}

static void setup_cipher(EVP_CIPHER_CTX *ctx, int encrypt)
{
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL,
                          NULL, NULL, encrypt) != 1) {
        fail("Error al inicializar AES.");
    }

    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        fail("Error al configurar el relleno.");
    }
}

static void crypt_block(EVP_CIPHER_CTX *ctx, uint64_t candidate,
                        const unsigned char *input,
                        unsigned char *output)
{
    unsigned char key[16];
    int written = 0;
    int final_written = 0;

    make_key(candidate, key);

    if (EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, -1) != 1 ||
        EVP_CipherUpdate(ctx, output, &written, input, MESSAGE_LEN) != 1 ||
        EVP_CipherFinal_ex(ctx, output + written, &final_written) != 1) {
        fail("Error al procesar el bloque AES.");
    }

    if (written + final_written != MESSAGE_LEN) {
        fail("Longitud inesperada del resultado.");
    }
}

static int is_valid_candidate(const unsigned char *plain)
{
    if (memcmp(plain, KNOWN_FRAGMENT, KNOWN_FRAGMENT_LEN) != 0) {
        return 0;
    }

    return memcmp(plain, message, MESSAGE_LEN) == 0;
}

int main(int argc, char **argv)
{
    int rank;
    int processes;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &processes);

    uint64_t base = TOTAL_KEYS / (uint64_t)processes;
    uint64_t remainder = TOTAL_KEYS % (uint64_t)processes;
    uint64_t start = (uint64_t)rank * base +
                     ((uint64_t)rank < remainder ? (uint64_t)rank : remainder);
    uint64_t count = base + ((uint64_t)rank < remainder ? 1 : 0);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fail("No se pudo crear el contexto de OpenSSL.");
    }

    unsigned char cipher[MESSAGE_LEN + EVP_MAX_BLOCK_LENGTH] = {0};
    unsigned char plain[MESSAGE_LEN + EVP_MAX_BLOCK_LENGTH] = {0};

    setup_cipher(ctx, 1);
    crypt_block(ctx, SECRET_KEY, message, cipher);

    MPI_Barrier(MPI_COMM_WORLD);
    double start_time = MPI_Wtime();
    setup_cipher(ctx, 0);

    uint64_t found = UINT64_MAX;
    uint64_t global_found = UINT64_MAX;
    uint64_t offset = 0;
    int active = 1;

    while (active) {
        uint64_t local_found = UINT64_MAX;

        if (offset < count) {
            uint64_t candidate = start + offset;
            crypt_block(ctx, candidate, cipher, plain);
            if (is_valid_candidate(plain)) {
                local_found = candidate;
            }
            offset++;
        }

        MPI_Allreduce(&local_found, &global_found, 1,
                      MPI_UINT64_T, MPI_MIN, MPI_COMM_WORLD);
        if (global_found != UINT64_MAX) {
            found = global_found;
            break;
        }

        int local_active = offset < count;
        MPI_Allreduce(&local_active, &active, 1,
                      MPI_INT, MPI_LOR, MPI_COMM_WORLD);
    }

    double elapsed = MPI_Wtime() - start_time;

    if (rank == 0) {
        if (found != UINT64_MAX) {
            setup_cipher(ctx, 0);
            crypt_block(ctx, found, cipher, plain);
            printf("Clave encontrada: %" PRIu64 "\n", found);
            printf("Mensaje: ");
            fwrite(plain, 1, MESSAGE_LEN, stdout);
            putchar('\n');
        } else {
            printf("No se encontro la clave.\n");
        }
        printf("Ejecucion: MPI con %d procesos\n", processes);
        printf("Tiempo: %.6f segundos\n", elapsed);
    }

    EVP_CIPHER_CTX_free(ctx);
    MPI_Finalize();
    return EXIT_SUCCESS;
}
