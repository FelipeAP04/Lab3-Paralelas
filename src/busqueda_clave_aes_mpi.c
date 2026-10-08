/*
 * Busqueda de una clave AES con reparto por bloques y Open MPI.
 *
 * Uso: mpirun -np N busqueda_clave_aes_mpi [-k clave] [-n rango] [-m mensaje]
 */

#define _POSIX_C_SOURCE 200809L

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Valores por defecto; se pueden cambiar con -n, -k y -m. */
#define DEFAULT_TOTAL_KEYS (UINT64_C(1) << 20)
#define DEFAULT_SECRET_KEY UINT64_C(12345)
#define DEFAULT_MESSAGE "Puedes lograrlo!"
#define MESSAGE_LEN 16
#define KNOWN_FRAGMENT_LEN 6

/*
 * Candidatas que cada proceso prueba entre dos sincronizaciones.
 * Sincronizar en cada candidata hacia que la comunicacion costara mas
 * que el descifrado; con bloques el costo se reparte.
 */
#ifndef CHECK_INTERVAL
#define CHECK_INTERVAL UINT64_C(4096)
#endif

/* Mensaje de un bloque, completado con espacios si es mas corto. */
struct params {
    uint64_t total_keys;
    uint64_t secret_key;
    unsigned char message[MESSAGE_LEN];
    size_t fragment_len;
};

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

static int is_valid_candidate(const unsigned char *plain,
                              const struct params *p)
{
    if (memcmp(plain, p->message, p->fragment_len) != 0) {
        return 0;
    }

    return memcmp(plain, p->message, MESSAGE_LEN) == 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Uso: mpirun -np N %s [-k clave] [-n rango] [-m mensaje]\n"
            "  -k clave    clave secreta, 0 <= clave < rango (por defecto %" PRIu64 ")\n"
            "  -n rango    cantidad de candidatas a probar (por defecto %" PRIu64 ")\n"
            "  -m mensaje  texto de 1 a %d bytes (por defecto \"%s\")\n",
            program, DEFAULT_SECRET_KEY, DEFAULT_TOTAL_KEYS,
            MESSAGE_LEN, DEFAULT_MESSAGE);
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;

    if (text[0] == '\0' || text[0] == '-') {
        return 0;
    }

    errno = 0;
    *value = (uint64_t)strtoull(text, &end, 10);
    return errno == 0 && *end == '\0';
}

/*
 * Todos los procesos reciben los mismos argumentos y los leen por su
 * cuenta. Devuelve 0 si son invalidos.
 */
static int parse_args(int argc, char **argv, struct params *p)
{
    const char *text = DEFAULT_MESSAGE;
    int option;

    p->total_keys = DEFAULT_TOTAL_KEYS;
    p->secret_key = DEFAULT_SECRET_KEY;

    while ((option = getopt(argc, argv, "k:n:m:h")) != -1) {
        switch (option) {
        case 'k':
            if (!parse_u64(optarg, &p->secret_key)) {
                return 0;
            }
            break;
        case 'n':
            if (!parse_u64(optarg, &p->total_keys)) {
                return 0;
            }
            break;
        case 'm':
            text = optarg;
            break;
        default:
            return 0;
        }
    }

    size_t len = strlen(text);

    if (optind != argc || p->total_keys == 0 ||
        p->secret_key >= p->total_keys ||
        len == 0 || len > MESSAGE_LEN) {
        return 0;
    }

    memset(p->message, ' ', MESSAGE_LEN);
    memcpy(p->message, text, len);
    p->fragment_len = len < KNOWN_FRAGMENT_LEN ? len : KNOWN_FRAGMENT_LEN;
    return 1;
}

int main(int argc, char **argv)
{
    int rank;
    int processes;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &processes);

    struct params p;

    if (!parse_args(argc, argv, &p)) {
        if (rank == 0) {
            usage(argv[0]);
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    uint64_t base = p.total_keys / (uint64_t)processes;
    uint64_t remainder = p.total_keys % (uint64_t)processes;
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
    crypt_block(ctx, p.secret_key, p.message, cipher);

    MPI_Barrier(MPI_COMM_WORLD);
    double start_time = MPI_Wtime();
    setup_cipher(ctx, 0);

    uint64_t found = UINT64_MAX;
    uint64_t offset = 0;

    for (;;) {
        /* local[0]: clave encontrada; local[1]: 1 si ya termino su bloque. */
        uint64_t local[2] = {UINT64_MAX, 0};
        uint64_t global[2];
        uint64_t limit = count - offset < CHECK_INTERVAL
                         ? count : offset + CHECK_INTERVAL;

        for (; offset < limit; offset++) {
            uint64_t candidate = start + offset;
            crypt_block(ctx, candidate, cipher, plain);
            if (is_valid_candidate(plain, &p)) {
                local[0] = candidate;
                break;
            }
        }
        local[1] = offset >= count;

        /*
         * Una sola colectiva por ronda: MPI_MIN da la clave encontrada
         * (o UINT64_MAX) y vale 1 en la segunda posicion solo si todos
         * los procesos terminaron su bloque.
         */
        MPI_Allreduce(local, global, 2, MPI_UINT64_T, MPI_MIN,
                      MPI_COMM_WORLD);
        if (global[0] != UINT64_MAX) {
            found = global[0];
            break;
        }
        if (global[1] == 1) {
            break;
        }
    }

    /* Se reporta el tiempo del proceso mas lento. */
    double local_elapsed = MPI_Wtime() - start_time;
    double elapsed = 0.0;
    MPI_Reduce(&local_elapsed, &elapsed, 1, MPI_DOUBLE, MPI_MAX, 0,
               MPI_COMM_WORLD);

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
        printf("Rango: %" PRIu64 " candidatas\n", p.total_keys);
        printf("Ejecucion: MPI con %d procesos\n", processes);
        printf("Tiempo: %.6f segundos\n", elapsed);
    }

    EVP_CIPHER_CTX_free(ctx);
    MPI_Finalize();
    return EXIT_SUCCESS;
}
