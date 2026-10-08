/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3169 - Computacion Paralela y Distribuida
 * Ejercicio:   Busqueda secuencial de una clave AES mediante fuerza bruta
 * Descripcion: un unico proceso prueba claves candidatas en orden
 *              y compara el mensaje descifrado con el texto original.
 *
 *              Para fines educativos, la busqueda se limita a
 *              1,048,576 candidatas del espacio de claves de AES.
 *              El cifrado utiliza la interfaz EVP de OpenSSL.
 *              Se mide el tiempo transcurrido durante la busqueda.
 *
 * Mejoras sobre la version original:
 *   1. (Fernando Rueda) El contexto de OpenSSL se configura una sola
 *      vez por operacion. En cada candidata solo se cambia la clave.
 *   2. (Felipe Aguilar) Cada candidata se valida primero con un
 *      fragmento conocido y luego con el mensaje completo.
 *   3. (Fernando Hernandez) La clave, el rango y el mensaje se reciben
 *      por linea de comandos:
 *        busqueda_clave_aes_mejorado [-k clave] [-n rango] [-m mensaje]
 *----------------------------------------------------------------------*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
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
 * Parametros de la busqueda. El mensaje ocupa un bloque de 16 bytes;
 * si es mas corto se completa con espacios.
 */
struct params {
    uint64_t total_keys;
    uint64_t secret_key;
    unsigned char message[MESSAGE_LEN];
    size_t fragment_len;
};

/* Muestra el error y termina el programa. */
static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/* Construye una clave AES no aleatoria a partir de la candidata. */
static void make_key(uint64_t candidate, unsigned char key[16])
{
    memset(key, 0, 16);

    for (int i = 0; i < 8; i++) {
        key[15 - i] = (unsigned char)(
            (candidate >> (8 * i)) & UINT64_C(0xFF)
        );
    }
}

/*
 * Configura el contexto para AES-128-ECB sin relleno.
 * encrypt = 1: cifrar; encrypt = 0: descifrar.
 * Se llama una sola vez antes de procesar varias claves, asi
 * OpenSSL no vuelve a buscar el algoritmo en cada candidata.
 */
static void setup_cipher(EVP_CIPHER_CTX *ctx, int encrypt)
{
    if (EVP_CipherInit_ex(
            ctx, EVP_aes_128_ecb(), NULL,
            NULL, NULL, encrypt) != 1) {
        fail("Error al inicializar AES.");
    }

    /* El mensaje ocupa exactamente un bloque, sin relleno. */
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        fail("Error al configurar el relleno.");
    }
}

/*
 * Cifra o descifra un bloque con el contexto ya configurado.
 * Solo se cambia la clave; el algoritmo, la direccion y el relleno
 * se mantienen de setup_cipher (encrypt = -1).
 * ECB se utiliza para un unico bloque educativo.
 */
static void crypt_block(
    EVP_CIPHER_CTX *ctx,
    uint64_t candidate,
    const unsigned char *input,
    unsigned char *output)
{
    unsigned char key[16];
    int written = 0;
    int final_written = 0;

    make_key(candidate, key);

    if (EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, -1) != 1) {
        fail("Error al cambiar la clave.");
    }

    if (EVP_CipherUpdate(
            ctx, output, &written,
            input, MESSAGE_LEN) != 1) {
        fail("Error al procesar el bloque.");
    }

    if (EVP_CipherFinal_ex(
            ctx, output + written, &final_written) != 1) {
        fail("Error al finalizar la operacion AES.");
    }

    if (written + final_written != MESSAGE_LEN) {
        fail("Longitud inesperada del resultado.");
    }
}

/* Compara primero el fragmento conocido y luego el bloque completo. */
static int is_valid_candidate(
    const unsigned char *plain,
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
        "Uso: %s [-k clave] [-n rango] [-m mensaje]\n"
        "  -k clave    clave secreta, 0 <= clave < rango (por defecto %" PRIu64 ")\n"
        "  -n rango    cantidad de candidatas a probar (por defecto %" PRIu64 ")\n"
        "  -m mensaje  texto de 1 a %d bytes (por defecto \"%s\")\n",
        program, DEFAULT_SECRET_KEY, DEFAULT_TOTAL_KEYS,
        MESSAGE_LEN, DEFAULT_MESSAGE);
    exit(EXIT_FAILURE);
}

/* Convierte un entero sin signo de 64 bits y rechaza texto invalido. */
static uint64_t parse_u64(const char *text, const char *program)
{
    char *end = NULL;

    if (text[0] == '\0' || text[0] == '-') {
        usage(program);
    }

    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);

    if (errno != 0 || *end != '\0') {
        usage(program);
    }

    return (uint64_t)value;
}

/* Lee -k, -n y -m; los que no se indiquen usan su valor por defecto. */
static void parse_args(int argc, char **argv, struct params *p)
{
    const char *text = DEFAULT_MESSAGE;
    int option;

    p->total_keys = DEFAULT_TOTAL_KEYS;
    p->secret_key = DEFAULT_SECRET_KEY;

    while ((option = getopt(argc, argv, "k:n:m:h")) != -1) {
        switch (option) {
        case 'k':
            p->secret_key = parse_u64(optarg, argv[0]);
            break;
        case 'n':
            p->total_keys = parse_u64(optarg, argv[0]);
            break;
        case 'm':
            text = optarg;
            break;
        default:
            usage(argv[0]);
        }
    }

    size_t len = strlen(text);

    if (optind != argc || p->total_keys == 0 ||
        p->secret_key >= p->total_keys ||
        len == 0 || len > MESSAGE_LEN) {
        usage(argv[0]);
    }

    memset(p->message, ' ', MESSAGE_LEN);
    memcpy(p->message, text, len);
    p->fragment_len = len < KNOWN_FRAGMENT_LEN ? len : KNOWN_FRAGMENT_LEN;
}

/* Obtiene el tiempo de un reloj monotono, en segundos. */
static double get_time(void)
{
    struct timespec current;

    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
        perror("Error al consultar el reloj");
        exit(EXIT_FAILURE);
    }

    return (double)current.tv_sec +
           (double)current.tv_nsec / 1000000000.0;
}

int main(int argc, char **argv)
{
    struct params p;

    parse_args(argc, argv, &p);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        fail("No se pudo crear el contexto de OpenSSL.");
    }

    unsigned char cipher[
        MESSAGE_LEN + EVP_MAX_BLOCK_LENGTH
    ] = {0};

    unsigned char plain[
        MESSAGE_LEN + EVP_MAX_BLOCK_LENGTH
    ] = {0};

    /*
     * Prepara el mensaje cifrado.
     * La clave secreta solo se utiliza para preparar el ejercicio.
     */
    setup_cipher(ctx, 1);
    crypt_block(ctx, p.secret_key, p.message, cipher);

    uint64_t found = UINT64_MAX;

    /* La medicion comienza despues de preparar el mensaje. */
    double start = get_time();

    setup_cipher(ctx, 0);

    /* Prueba las claves consecutivamente desde cero. */
    for (uint64_t key = 0; key < p.total_keys; key++) {
        crypt_block(ctx, key, cipher, plain);

        /* Primero valida el fragmento y luego el mensaje completo. */
        if (is_valid_candidate(plain, &p)) {
            found = key;
            break;
        }
    }

    double elapsed = get_time() - start;

    if (found != UINT64_MAX) {
        printf("Clave encontrada: %" PRIu64 "\n", found);
        printf("Mensaje: ");
        fwrite(plain, 1, MESSAGE_LEN, stdout);
        putchar('\n');
    } else {
        printf("No se encontro la clave.\n");
    }

    printf("Rango: %" PRIu64 " candidatas\n", p.total_keys);
    printf("Ejecucion: secuencial\n");
    printf("Tiempo: %.6f segundos\n", elapsed);

    EVP_CIPHER_CTX_free(ctx);

    return EXIT_SUCCESS;
}