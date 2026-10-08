# Compilacion del Laboratorio 03 (CC3069)
# En Linux basta con libssl-dev. En macOS se usa el OpenSSL de Homebrew.

CC      = gcc
MPICC   = mpicc
CFLAGS  = -std=c11 -O2 -Wall -Wextra
LDLIBS  = -lcrypto

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null)
  CFLAGS  += -I$(OPENSSL_PREFIX)/include
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

BIN = bin
SRC = src

PROGRAMAS = $(BIN)/busqueda_clave_aes_secuencial \
			$(BIN)/busqueda_clave_aes_mejorado \
			$(BIN)/busqueda_clave_aes_mpi

all: $(PROGRAMAS)

$(BIN):
	mkdir -p $(BIN)

$(BIN)/busqueda_clave_aes_secuencial: $(SRC)/busqueda_clave_aes_secuencial.c | $(BIN)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

$(BIN)/busqueda_clave_aes_mejorado: $(SRC)/busqueda_clave_aes_mejorado.c | $(BIN)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

$(BIN)/busqueda_clave_aes_mpi: $(SRC)/busqueda_clave_aes_mpi.c | $(BIN)
	$(MPICC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(BIN)

.PHONY: all clean
