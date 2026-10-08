# Laboratorio 03 - Búsqueda de clave AES con Open MPI

CC3069 Computación Paralela y Distribuida, UVG, ciclo 2 de 2026.

## Integrantes

- Fernando Rueda
- Felipe Aguilar
- Fernando Hernández

## Estructura

```
src/          programas en C (original, mejorado y MPI)
evidencia/    capturas de compilación y ejecución, una carpeta por integrante
INFORME.md    respuestas a los ejercicios
```

## Compilación y ejecución

En Ubuntu/WSL:

```bash
sudo apt update
sudo apt install libssl-dev openmpi-bin libopenmpi-dev
make
./bin/busqueda_clave_aes_secuencial
```

En macOS: `brew install openssl@3 open-mpi` y luego `make`.

El programa mejorado y la versión MPI aceptan la clave, el rango y el mensaje
(de 1 a 16 bytes) por línea de comandos. Si no se indican, usan los valores del
original: clave 12345, rango 2^20 y `"Puedes lograrlo!"`.

```bash
./bin/busqueda_clave_aes_mejorado -k 999999 -n 1048576 -m "Hola MPI"
mpirun -np 4 ./bin/busqueda_clave_aes_mpi -k 999999 -n 1048576 -m "Hola MPI"
```

## Orden de commits

Cada integrante hace sus commits seguidos y hace pull antes de empezar.

| # | Integrante | Commit |
|---|---|---|
| 1 | Fernando Rueda | Estructura inicial y programa secuencial original |
| 2 | Fernando Rueda | Mejora 1: contexto de OpenSSL configurado una sola vez |
| 3 | Fernando Rueda | Informe: investigación AES (1a, 1b) y mejora 1 |
| 4 | Felipe Aguilar | Mejora 2: verificar candidatas con un fragmento conocido |
| 5 | Felipe Aguilar | Versión MPI con reparto por bloques y terminación coordinada (4a) |
| 6 | Felipe Aguilar | Informe: diagrama de flujo (1c), análisis (2), mejora 2 y diseño MPI |
| 7 | Fernando Hernández | Mejora 3: clave, rango y mensaje por línea de comandos |
| 8 | Fernando Hernández | Medición con MPI_Wtime y script de verificación |
| 9 | Fernando Hernández | Informe: errores conceptuales (3a), mejora 3 y speedup (4b) |
| 10-12 | Los tres | Evidencia de sus corridas en `evidencia/<nombre>/` |

Las corridas de evidencia son las mismas para todos: compilación y ejecución del
secuencial original, del mejorado y de la versión MPI con 2, 3 y 4 procesos.
