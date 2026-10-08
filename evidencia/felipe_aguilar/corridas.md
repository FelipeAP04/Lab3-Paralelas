# Evidencia de corridas - Felipe Aguilar

## Compilacion

Comando ejecutado:

```bash
make clean && make
```

Resultado: compilación correcta de los programas secuencial original, mejorado y MPI con `mpicc`, sin warnings.

## Programa secuencial original

```text
$ ./bin/busqueda_clave_aes_secuencial
Clave encontrada: 12345
Mensaje: Puedes lograrlo!
Ejecucion: secuencial
Tiempo: 0.004433 segundos
```

## Programa secuencial mejorado

```text
$ ./bin/busqueda_clave_aes_mejorado
Clave encontrada: 12345
Mensaje: Puedes lograrlo!
Rango: 1048576 candidatas
Ejecucion: secuencial
Tiempo: 0.001246 segundos
```

## Version MPI con 2 procesos

```text
$ mpirun --oversubscribe -np 2 ./bin/busqueda_clave_aes_mpi
Clave encontrada: 12345
Mensaje: Puedes lograrlo!
Rango: 1048576 candidatas
Ejecucion: MPI con 2 procesos
Tiempo: 0.000692 segundos
```

## Version MPI con 3 procesos

```text
$ mpirun --oversubscribe -np 3 ./bin/busqueda_clave_aes_mpi
Clave encontrada: 12345
Mensaje: Puedes lograrlo!
Rango: 1048576 candidatas
Ejecucion: MPI con 3 procesos
Tiempo: 0.000717 segundos
```

## Version MPI con 4 procesos

```text
$ mpirun --oversubscribe -np 4 ./bin/busqueda_clave_aes_mpi
Clave encontrada: 12345
Mensaje: Puedes lograrlo!
Rango: 1048576 candidatas
Ejecucion: MPI con 4 procesos
Tiempo: 0.000719 segundos
```

Todas las ejecuciones recuperaron la misma clave y el mismo mensaje.
