#!/usr/bin/env bash
# Verifica que el secuencial original, el mejorado y la version MPI con
# 2, 3 y 4 procesos recuperen la misma clave y el mismo mensaje, y mide
# su tiempo promedio.
#
# Uso: scripts/verificar.sh [clave] [rango] [mensaje]
#
#   Sin argumentos se usan los valores del original (clave 12345, rango
#   2^20). El secuencial original no acepta argumentos, asi que solo se
#   compara cuando se usan esos valores.
#
# Variables de entorno:
#   REPETICIONES  corridas por programa para promediar el tiempo (3)
#   PROCESOS      cantidades de procesos MPI a probar ("2 3 4")
#   MPIRUN_FLAGS  opciones extra para mpirun, p. ej. --oversubscribe

set -euo pipefail

cd "$(dirname "$0")/.."

CLAVE="${1:-12345}"
RANGO="${2:-1048576}"
MENSAJE="${3:-Puedes lograrlo!}"
REPETICIONES="${REPETICIONES:-3}"
PROCESOS="${PROCESOS:-2 3 4}"
MPIRUN_FLAGS="${MPIRUN_FLAGS:-}"

make -s

ARGS=(-k "$CLAVE" -n "$RANGO" -m "$MENSAJE")

# Ejecuta un programa varias veces. Deja la clave y el mensaje de la
# ultima corrida y el tiempo promedio en variables globales.
correr() {
    local suma=0 salida tiempo
    for ((i = 0; i < REPETICIONES; i++)); do
        salida="$("$@")"
        tiempo="$(sed -n 's/^Tiempo: \([0-9.]*\) segundos$/\1/p' <<< "$salida")"
        suma="$(awk -v a="$suma" -v b="$tiempo" 'BEGIN { print a + b }')"
    done
    R_CLAVE="$(sed -n 's/^Clave encontrada: //p' <<< "$salida")"
    R_MENSAJE="$(sed -n 's/^Mensaje: //p' <<< "$salida")"
    R_TIEMPO="$(awk -v s="$suma" -v n="$REPETICIONES" 'BEGIN { printf "%.6f", s / n }')"
}

FALLOS=0
BASE=""

reportar() {
    local nombre="$1" estado="OK" speedup
    if [[ "$R_CLAVE" != "$CLAVE" || "$R_MENSAJE" != "$ESPERADO" ]]; then
        estado="FALLO"
        FALLOS=$((FALLOS + 1))
    fi
    [[ -z "$BASE" ]] && BASE="$R_TIEMPO"
    speedup="$(awk -v b="$BASE" -v t="$R_TIEMPO" 'BEGIN { printf "%.2f", b / t }')"
    printf "| %-22s | %-8s | %-18s | %10s | %7s | %-6s |\n" \
        "$nombre" "$R_CLAVE" "\"$R_MENSAJE\"" "$R_TIEMPO" "$speedup" "$estado"
}

# El mensaje se completa con espacios hasta 16 bytes, igual que en C.
ESPERADO="$(printf "%-16s" "$MENSAJE")"

echo "Clave: $CLAVE  Rango: $RANGO  Mensaje: \"$MENSAJE\"  Repeticiones: $REPETICIONES"
echo "Speedup respecto al mejorado secuencial."
echo
printf "| %-22s | %-8s | %-18s | %10s | %7s | %-6s |\n" \
    "Programa" "Clave" "Mensaje" "Tiempo (s)" "Speedup" "Estado"
echo "|------------------------|----------|--------------------|------------|---------|--------|"

correr ./bin/busqueda_clave_aes_mejorado "${ARGS[@]}"
reportar "Mejorado (secuencial)"

if [[ "$CLAVE" == "12345" && "$RANGO" == "1048576" && "$MENSAJE" == "Puedes lograrlo!" ]]; then
    correr ./bin/busqueda_clave_aes_secuencial
    reportar "Original (secuencial)"
fi

for n in $PROCESOS; do
    # shellcheck disable=SC2086
    correr mpirun $MPIRUN_FLAGS -np "$n" ./bin/busqueda_clave_aes_mpi "${ARGS[@]}"
    reportar "MPI con $n procesos"
done

echo
if ((FALLOS == 0)); then
    echo "Todas las versiones recuperaron la misma clave y el mismo mensaje."
else
    echo "$FALLOS version(es) no recuperaron la clave o el mensaje esperado."
    exit 1
fi
