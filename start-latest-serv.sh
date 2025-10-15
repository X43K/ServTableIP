#!/bin/bash

# Obtener el nombre del usuario actual
user=$(whoami)

# Buscar el archivo con la versión más alta
script=$(ls /home/"$user"/ServTableIP/serv-table-ip*.py 2>/dev/null | \
    sed -E 's/.*serv-table-ip-([0-9]+)\.([0-9]+)\.py/\1 \2 &/' | \
    sort -k1,1n -k2,2n | \
    tail -n 1 | \
    awk '{print $3}')

# Verificar que se haya encontrado un archivo válido
if [ -z "$script" ]; then
    echo "No se encontró ningún archivo válido en /home/$user/serv-table-ip/"
    exit 1
fi

# Ejecutar el script con Python
exec /usr/bin/python3 "$script"

