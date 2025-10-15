ACTUALIZACION TERMINADA!!!


si es la primera vez que ves el siguiente mensaje...
POR SEGURIDAD SE RECOMIENDA:

Editar el archivo "credservpas.xk" con nano, vin, etc..
el usuario (primera fila)
y la contraseña (segunda fila)

Por defecto:
root
1234

Igualmente se mantiene un acceso de respaldo en caso de error
o falta del archivo "credservpas.xk" con:
usuario "admin"
contraseña "admin"
*estas credenciales solo se activan en caso de faltar
o fallar el archivo en cuestion.


RECUERDA reiniciar el servicio una vez realizados cambios en
el archivo "serv-table-ip-*.py con el comando:

sudo systemctl restart serv-table-ip.service

PARA ACCEDER AL SERVICIO ACCEDE A:
http://localhost:5000  (para remoto sustituir "localhost" por la IP)



