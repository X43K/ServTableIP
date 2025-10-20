# ServTableIP<br>
<img src="https://raw.githubusercontent.com/X43K/ServTableIP/refs/heads/main/static/Logo.webp">
Crea un servidor con una lista de los dispositivos conectados a tu red

**PROBADO EN RASPBERRY OS y KALI**

<p>INSTALACION:<br>
Descargar, dar permiso de ejecucion y ejecutar INSTALL-serv-table-ip.sh:<br>
**Una vez instalado podemos borrar el instalador<br>
<pre>
wget https://raw.githubusercontent.com/X43K/ServTableIP/refs/heads/main/INSTALL-serv-table-ip.sh
sudo chmod +x INSTALL-serv-table-ip.sh
sudo ./INSTALL-serv-table-ip.sh
rm -r INSTALL-serv-table-ip.sh
</pre>
*Automaticamente descargara el resto de archivos; creara, activara y ejecutara el servicio para que inicie de forma automatica.<br>

**TRAS LA INSTALACION ACCEDA A localhost:5000 Y SIGA LOS PASOS PARA CREAR LAS NUEVAS CREDENCIALES**</p>

<p>ACTUALIZACION:<br>
Dentro del directorio /home/$USER/ServTableIP/ ejecutar UPDATE-serv-table-ip.sh:<br>
<pre>
sudo ./ServTableIP/UPDATE-serv-table-ip.sh
</pre>
*Automaticamente comprueba y descarga los nuevos archivos, eliminando versiones antiguas y/o modificaciones, respetando logs y credenciales. Al terminar, reiniciara el servicio.</p>

**SI VIENE DE UNA VERSION ANTERIOR A 9.0 ACCEDA A localhost:5000 Y SIGA LOS PASOS PARA CREAR LAS NUEVAS CREDENCIALES**</p>

<p>IDIOMAS:<br>
Español</p>

<img src="https://raw.githubusercontent.com/X43K/ServTableIP/refs/heads/main/static/Ejemplo.webp">

<p>**Ahora es posible personalizar desde la interfaz web el "Host", "Tipo", "Icono"y "Color" de manera sencilla e intuitiva.</p>

<img src="https://raw.githubusercontent.com/X43K/ServTableIP/refs/heads/main/static/Ejemplo2.webp">
