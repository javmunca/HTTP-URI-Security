#!/bin/sh

####  MLA_launcher.sh  #################
# Recibe un fichero de texto de entrada con URIs (x.uri)  y:
# 1) Genera (en la carpeta indicada como segundo argumento, local por defecto) un fichero
#    con la extension "x.time" con la sintaxis: [TimeStamp]\t[URI]
# 2) Lanza esas URIs contra el servidor Web (configurar la variable "SERVERURL")
# 3) Extrae el log generado "modsec_audit.log" y lo copia en la carpeta del tercer argumento como "x.log"


# Llamada:   MLA_launcher.sh    fichero.uri    dir_out_time    dir_out_log
# + "fichero.uri": Fichero de texto ".uri" con lista de URIs a analizar. Cada linea: URI
# + "dir_out_time": directorio donde generar "fichero.time". Cada linea: [TimeStamp]\tURI
# + "dir_out_log": directorio donde guardar el log (modsec_Audit.log) generado por Apache como "fichero.log"


# Ejemplo de llamada:
#
#     MLA_launcher.sh     01-Raw/URIs-20190907_203640.uri     02A-Time/   02B-Log/

########################################33


### Configuración. Posible carga externa
if [ -f ./MLA.conf ]; then
    ./MLA.conf
else
    SERVERURL="http://localhost"	# Parte de Servidor de la URL (a la que se añaden las URIs)
					# para generar las URLs completas lanzadas contra APache
				        #IMPORTANTE: No poner "/" final para no provocar una doble "//"
    VERSION_MLA_LAUNCHER="1.0"		# Version del programa

    MODSEC_CONF="/etc/httpd/owasp-modsecurity-crs/crs-setup.conf"	# Fichero de configuracion de CRS

    # Ubicacion ficheros de logs de Mod_Security
    DIR_MODLOG="/var/log/httpd"
    MODLOG="${DIR_MODLOG}/modsec_audit.log"
    BCK_MODLOG="${MODLOG}-bck"

    # CADENAS IMPRESION EN "fichero.index"
    # 1) Separadores: Corchetes
    Si="["
    Sf="]"
    TAB="$(printf \\t)"
    # 2) Textos
    TIMESTAMP_IMP="TimeStamp"
    URI_IMP="Uri"
    PLMin_IMP="PLmin"
    SCORE_IMP="Score"
    NATAQUES_IMP="Nattacks"

fi
#####

# Impresion sintaxis si llamada sin argumentos
if [ "$#" -ne 3 ]; then
    printf "\n\nMLA - launcher (version %s)\n\n" "${VERSION_MLA_LAUNCHER}"
    printf "FORMATO:\n\n"
    printf "   MLA_launcher.sh    fichero.uri    dir_out_time    dir_out_log\n"
    printf "* \"fichero.uri\": Fichero de texto \".uri\" con lista de URIs a analizar. Cada linea: URI\n"
    printf "* \"dir_out_time\": directorio donde generar \"fichero.time\". Cada linea: [TimeStamp]\tURI\n"
    printf "* \"dir_out_log\": directorio donde guardar el log (modsec_Audit.log) generado por Apache como \"fichero.log\"\n"
    printf "Si algún fichero de salida ya existe, el programa sale inmediatamente.\n\n\n"
    exit 1
fi
#############


### Lectura de Argumentos y Variables Globales

TIMESTAMP_FILES="$(date +%F-%H%M%S)" 			# Para el nombre de los ficheros temporales
TMP="/tmp/lanzador-${TIMESTAMP_FILES}.tmp"		# Fichero de trabajo temporal

IN="$1"					# Fichero con URIs de entrada

DIROUT_TIME="$2"				# Directorio de salida ".time"
#[ "${DIROUT_TIME}" = "" ] && DIROUT_TIME="./"	# Si no segundo argumento => Dir. actual
OUT_TIME="${DIROUT_TIME}/$(basename ${IN%.*}).time"   #Fichero de salida
					    # Se mantiene mismo nombre que a entrada,
					    #quitando su extension y añadiendo ".time"
#OUT="${DIROUT}/URIs-${TIMESTAMP_FILES}.time"		# Alternativa: Nuevo nombre independiente

DIROUT_LOG="$3"				# Directorio de salida ".log"
#[ "${DIROUT_LOG}" = "" ] && DIROUT_LOG="./"	# Si no segundo argumento => Dir. actual
OUT_LOG="${DIROUT_LOG}/$(basename ${IN%.*}).log"   #Fichero de salida
					    # Se mantiene mismo nombre que a entrada,
					    #quitando su extension y añadiendo ".log"
#####


### Análisis de los argumentos

[ -f  "${IN}" ] || { echo "No existe el fichero de entrada \"${IN}\". Se sale..." && exit 1; }


if [ -f  "${OUT_TIME}" ]; then
    echo "Fichero de salida  \"${OUT_TIME}\" ya existe. Se sale..."
    exit 1
elif [ -f  "${OUT_LOG}" ]; then
    echo "Fichero de salida  \"${OUT_LOG}\" ya existe. Se sale..."
    exit 1
else
    echo "Creando ficheros de salida:"

    echo "+ \"${OUT_TIME}\"..."
    > "${OUT_TIME}"
    [ -f  "${OUT_TIME}" ] || { echo "No ha sido posible crear el fichero de salida \"${OUT_TIME}\". Se sale..." && exit 1; }

    echo "+ \"${OUT_LOG}\"..."
    > "${OUT_LOG}"
    [ -f  "${OUT_LOG}" ] || { echo "No ha sido posible crear el fichero de salida \"${OUT_LOG}\". Se sale..." && exit 1; }

fi

#####


### Funciones


# Problemas para obtener la linea del fichero de entrada ".time" asociada a la URI de una transaccion en el Log, sin ambigüedad:
# * Buscando la cadena "URI": no es suficiente con que no haya URIs duplicadas en el fichero de entrada, pues en el fichero de logs
#                             pueden seguir apareciendo varias transacciones para la misma URI de otro fichero de entrada.
# * Añadiendo TimeSTamp junto a la URI: dicho timestamp debe ser identico al del fichero de log. El problema es que varias URIs
#                                       tienen asignadao el mismo timestamp (modsec_audit.log usa precision de segundos)

# Soluciones:
# 1) Añadir a "modsec_audit.log" precision de milisegundos: NO configurable
# 2) Buscar la URI asociada por "TimeStamp" y "URI"

# Genera fichero de salida con URIs y TimeStamp (usado para asociar URIs de log con URIs de entrada)
# Se basa en el fichero de logs: modsec_audit.log
# Llamada: anadirUriTime  URI
anadirUriTime()
{
    uriA="$1"

    # Marca de tiempo en (hay que añadirla exactamente igual, el formato es configurable con "LogFormat" y "CustomLog"):
    
    # mod_audit: [08/Jul/2019:19:10:14 +0200]	<== Usamos este!
    #	$(date "+%d/%b/%Y:%H:%M:%S %z")
    # error_log: [Tue Jul 09 21:37:40.197928 2019]
    TIMESTAMP_MODAUDIT="${Si}$(date "+%d/%b/%Y:%H:%M:%S %z")${Sf}"
    printf "%s\t%s" "${TIMESTAMP_MODAUDIT}" "${uriA}" >> "${OUT_TIME}"
    
    # Añadimos Newline final
    printf "\n" >> "${OUT_TIME}"
}


# Genera el mensaje HTTP contra Apache ModSecurity para que lo analice
# Llamada: generarMensajeHTTP  URI
generarMensajeHTTP()
{
    uriM="$1"
    curl "${SERVERURL}${uriM}"  >/dev/null  2>&1
}

#####





### Main()

# 0) Se indica el PL (Paranoia Level) actualmente configurado
PL=$(cat "${MODSEC_CONF}" | grep -v -e "^\#" | grep "setvar:tx.executing_paranoia_level" | cut -f2 -d "=" | cut -f1 -d "\"")
printf "\n\nNivel de Paranoia (PL) actualmente configurado en CRS Mod Security: ${PL}\n\n"


# 1) Desplazando fichero de logs actual de ModSecurity
# No se puede hacer, pache seguiría escribiendo en el ".bck" (usa el ID del fichero) hasta hacerle un "restart"
#mv "${MODLOG}" "${BCK_MODLOG}" 1>/dev/null 2>&1

# Generando nuevo fichero de logs vacio
printf "Vaciando (temporalmente) fichero de logs de Mod Security  \"${MODLOG}\"...\n\n"
> "${MODLOG}"
[ -f  "${MODLOG}" ] || { echo "No ha sido posible vaciar el fichero de salida \"${MODLOG}\". Se sale..." && exit 1; }


# 2) Se analiza el fichero de entrada linea a linea,
#    Asegurando fichero de entrada termina en 1 y solo 1 Intro (para que "read" la lea y no lea linea sin URI)
#    Y eliminar lineas vacias
NTOTAL_ENTRADAS="$(wc -l "${IN}" | cut -f1 -d " ")"		# No se eliminan lineas vacias (para que coincidan numeros de linea de URIs)
lineaInputActual=0		# Linea del fichero de entrada a analizar

printf "Generando \"${OUT_TIME}\" y Enviando solicitudes HTTP a Apache Mod Security para su analisis (${MODLOG})...\n\n"

cp "${IN}" "${TMP}"
printf "\n" >> "${TMP}"					# 1º Añadir Intro final para asegurar lectura de ultima URI
#printf %s "$(cat "${IN}")" > "${IN}"			# Opuesto: Eliminar ultimo "\n" si existe
sed -i '/^$/d' "${TMP}"					# 2º Eliminar lineas vacias
# 3º Eliminar líneas (uris) repetidas e insertar resultado en bucle <== Desactivado, interesa MISMO analisis "Inspector Log"
#cat -n "${TMP}" | sort -uk2 | sort -nk1 | cut -f2- | while read uri; do
while read uri; do
    # Se DESACTIVAN comprobaciones para acelerar
    #uri=$(printf "%s" $uri | xargs)		    		     # Se eliminan posibles espaciados anteriores a la URI
    #[ $(printf "%s" "${uri}" | cut -c1) != "/" ] && uri="/${uri}"    # Se asegura que el primer caracter de la uri es "/", si no se añade

    lineaInputActual=$((lineaInputActual+1))		# Incrementamos contador de lectura

    # Imprimimos en pantalla la uri que esta actualmente siendo analizada (progreso)
    #printf "\n(%s/%s)\t%s\t%s\t"  "${lineaInputActual}"  "${NTOTAL_ENTRADAS}"   "${uri}"
    #Para acelerar, solo imprimimos el numero (cambiante en la misma posición)
    # Opcion 1:
    #tput sc; tput el		# Guardamos posicion cursor y borramos linea
    #printf "(%s/%s)"  "${lineaInputActual}"  "${NTOTAL_ENTRADAS}"
    #tput rc			# Recuperamos posicion cursor
    # Opcion 2 (mas eficiente, menos comandos):
    printf "\r                                          "
    printf "\r(%s/%s)"  "${lineaInputActual}"  "${NTOTAL_ENTRADAS}"

    # Añadimos entradas a los ficheros de salida
    anadirUriTime  	"${uri}"	# Se añade linea a "fichero.time"
    generarMensajeHTTP  "${uri}"	# Se envia mensaje HTTP con la URI a Apache (Mod Security) para que lo analice
done < "${TMP}"
rm -f "${TMP}"  >/dev/null  2>&1


# 3) Recoger el fichero de log generado
printf "\n\nGuardando el fichero de log generado como \"${OUT_LOG}\"...\n\n"
sleep 1 # Esperamos a que Apache termine de escribir en el log
cp -f "${MODLOG}" "${OUT_LOG}"



# 4)  Restaurando fichero de logs original de ModSecurity
#mv "${BCK_MODLOG}" "${MODLOG}" 1>/dev/null 2>&1

#####
