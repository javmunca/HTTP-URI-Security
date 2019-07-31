#!/bin/sh

####  MLA_detector.sh  (Modsecurity Log Analizer) #################
# Recibe los ficheros "fichero.time" y "fichero.index", devolviendo:
# * "fichero.attacks": Lista de URIs    identificadas como ataques (trafico de ataque).
# * "fichero.clean":   Lista de URIs NO identificadas como ataques (trafico limpio).

# Llamada:   MLA_detector.sh    fichero.time    dir_index   dir_out_attacks   dir_out_clean
# + "fichero.time": Fichero de texto ".time". Cada linea:  [Timestamp]\tURI
# + "dir_out_index": Directorio en el que buscar "fichero.log"
# + "dir_out_attacks": Directorio donde generar el fichero de ataques "fichero.attacks"
# + "dir_out_clean":   Directorio donde generar el fichero de tráfico limpio "fichero.clean"
# Mismo nombre que fichero de entrada "fichero.time" cambiando la extensión

# Ejemplo de llamada:
#
#     MLA_detector.sh    02-Time/URIs-20190907_203640.time     03-Index/   04A-Attacks/    04B-Clean/

########################################33


### Configuración. Posible carga externa
if [ -f ./MLA.conf ]; then
    ./MLA.conf
else
    VERSION_MLA_DETECTOR="1.0"			# Version del programa

    # CADENAS IMPRESION EN "fichero.index"
    # 1) Separadores: Corchetes
    Si=" ["
    Sf="]"
    # 2) Textos
    PAQUETE_IMP="Packet"
    TIMESTAMP_IMP="TimeStamp"
    URI_IMP="Uri"
    PLMin_IMP="PLmin"
    SCORE_IMP="Score"
    NATAQUES_IMP="Nattacks"
fi
#####

# Impresion sintaxis si llamada sin argumentos
if [ "$#" -ne 4 ]; then
    printf "\n\nMLA_detector  (version %s)\n\n" "${VERSION_MLA_DETECTOR}"
    printf "Recibe los ficheros \"fichero.time\" y \"fichero.index\", devolviendo:\n"
    printf "* \"fichero.attacks\": Lista de URIs    identificadas como ataques (trafico de ataque).\n"
    printf "* \"fichero.clean\":   Lista de URIs NO identificadas como ataques (trafico limpio).\n\n"
    printf "FORMATO:\n\n"
    printf "    MLA_detector.sh    fichero.time    dir_index   dir_out_attacks   dir_out_clean\n\n"
    printf "* \"fichero.time\": Fichero de texto \".time\". Cada linea:  [Timestamp]\tURI\n"
    printf "* \"dir_out_index\": Directorio en el que buscar \"fichero.log\"\n"
    printf "* \"dir_out_attacks\": Directorio donde generar el fichero de ataques \"fihcero.attacks\"\n"
    printf "* \"dir_out_clean\":   Directorio donde generar el fichero de tráfico limpio \"fihcero.clean\"\n\n"
    printf "Mismo nombre que el fichero de entrada \"fichero.time\" cambiando la extensión.\n"
    printf "Si algún fichero de salida ya existe, se sale inmediatemente.\n\n\n"
    exit 1
fi
#############

### Lectura de Argumentos y Variables Globales

TAB="$(printf \\t)"
TIMESTAMP_FILES="$(date +%F-%H%M%S)" 			# Para el nombre de los ficheros temporales
TMP="/tmp/lanzador-${TIMESTAMP_FILES}.tmp"		# Fichero de trabajo temporal

IN_TIME="$1"					# Fichero de entrada "fichero.time"

DIRIN_INDEX="$2"				# Directorio de entrada ".index"
#[ "${DIINT_INDEX}" = "" ] && DIRIN_INDEX="./"	# Si no segundo argumento => Dir. actual
IN_INDEX="${DIRIN_INDEX}/$(basename ${IN_TIME%.*}).index"   #Fichero de salida
					    # Se mantiene mismo nombre que a entrada,
					    #quitando su extension y añadiendo ".index"

DIROUT_ATTACKS="$3"				# Directorio de salida ".attacks"
#[ "${DIROUT_ATTACKS}" = "" ] && DIROUT_ATTACKS="./"	# Si no segundo argumento => Dir. actual
OUT_ATTACKS="${DIROUT_ATTACKS}/$(basename ${IN_TIME%.*}).attacks"   #Fichero de salida de ATAQUES
					    # Se mantiene mismo nombre que a entrada,
					    #quitando su extension y añadiendo ".attacks"

DIROUT_CLEAN="$4"				# Directorio de salida ".clean"
#[ "${DIROUT_CLEAN}" = "" ] && DIROUT_CLEAN="./"	# Si no segundo argumento => Dir. actual
OUT_CLEAN="${DIROUT_CLEAN}/$(basename ${IN_TIME%.*}).clean"   #Fichero de salida de trafico LIMPIO
					    # Se mantiene mismo nombre que a entrada,
					    #quitando su extension y añadiendo ".clean"
#####



# Patrones para buscar datos de interes en "fichero.index"
# ID Regla
PATRONIDinicio='[id "'
PATRONIDfin='"]'

# Score Reglas
PATRONSCOREinicio='[msg "Incoming Anomaly Score: '
PATRONSCOREfin='"]'


# Contadores globales para Cabecera resumen en "fichero.attacks"
num_uris=0				# Numero de URIs analizadas
num_clean=0				# Idem son ataques
num_ataques=0				# Idem estan limpias

#####


### Análisis de los argumentos
[ -f  "${IN_TIME}" ] || { echo "No existe el fichero de entrada \"${IN_TIME}\". Se sale..." && exit 1; }
[ -f  "${IN_INDEX}" ] || { echo "No existe el fichero de entrada \"${IN_INDEX}\". Se sale..." && exit 1; }


if [ -f  "${OUT_ATTACKS}" ]; then
    echo "Fichero de salida  \"${OUT_ATTACKS}\" ya existe. Se sale..."
    exit 1
elif [ -f  "${OUT_CLEAN}" ]; then
    echo "Fichero de salida  \"${OUT_CLEAN}\" ya existe. Se sale..."
    exit 1
else
    echo "Creando ficheros de salida \"${OUT_ATTACKS}\" y \"${OUT_CLEAN}\"..."
    > "${OUT_ATTACKS}"
    > "${OUT_CLEAN}"
    [ -f  "${OUT_ATTACKS}" ] || { echo "No ha sido posible crear el fichero de salida \"${OUT_ATTACKS}\". Se sale..." && exit 1; }
    [ -f  "${OUT_CLEAN}"   ] || { echo "No ha sido posible crear el fichero de salida \"${OUT_CLEAN}\". Se sale..."   && exit 1; }
fi

#####


### Funciones

# Imprime resumen del analisis (en fichero de ataques)
# Llamada: imprimirCabeceraResumenAtaques
insertarCabeceraResumenAtaques()
{
    #sed -i '1iCABECERA' fichero
    IMPRIMIR1="---------------------- Statistics of URIs analyzed------------------------"
    IMPRIMIR2="[${num_uris}] input, [${num_clean}] clean, [${num_ataques}] attacks"
    IMPRIMIR3="--------------------------- Analysis results -----------------------------"
    sed -i "1i$IMPRIMIR3"  "${OUT_ATTACKS}"
    sed -i "1i$IMPRIMIR2"  "${OUT_ATTACKS}"
    sed -i "1i$IMPRIMIR1"  "${OUT_ATTACKS}"

    # Imprimimos en pantalla la finalizacion del analisis de eset fichero (imprimiendo el fichero de ataque generado)
    echo "${IMPRIMIR2}"
    echo "\\ ${OUT_ATTACKS}"
}

# Imprime linea de ataque
# Llamada: imprimirAtaque  linea   resto_datos_ataque
imprimirAtaque()
{
    # Lectura de argumentos
    lineaF="$1"
    restoDatosAtaque="$2"

    # Variables de impresion
    PAQUETE="${PAQUETE_IMP}${Si}${lineaF}${Sf}"					# Numero_linea_en_input

    # Impresion
    # "restoDatosAtaque" ya empieza por tabulacion (por eso no se pone "\t")
    printf "%s%s"   "${PAQUETE}"  "${restoDatosAtaque}"	>> "${OUT_ATTACKS}"
    printf \\n  						>> "${OUT_ATTACKS}"
}

# Imprime linea de URI limpia
# Llamada: imprimirLimpio  uri
imprimirLimpio()
{
    # Lectura argumentos
    uriF=$(printf "%s" "$1" | xargs)		    		     # Se eliminan posibles espaciados anteriores a la URI

    # Variables de impresion
    NCARACT="$(($(echo "${uriF}" | wc -c)-1))"				# Numero caracteres de la URI ("-1" por el EOF)
    URILIMP="${uriF}"							# URI LIMPIA

    # Impresion
    printf "%s\t%s"   "${NCARACT}"  "${URILIMP}" >> "${OUT_CLEAN}"
    printf \\n  				 >> "${OUT_CLEAN}"
}


# Busca la URI (y su TimeStamp) en "fichero.index"
# (se invoca 1 vez por cada linea del fichero de entrada)
# Llamada: buscarUriEnIndex  timestamp   URI   lineaFicheroEntrada
# Salida: Añade linea en fichero de Ataques (URI_ENCONTRADO) o de Trafico Limpio (otro caso)
buscarUriEnIndex()
{
    # Lectura de argumentos: Datos del fichero de entrada (URIs con TimeStamp)
    timestampUriF="$1"		# TimeStamp de la URI en el fichero de entrada
    uriF="$2"			# URI de entrada a analizar
#   uriF=$(printf "%s" "$2" | xargs)		    		     # Se eliminan posibles espaciados anteriores/posteriores a la URI
    lineaInput="$3"		# Linea del fichero de entrada (time) en que se encuentra esa URI
    
    # Imprimimos en pantalla la entrada que esta actualmente siendo analizada (progreso)
    #printf "\n(%s/%s)\t%s\t%s\t"  "${lineaInput}"  "${NTOTAL_ENTRADAS}"   "${timestampUriF}"   "${uriF}"
    #Para acelerar, solo imprimimos el numero (cambiante en la misma posición)
    # Opcion 1:
    #tput sc; tput el		# Guardamos posicion cursor y borramos linea
    #printf "(%s/%s)"  "${lineaInput}"  "${NTOTAL_ENTRADAS}"
    #tput rc			# Recuperamos posicion cursor
    # Opcion 2 (mas eficiente, menos comandos):
    printf "\r                                          "
    printf "\r(%s/%s)"  "${lineaInput}"  "${NTOTAL_ENTRADAS}"

#echo; echo "URI: $uriF"	####
	    			####
#sleep 2			# Descomentar si se quiere una pausa entra cambios de URIs analizadas
				####
				####

    # Incrementamos el contador global con el numero de URIs analizadas
    num_uris="$((num_uris+1))"

    # Variables de analisis
    ATAQUE=""				# Nada encontrado inicialmente

    # Buscamos la "URI+TimeSTamp" indicada en "fichero.index"
    # Solo la primera coincidencia (por si hay URIs repetidas, incluso con el mismo TimeStamp)
    BUSCAR="$(printf "${TIMESTAMP_IMP}${Si}%s${Sf}\t${URI_IMP}${Si}%s${Sf}" "${timestampUriF}" "${uriF}")"
    ATAQUE=$(stdbuf -oL grep -F -- "${BUSCAR}" ${IN_INDEX} | head -n1)
    # QUITAMOS el TimeStamp a la linea del ataque
    ATAQUE=${ATAQUE#*]}

    # TRAS ANALIZAR "fichero.index" en busca de esta Uri
    if [ -z "${ATAQUE}" ]; then
	# URI NO encontrada en logs => Trafico LIMPIO
	imprimirLimpio   "${uriF}"
	
	# Incrementamos el contador global con el numero de URIs limpias
	num_clean="$((num_clean+1))"

        # Imprimimos resultados en pantalla
	printf "%s"  "(OK -> Limpio)"

    else
        # URI SI encontrada        => Trafico de ATAQUE
        imprimirAtaque  "${lineaInput}"   "${ATAQUE}"

        # Incrementamos el contador global con el numero de URIs de ataque detectadas
        num_ataques="$((num_ataques+1))"

        # Imprimimos resultados en pantalla
        printf "%s"  "(OK -> Ataque)"
    fi
}
#####





### Main()

# Impresion del comienzo del analisis
#NTOTAL_ENTRADAS="$(sed '/^$/d' "${IN}" | wc -l | cut -f1 -d " ")"		# No se cuentan las lineas vacias
NTOTAL_ENTRADAS="$(wc -l "${IN_TIME}" | cut -f1 -d " ")"		# No se eliminan lineas vacias (para que coincidan numeros de linea de URIs)

# Cada URI del fichero de entrada ".time" (IN_TIME) es buscada en "fichero.index".
# Cuando se encuentra, se inserta la URI en "fichero.attacks" (si se encuentra) o "fichero.clean" (si no)

if [ ! -s "${IN_INDEX}" ]; then		# Si "fichero.index" esta vacio (ningun ataque detectado)
    # PARA ACELERAR: Si ningun ataque => ".attacks" sin ataque y ".clean=-raw.uri"
    num_uris="${NTOTAL_ENTRADAS}"
    num_ataques="0"
    num_clean="${num_uris}"

    # PROVISIONAL, para acelerar!!!
    DIRIN_RAWURI="00-Raw.uri"
    IN_RAWURI="${DIRIN_RAWURI}/$(basename ${IN_TIME%.*})-raw.uri"   #Fichero de salida
    cp ${IN_RAWURI} ${OUT_CLEAN}
    # Cambiamos el espacio entre "Nº caracteres" y "URI" por tabulacion
    sed -i -e "s/\ /${TAB}/g" ${OUT_CLEAN}
    printf \\n > ${OUT_ATTACKS}
    echo ${IN_RAWURI}
    
else				# Si se han detectado ataques
    printf "\n\nAnalizando el fichero de entrada \"%s\" (Total entradas %s):\n" "${IN_TIME}" "${NTOTAL_ENTRADAS}"
    lineaInputActual=0		# Linea del fichero de entrada a analizar
    while read lineaTimeUri; do

	# Extraemos campos de la linea actual del fichero de entrada
        lineaInputActual=$((lineaInputActual+1))		# Incrementamos contador de lectura
	TAB="$(printf \\t)"
        timestampUri=$(printf "%s" "${lineaTimeUri}" | cut -f1 -d"${TAB}" | cut -f1 -d"]" | cut -f2 -d"[")		# TimeSTamp en "fichero.time"
	uri=$(printf "%s" "${lineaTimeUri}" | cut -f2 -d"${TAB}")			# URI en "fichero.time"

        # Buscamos esa Uri leida (con su TimeStamp) en "fichero.index"
        [ -n "${uri}" ] && buscarUriEnIndex  "${timestampUri}"   "${uri}"    "${lineaInputActual}"
        # FORMATOS Esperados:
        # * "timestampUri": leido de la primera columna del fichero de entrada ".time", incluye corchetes como delimitadores
        #    (en modsec_audit.log tambien estan los corchetes, por lo que se mantienen)		[11/Jul/2019:12:05:46 +0200]
        # "uri": leido de la segunda columna del fichero de entrada ".time". Se espera que comience por "/"
    done < "${IN_TIME}"
fi

printf \\n

# Tras analizar todas las URIs de entrada, se imprime la CABECERA resumen
insertarCabeceraResumenAtaques
#####
