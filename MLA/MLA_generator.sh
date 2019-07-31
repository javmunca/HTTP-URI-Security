#!/bin/sh

# Recibe un fichero "X-raw.uri" (= formato ".clean"): Nº_caracteres URI
# y genera un fichero con el nombre "X.uri" de tipo ".raw" (URI)
# Llamada:
#   MLA_generador.sh   file-raw.uri   [ dir_out_uri ]


# Ejemplo de llamada:
#
#     MLA_generator.sh     00-Raw.uri/access_log-20170108-raw.uri     01-Uri/

# Activar debig:    set -x
# Desactivar debug: set +x

### Configuración. Posible carga externa
if [ -f ./MLA.conf ]; then
    ./MLA.conf
else
    VERSION_MLA_GENERATOR="1.0"		# Version del programa
fi
###########


# Impresion sintaxis si llamada sin argumentos
if [ "$#" -eq 0 ]; then
    printf "\n\nMLA - generator (version %s)\n\n" "${VERSION_MLA_GENERATOR}"
    printf "\n\nConversor de formato \"raw.uri\" a formato URI simple (sin longitid en primera columna).\n\n"
    printf "FORMATO:\n\n"
    printf "   MLA_generador.sh   file-raw.uri   [ dir_salida ]\n\n"
    printf "* \"file-raw.uri\": Ruta del fichero de entrada con el formato \"raw.uri\": Nº_caracteres\tURI\n"
    printf "* \"dir_salida\": directorio donde generar el fichero de salida \"file.uri\" (contiene URIs sin Nº caracteres).\n"
    printf "                Por omisión, en la carpeta actual. Si el fichero de salida ya existe, el programa sale inmediatamente.\n"
    printf "Si el fichero de salida ya existe, se sale inmediatemente.\n\n\n"
    exit 1
fi
#############

### Lectura de Argumentos y Variables Globales

TIMESTAMP_FILES="$(date +%F-%H%M%S)" 			# Para el nombre de los ficheros temporales
TMP="/tmp/lanzador-${TIMESTAMP_FILES}.tmp"		# Fichero de trabajo temporal

IN="$1"					# Fichero "-raw.uri" de entrada

DIROUT="$2"				# Directorio de salida de los ficheros ".uri"
[ "${DIROUT}" = "" ] && DIROUT="./"	# Si no segundo argumento => Dir. actual

OUT="${DIROUT}/$(basename ${IN%-raw.uri}).uri"   #Fichero de salida ".uri"
					    # Se mantiene mismo nombre que a entrada,
					    #quitando su extension "-raw.uri" y añadiendo ".uri"
#OUT="${DIROUT}/URIs-${TIMESTAMP_FILES}.uri"		# Alternativa: Nuevo nombre independiente

#####



### Análisis de los argumentos

[ -f  "${IN}" ] || { echo "No existe el fichero de entrada \"${IN}\". Se sale..." && exit 1; }


if [ -f  "${OUT}" ]; then
    echo "Fichero de salida  \"${OUT}\" ya existe. Se sale..."
    exit 1
else
    echo "Creando fichero de salida \"${OUT}\"..."
    > "${OUT}"
    [ -f  "${OUT}" ] || { echo "No ha sido posible crear el fichero de salida \"${OUT}\". Se sale..." && exit 1; }
fi

#####


## Main(): Varias opciones:

# Mas eficiente
sed -e "s/.*[\ ]//g" "${IN}" > "${OUT}"

# menos eficiente
#while read l; do
#    printf "%s %s" $l | cut -f2- -d" " >> "${OUT}"
#done < "${IN}"

#####
