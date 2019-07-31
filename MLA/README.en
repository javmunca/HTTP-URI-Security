

                                          Modsecurity Log Analyzer (MLA)
                                                 Copyright (C) 2019
                                             Fco. Javier Muñoz Calle

                                              Version 2.0 - 25/07/2019

                                                 README - Spanish
------------------------------------------------------------------------------------------------------------------------------------------

CHANGELOG v1.0 (Fco. Javier Muñoz Calle)

- Primera versión funcional

CHANGELOG v2.0 (Fco. Javier Muñoz Calle)

- Optimización del sistema de búsqueda mediante la creación de "resúmenes" (ficheros.index) de los ficheros de log.



COMPILACION

* PREREQUISITOS

- Es necesario un sistema linux con los paquetes básicos de trabajo en shell-script. En principio cualquier distribucion linux es compatible.


* INSTALACION

- No requiere compilación (POSIX Shell-script).

-----------------------------------------------

FUNCIONAMIENTO

El programa analiza las URIs indicadas en el fichero de entrada y las busca en los ficheros trazas (logs) tipo "modsec_audit.log" (ModSecurity),
inidcando si son detectadas como ataques (alertas asociadas).

Para ello, la herramienta consta de 4 aplicaciones. Para cada una se indica:

a) Descripción
b) E/S: Entrada -> Salida
c) Sintaxis (de llamada)

Posteriormente se describen en mayor detalle los formatos de los distintos tipos de ficheros empleados.

#########
1) MLA_generator.sh

a) Descripción: Recibe un fichero "X-raw.uri" (= formato ".clean")
  y genera un fichero con el nombre "X.uri" de tipo ".raw" (URI)

b) E/S: file-raw.uri -> file.uri

c) Sintaxis:
   MLA_generador.sh   file-raw.uri   [ dir_out_uri ]

    * "file-raw.uri": Fichero de texto "-raw.uri" con lista de URIs a analizar.
    * "dir_out_uri": Carpeta donde guardar el fichero de salida "file.uri" (local por defecto).
#########


#########
2) MLA_launcher.sh

a) Descripción: Recibe un fichero de texto de entrada con URIs (file.uri)  y:
   * Genera (en la carpeta indicada como segundo argumento, local por defecto) un fichero
     de tipo ".time" (asocia TimeStamp a URI).
   * Lanza esas URIs contra el servidor Web (variable "SERVERURL" por omisión "http://localhost/")
   * Extrae el log generado "modsec_audit.log" y lo copia en la carpeta del tercer argumento como "file.log"

b) E/S: file.uri -> file.time, file.log

c) Sintaxis:
   MLA_launcher.sh    file.uri    dir_out_time    dir_out_log

   * "file.uri": Fichero de texto ".uri" con lista de URIs a analizar.
   * "dir_out_time": directorio donde generar el fichero "file.time".
   * "dir_out_log": directorio donde guardar el log (modsec_Audit.log) generado por Apache como "file.log"
#########


#########
3) MLA_analyzer.sh

a) Descrición: Recibe un fichero de entrada ".log" (formato modsec_audit.log) y lo procesa generando
   un fichero de resumen ".index" con los ataques registrados en el log.

b) E/S: file.log -> file.index

c) Sintaxis:
   MLA_analyzer.sh    file.log    [ dir_index ]

   * "file.log": Fichero de log de entrada (formato modsec_audit.log) a analizar.
   * "dir_index": directorio donde generar el fichero resumen "file.index" (local por defecto).

   NOTA: Los ficheros de LOGs los buscan en su ubicación estándar:
   * Carpeta: /var/log/httpd/
   * Nombre:  modsec_audit.log
#########


#########
4) MLA_detector.sh

a) Descripción: Recibe los ficheros "file.time" y "file.index", e identifica las URIs de ataque y limpias.

b) E/S: file.time, file.index -> file.attacks, file.clean

c) Sintaxis:
   MLA_detector.sh    file.time    dir_index   dir_out_attacks   dir_out_clean

   * "file.time": Fichero de texto ".time" con las URIs analizadas (y su TimeStamp).
   * "dir_out_index": Directorio en el que buscar el fichero "file.log" con el analisis de Mod Security asociado.
   * "dir_out_attacks": Directorio donde generar el fichero de ataques "file.attacks"
   * "dir_out_clean":   Directorio donde generar el fichero de tráfico limpio "file.clean"
   NOTA: Se asume mismo nombre que fichero de entrada "file.time" cambiando la extensión.
#########


############################
FORMATO DE FICHEROS EMPLEADOS POR MLA (todos ficheros de texto)

1) "file-raw.uri": fichero con URIs a analizar y el número de caracteres de cada una. Formato:

   Nº_caracteres_URI URI


2) "file.uri": fichero con solo las URIs a analizar. Formato:

   URI


3) "file.time": fichero con las URIs enviadas a Apacje Mod Security para su analisis y el TimeStamp en que se han enviado. Formato:

   [TIMESTAMP]\t[URI]

    NOTA: "\t" denota "tabulación"

   Ejemplo:

   [23/Jul/2019:14:43:49 +0200]	[/educacion/educacion/noticias/scholar.google.com]


4) "modsec_audit.log": Fichero de log generado por Mod Security con los detalles del ataque en "Secciones".


5) "file.index": Fichero resumen con los datos de interés del "log", con una línea por ataque. Formato:

    TimeStamp [TIMESTAMP]\tUri [URI]\tPLmin [n]\tScore [n]\tNattacks [n]\t[ID1]\t[ID2]...

    Campos:
    * PLmin (1-4, o vacío=1): Mínimo PL (Paranoia Level de Mod Security) a partir del cual esta URI se detecta como ataque.
    * Score (0-5): Nivel de peligrosidad del ataque según las reglas OWASP CRS de ModSecurity.
    * Nattacks: Nº de reglas que se han activado con esta URI.
    * "IDn": ID de las reglas que se han activado.

    Ejemplo:

    TimeStamp [23/Jul/2019:14:43:49 +0200]  Uri [/educacion/educacion/noticias/scholar.google.com]  PLmin [2]    Score [5]       Nattacks [3]    [920440]        [949110]        [980130]


6) "file.attacks": Salida del análisis con el tráfico detectado como ataque. Formato: tras una cabecera resumen
   (Nº de URIs analizadas, cuantas son de ataque y cuantas limpias), cada linea presenta el formato:

    Packet [Nº_linea]\tUri [URI]\tPLmin [n]\tScore [n]\tNattacks [n]\t[ID1]\t[ID2]...

    Campos:
    + Packet: Nº de la línea del fichero "file-raw.uri" en la que se encuentra la URI a que se refiere el ataque
              (obtenida usando el "TimeStamp" del fichero "file.time")

    Ejemplo:

    ---------------------- Statistics of URIs analyzed------------------------
    [1] input, [0] clean, [1] attacks
    --------------------------- Analysis results -----------------------------
    Packet [296942] Uri [/educacion/educacion/noticias/scholar.google.com]  PLmin [2]        Score [5]  Nattacks [3]     [920440]        [949110]        [980130]


7) "file.clean": Salida del análisis con el tráfico limpio. Formato:

   Nº_caracteres_URI\tURI
