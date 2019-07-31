

                                                      INSPECTORLOG
                                                 Copyright (C) 2013-2017 
                                          Antonio Morales Maldonado (v1.0)
                                             Jesús E. Díaz Verdejo (v2.0)

                                                      Version 3.0 - 19/12/2017

                                                     README - Spanish
------------------------------------------------------------------------------------------------------------------------------------------
CHANGELOG v3.1
- Optimizada decodificación de URI para mejorar rendimiento ante múltiple encoding tipo %25 (e.j. %25252525)

CHANGELOG v3.0
- Modificaciones para optimización de velocidad (definiciones de variables)
- Las expresiones regulares asociadas a las reglas se compilan e inicializan al cargar la regla, no al aplicarla (estructura rules modificada, liberación de expresiones pcre al finalizar)
- Se reconoce la clave http_method para eliminar el content asociado a un método. No se distingue entre métodos para aplicar las reglas (TODO) y se consideran métodos válidos GET, POST, HEAD, PROPINFO


CHANGELOG v2.0.2
- Modificado para permitir líneas incompletas o mal formateadas en el log (no se procesan)
- Corregido error en parser de log (gestión de IP)
- Corregido error gestión de memoria con modificadores de campos pcre
- Corregida salida filtrada en formato uri para que incluya el número de uris en la primera linea
- Añadido soporte para reglas en formato suricata (uricontent)
- Añadida cobertura %encoding hasta %ff (NO SE INCLUYEN ALGUNOS QUE NO TIENEN REPRESENTACION ASCII)
- Añadida cobertura para %encoding con UTF8 para los caracteres más comunes en español. Por alguna extraña razón, no funciona strcasestr con los encoding de UTF y se han codificado a mano versiones mayúsculas y minúsculas.
- Añadido soporte para las negaciones en content y pcre.
- Añadida opción para suprimir los mensajes de aviso de decodificación %encoding

CHANGELOG v2.0.1
- Añadido soporte para múltiples pcre

CHANGELOG v2.0 (Jesús Díaz Verdejo)

- Se han reorganizado los archivos para reducir su número y los parámetros y funciones globales.
- Se ha añadido capacidad de procesar diferentes formatos de archivos de traza.
- Se ha añadido la gestión de la codificación % (urlencode / urldecode). Ahora se procesan los uri antes y después de decodificar iterativamente (para detectar múltiple encoding).
- Se gestionan los campos "urilen" y "dsize" de las reglas.
- Se prorporciona a la salida el archivo de traza filtrado (opcional).
- Se gestiona el campo "nocase" a nivel de contenido individual en la regla (content y pcre).
- Se puede activar globalmente "nocase" para ignorar mayúsculas/minúsculas.
- Se modifica la salida para que sea compatible con herramientas previas (u2uri) y proporcione el listado de alertas (sid) asociado a cada uri.
- Se añade salida extendida: información sobre mensaje y sid de cada alerta. 
- No se ha modificado la funcionalidad asociada a MySQL (que no ha sido verificada en esta versión).
- Se ha añadido información sobre eventos/excepciones durante el procesamiento de los archivos de regla para mejorar el seguimiento de las reglas procesadas.
- Se ha añadido información sobre la correspondencia entre alerta y línea del archivo de traza para posibilitar el emparejamiento a posteriori.
- Se ha mejorado la capacidad de detección de reglas relativas a servidores http (números de puerto configurables y actuación como servidor).
- Se ordenan las alertas por sid en la salida.

COMPILACION

- PREREQUISITOS

- Es necesario un sistema linux para poder compilar y ejecutar el programa. En principio cualquier distribucion linux es compatible.
- Se requieren las librerías pcre-dev, mysqlclient y mysqlclientdev. Para más información consulte los apartados "instalación pcre" e "instalación mysql" más adelante.

- INSTALACION

- Para compilar el programa ejecutar "make" en el directorio src.
- Por defecto, se instala en el directorio src.
- En el directorio mysql se proporciona la macro para crear la base de datos necesaria (en su caso)

-----------------------------------------------

FUNCIONAMIENTO

- El programa analiza archivos de trazas conteniendo URIs en diferentes formatos y aplica las reglas contenidas en los archivos del directorio de reglas, informando sobre las alertas asociadas.

FORMATO:
    inspectorlog -l logFile [-t <list|apache|wellness|uri>] [-r ruleDir] [--user=<MySQL User>] [--pass=<MySQL Pass>] [--schema=<MySQL Schema>] [-o <salida log limpio>] [-n (nocase)] [-e (extended_alerts)]

    -l logFile                          Archivo de traza a procesar
    -t <list|apache|wellness|uri>       Formato del archivo de traza. Por defecto, se usa apache. Véanse ejemplos de formatos más adelante.
    -r ruleDir                          Directorio con las reglas de Snort. Se procesan TODOS los archivos en el directorio. Por defecto, se usa ./rules
    --user=<MySQL User>                 Usuario para acceder a la base de datos MySQL con las alertas (en su caso)
    --pass=<MySQL Pass>                 Password para el acceso a la base de datos
    --schema=<MySQL Schema>             Tabla a utilizar 
    -o <salida log limpio>              Archivo con los elementos de la traza que no han generado alertas (filtrado). El formato será el mismo que el de entrada
    -n                                  Aplicar las reglas ignorando mayúsculas y minúsculas en todos los casos. En caso contrario, se usará la regla de acuerdo a la etiqueta "nocase" existente o al switch de la expresión regular correspondiente.
    -e                                  Activar información extendida de las alertas (se incluye mensaje de alerta y sid). En caso contrario sólo se indica el sid
    -w                                  Generar avisos cuando no se pueden decodificar caracteres %encoded
    
FORMATOS DE TRAZAS:
    Los formatos disponibles por el momento para el archivo de traza son:
    - list                              Lista de URIs sin método ni campos adicionales
    - apache                            Formato estándar de apache
    - wellness                          Formato proporcionado para las trazas de wellnes
    - uri                               Formato usado por los archivos de uri de la herramienta ssmv4. La primera línea contiene el número de uris. Cada línea incluye la longitud y el uri
   
Ejemplos:
   /* Mapeos de campos (dependientes del tipo) */
    /* TIPO WELLNESS (10 campos)
    2017-06-22T06:25:15.356441+02:00 A-SQU-BAL-HAP03 haproxy[5518]: 10.128.2.64:46469 {www.wtelecom.es} "GET / HTTP/1.1" main_http_frontend WT_www_be/A-WTE-INF-WEB03
    TIMESTAMP NODE PLACE IP:PORT {server} "METHOD URI VER" CODE1 CODE2
    
    TIPO APACHE (12 campos)
    172.16.16.210 - - [02/May/2017:12:21:07 +0200]  "GET http://127.0.0.1/finger HTTP/1.1" 404 289 "-" "Wget/1.17.1 (linux-gnu)"  
    37.152.139.155 - - [07/Nov/2013:17:00:31 -0800] "GET /2003/padron.html HTTP/1.1" 200 11800 "-" "Java/1.7.0_15" "ajedreznd.com"
    IP USERIDENTIFIER USERID [TIMESTAMP DIF] "METHOD URI PROTOCOL" CODE1 CODE2 "-" "REFERER"

    TIPO LIST (URI en el primer campo)
    TIPO URI (URI en el segundo campo (y 1a linea con numero de uris)
    
    */   
    
ARCHIVOS DE REGLAS
    Se procesan las reglas en el formato estándar de Snort (VRT).
    Sólo se consideran los siguientes campos para la aplicación de la regla:
    - content           Se incluyen todos los campos content encontrados hasta un máximo de MAX_PATTERNS
    - pcre              Sólo se considera un campo pcre. Esto es una limitación de la versión actual de la herramienta.
    - dsize             Se consideran los tamaños de los payloads y su sentido (mayor, menor, igual), aunque se aplican al campo URI
    - urilen            Igual que dsize. De hecho, se procesan como un solo campo
    - nocase            Se aplica al campo inmediatamente anterior
    
    Los campos que se almacenan son:
    - msg               Descripción de la regla
    - reference         Referencias de la regla (puede haber varias con un límite superior)
    - classtype         Campo classtype de la regla
    - sid               SID de la regla
    
    Los restantes campos son ignorados.
    
    ¡¡IMPORTANTE!! Todos los archivos que se encuentren en el directorio "rules" o en alguno de sus subdirectorios deben pertenecer a archivos de reglas.
    En caso de descomprimir los archivos de reglas de Snort directamente en dicho directorio o en alguno de sus directorios, es importante que se borren  aquellos archivos que no correspondan a reglas de Snort (como archivos de "disclaimer" o de licencias). En caso contrario el comportamiento puede ser inesperado.
    
    Limitaciones en relación a las reglas:
    --------------------------------------
    
    Obviamente, no se pueden considerar los criterios relacionados con los flujos (flowbits, flow), por lo que se pueden producir muchos falsos positivos, especialmente en el caso de reglas muy genéricas a nivel de content o pcre. Esta limitación es insalvable.
    
    Los campos que determinan las posiciones (depth, distance, etc.) no son considerados en la versión actual de la herramienta. Esto también puede dar lugar a falsos positivos. Esta limitación podría ser paliada en versiones sucesivas de la herramienta mediante el uso de expresiones regulares para concatenar las expresiones (distance) o aplicar la regla a partir de posiciones del uri (depth).
    
    (SOLUCIONADO v2.0.1) Sólo se considera un campo pcre en esta versión. Existen algunas reglas VRT con más de un campo pcre. Esta limitación podría ser fácilmente soslayada aumentando el número de campos (TODO).
    
    (SOLUCIONADO v2.0.2) No se gestiona adecuadamente la negación en los campos a buscar en las reglas. Se extraen e identifican los campos negados, pero no se aplica correctamente. Esto debe ser corregido (TODO / BUG).
    
    Se han identificado casos de aplicación incorrecta de reglas con expresiones pcre que impliquen repetición. No se ha encontrado solución aún (BUG).
    
    No se comprueba el método utilizado. Se generan falsos positivos por no corresponder el método. Se podría gestionar en algunos formatos de trazas, no en otros (TODO).
    
    Se han identificado problemas en reglas conteniendo %00 (BUG).

FORMATO DE SALIDA:

    La salida se realiza por pantalla e incluye dos secciones:
    - Información inicial sobre las reglas cargadas y su procesamiento. 
    - Resultado del análisis de las trazas: 
    
        Packet [<numero_linea_en_log>]\tUri [<uri analizado>]\tNattacks [<num_alertas_generadas>]\t[<info_alerta_1>]\t ... \t [<info_alerta_n>]
    
        info_alerta_n puede ser únicamente el sid (salida normal) o la descripción de la alerta y el sid separados por '-' (salida extendida)
    Ejemplo:
    
            ------------------------- Initializing Rules ---------------------
            Rules directory : "/media/sf_work/siva/tools/InspectorLogv2.0/rules-kk"
                Opening ../rules-kk/http_kk.rules... done
                Reglas: leídas [1], erróneas [0], URI [1]
            --------------------------- Statistics ------------------------------
            Read [1] rules, [1] http-related, [0] with errors
            --------------------------- Analysis results -----------------------------
            #Alertas y firmas generadas: ./inspectorlog -l ../kk.txt -r ../rules-kk
            Packet [1]	Uri [127.0.0.1/cgi-bin/phf?Qname=%0Acat%20/etc/passwd]	Nattacks [3]	Signatures	[886]	[1122]	[1147]
            Packet [2]	Uri [127.0.0.1/cgi-bin/phf?Qname=%0Acd%20/%0als]	Nattacks [1]	Signatures	[886]
            # N. paquetes [2], [0] con alertas, N. Alertas [0]
            Execution time: 0.006367 s

            -------------------------------------------------------------------------------
    
PRUEBAS y EJEMPLOS:

- En el archivo "access.log" ubicado en el directorio 'pruebas', se proporciona un ejemplo de log de gran tamaño(+15000entradas) para probar el
  funcionamiento del programa. Dicho archivo contiene diversas amenazas que implican diversas reglas de diversos archivos de reglas distintos,
  demostrando la detección tanto de patrones como de expresiones regulares.

- Para probar dicho archivo, ejecutar la siguiente orden desde el directorio principal:
	./inspectorlog -l Pruebas/access.log

- Por defecto los archivos de reglas deben de ir en la carpeta "rules", pero se puede cambiar pasandole la opción "--rules [dir]" como argumentos 
  al programa. Se incluyen 2 directorios de reglas 'rules' y 'rules2', que contienen las reglas VRT de Snort y un conjunto de reglas personalizado respectivamente.

- También se incluyen otros archivos de pruebas utilizados para las distintas mediciones realizadas.

  
- Para poder obtener un análisis detallado de la información de salida mediante Snort Report, es necesario contar con un servidor MySQL instalado en 
  local, así como con un servidor web con capacidad para interpretar PHP. Puede obtener Snort Report desde la página web de los creadores:
													http://www.symmetrixtech.com/download.html

- Para más información acerca de los parámetros de entrada utilizar el argumento "--help".

-----------------------------------------------------------------------------

INSTALACION PCRE

- En sistemas debian y derivados basta con ejecutar la siguiente orden desde consola (se necesitan permisos de administrador):
	[sudo] apt-get update
	[sudo] apt-get install libpcre3 libpcre3-dev

- Para otras distribuciones acuda a la página web de dicha libreria (http://www.pcre.org/) y siga los pasos de instalación.

------------------------------------------------------------------------------
INSTALACION MYSQL

- En sistemas debian y derivados ejecutar las siguientes ordenes desde consola (se necesitan permisos de administrador):
	[sudo] apt-get update
	[sudo] apt-get install libmysqlclient libmysqlclient-dev

- Para otras distribuciones descargar y compilar el conector para C desde la dirección: http://dev.mysql.com/downloads/connector/c/
