#ifndef __GLOBAL
#define __GLOBAL

/*
** INSPECTORLOG
** Copyright (C) 2013-2014, Antonio Morales Maldonado, Granada, España.
** Todos los derechos reservados
**
** Antonio Morales Maldonado - <antoniomoralesmaldonado@gmail.com>
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Versión 3.0 JEDV - 19/12/2017
** 
*/

#define _XOPEN_SOURCE 700

#undef DEBUG

//C INCLUDES
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <mysql/mysql.h>
#include <ftw.h>
#include <pcre.h>

// Defines

#define MAX_URI_RULES 50000     // Número máximo de URIs a almacenar
#define RULES_DIR "rules"       // Directorio reglas por defecto
#define PATH_MAX 16385           // Tamaño máximo del path
#define URILENGTH 16385         //Maximum length of a URI?? -> http://stackoverflow.com/questions/2659952/maximum-length-of-http-get-request
#define WORDLENGTH 128
#define MAXLOG_LINE 16385
#define MAX_ALERTS_PER_URI 124
#define MYSQL_QUERYLENTGH 4096
#define SNORT_RULE_MAX 20096    // Tamaño maximo de una regla de snort (una linea)
#define RULES_DIR "rules"       // Directorio reglas por defecto


#define MAX_REFERENCES 18
#define MAX_PATTERNS 18
#define MAX_PCRE 6
#define CONTENT_LENGTH 1024
#define MAX_BYTECODES 100


// Tipos de archivos de traza

#define LOG_APACHE 0
#define LOG_WELLNESS 1
#define LOG_LIST 2
#define LOG_URI 3

#define URILENEQ 3
#define URILENGT 2
#define URILENLT 1

/* Estructuras  */

typedef struct{
    int negated;                               //Establece si dicha expresión regular está negada o no (hace uso de '!')
    unsigned char * regExp;
    unsigned char * modifier;
	pcre *pattern;
}_pcre;

typedef struct{
    int negated;
    unsigned char * pattern_str;
    bool nocase;
}_uriPattern;


/* Estructura para almacenar una regla */

typedef struct{

    // Cadenas (content o pcre)
    int num_patt;                           //Number of patterns
    _uriPattern URI_pattern[MAX_PATTERNS];  //Hasta 'MAX_PATTERNS' patrones distintos, cada uno de ellos con distintos modificadores
    int num_pcre;                           //¿Varios PCRE o uno solo por regla??? -> Solo se admite un pcre por regla!
    _pcre pcre[MAX_PCRE];                   //Expresiones regulares

    // Modificadores
    int urilen;                             // Longitud del uri
    int uritype;                            // 0=void, 1=menor, 2=mayor, 3=igual

    // Información adicional

    unsigned char * description;            //Message description of the rule
    int num_ref;                            //Number of references
    unsigned char * references[MAX_REFERENCES]; //Reference to the solution
    unsigned char * attack_type;            // Tipo de ataque

    // Identificador único
    int sid;                                //Identificador único de dicha regla

} URI_rule;

//VARIABLES GLOBALES

extern int Detection_list;                  // Número de detecciones
extern int BD;                              // Switch base de datos activa
extern int outputf;                         // Switch salida trazas
extern int log_type;                        // Código formato del archivo log (0 = apache normal, 1 = lista, 2 = wellness)

extern MYSQL *con;                                 // Conector BD
extern bool nocase;                                  // Activar/desativar nocase global
extern bool ealert;                         // Formato extendido para las alertas (msg + sid)
extern bool warns;                          // Generar warnings por %encodings no encontrados

extern unsigned char log_path[PATH_MAX+1];      // Path al archivo de log
extern unsigned char rules_path[PATH_MAX+1];    // Path al archivo de reglas
// extern unsigned char log_typed[PATH_MAX+1];     // Tipo de archivo de log
extern unsigned char output_file[PATH_MAX+1];     // Path al archivo de salida


extern unsigned char mysql_user[WORDLENGTH];           // Usuario mysql
extern unsigned char mysql_pass[WORDLENGTH];           // Password mysql
extern unsigned char mysql_schema[WORDLENGTH];         // Esquema mysql
extern MYSQL *con;

extern int num_rules;                       // Número de reglas leídas
extern int num_URIrules;                    // Número de reglas HTTP
extern int num_errorrules;                  // Número de reglas con errores de parsing
extern int num_rules_file;

extern URI_rule * URI_rules[MAX_URI_RULES]; // Reglas


#ifdef DEBUGTIME

extern time_t rawtime;
extern struct tm *timeinfo;

#endif

/* Prototipos de funciones públicas */

/* inspector.c */

unsigned char *uchar_malloc(int num_bytes);

/* engine.c */

int detect_URI(const char * URI, int * rules_detected);

/* logs.c */

void scan_logFile(const char *fileName);

/* bd.c */

bool connect_MySQL(MYSQL **connector);

bool query(char *str_query);

void disconnect_MySQL(MYSQL *connector);

/* rules.c */

void load_rules(char *r_path);
void free_rule(URI_rule * rule);

/* arguments.c */

bool parse_clArgs(int argc, char **argv);

void show_help();

#endif
