/*
** INSPECTORLOG
** Copyright (C) 2013-2014, Antonio Morales Maldonado, Granada, España.
** Todos los derechos reservados
**
** Antonio Morales Maldonado - <antoniomoralesmaldonado@gmail.com>
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
**  Versión 3.0 JEDV - 19/12/2017
** 
*/

//some extra functions that are defined in the X/Open and POSIX standards.
#define _XOPEN_SOURCE 700

#define _GNU_SOURCE

//C INCLUDES
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <ftw.h>


//INSPECTORLOG INCLUDES
#include <inspector.h>

//VARIABLES GLOBALES

unsigned char log_path[PATH_MAX+1];
unsigned char rules_path[PATH_MAX+1];
unsigned char output_file[PATH_MAX+1];
unsigned char mysql_user[WORDLENGTH] = "";
unsigned char mysql_pass[WORDLENGTH] = "";
unsigned char mysql_schema[WORDLENGTH] = "";
URI_rule * URI_rules[MAX_URI_RULES];
int Detection_list;
int BD = 0;
bool nocase = false;
bool ealert = false;
bool warns = false;
int outputf = 0;
MYSQL *con;
int debug;

#ifdef DEBUGTIME
time_t rawtime;
struct tm *timeinfo;
#endif

int log_type=LOG_APACHE;                        // Código formato del archivo log 
int num_rules=0;                       // Número de reglas leídas
int num_URIrules=0;                    // Número de reglas HTTP
int num_errorrules=0;                  // Número de reglas con errores de parsing
int num_rules_file = 0;

struct timespec tp;
long begin, end;
long time_spent;

void print_error(){

    if(debug) //Si esta activado el modo DEBUG
        printf("Error");

}

void free_all(){

    //Liberamos todas las reglas existentes
    for(int i=0; i<num_URIrules; i++){
        free_rule(URI_rules[i]);
        if(URI_rules[i]){
            free(URI_rules[i]);
        }
    }
}

/* Cronómetro: inicio */

void time_start(){

    if(clock_gettime(CLOCK_REALTIME, &tp) == 0){
        begin = tp.tv_nsec;
    } else {
        printf("[time_start] Error en 'time_start()' : No fue posible realizar la medicion del tiempo\n");
    }
}

/* Cronómetro: final */

void time_end(){

    if(clock_gettime(CLOCK_REALTIME, &tp) == 0){

        end = tp.tv_nsec;
        time_spent = end-begin;
        printf("Execution time: %f s\n", ((float)abs(time_spent))/1000000000.0);
    } else {
        printf("[time_end] Error en 'time_end()' : No fue posible realizar la medicion del tiempo\n");
    }
}

/************************************************/
/* Gestión memoria                              */
/************************************************/

unsigned char * uchar_malloc(int num_bytes){

    unsigned char * ptr;

    ptr = (unsigned char*) malloc(num_bytes);
    if(ptr == NULL){
        printf("Error en 'uchar_malloc' : Fallo en la reserva de memoria \n");
        exit(EXIT_FAILURE);
    }

    return ptr;
}

/************************************************/
/* PROGRAMA PRINCIPAL                          */
/************************************************/


int main(int argc, char **argv){


	//For time measure
    time_start();

    //Set function to be executed on exit
    if( atexit(free_all) != 0){
        printf("[%s] Error en 'main' : Error al invocar 'atexit'\n",argv[0]);
    }

    //Default arguments
    strncpy(rules_path, RULES_DIR, PATH_MAX);
    
    printf("# inspectorlog v3.0\n");

#ifdef DEBUG
    printf("> Iniciamos procesamiento\n");
#endif
    
    //Parse command line arguments
    if( !parse_clArgs(argc, argv))
        exit(EXIT_FAILURE);

#ifdef DEBUG
    printf("> Leídos argumentos ...\n");
#endif

    if(BD){

        if(!connect_MySQL(&con))
            exit(EXIT_FAILURE);
    }

    // Cargamos las reglas

    load_rules(rules_path);
#ifdef DEBUG
    printf("> Cargadas [%d] reglas útiles de [%d] totales ...\n", num_URIrules, num_rules);
#endif
    
    printf("#Alertas y firmas generadas: %s", argv[0]);
    for(int i=1;i<argc;i++) printf(" %s",argv[i]);
    printf("\n");
    

    // Leemos fichero de traza
    
#ifdef DEBUTIME
    time(&rawtime);
   
#endif
    scan_logFile(log_path);

    if(BD){
        disconnect_MySQL(con);

        printf(">> Contenido volcado en la base de datos '%s'. Puede consultar más detalles a través de la herramienta Snort Report.", mysql_schema);
    }

    //For time measure
    time_end();

    return 0;
}
