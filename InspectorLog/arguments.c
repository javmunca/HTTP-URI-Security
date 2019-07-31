/*
** INSPECTORLOG
** Copyright (C) 2013-2014, Antonio Morales Maldonado, Granada, España.
** Todos los derechos reservados
**
** Antonio Morales Maldonado - <antoniomoralesmaldonado@gmail.com>
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
**  Versión 3.0 JEDV - 19/12/2017
*/

//C INCLUDES
#include <getopt.h>

//INSPECTORLOG INCLUDES
#include "inspector.h"

//Parse command line arguments

bool parse_clArgs(int argc, char **argv){

    bool isOK = true;

    int c;

    /* Flag set by ‘--verbose’. */
    static int verbose_flag;

    if(argc < 3)
        show_help();

    while (1){

        static struct option long_options[] =
             {
               /* These options set a flag. */
               {"verbose", no_argument,       &verbose_flag, 1},
               {"brief",   no_argument,       &verbose_flag, 0},

               /* These options don't set a flag.
                  We distinguish them by their indices. */
               {"help",  no_argument,       0, 'h'},
               {"log",  required_argument, 0, 'l'},
               {"rules",  required_argument, 0, 'r'},
               {"user",  required_argument, 0, 'u'},
               {"pass",  required_argument, 0, 'p'},
               {"schema",  required_argument, 0, 's'},
               {"logtype", required_argument, 0, 't'},
               {"output", required_argument, 0, 'o'},
               {"ealert", no_argument, 0, 'e'},
               {"nocase", no_argument, 0, 'n'},
               {"warnings",no_argument, 0, 'w'},
               {0, 0, 0, 0}
             };
           /* getopt_long stores the option index here. */
           int option_index = 0;


        c = getopt_long(argc, argv, "hnel:r:t:o:w", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

#ifdef DEBUG
            printf("Detectada opción %c, %s\n",c,optarg);
#endif        
        switch (c){

            case 0:
                /* If this option set a flag, do nothing else now. */
               if (long_options[option_index].flag != 0)
                    break;

               printf ("option %s", long_options[option_index].name);
               if (optarg) 
                    printf (" with arg %s", optarg);
               printf ("\n");
               break;

            case 'u':
               strncpy((char*)&mysql_user, optarg, WORDLENGTH);
               BD = 1;
               break;

            case 'p':
               strncpy((char*)&mysql_pass, optarg, WORDLENGTH);
               BD = 1;
               break;

            case 's':
               strncpy((char*)&mysql_schema, optarg, WORDLENGTH);
               BD = 1;
               break;

            case 'l':
                //printf ("option -l with value '%s'\n", optarg);
                strncpy((char*)&log_path, optarg, PATH_MAX);
                break;

            case 't':
                if (!strcmp(optarg,"list")) {
                    log_type = LOG_LIST;
                } else if (!strcmp(optarg,"apache")) {
                    log_type = LOG_APACHE;
                } else if (!strcmp(optarg,"wellness")) {
                    log_type = LOG_WELLNESS;
                } else if (!strcmp(optarg,"uri")) {
                    log_type = LOG_URI;
                } else {
                    printf("InspectorLog: tipo de log [%s] no reconocido\n",optarg);
                    exit(-1);
                }
                break;
            case 'o':
                strncpy((char *)&output_file, optarg, PATH_MAX);
                outputf = true;
                break;
            case 'r':
               //printf ("option -d with value `%s'\n", optarg);
                strncpy((char*)&rules_path, optarg, PATH_MAX);
               break;

            case 'f':
               printf ("option -f with value `%s'\n", optarg);
               break;

            case '?':
               /* getopt_long already printed an error message. */
               break;
            case 'n':
               nocase = true;
               break;
            case 'e':
               ealert = true;
               break;
            case 'w':
               warns = true;
               break;
            default:
               show_help();
        }
    }
#ifdef DEBUG
    printf(">> Argumentos de línea de comando procesados ...\n");
#endif
       /* Instead of reporting ‘--verbose’
          and ‘--brief’ as they are encountered,
          we report the final status resulting from them. */
       if (verbose_flag)
         puts ("verbose flag is set");

    /* Print any remaining command line arguments (not options). */
    if (optind < argc){
           printf ("[parse_clArgs] Argumento(s) erroneo(s): ");
           while (optind < argc)
             printf ("%s ", argv[optind++]);
           putchar ('\n');
    }

    return isOK;
}


void show_help(){

    printf("FORMATO: inspectorlog -l logFile [-t <list|apache|wellness|uri>] [-r ruleDir] [--user=<MySQL User>] [--pass=<MySQL Pass>] [--schema=<MySQL Schema>] [-o <salida log limpio>] [-n (nocase)] [-e (extended_alerts)] [-w (encoding warnings)]\n");
    exit(EXIT_SUCCESS);

}

