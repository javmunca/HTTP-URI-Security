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


//some extra functions that are defined in the X/Open and POSIX standards.
#define _XOPEN_SOURCE 700

//INSPECTORLOG INCLUDES
#include "inspector.h"

typedef enum{
    GET,
    POST,
    HEAD,
    PROPFIND,
	NONE
}_requestMethod;

typedef enum{
    _1_0,
    _1_1
}_httpProtocol;

int nlineas = 0;

/*  Log entries in a format known as the Common Log Format (CLF).
    http://en.wikipedia.org/wiki/Common_Log_Format
*/

#define APACHE_LOG_ITEMS 11 //Number of elements on Apache Logs
typedef struct {

    unsigned char ip_address[4];        //IP address of the client
    char user_identifier[WORDLENGTH];   //RFC 1413 identify
    char user_id[WORDLENGTH];           //Userid of the person requesting the document
    struct tm time;                     //Time in strftime format -> tm struct
    _requestMethod request_method;
    char URI[URILENGTH];                //Maximum length of a URI?? -> http://stackoverflow.com/questions/2659952/maximum-length-of-http-get-request
    _httpProtocol Protocol;             //HTTP Protocol
    int16_t status_code;                //HTTP Status Code -> http://www.w3.org/Protocols/rfc2616/rfc2616.txt
    int32_t return_size;                //The size of the object returned to the client

    /* --- Additional fields for Combined Log Format ---*/
    char referer[URILENGTH];
    char user_agent[URILENGTH];         // UserAgent maximum length -> http://httpd.apache.org/docs/2.4/mod/core.html#limitrequestfieldsize

} Apache_logEntry;

// Mapeo de campos en logs a partir de separación por espacios

typedef struct log_map {
        int ip;
        int useridentifier;
        int userid;
        int timestamp;
        int dif;
        int method;
        int uri;
        int protocol;
        int status_code;
        int return_size;
        int referer;
        int user_agent;       
} log_map;

/****************************/
/* Rutinas auxiliares     */
/****************************/

/************************************************/
/* Funciones gestión IPs                        */
/************************************************/

//Convert ip from string to 4 bytes representation
void convert_ip(const char ip_string[16], unsigned char ip_byte[4]){

    char * token = strtok((char *)ip_string, ".");
    for(int n=0; n<4; n++){
        int tmp = atoi(token);
        ip_byte[n] = (unsigned char)tmp;
        //printf ("%s\n", token);
        token = strtok(NULL, ".");
    }

}

unsigned int dec_toIP(unsigned char ip_address[4]){

    unsigned int IP = 0;
    IP |= (ip_address[0] << 24 );
    IP |= (ip_address[1] << 16 );
    IP |= (ip_address[2] <<  8 );
    IP |= (ip_address[3]       );

    return IP;
}

void init_log_map(log_map *m ) {

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
    
    if (log_type == LOG_APACHE) {
        m->ip = 0;
        m->useridentifier = 1;
        m->userid = 2;
        m->timestamp = 3;
        m->dif = 4;
        m->method = 5;
        m->uri = 6;
        m->protocol = 7;
        m->status_code = 8;
        m->return_size = 9;
        m->referer = 10;
        m->user_agent=11;        
    } else if (log_type == LOG_WELLNESS) {
        m->ip=3;
        m->useridentifier = -1;
        m->userid = -1;
        m->timestamp = 0;
        m->dif = -1;
        m->method = 5;
        m->uri = 6;
        m->protocol = 7;
        m->status_code = -1;
        m->return_size = -1;
        m->referer = -1;
        m->user_agent = -1;
    } else if (log_type == LOG_LIST) {
        m->ip=-1;
        m->useridentifier = -1;
        m->userid = -1;
        m->timestamp = -1;
        m->dif = -1;
        m->method = -1;
        m->uri = 0;
        m->protocol = -1;
        m->status_code = -1;
        m->return_size = -1;
        m->referer = -1;
        m->user_agent = -1;
    } else if (log_type == LOG_URI) {
        m->ip=-1;
        m->useridentifier = -1;
        m->userid = -1;
        m->timestamp = -1;
        m->dif = -1;
        m->method = -1;
        m->uri = 1;
        m->protocol = -1;
        m->status_code = -1;
        m->return_size = -1;
        m->referer = -1;
        m->user_agent = -1;
    }
    
    return;
}  
    
/* Extracción de campos de una línea del archivo de traza */
/* TODO: Adaptar a los diferentes tipos de traza contemplados */

int parse_logEntry(char * logLine, Apache_logEntry * logEntry, log_map map){

    #define APACHE_LOG_TOKENS 12 //Maximum number of tokens on Apache entries

    //Temp strings in tokenizer process
    char * tmp_str[APACHE_LOG_TOKENS];
    char * p;
    int pos,n ;
 
    //Tokenizer by white-space
    tmp_str[0] = strtok((char *)logLine, " ");
    for(n=1; n<APACHE_LOG_TOKENS && tmp_str[n-1]!=NULL; n++){
        tmp_str[n] = strtok(NULL, " ");
#ifdef DEBUG
        printf("\t[%s]",tmp_str[n]);
#endif
    }
#ifdef DEBUG
        printf("\n[%d campos]",n );
#endif

    /* Comprobación básica tipo log, n tiene el numero de campos mas 1 */
    
    if (((log_type == LOG_APACHE) && (n<10)) || ((log_type == LOG_WELLNESS) && (n != 11)) || ((log_type == LOG_LIST) && (n > 2)) || ((log_type == LOG_URI) && (n !=3))) {
        if (nlineas == 1) { 
            printf("[parse_logEntry]: Número incorrecto de campos en log [%d], linea [%d] probablemente el tipo de log sea incorrecto\n",n,nlineas);
            exit(-1); 
        } else  {
            printf("[parse_logEntry]: Error parser linea [%d] [",nlineas);
            for (pos=0;pos<n-2;pos++) printf("%s ",tmp_str[pos]);
            printf("%s]\n",tmp_str[n-2]);
            return(-1);
        }
    }
    
    /* Procesamos los campos */

    if (map.ip >= 0) {
        if (log_type == LOG_WELLNESS) {         /* Separamos IP:puerto */

            p = strstr(tmp_str[map.ip],":");
            if (p) *p = '\0';

        };
        if (strlen(tmp_str[map.ip]) > 16) {
            printf("[parse_logEntry]: Formato erróneo en campo IP [%s], linea [%d]\n",tmp_str[map.ip],nlineas);
            return(-1);
        }

        convert_ip(tmp_str[map.ip], logEntry->ip_address);

    }
    
    if (map.useridentifier >= 0) 
        if (tmp_str[map.useridentifier])
            strcpy(logEntry->user_identifier,tmp_str[map.useridentifier]); 
    
    if (map.userid >0)
        if (tmp_str[map.userid])
            strcpy(logEntry->user_id, tmp_str[map.userid]);

    if (map.timestamp >= 0) 
        if(tmp_str[map.timestamp]) {
            if (log_type == LOG_APACHE) {
                char tmp[128];
                strcpy(tmp, tmp_str[map.timestamp]);
                strcat(tmp, tmp_str[map.dif]);
                strptime(tmp, "[%d/%b/%Y:%T%z]", &logEntry->time);
            } else if (map.timestamp >0) strptime(tmp_str[map.timestamp], "[%d/%b/%Y:%T%z]", &logEntry->time);  

        }

    /* Metodos validos */

    if (map.method >= 0) {
        if (!tmp_str[map.method]) {
           printf("[parse_logEntry]: No se encuentra método, línea [%d] \n",nlineas);
            return(-1);            
        }

        if( strstr(tmp_str[map.method], "GET") != NULL )
            logEntry->request_method = GET;
        else if(strstr(tmp_str[map.method], "HEAD") != NULL )
            logEntry->request_method = HEAD;
        else if(strstr(tmp_str[map.method],"POST") != NULL)
            logEntry->request_method = POST;
        else if (strstr(tmp_str[map.method],"PROPFIND") != NULL)
            logEntry->request_method = PROPFIND;

    }
    
    /* URI: Este es el único campo obligatorio */
    
    pos = 0;
    if (!tmp_str[map.uri]) {
           printf("[parse_logEntry]: No se encuentra uri, línea [%d]\n",nlineas);
           return(-1);            
    }
    while (tmp_str[map.uri][pos] == '"') pos++;
    if (!strncmp(&tmp_str[map.uri][pos],"http://",7) ) pos += 7;     // Quitamos http:// para evitar reglas con :
    strcpy(logEntry->URI, &tmp_str[map.uri][pos]);
    
    pos = strlen(logEntry->URI);
    if (logEntry->URI[pos-1] == '"') pos--;
    while (logEntry->URI[pos-1] == '\n') pos--;
    logEntry->URI[pos] = '\0';

    /* Protocol */

    if (map.protocol > 0) 
        if (tmp_str[map.protocol]) 
            if( strstr(tmp_str[map.protocol], "HTTP/1.0") != NULL )
                logEntry->Protocol = _1_0;
            else if( strstr(tmp_str[map.protocol], "HTTP/1.1") != NULL )
                logEntry->Protocol = _1_1;
    

    if (map.status_code >= 0) if(tmp_str[map.status_code]) logEntry->status_code = atoi(tmp_str[map.status_code]);

    if (map.return_size >= 0) if(tmp_str[map.return_size]) logEntry->return_size = atoi(tmp_str[map.return_size]);

    //Presencia de campos opcionales en el log
    
    if (map.referer >= 0) 
        if(tmp_str[map.referer]) 
            if(tmp_str[map.referer][1] == '-')
                logEntry->referer[0] = '\0';
            else
                strcpy(logEntry->referer, tmp_str[map.referer]);
        

    if (map.user_agent >= 0) if(tmp_str[map.referer])  strcpy(logEntry->user_agent, &tmp_str[map.user_agent][1]);
    
    return(0);
 #ifdef DEBUG   
    printf("[parse_logEntry]: URI [%s]\n",logEntry->URI);
#endif
}

/* Limpia el registro de la traza */

void init_Apache_logEntry(Apache_logEntry * logEntry){

    logEntry->ip_address[0] = 0;
    logEntry->user_identifier[0] = 0;
    logEntry->user_id[0] = 0;
    logEntry->request_method = NONE;
    logEntry->URI[0] = 0;
    logEntry->Protocol = 0;
    logEntry->status_code = 0;
    logEntry->return_size = 0;

    /* --- Additional fields for Combined Log Format ---*/
    logEntry->referer[0] = 0;
    logEntry->user_agent[0] = 0;

}

int compare( const void* a, const void* b)
{
    unsigned int int_a = * ( (unsigned int*) a );
    unsigned int int_b = * ( (unsigned int*) b );

     if ( int_a == int_b ) return 0;
     else if ( int_a < int_b ) return -1;
     else return 1;
}

/****************************/
/* Rutinas públicas         */
/****************************/

/* Análisis línea a línea de un archivo log                 */
/* Genera la salida por pantalla para las uris con alertas  */

void scan_logFile(const char *fileName ){

   int total_alertas = 0;
   int npackets = 0;
   int npackets_with_alerts = 0;
   struct log_map map;
   int tmp;

   
//   char logLine[MAXLOG_LINE];
   char out_logline[MAXLOG_LINE];
   size_t lineLength;
   ssize_t read;

    //open file
    FILE * logFile = fopen(fileName, "r");
    FILE *fout;
    Apache_logEntry logEntry;
    int rules_detected[MAX_ALERTS_PER_URI], sid_detected[MAX_ALERTS_PER_URI]; /* Lista de reglas que han dado positivo para una línea de log */

    if(logFile != NULL){

        char * logLine = (char*) malloc (sizeof(char)*MAXLOG_LINE);

        // Conectar con la base de datos si es preciso

        int nLog=1;
        if(BD){
            if(query("SELECT MAX(sid) FROM event")){
                MYSQL_RES *result = mysql_store_result(con);
                MYSQL_ROW row = mysql_fetch_row(result);
                if(row[0] && isdigit(row[0][0]))
                    nLog = atoi(row[0])+1;
                mysql_free_result(result);
            }
        }

        // Inicializamos mapeo del log

        
        init_log_map(&map);
        
        if (outputf) {
#ifdef DEBUG   
            printf("Abriendo archivo salida limpia <%s>\n",output_file);
#endif
            fout = fopen(output_file,"w");
            if (!fout) {
                printf("[scan_logFile]: Error abriendo archivo salida [%s]\n",output_file);
                exit(-1);
            }
#ifdef DEBUG   
            printf(" ... Hecho \n");
#endif         
        };

        // Leemos primera linea de LOG_URI
        if (log_type == LOG_URI) {
			read = getline(&logLine, &lineLength, logFile);

			// Escribimos en la cabecera el número de líneas (máximo el valor de read): Maximo 1M de líneas

			tmp = sscanf(logLine,"%d\n",&npackets_with_alerts);
			if (tmp != 1) {
                printf("[scan_logFile]: Error leyendo número de líneas en [%s]\n",output_file);
                exit(-1);				
			}
			if (outputf) fprintf(fout,"%6d\n",npackets_with_alerts);
			npackets_with_alerts = 0;
    	}
		
        //Lee cada una de las lineas -> Aplicacion Individual
        nlineas = 0;
        for(int i=1; (read = getline(&logLine, &lineLength, logFile)) != -1; i++) {
 
 			if (read > URILENGTH) {
					printf("[scan_LogFile] Packet [%d] too long (%d chars)\n", i, read);
					continue;
			}
            nlineas++;
            //Parsea cada una de las lineas del log

            init_Apache_logEntry(&logEntry);

            if (outputf) strcpy(out_logline,logLine);
            if (parse_logEntry(logLine, &logEntry, map) == -1) continue;
           
            
            /* ---------- INDIVIDUAL RULES ----------
                Se aplican de forma individual a cada una de las entradas del log
                No tienen en cuenta ninguna otra entrada más que la entrada actual
            */

            //Detecta patrones de ataque en la URI

            int pos_matches = 0; 			//Number of positive matches via Individual Rules Scan
            for (int j=0; j < MAX_ALERTS_PER_URI; j++) { rules_detected[j]=0; sid_detected[j]=0; };

            npackets ++;
#ifdef DEBUGTIME
            time(&rawtime);
            printf("Parsing packet [%d]= \"%s", i, ctime(&rawtime));
#endif  

            pos_matches = detect_URI(logEntry.URI, rules_detected);

            if( pos_matches > 0 ){
                
                // Se han activado reglas: imprimir (formato compatible con u2uri)
                 
                printf("Packet [%d]\tUri [%s]\tNattacks [%u]\tSignatures", i, logEntry.URI, pos_matches);
                total_alertas += pos_matches;
                
                // Ordenamos las alertas por sid 

                for (int n= 0; n< pos_matches;n++) sid_detected[n] = URI_rules[rules_detected[n]]->sid;
              
                qsort(sid_detected, pos_matches, sizeof(unsigned int), compare);
              
                for(int n=0; n<pos_matches; n++){
//                    printf("%s encontrado en linea %i!! \n", URI_rules[rules_detected[n]]->description, i);

//                    printf("\t[%u]",URI_rules[rules_detected[n]]->sid);

                    /* En formato extendido no se ordenan las alertas por sid */

                    if (ealert) {
                        printf("\t[%s - sid: %u]",URI_rules[rules_detected[n]]->description,URI_rules[rules_detected[n]]->sid);
                    } else printf("\t[%u]",sid_detected[n]);
                    
                    if(BD){
                        char q[MYSQL_QUERYLENTGH];

                        time_t epoch;                   //Unix timestamp
                        epoch = mktime(&logEntry.time);

                        sprintf(q,"INSERT INTO event VALUES(%d, %d, %d, FROM_UNIXTIME(%lu))", nLog,i,URI_rules[rules_detected[n]]->sid, epoch);
                        query(q);

                        sprintf(q,"INSERT INTO iphdr VALUES(%d, %d, %d, 0000, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 23, NULL)", nLog,i, dec_toIP(logEntry.ip_address));
                        query(q);

                        sprintf(q,"INSERT INTO signature VALUES(%d, '%s', 10, NULL, NULL, NULL, NULL);", URI_rules[rules_detected[n]]->sid, URI_rules[rules_detected[n]]->description);
                        query(q);
                    }
                }
                printf("\n");
                npackets_with_alerts++;
            } else if (outputf) {
                fprintf(fout,"%s",out_logline);
            }

        }
        
        if (outputf) {
			if (log_type == LOG_URI) {	// Rebobinamos y reajustamos el número de líneas en archivo limpio
				rewind(fout);
				fprintf(fout,"%6d\n",npackets-npackets_with_alerts);
			}; 
			fclose(fout);
        };
//         Resumen final (compatible formato u2uri)
        printf("# N. paquetes [%d], [%d] con alertas, N. Alertas [%d]\n",npackets, npackets_with_alerts, total_alertas);

        free(logLine);

        fclose(logFile);
    }else{
        printf("[scan_logFile]: Error - La ruta del log proporcionada es incorrecta = %s\n", fileName);
    }
}


