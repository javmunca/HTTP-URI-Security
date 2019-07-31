/*
** INSPECTORLOG
** Copyright (C) 2013-2014, Antonio Morales Maldonado, Granada, España.
** Todos los derechos reservados
**
** Antonio Morales Maldonado - <antoniomoralesmaldonado@gmail.com>
**
** Copyright (C) 2017, Jesús E. Díaz Verdejo
** Versión 3.0 - JEDV 19/12/2017
*/

//some extra functions that are defined in the X/Open and POSIX standards.
// #define _XOPEN_SOURCE 700
#define _XOPEN_SOURCE 700

//INSPECTORLOG INCLUDES
#include "inspector.h"

#undef DEBUG

// Puertos considerados servidores de HTTP

const char *http_ports[]={"$HTTP_PORTS","80","8080","8081","81","311","383","591","593","901","1220","1414","1741","1830","2301","2381","2809","3037","3128","3702","4343","4848","5250","6988","7000","7001","7144","7145","7510","7777","7779","8000","8008","8014","8028","8080","8085","8088","8090","8118","8123","8180","8181","8243","8280","8300","8800","8888","8899","9000","9060","9080","9090","9091","9443","9999","11371","34443","34444","41080","50002","55555"};

#define nhttp_ports (sizeof(http_ports) / sizeof(const char *))

/****************************/
/* Rutinas auxiliares       */
/****************************/

// Removes all spaces from a (non-const) string.
void delete_whiteSpaces(char *str){

    char *src = str;
    char *dst = src;

    while (*src != '\0') {

        // If it's not a space, transfer and increment destination.
        if (*src != ' ')
            *dst++ = *src;

        // Increment source no matter what.

        src++;
    }
    *dst = '\0';
}

unsigned char char_toHex(char s){

    //Suponiendo codificación ASCII
    unsigned char hex = 1;

    if(s>='0' && s<='9'){
        hex = s - '0';
    }else if(s>='A' && s<='F'){
        hex = s -'A' + 10;
    }else if(s>='a' && s<='f'){
        hex = s -'a' + 10;
    }else{
        printf("Error en 'char_toHex' : La entrada no corresponde a un valor hexadecimal\n\n");
    }

    return hex;
}

/* Crea una regla vacía */

URI_rule * init_rule() {

    URI_rule * rule = (URI_rule*) uchar_malloc(sizeof(URI_rule));
    int i;
	
    rule->num_patt = 0;
    rule->num_pcre = 0;
    rule->num_ref = 0;
    rule->description = NULL;
    rule->attack_type = NULL; 
    rule->urilen = 0;
    rule->uritype = 0;

    for(i=0; i<MAX_PATTERNS; i++){
        rule->URI_pattern[i].negated = 0;
        rule->URI_pattern[i].nocase = false;
    }

    for(i=0; i<MAX_PCRE; i++) {
        rule->pcre[i].negated = 0;
        rule->pcre[i].modifier = NULL;
        rule->pcre[i].regExp = NULL;
		rule->pcre[i].pattern = NULL;
    }
    rule->sid = 0;  

    return rule;
}

// Convierte los bytecodes de un content o pcre a char 

void convert_bytecode(char * bytecode){

    delete_whiteSpaces(bytecode); //Eliminamos los espacios en blanco

    char * ptr = bytecode;

    unsigned char byte;
	int length = 0, j = 0, i=0;

    length = strlen(bytecode);
    if( length <= 0){
        printf("[convert_bytecode] Error - Se paso un bytecode vacio\n");
    }else if( (length % 2) != 0 ){
        printf("[convert_bytecode] Error - Se paso un bytecode de tamaño impar\n");
    }else{
        j=0;
        for(i=0; i<length; i=i+2, j++){

            unsigned char byte1 = char_toHex(ptr[i]);
            unsigned char byte2 = char_toHex(ptr[i+1]);

            byte = byte1*16 + byte2;

            bytecode[j] = byte;
        }
        bytecode[j] = '\0';
    }
}

// Preprocesa expresiones regulares para almacenarlas en la regla 

void parse_snortPcre(unsigned char * pcre, URI_rule * rule){

    char * msg_i = strchr (pcre, '/');
    if( msg_i != NULL ){
        msg_i++;
        char * msg_e = strrchr (pcre, '/');
        if( msg_e != NULL ){
            size_t length = msg_e - msg_i;
            rule->pcre[rule->num_pcre].regExp = uchar_malloc(length+1);
            strncpy(rule->pcre[rule->num_pcre].regExp, msg_i, length);
            rule->pcre[rule->num_pcre].regExp[length] = '\0';

            msg_e++;
            size_t length2 = strlen(msg_e);
            rule->pcre[rule->num_pcre].modifier = uchar_malloc(length2+1);
            strncpy(rule->pcre[rule->num_pcre].modifier, msg_e,length2); //Copy the post-re modifiers
			rule->pcre[rule->num_pcre].modifier[length2]='\0';
        }
    }
    return;
}

// Preprocesa campos content para almacenarlos en la regla

void parse_snortContent(char * content){

    unsigned char hexCodes_str[CONTENT_LENGTH];

    char tmp[CONTENT_LENGTH];
    tmp[0]='\0';

    char *aux = content;
    int i;
    for(i=0; i<MAX_BYTECODES; i++){ //Limitado por el número máximo de bytecodes diferentes en un mismo 'content'

        char * msg_i = strstr(aux, "|"); //The init of the "msg" field
        if( msg_i != NULL ){
            msg_i += strlen("|");
            char * msg_e = strstr(msg_i, "|"); //The end of the "msg" field
            if( msg_e != NULL ){

                size_t length2 = msg_i-aux-1;
                strncat(tmp, aux, length2);

                size_t length = msg_e - msg_i;

                strncpy(hexCodes_str, msg_i, length);
                hexCodes_str[length] = '\0';
                aux = msg_e+1;

                convert_bytecode(hexCodes_str); //|0D 0A 0D 0A| ->\r\n\r\n

                strcat(tmp, hexCodes_str);
            }
        }else{
            strcat(tmp, aux); //Se copia la cadena restante de 'content'
            break;
        }
    }
    
    if(i>0) //Si habia algun bytecode en la cadena 'content'
        strcpy(content, tmp);

}

//Parsea una regla(texto) y la añade a la lista de reglas
/* ----------------- PARSE HEADER ----------------- */

#define SNORT_HEADER_TOKENS 7
#define ACTION 1                // Acción de la regla: "alert"
#define PROTO 2                 // Protocolo: "tcp"
#define IPORIG 3                // Direccion IP origen: $EXTERNAL_NET (toda la red)
#define PORIG 4                 // Puerto IP origen: any (cualquiera)
#define IPSDEST 5               // Direccion IP destino: $HOME_NET (toda nuestra red)
#define PDEST 6                 // Puerto IP destino: any (cualquiera)
#define DIR 7                   // Dirección de la operación: "->" (puede ser ->, <-, )

bool parse_snortRule(const char * origRule){

    bool isRuleOK = true; 		//El parseo de la regla ha sido correcto

    bool is_HTTP_rule = false; 	//Se trata de una regla http, y la tendremos en cuenta
    bool cwarning = false, rwarning = false;    // Avisos de numero de campos excesivos
    int j;
    char rule_str[SNORT_RULE_MAX], opt_str[SNORT_RULE_MAX], content[SNORT_RULE_MAX];
	int options;					// Opciones para pcre
    int error_id;
    int error_offset;
    const char *error;
	
    //To avoid modification of "origRule"

    if (strlen(origRule) > SNORT_RULE_MAX) {
        printf("[snort_rule]: Rule longer than SNORT_RULE_MAX [%d]\n",SNORT_RULE_MAX);
        num_errorrules ++;
        return(false);
    } else {
        strncpy(rule_str, origRule, SNORT_RULE_MAX);       
    }
	

#ifdef DEBUG
    printf(">>>> Parseando la linea [%d]: Regla [%s]\n",num_rules_file,rule_str);
#endif
    /* CABECERA DE LA REGLA  */
    //Temp pointer strings in tokenizer header process
    
    char * hdr_str[SNORT_HEADER_TOKENS];

    //Tokenizer by white-space

    int n;
    hdr_str[0] = strtok((char *)rule_str, " ");
    for(n=1; hdr_str[n-1]!=NULL && n<SNORT_HEADER_TOKENS; n++){
        hdr_str[n] = strtok(NULL, " ");
    }

    if(n != SNORT_HEADER_TOKENS){
        num_errorrules ++;
        printf("[snort_rule]: Incorrect header in rule [%d], only [%d] fields\n",num_rules_file,n);
        isRuleOK = false;
    } else {
        for (j=0; j < nhttp_ports; j++) {
            if (!strcmp(hdr_str[PDEST], http_ports[j])) {
                is_HTTP_rule = true;
                break;
            };
        }
    }

    /* ----------------- PARSE OPTIONS ----------------- */

    if(isRuleOK && is_HTTP_rule){ //Check if header is OK

        //Get the options string
        char *tmpfield = NULL, *tmpvalue = NULL;
        size_t length;

#ifdef DEBUG2
        printf("\t> La regla es HTTP -> descomponiendola\n");
#endif
        strncpy(rule_str, origRule, SNORT_RULE_MAX);
        tmpfield = strstr(rule_str,"(");            /* Puntero al inicio de las opciones */
        if (!tmpfield) {                              // Error en las opciones
            printf("[snort_rule]: Rule [%d] Error processing options - Not found\n",num_rules_file);
            isRuleOK = false;
            num_errorrules ++;
            return(isRuleOK);
        };
        
        URI_rule * rule = init_rule();      /* Creamos una regla vacía */


       	strncpy(opt_str,tmpfield+1,SNORT_RULE_MAX);
#ifdef DEBUG2
        printf("\tOpciones: %s\n",opt_str);
#endif
        /* Vamos parseando las opciones una a una y clasificándolas */
       
        tmpfield = strtok(opt_str,";");

        /* Segmentamos los campos y vamos seleccionando los que nos interesan */
        
        while ((tmpfield) && strcmp(tmpfield,")")) {
#ifdef DEBUG
        	printf("\t\tSegmento [%s]\n",tmpfield);
#endif
        	while(tmpfield[0]==' ') tmpfield ++;    /* Limpiamos espacios en blanco al inicio */
            if (!strncmp(tmpfield,"msg:",4)) {     /* Mensaje */
            
                tmpvalue = tmpfield + strlen("msg:"); /* Evitamos las comillas iniciales */
                
                if (tmpvalue[0] == '\"') tmpvalue++; /* Evitamos las comillas inicial y final */
                length = strlen(tmpvalue);
                if (tmpvalue[length-1] == '\"') {
                    tmpvalue[length-1] = '\0';
                    length--;
                }
                if (length > 0) {
                    rule->description = uchar_malloc(length+1);
                    strncpy(rule->description, tmpvalue, length);
                    rule->description[length] = '\0';   
#ifdef DEBUG
                    printf("\t\t\tExtraida descripción: [%s]\n",rule->description);
#endif
                }

                
            } else if (!strncmp(tmpfield,"reference:",10)) {
                    
                if (rule->num_ref < MAX_REFERENCES) {
                    tmpvalue = tmpfield + strlen("reference:"); 
                    length = strlen(tmpvalue);
                    rule->references[rule->num_ref] = uchar_malloc(length+1);
                    strncpy(rule->references[rule->num_ref], tmpvalue, length);
                    rule->references[rule->num_ref][length] = '\0';
#ifdef DEBUG
                printf("\t\t\tExtraida reference: [%s]\n",rule->references[rule->num_ref]);
#endif
                    rule->num_ref++;
                } else if (!rwarning) {
                    printf("[parse_snortrule]: WARNING - Regla [%d] supera número permitido de referencias\n",num_rules_file);
                    rwarning = true;
                }

            } else if (!strncmp(tmpfield,"classtype:",10)) {

                    tmpvalue = tmpfield + strlen("classtype:"); 
                    length = strlen(tmpvalue);
                    rule->attack_type = uchar_malloc(length+1);
                    strncpy(rule->attack_type, tmpvalue, length);
                    rule->attack_type[length] = '\0';
#ifdef DEBUG
                printf("\t\t\tExtraido attack_type: [%s]\n",rule->attack_type);
#endif
            } else if (!strncmp(tmpfield,"pcre:",5)) {

                if (rule->num_pcre >= MAX_PCRE) printf("[parse_snortRule] WARNING: Regla [%d] excede número de campos pcre\n",num_rules_file);
                tmpvalue = tmpfield + strlen("pcre:");                
                if (tmpvalue[0] == '"') tmpvalue++; /* Evitamos las comillas inicial y final */
                length = strlen(tmpvalue);
                
                /* Caso particular: el ; aparece en el campo pcre o content: tenemos que añadir trozos */
                
                if (tmpvalue[length-1] == '\"') {
                    tmpvalue[length-1] = '\0';
                    length--;
                    strncpy(content,tmpvalue,length);
                    content[length]='\0';
                } else {
                    /* Caso particular: el ; aparece en el campo pcre o content: tenemos que añadir trozos */

                    strncpy(content,tmpvalue,length);
                    content[length]='\0';
                    strcat(content,";");
                    if (tmpvalue[length+1]!='"') {    /* Hay un problema en el caso de que el ; sea el último carácter del contenido */
                            tmpfield=strtok(NULL,"\";");
                            if (!tmpfield) {
                                printf("[parse_snortRule]: Error en campo pcre regla [%d]\n", num_rules_file);
                                exit(-1);                      
                            }
                            strcat(content,tmpfield);
                            length += strlen(tmpfield)+1; 
                    } else {
                            length +=1;
                    }       
                        
                }
                
                if (length > 0) {

                    if  ( content[0] == '!')   {  //Se trata de una expresión regular negada
                        rule->pcre[rule->num_pcre].negated = true;
                        tmpvalue++;
                    } else {
                        rule->pcre[rule->num_pcre].negated = false;
                    }

                    /* OJO: No se gestionan los bytecodes ni caracteres especiales o escapados en pcre */
                    
                    parse_snortPcre(content, rule);		// Aquí se procesa y carga la expresión regular en la regla
					
					/* Compilamos el pcre */
					
					if (nocase) options = PCRE_CASELESS || PCRE_DOTALL;
					else options = PCRE_DOTALL;
					
					if (strchr(rule->pcre[rule->num_pcre].modifier,'i')) options = options || PCRE_CASELESS;

					rule->pcre[rule->num_pcre].pattern = pcre_compile2(rule->pcre[rule->num_pcre].regExp, options, &error_id, &error, &error_offset, NULL);

					if (!rule->pcre[rule->num_pcre].pattern) printf("[parse_snortRule]: pcre_compile failed (offset: %d) error %s en regla [%d]\n", error_offset, error,num_rules_file);

#ifdef DEBUG
                    printf("\tExtraido pcre: [%s]\n",rule->pcre[rule->num_pcre].regExp);
#endif
                    rule->num_pcre++;

                }            
            } else if ((!strncmp(tmpfield,"content:",8)) || (!strncmp(tmpfield,"uricontent:",11))) {
                if (rule->num_patt < MAX_PATTERNS) {
                    if (!strncmp(tmpfield,"content:",8)) tmpvalue = tmpfield + strlen("content:");
                    else tmpvalue = tmpfield + strlen("uricontent:");                    
                    if (tmpvalue[0] == '"') tmpvalue++; /* Evitamos las comillas inicial y final */
                    length = strlen(tmpvalue);
                    if (tmpvalue[length-1] == '\"') {
                        tmpvalue[length-1] = '\0';
                        length--;
                        strncpy(content,tmpvalue,length);
                        content[length]='\0';
                    } else { /* Caso particular: el ; aparece en el campo pcre o content: tenemos que añadir trozos */
                        strncpy(content,tmpvalue,length);
                        content[length]='\0';
                        strcat(content,";");
                        if (tmpvalue[length+1]!='"') {    /* Hay un problema en el caso de que el ; sea el último carácter del contenido */
                            tmpfield=strtok(NULL,"\";");
                            if (!tmpfield) {
                                printf("[parse_snortRule]: Error en campo content regla [%d]\n", num_rules_file);
                                exit(-1);                      
                            }
                            strcat(content,tmpfield);
                            length += strlen(tmpfield)+1; 
                        } else {
                            length +=1;
                        }                     
                    }                

                    if (length > 0) {
                        
                        rule->URI_pattern[rule->num_patt].pattern_str = uchar_malloc(length+1);
                        strncpy(rule->URI_pattern[rule->num_patt].pattern_str, content, length);
                        rule->URI_pattern[rule->num_patt].pattern_str[length] = '\0';

                        parse_snortContent(rule->URI_pattern[rule->num_patt].pattern_str);
                        rule->URI_pattern[rule->num_patt].nocase = false;
#ifdef DEBUG
                        printf("\t\t\tExtraido content: [%s]\n",rule->URI_pattern[rule->num_patt].pattern_str);
#endif
                        rule->num_patt++;

                    } else {
                        printf("[parse_snortrule]: WARNING - Error parseando content en regla [%d]\n",num_rules_file);
                    }   
                } else if (!cwarning) {                  
                    printf("[parse_snortrule]: WARNING - Regla [%d] supera número permitido de contents\n",num_rules_file);
                    cwarning = true;
                }               
            } else if (!strncmp(tmpfield,"urilen:",7)) {
                    tmpvalue = tmpfield + strlen("urilen:"); 
                    length = strlen(tmpvalue);
                    if (tmpvalue[0]=='>') {
                        tmpvalue++;
                        rule->uritype=URILENGT;
                    } else if (tmpvalue[0]=='<') {
                        tmpvalue++;
                        rule->uritype=URILENLT;
                    } else rule->uritype=URILENEQ;
                    sscanf(tmpvalue,"%d",&rule->urilen);
#ifdef DEBUG
                    printf("\t\t\tExtraido urilen: [%d]\n",rule->urilen);
#endif
            } else if (!strncmp(tmpfield,"dsize:",6)) {
                    tmpvalue = tmpfield + strlen("dsize:"); 
                    length = strlen(tmpvalue);
                    if (rule->urilen == 0) {
                        if (tmpvalue[0]=='>') {
                            tmpvalue++;
                            rule->uritype=URILENGT;
                        } else if (tmpvalue[0]=='<') {
                            tmpvalue++;
                            rule->uritype=URILENLT;
                        } else rule->uritype=URILENEQ;
                        sscanf(tmpvalue,"%d",&rule->urilen);
                    }
#ifdef DEBUG
                    printf("\t\t\tExtraido dsize como urilen: [%d]\n",rule->urilen);
#endif
            } else if (!strncmp(tmpfield,"nocase",6)) {
                if (rule->num_patt > 0) {
                    rule->URI_pattern[rule->num_patt-1].nocase = true;
#ifdef DEBUG
                    printf("\t\t\tExtraido nocase para content [%d]\n",rule->num_patt-1);
                } else {
                    printf("[parse_snortRule] WARNING: encontrado nocase sin content previo - Regla [%d]\n",num_rules_file);
#endif
				}
            } else if (!strncmp(tmpfield,"sid:",4)) {
                    tmpvalue = tmpfield + strlen("sid:"); 
                    length = strlen(tmpvalue);
                    sscanf(tmpvalue,"%d",&rule->sid);
#ifdef DEBUG
                    printf("\t\t\tExtraido sid: [%d]\n",rule->sid);
#endif
            } else if (!strncmp(tmpfield,"http_method",11)) {
                    if ( (!strstr(rule->URI_pattern[rule->num_patt-1].pattern_str, "GET") || !strstr(rule->URI_pattern[rule->num_patt-1].pattern_str, "POST") || 
						!strstr(rule->URI_pattern[rule->num_patt-1].pattern_str, "HEAD") || !strstr(rule->URI_pattern[rule->num_patt-1].pattern_str, "PROPFIND") ) )  {
								rule->num_patt--;
								free(rule->URI_pattern[rule->num_patt].pattern_str);
								rule->URI_pattern[rule->num_patt].pattern_str = NULL;
								rule->URI_pattern[rule->num_patt].nocase = false;
								rule->URI_pattern[rule->num_patt].negated = false;
					} else {
						printf("[parse_snortRule] WARNING: encontrado method sin content asociado previo valido - Regla [%d] Método [%s] -> Descartada \n",num_rules_file,rule->URI_pattern[rule->num_patt-1].pattern_str);	
						isRuleOK = false;
					};
#ifdef DEBUG
                    printf("\t\t\tEliminado content asociado a método en regla [%d]\n",num_rules);
#endif
            }
            tmpfield = strtok(NULL, ";");       

        }
     
        /* Hemos terminado de procesar la regla: comprobaciones */
        
        if (isRuleOK) {
			if ( (rule->sid > 0) && ((rule->num_patt > 0) || (rule->num_pcre > 0) )) {   /* Regla con campos mínimos */
				if(num_URIrules < MAX_URI_RULES){
					URI_rules[num_URIrules] = rule;
					num_URIrules++;
				}else{
					printf("[parse_snortRule] : Se supero el numero maximo de reglas cargadas = %i\n", MAX_URI_RULES);
				}
			} else {
				printf("[parse_snortRule] : WARNING - Regla [%d] sin campos obligatorios\n", num_rules_file);
				isRuleOK = false;
			};
		};
    } else {
        isRuleOK = false;
    }

    return isRuleOK;
}

/* Procesa un archivo de reglas */

void process_ruleFile(FILE * rulesFile){

    size_t lineLength = 0;
    char * line = NULL;
    ssize_t read;

    int loadedRules = 0; //The number of correct loaded rules FOR THIS FILE (Not total)
	int i;

    //Read each of the lines ot the rules file
    for(i=1; (read = getline(&line, &lineLength, rulesFile)) != -1; i++){
        
        num_rules++;
        num_rules_file++;
 
        //Look if first character is '#' (that line is a comment)
        if(line[0] != '#' && line[0] != '\n'){
            if(parse_snortRule(line))
                loadedRules++;
        }      
    }

    free(line);
}

/* Recorre la estructura de directorio de las reglas y carga los archivos correspondientes */

int fileTree_handler(const char *relPath, const struct stat *sbuf, int type, struct FTW *ftwb){

    //Show the main path in absolute path form
#ifdef DEBUG
	printf("%d",ftwb->base);
#endif
    if ( ftwb->level == 0){
        char absPath[PATH_MAX]; //Maximum number of bytes in a pathname, including terminating null byte
        if(realpath(relPath, absPath) != NULL)
            printf("Rules directory : \"%s\"\n", absPath);
        else
            printf("Rules directory : \"%s\"\n", relPath);

    }else if(ftwb->level > 0){

        //If type == FILE
#ifdef DEBUG
    	printf(">>> Abriendo archivo [%s]\n",relPath);
#endif
        if(type == FTW_F){
            printf("\tOpening %s... ", relPath);
            FILE * rulesFile = fopen(relPath, "r");
                if(rulesFile == NULL){
                    printf("fail");
                }else{
                    printf("done\n");
                    int newrules = num_rules;
                    int newurirules = num_URIrules;
                    int newerrors = num_errorrules;
                    num_rules_file = 0;
                    process_ruleFile(rulesFile);
                    printf("\tReglas: leídas [%d], erróneas [%d], URI [%d]\n",num_rules-newrules,num_errorrules-newerrors,num_URIrules-newurirules);
                    fclose(rulesFile);
                }

        //If type == DIR
        }else if(type == FTW_D){
            printf("\tOpening %s... done\n", relPath);
        }
    }

    return 0;
}

/****************************/
/* Rutinas públicas        */
/****************************/

/* Liberación de reglas */

void free_rule(URI_rule * rule){
	int i;
	
    if(rule->num_pcre){
        for(int i=0; i < rule->num_pcre; i++) {
			free(rule->pcre[i].regExp);
			if (rule->pcre[i].pattern) pcre_free(rule->pcre[i].pattern);
		};
        rule->num_pcre = 0;
    }

    for(i=0; i<rule->num_patt; i++){
        free(rule->URI_pattern[i].pattern_str);
    }
    rule->num_patt = 0;

    if(rule->description){
        free(rule->description);
    }

    for(i=0; i<rule->num_ref; i++){
        free(rule->references[i]);
    }
    rule->num_ref = 0;

    if(rule->attack_type){
        free(rule->attack_type);
    }

    return;
}

/* Lectura de todos los archivos de reglas */

void load_rules(char *r_path){

    printf("\n------------------------- Initializing Rules ---------------------\n");
    if( nftw(r_path, fileTree_handler, 10, 0) == -1){
        printf("Error en 'load_rules' : No se encontro el directorio de reglas = %s\n", r_path);
    }

    printf("--------------------------- Statistics ------------------------------\n");
    printf("Read [%d] rules, [%d] http-related, [%d] with errors\n", num_rules, num_URIrules, num_errorrules);
    printf("--------------------------- Analysis results -----------------------------\n");
}
