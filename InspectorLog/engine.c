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
#include <stdbool.h>
#include <stdio.h>


//INSPECTORLOG INCLUDES

#include <inspector.h>

//                        ¡         Á         É          Í         Ó        Ú         Ü          á         é         í           ó      ú         ü          Ñ         ñ            ~      `              ,          º       ª
char *utfescaped [] = { "%C2%A1", "%C3%81",  "%C3%89", "%C3%8D", "%C3%93", "%C3%9A", "%C3%9C", "%C3%A1", "%C3%A9", "%C3%AD", "%C3%B3", "%C3%BA", "%C3%BC", "%C3%91", "%C3%B1", "%CB%9C", "%E2%82%AC", "%E2%80%9A", "%C2%BA", "%C2%AA", "%C2%AD", "%C2%B4",
                        "%c2%a1", "%c3%81",  "%c3%89", "%c3%8D", "%c3%93", "%c3%9A", "%c3%9c", "%c3%a1", "%c3%a9", "%c3%ad", "%c3%b3", "%c3%bA", "%c3%bc", "%c3%91", "%c3%b1", "%cb%9c", "%e2%82%ac", "%e2%80%9a", "%c2%ba", "%c2%aa", "%c2%ad", "%c2%b4",
                        };

char *utfunescaped[] = { "¡", "Á", "É", "Í", "Ó", "Ú", "Ü", "á", "é", "í", "ó", "u", "ü", "Ñ", "ñ", "~", "%80", "%82", "º", "ª", " ", "%B4",
                        "¡", "Á", "É", "Í", "Ó", "Ú", "Ü", "á", "é", "í", "ó", "u", "ü", "Ñ", "ñ", "~", "%80", "%82" , "º", "ª", " " , "%B4" };


char *escaped[]={"%20","%21","%22","%23","%24","%25","%26","%27","%28","%29","%2A","%2B","%2C","%2D","%2E","%2F",
                 "%30","%31","%32","%33","%34","%35","%36","%37","%38","%39","%3A","%3B","%3C","%3D","%3E","%3F",
                 "%40","%41","%42","%43","%44","%45","%46","%47","%48","%49","%4A","%4B","%4C","%4D","%4E","%4F",
                 "%50","%51","%52","%53","%54","%55","%56","%57","%58","%59","%5A","%5B","%5C","%5D","%5E","%5F",
                 "%60","%61","%62","%63","%64","%65","%66","%67","%68","%69","%6A","%6B","%6C","%6D","%6E","%6F",
                 "%70","%71","%72","%73","%74","%75","%76","%77","%78","%79","%7A","%7B","%7C","%7D","%7E",
                 "%80",      "%82","%83","%84","%85","%86","%87","%88","%89","%8A","%8B","%8C",      "%8E",
                       "%91","%92","%93","%94","%95","%96","%97","%98","%99","%9A","%9B","%9C",      "%9E", "%9F",  
                 "%A0","%A1","%A2","%A3","%A4","%A5","%A6","%A7","%A8","%A9","%AA","%AB","%AC",       "%AE","%AF",
                 "%B0","%B1","%B2","%B3","%B4","%B5","%B6","%B7","%B8","%B9","%BA","%BB","%BC","%BD", "%BE","%BF",
                 "%C0","%C1","%C2","%C3","%C4","%C5","%C6","%C7","%C8","%C9","%CA","%CB","%CC","%CD", "%CE","%CF",
                 "%D0","%D1","%D2","%D3","%D4","%D5","%D6","%D7","%D8","%D9","%DA","%DB","%DC","%DD", "%DE","%DF",
                 "%E0","%E1","%E2","%E3","%E4","%E5","%E6","%E7","%E8","%E9","%EA","%EB","%EC","%ED", "%EE","%EF",
                 "%F0","%F1","%F2","%F3","%F4","%F5","%F6","%F7","%F8","%F9","%FA","%FB","%FC","%FD", "%EF","%FF",

//                 "%2a","%2b","%2c","%2d","%2e","%2f",
//                 "%3a","%3b","%3c","%3d","%3e","%3f",
//                 "%4a","%4b","%4c","%4d","%4e","%4f",
//                 "%5a","%5b","%5c","%5d","%5e","%5f",
//                 "%6a","%6b","%6c","%6d","%6e","%6f",                 
//                 "%7a","%7b","%7c","%7d","%7e",
                 "%0A","%0D","%0a","%0d"};
char *unescaped[]={" ","!",  "\"", "#",  "$",  "%",  "&",  "'",  "(",  ")",  "*",  "+",  ",",  "-",  ".",  "/",  
                 "0","1","2","3","4","5","6","7","8","9",":",  ";",  "<",  "=",  ">",  "?",  
                 "@","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O",  
                 "P","Q","R","S","T","U","V","W","X","Y","Z", "[",  "\\", "]",  "^",  "_",  
                 "`","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o", 
                 "p","q","r","s","t","u","v","w","x","y","z","{",  "|",  "}",  "~", 
                 "‚",    "ƒ","„","†","‡","^","‰","Š","‹","Œ",   "Ž",  
                 "‘", "’", "“", "”", "•", "–", "—", "˜", "™", "š", "›", "œ", "ž", "Ÿ",
                 " ","¡", "¢", "£", "¤","¥","¦","§","¨","©","ª","«","¬","­","®", "¯",
                 "°","±","²","³","´","µ","¶","·","¸","¹","º","»","¼","½","¾","¿", 
                 "À","Á","Â","Ã","Ä","Å","Æ","Ç","È","É","Ê","Ë","Ì","Í","Î","Ï",  
                 "Ð","Ñ","Ò","Ó","Ô","Õ","Ö","×","Ø","Ù","Ú","Û","Ü","Ý","Þ","ß",  
                 "à","á","â","ã","ä","å","æ","ç","è","é","ê","ë","ì","í","î","ï",                 
                 "ð","ñ","ò","ó","ô","õ","ö","÷","ø","ù","ú","û","ü","ý","þ","ÿ",
//                 "*",  "+",  ",",  "-",  ".",  "/",  
//                 ":",  ";",  "<",  "=",  ">",  "?",  
//                 "J","K","L","M","N","O",
//                 "Z","[",  "\\", "]",  "^",  "_", 
//                 "j","k","l","m","n","o",                 
//                 "z","{",  "|",  "}",  "~",
                 "\n","\n","\n","\n","A"};

#define nescapes (sizeof(escaped) / sizeof(const char *))
#define nutf8 (sizeof(utfescaped) / sizeof(const char *))

// Cambia todos los caracteres escapados con % de la lista por su versión ascii
// Se asume que las versiones escapadas son más cortas que las sin escapar

void unescape_uri(char *str) {
    int i,j;
    char tmpchar[URILENGTH+1];
    char *p, *f;

    strcpy(tmpchar,str);

    for(i=0;i<nescapes;i++) {
        
        while (p = strcasestr(tmpchar,escaped[i])) {
            f = p+strlen(escaped[i]);
            j=0;
            while (j < strlen(unescaped[i])) {
                *p++ = unescaped[i][j++];
            }
            while (*f != '\0') *p++ = *f++;
            *p = '\0';             
        }
    }
                
    strcpy(str,tmpchar);

 return;
}

bool utf8decode(char *utfstr) {
    int i,j;
    char tmpc[URILENGTH+1];
    char *p, *f;
    bool found;

    strncpy(tmpc,utfstr,URILENGTH);

//    printf("%d %d %d %s\n",nutf8,nescapes, sizeof(utfescaped),tmpc);
    for(i=0;i< nutf8; i++) {
//        printf("%d -> %s\n",i,utfescaped[i]);
        
        while (p = strstr(tmpc,utfescaped[i])) {
            found = true;
#ifdef DEBUG
            printf("Encontrado [%s]\n",utfescaped[i]);
//            printf("%s\n",p);
#endif
            f = p+strlen(utfescaped[i]);

            j=0;
            while (j < strlen(utfunescaped[i])) {
                *p++ = utfunescaped[i][j++];
            }
//            printf("Sustituido ...\n");
//            memmove(p,f,strlen(f));
            
            while (*f != '\0') *p++ = *f++;
            *p = '\0';             
//            printf("%s\n",tmpc);
        }

    }
                
    if (found) strcpy(utfstr,tmpc);

 return found;
}    

bool urldecode(char *str) {
    int i, j;
    bool found;
    char tmpchar[URILENGTH+1];
    char code[4];
    char *p, *f;
    
    tmpchar[0] = '\0';
    p = str;
    f = tmpchar;
       
    while (*p != '\0') {
        if (*p == '%')  {
//            printf("Encontrado %s\n",p);
            strncpy(code,p,3);
            code[3]='\0';
            found = false;
            j = 0;
            
            /* Optimización: caso particular de %2525 (múltiple encoding de %) */

            if (!strncmp(code,"%25",3) ) {
                p += 3;
                while( (p[0] == '2') && (p[1] == '5')) p+=2;
                *f = '%';
                f++;
            } else {
                
    //            printf("Buscando [%s]\n",code);
                while ((j < nescapes) && !found ) {
                    if (!strncasecmp(escaped[j],code,3)) {
                        strcat(tmpchar,unescaped[j]);
                        found = true;
                        p += 3;
                        f += strlen(unescaped[j]);
                    } else j++;
                }
                if ((!found)) {
                    if (warns) printf("[urldecode] WARNING Error decodificando [%s] en uri [%s] \n",code,str);
                    return(true);
                }
            }
        } else {
            *f++ = *p++;
            *f = '\0';
        }
    }
    strcpy(str,tmpchar);
    return(false);   
}

#undef DEBUG
//Return 'true' if the given 'URI' matches the given 'rule'
bool check_URIpatterns(const char * URI, URI_rule * rule){

    bool match = true;
    char *pos = NULL;
    int OVECCOUNT = 1024;
    int ovector[OVECCOUNT];
	int offset;
	int p=0, i=0;

    /* Comprobamos urilen */

    if ((rule->uritype == URILENEQ) && (rule->urilen != strlen(URI))) return(false);
    if ((rule->uritype == URILENLT) && (rule->urilen < strlen(URI))) return(false);
    if ((rule->uritype == URILENGT) && (rule->urilen > strlen(URI))) return(false);

#ifdef DEBUG
    printf("Aplicando regla [%d]\n",rule->sid);
#endif
    //Para que una regla se cumpla, esta debe de contener todos los patrones de dicha regla
    for(i=0; i<rule->num_patt; i++){
#ifdef DEBUG
        printf("Comprobando cadena [%s] con patron content [%s] (negado=%d)-> ",URI, rule->URI_pattern[i].pattern_str,rule->URI_pattern[i].negated);
#endif
        if ((rule->URI_pattern[i].nocase) || (nocase)) {
            pos = strcasestr(URI, rule->URI_pattern[i].pattern_str);
        } else {     
            pos = strstr(URI, rule->URI_pattern[i].pattern_str);
        }
        if ( (pos == NULL) && !(rule->URI_pattern[i].negated)) {
#ifdef DEBUG 
            printf(" fail\n");
#endif
            match = false;
            break;
#ifdef DEBUG
        } else printf(" ok\n");
#else
        } 
#endif

    }

    //También debe de cumplir la coincidencia con la expresión regular dada en formato "pcre"

    if(match && rule->num_pcre){ //Si se han encontrado todos los patrones literales

        match = true;
        
#ifdef DEBUGTIME
            timeinfo = localtime(&rawtime);
            printf("-> Expresión pcre [%d de %d] = \"%s\"\n", p, rule->num_pcre, asctime(timeinfo));
#endif
      
        for (p=0;p < ((rule->num_pcre) && (match == true)); p++) { /* Probamos todas las expresiones regulares */
        
#ifdef DEBUGTIME
            time(&rawtime);
            printf("-> Expresión pcre [%d de %d] SID (%d)= \"%s\"\n", p, rule->num_pcre, rule->sid, ctime(&rawtime));
#endif        
    #ifdef DEBUG
                printf("Comprobando [%s] con expresión pcre [%s]\n",URI,rule->pcre[p].regExp);
    #endif

                offset = pcre_exec(
                    rule->pcre[p].pattern,              /* the compiled pattern */
                    0,                    /* no extra data - pattern was not studied */
                    URI,                  /* the string to match */
                    strlen(URI),          /* the length of the string */
                    0,                    /* start at offset 0 in the subject */
                    0,                    /* default options */
                    ovector,              /* output vector for substring information */
                    OVECCOUNT);           /* number of elements in the output vector */

                //En ovector puedo encontrar la posición de la cadena donde se ha detectado el patron
                if ((offset < 0) && !rule->pcre[p].negated) {
                    match = false;
                }
        }
    }

    return match;
}

//Return the number of positives matches for the given 'URI' against the actually loaded rules
int detect_URI(const char * URI, int * rules_detected){

    int positives = 0;
    int found, j=0, n=0;
    char tmpuri[URILENGTH];
    bool utf8= false, urlcoded = false;          /* Control de existencia de % no decodificables */
    
    /* Primero probamos las URI tal cual */
    
    for(n=0; n < num_URIrules; n++){ //Comprobamos cada una de las reglas

        if( check_URIpatterns(URI, URI_rules[n]) ){
            rules_detected[positives] = n;
            positives++;
        }
    }

    /* Y comprobamos si hay algún carácter escapado, en cuyo caso repetimos bucle (iteramos mientras queden % */
    strcpy(tmpuri,URI);
    
    // Primero decodificamos utf8decode

#define DEBUG    
#ifdef DEBUG
        printf("ANTES:   [%s]\n",tmpuri);
#endif 
    utf8 = utf8decode(tmpuri);
#ifdef DEBUG
        printf("UTF:   [%s]\n",tmpuri);
#endif
    
    while (strstr(tmpuri,"%") && !urlcoded) {
        
//        unescape_uri(tmpuri);     /* Si se activa esta función se hace la sustitución de todos las apariciones por orden de encode */
        urlcoded = urldecode(tmpuri);          /* Esta versión permite ir decodificando por pasos (procesa doble, triple, etc. encoding)       */
#ifdef DEBUG
        printf("DESPUES: [%s]\n",tmpuri);
#endif
        for(int n=0; n < num_URIrules; n++){ //Comprobamos cada una de las reglas

            if( check_URIpatterns(tmpuri, URI_rules[n]) ){ // Se cumple, comprobamos que es nueva
                found = false;
                for(j=0; j < positives; j++) {
                    if (rules_detected[j] == n) found = true;
                };
                if (!found) {
                    rules_detected[positives] = n;
                    positives++;
                }
            }
        }
    } 
    
    return positives;
}

