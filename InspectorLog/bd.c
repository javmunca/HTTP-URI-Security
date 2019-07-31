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

//INSPECTORLOG INCLUDES

#include "inspector.h"

bool connect_MySQL(MYSQL **connector){

    if(strlen(mysql_user)==0||strlen(mysql_pass)==0||strlen(mysql_schema)==0){
        exit(EXIT_FAILURE);
    }

    MYSQL *tmp = mysql_init(NULL);

    if (tmp == NULL){
        printf("Error en 'connect_MySQL' : No se pudo realizar la inicialización del conector\n");
        return false;
    }

    if (mysql_real_connect(tmp, "localhost", mysql_user, mysql_pass, mysql_schema, 0, NULL, 0) == NULL){
        printf("Error en 'connect_MySQL' : No se pudo realizar la conexión con la base de datos\n");
        return false;
    }

    *connector = tmp;

    return true;
}

bool query(char *str_query){

    if (mysql_query(con, str_query) != 0){
        //printf("\nError en 'query' : Fallo en la función mysql_query para la entrada %s\n\n", str_query);
        return false;
    }

    return true;
}

void disconnect_MySQL(MYSQL *connector){

    mysql_close(connector);
}

