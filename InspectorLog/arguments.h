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

#ifndef __ARGUMENTS
#define __ARGUMENTS

//C INCLUDES
#define WLENGTH 128

#include <stdbool.h>

bool parse_clArgs(int argc, char **argv);

void show_help();

#endif

