/*
 *  OpenLDAP pwdPolicy/shadowAccount Overlay
 *  Copyright (c) 2023 David M. Syzdek <david@syzdek.net>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted only as authorized by the OpenLDAP
 *  Public License.
 *
 *  A copy of this license is available in the file LICENSE in the
 *  top-level directory of the distribution or, alternatively, at
 *  <http://www.OpenLDAP.org/license.html>.
 */
#ifndef _SRC_PWDSHADOW_H
#define _SRC_PWDSHADOW_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////

#include "portable.h"
//#include <ldap.h>
#include "slap.h"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

extern int
init_module(
	int				argc,
	char *				argv[] );


extern int
pwdshadow_initialize( void );


#endif /* end of header file */
