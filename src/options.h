/* 
 * Copyright (C) 2001-2003 Bart Trojanowski <bart@jukie.net>
 *
 * This file is a part of the elfsign utility
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ident "%Z%%M% %I%      %E% Bart Trojanowski <bart@jukie.net>"

#ifndef ELFSIGN_OPTIONS_H
#define ELFSIGN_OPTIONS_H

#include <linux/stddef.h>
#include <sys/types.h>

#include "debug.h"

typedef struct elfsign_options_s {

  enum { NONE=0, SIGN, VERIFY } operation;

  /* debug level */
  int verbose;

  /* force through some errors */
  int force;

  /* maximum width of a file name */
  int file_name_max;
  
  /* what key to use */
  char *keyname;

  /* what keyring to use */
  char *keyring;

  /* algorithm for signing */
  char *algname;


} elfsign_options_t;

extern elfsign_options_t *opts;

static inline void
init_options( void )
{
  opts->operation = NONE;
  opts->verbose = NORM;
  opts->force   = 0;
  opts->file_name_max = 10;
  opts->keyname = NULL;
  opts->keyring = NULL;
  opts->algname = NULL;
}


#endif
