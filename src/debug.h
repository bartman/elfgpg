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

#ifndef ELFSIGN_DEBUG_H
#define ELFSIGN_DEBUG_H

#include <stdio.h>
#include <errno.h>
#include <unistd.h>


#define FATAL 0		/* errors that are not ignored */
#define ERROR 1		/* errors which can be ignored */
#define WARN  2		/* warnings that are worked around */
#define NORM  3		/* normal printed output */
#define INFO  4		/* not always needed statistics and info */
#define DEBUG 5		/* only for ppl that want to read the code */

#define ES_SHOW(lvl) \
((lvl)<=opts->verbose)

#define ES_PRINT(lvl,fmt,arg...) \
(ES_SHOW(lvl))?(fprintf(stderr,fmt,## arg)):(0)

#define TODO() do{ ES_PRINT(ERROR, \
"TODO: " __FILE__ ":%d (" __PRETTY_FUNCTION__ ")\n", __LINE__); }while(0)
  
/* include options after the macro definitions on purpose */
#include "options.h"

static inline void
dbg_dump_to_file( const char *fname, void* data, size_t len )
{
	FILE *f = fopen( fname, "w" );
	fwrite( data, len, 1, f );
	fclose(f);
}


#endif
