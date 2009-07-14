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

#ifndef ELFPGP_H
#define ELFPGP_H

#include <libelf.h>

/* new sections that will be used by elfgpg */

#define SHT_PGPTAB  (SHT_LOUSER|('p'<<16)|('g'<<8)|'p')
#define SHT_PGPSIG  SHT_PGPTAB+1

/* .pgptab entry types */
#define ELF_PT_EHDR 0
#define ELF_PT_PHDR 1
#define ELF_PT_SCN  2

/* .pgptab entry structure */
typedef struct
{
	Elf32_Word    pt_type;		/* Type of pgp table entry */
	Elf32_Word    pt_size;		/* Symbol size */
	Elf32_Section pt_shndx;		/* Section index */
} Elf32_Pgp;


#endif
