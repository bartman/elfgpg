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

#include <libelf.h>
#include "debug.h"

const char *
elf_sht_string (int sh_type)
{
	if (sh_type == SHT_NULL)		return "NULL";
	if (sh_type == SHT_PROGBITS)		return "PROGBITS";
	if (sh_type == SHT_SYMTAB)		return "SYMTAB";
	if (sh_type == SHT_STRTAB)		return "STRTAB";
	if (sh_type == SHT_RELA)		return "RELA";
	if (sh_type == SHT_HASH)		return "HASH";
	if (sh_type == SHT_DYNAMIC)		return "DYNAMIC";
	if (sh_type == SHT_NOTE)		return "NOTE";
	if (sh_type == SHT_NOBITS)		return "NOBITS";
	if (sh_type == SHT_REL)			return "REL";
	if (sh_type == SHT_SHLIB)		return "SHLIB";
	if (sh_type == SHT_DYNSYM)		return "DYNSYM";
	if (sh_type == SHT_INIT_ARRAY)		return "INIT_ARRAY";
	if (sh_type == SHT_FINI_ARRAY)		return "FINI_ARRAY";
	if (sh_type == SHT_PREINIT_ARRAY)	return "PREINIT_ARRAY";
	if (sh_type == SHT_GROUP)		return "GROUP";
	if (sh_type == SHT_SYMTAB_SHNDX)	return "SYMTAB_SHNDX";
	if (sh_type == SHT_NUM)			return "NUM";
	if (sh_type == SHT_LOOS)		return "LOOS";
	if (sh_type == SHT_GNU_LIBLIST)		return "GNU_LIBLIST";
	if (sh_type == SHT_CHECKSUM)		return "CHECKSUM";
	if (sh_type == SHT_LOSUNW)		return "LOSUNW";
	if (sh_type == SHT_SUNW_move)		return "SUNW_move";
	if (sh_type == SHT_SUNW_COMDAT)		return "SUNW_COMDAT";
	if (sh_type == SHT_SUNW_syminfo)	return "SUNW_syminfo";
	if (sh_type == SHT_GNU_verdef)		return "GNU_verdef";
	if (sh_type == SHT_GNU_verneed)		return "GNU_verneed";
	if (sh_type == SHT_GNU_versym)		return "GNU_versym";
	if (sh_type == SHT_HISUNW)		return "HISUNW";
	if (sh_type == SHT_HIOS)		return "HIOS";
	if (sh_type == SHT_LOPROC)		return "LOPROC";
	if (sh_type == SHT_HIPROC)		return "HIPROC";
	if (sh_type == SHT_LOUSER)		return "LOUSER";
	if (sh_type == SHT_HIUSER)		return "HIUSER";

	return NULL;
}


