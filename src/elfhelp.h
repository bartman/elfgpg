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

#ifndef ELFSIGN_ELFHELP_H
#define ELFSIGN_ELFHELP_H

#include <string.h>
#include <inttypes.h>
#include "debug.h"

/* 
 * create_data() and create_section() was taken from libelf-examples-0.1.0 
 * Copyright (C) 1997 Michael Riepe <michael@stud.uni-hannover.de>
 */

static Elf_Data* create_data(Elf_Scn *scn, void *buf, size_t size, 
		Elf_Type type, size_t align) __attribute__ ((unused));
static Elf_Scn* create_section(Elf *elf, unsigned type, char *name) 
	__attribute__ ((unused));

#define elferr(str) fprintf(stderr, "%s: %s\n", str, elf_errmsg(-1))

static Elf_Data*
create_data(Elf_Scn *scn, void *buf, size_t size, Elf_Type type, size_t align) 
{
	Elf_Data *data;

	if ((data = elf_newdata(scn))) {
		data->d_align = align;
		data->d_size = size;
		data->d_type = type;
		data->d_buf = buf;
		return data;
	}

	ES_PRINT(ERROR, "%s: elf_newdata(scn=%p,buf=%p,size=%"PRIuMAX",type=%u,"
			"align=%"PRIuMAX"): %s\n", __PRETTY_FUNCTION__, scn, 
			buf, size, type, align, elf_errmsg(-1));
	return NULL;
}

static Elf_Scn*
create_section(Elf *elf, unsigned type, char *name) 
{
	static char shstrtab[] = ".shstrtab";
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	Elf_Data *data;
	Elf_Scn *scn, *strscn;

	if (!(ehdr = elf32_getehdr(elf))) {
		ES_PRINT(ERROR, "%s: elf32_getehdr(%p): %s\n",
				__PRETTY_FUNCTION__, elf, elf_errmsg(-1));
		return NULL;
	}
	if (!ehdr->e_shstrndx) {
		ehdr->e_version = EV_CURRENT;
		if (!(shdr = elf32_getshdr(strscn = elf_newscn(elf)))) {
			ES_PRINT(ERROR, "%s: elf32_getshdr(%p): %s\n",
				__PRETTY_FUNCTION__, elf, elf_errmsg(-1));
			return NULL;
		}
		shdr->sh_type = SHT_STRTAB;
		ehdr->e_shstrndx = elf_ndxscn(strscn);
		if (!create_data(strscn, "", 1, ELF_T_BYTE, 1)) {
			return NULL;
		}
		if (!(data = create_data(strscn, shstrtab, sizeof(shstrtab), 
						ELF_T_BYTE, 1))) {
			return NULL;
		}
		if (elf_update(elf, ELF_C_NULL) == -1) {
			ES_PRINT(ERROR, "%s: elf_update(%p,ELF_C_NULL): %s\n",
				__PRETTY_FUNCTION__, elf, elf_errmsg(-1));
			return NULL;
		}
		shdr->sh_name = data->d_off;
	}
	else if (!(strscn = elf_getscn(elf, ehdr->e_shstrndx))) {
		ES_PRINT(ERROR, "%s: elf_getscn(%p,%u): %s\n",
				__PRETTY_FUNCTION__, elf, ehdr->e_shstrndx,
				elf_errmsg(-1));
		return NULL;
	}
	if (!(shdr = elf32_getshdr(scn = elf_newscn(elf)))) {
		ES_PRINT(ERROR, "%s: elf32_getshdr(%p): %s\n",
				__PRETTY_FUNCTION__, elf, elf_errmsg(-1));
		return NULL;
	}
	if (!(data = create_data(strscn, name, 1 + strlen(name), 
					ELF_T_BYTE, 1))) {
		return NULL;
	}
	if (elf_update(elf, ELF_C_NULL) == -1) {
		ES_PRINT(ERROR, "%s: elf_update(%p,ELF_C_NULL): %s\n",
				__PRETTY_FUNCTION__, elf, elf_errmsg(-1));
		return NULL;
	}
	shdr->sh_name = data->d_off;
	shdr->sh_type = type;
	return scn;
}

static Elf_Scn*
elf_findscn(Elf *elf, const char *name) 
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	Elf_Scn *scn;
	char *str;

	if ((ehdr = elf32_getehdr(elf))) {
		scn = NULL;
		while ((shdr = elf32_getshdr(scn = elf_nextscn(elf, scn)))) {
			if (shdr->sh_type == SHT_NULL) {
				continue;
			}
			if (!(str = elf_strptr(elf, ehdr->e_shstrndx, 
							shdr->sh_name))) {
				break;
			}
			if (!strcmp(str, name)) {
				return scn;
			}
		}
	}
	return NULL;
}


#endif
