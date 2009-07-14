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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdlib.h>
#include <stdio.h>

#include "options.h"
#include "verify.h"
#include "elfgpg.h"
#include "elfhelp.h"
#include "elfstrings.h"

/* there is a bit of a context for processing an elf file, this structure
 * saves us from using a long paramters list when calling implementation
 * functions */
typedef struct dump_session_s {
	const char *file;
	int fd;

	/* elf processing variables */
	Elf *elf;

	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;

	/* the two section worth preloading */
	Elf32_Shdr *pgptab_hdr, *pgpsig_hdr;
	Elf_Scn *pgptab_scn, *pgpsig_scn;
	Elf_Data *pgptab_data, *pgpsig_data;

	/* entry in the .pgptab */
	Elf32_Pgp pgp; 

	/* section currently processed */
	Elf32_Shdr *shdr;
	Elf_Data *data;
	Elf_Scn *scn;
} dump_session_t;

static int
init_process_elf( dump_session_t *s )
{
	int err;

	s->elf = elf_begin( s->fd, ELF_C_READ, NULL );
	switch( elf_kind(s->elf) ) {
	case ELF_K_ELF:
		ES_PRINT(DEBUG, "%s: ELF file format detected\n", s->file);

		s->phdr = NULL;
		err = 1;

		/* get Elf Program Headers then the scn/shdr/data for the tab/sig scns */
		if( !(s->ehdr = elf32_getehdr(s->elf)) ) {
			ES_PRINT(ERROR, "%s: %s\n", s->file, elf_errmsg(-1));

		} else if ( s->ehdr->e_phnum 
				&& !(s->phdr = elf32_getphdr(s->elf)) ) {
			ES_PRINT(ERROR, "%s: %s\n", s->file, elf_errmsg(-1));

		} else {
			err = 0;
		} 
		
		/* the rest of the components are not manditory */
		if ( !(s->pgptab_hdr = elf32_getshdr( s->pgptab_scn 
					= elf_findscn(s->elf, ".pgptab"))) ) {
			if ( elf_errno() ) {
				ES_PRINT(ERROR, "%s: find .pgptab: %s\n", 
						s->file, elf_errmsg(-1));
			}

		} else if ( !(s->pgptab_data = elf_getdata(s->pgptab_scn, 
						NULL)) ) {
			ES_PRINT(ERROR, "%s: data .pgptab: %s\n", s->file, 
					elf_errmsg(-1));

		} 
		
		if ( !(s->pgpsig_hdr = elf32_getshdr( s->pgpsig_scn 
					= elf_findscn(s->elf, ".pgpsig"))) ) {
			if ( elf_errno() ) {
				ES_PRINT(ERROR, "%s: find .pgpsig: %s\n", 
						s->file, elf_errmsg(-1));
			}

		} else if ( !(s->pgpsig_data = elf_getdata(s->pgpsig_scn, 
						NULL)) ) {
			ES_PRINT(ERROR, "%s: data .pgpsig: %s\n", s->file, 
					elf_errmsg(-1));

		}
		break;

	case ELF_K_AR:
		err = 1;
		ES_PRINT(ERROR, "%s: elf_kind of ELF_K_AR is not supported\n", 
				s->file);
		break;

	default:
		err = 1;
		ES_PRINT(ERROR, "%s: file format not recognized", s->file);
		break;
	}

	return err;
}

static int 
dump_pgpsig( dump_session_t *s )
{
	unsigned int max, cnt;
	unsigned char *bytes;

	if (!s->pgpsig_hdr || !s->pgpsig_scn || !s->pgpsig_data) {
		ES_PRINT (WARN, "%s: .pgpsig section is absent\n",
				s->file);
		goto done;
	}

	if (s->pgpsig_data->d_size < sizeof(Elf32_Pgp)) {
		ES_PRINT (WARN, "%s: .pgpsig section is empty\n",
				s->file);
		goto done;
	}

	ES_PRINT (NORM, "%s: .pgpsig section\n", s->file);

	max = s->pgpsig_data->d_size;
	bytes = s->pgptab_data->d_buf;

	ES_PRINT (NORM, "  len = %d bytes\n    ", max);

	for (cnt=1; cnt<=max; cnt++) {
		inline const char * separator () {
			if (cnt>=max) return "\n";
			if ((cnt & 15) == 0) return "\n    ";
			if ((cnt & 7) == 0) return "   ";
			if ((cnt & 3) == 0) return "  ";
			return " ";
		}
		ES_PRINT (NORM, "%02x%s", *(bytes++), separator());
	}

done:
	return 0;
}

static int 
dump_pgptab( dump_session_t *s )
{
	unsigned int max, offset, cnt;

	if (!s->pgptab_hdr || !s->pgptab_scn || !s->pgptab_data) {
		ES_PRINT (WARN, "%s: .pgptab section is absent\n",
				s->file);
		goto done;
	}

	if (s->pgptab_data->d_size < sizeof(Elf32_Pgp)) {
		ES_PRINT (WARN, "%s: .pgptab section is empty\n",
				s->file);
		goto done;
	}

	ES_PRINT (NORM, "%s: .pgptab section\n", s->file);

	ES_PRINT (NORM, "  %3s  %-8s  %9s\n",  
			"ndx", "entry", "size");

	max = s->pgptab_data->d_size - sizeof(Elf32_Pgp);

	for (cnt=0, offset=0; offset<=max; cnt++, offset+=sizeof(Elf32_Pgp)) {

		/* compute where this pgp entry is */
		Elf32_Pgp *pgp = (void*)s->pgptab_data->d_buf + offset;

		switch (pgp->pt_type) {
		case ELF_PT_SCN:
			ES_PRINT (NORM, "  %3d  SCN %-4d  %9d\n",  cnt, 
					pgp->pt_shndx,
					pgp->pt_size);
			break;
		case ELF_PT_EHDR:
			ES_PRINT (NORM, "  %3d  EHDR      %9d\n",  cnt, 
					pgp->pt_size);
			break;
		case ELF_PT_PHDR:
			ES_PRINT (NORM, "  %3d  PHDR      %9d\n",  cnt, 
					pgp->pt_size);
			break;
		}

	}

done:
	return 0;
}

static int
pgptab_find_section ( dump_session_t *s, int index )
{
	unsigned int max, offset;

	if (!s->pgptab_hdr || !s->pgptab_scn || !s->pgptab_data) {
		return 0;
	}

	if (s->pgptab_data->d_size < sizeof(Elf32_Pgp)) {
		return 0;
	}

	max = s->pgptab_data->d_size - sizeof(Elf32_Pgp);

	for (offset = 0; offset <= max; offset += sizeof(Elf32_Pgp)) {

		/* compute where this pgp entry is */
		Elf32_Pgp *tmp_pgp = (void*)s->pgptab_data->d_buf + offset;

		/* if no match continue */
		if (tmp_pgp->pt_shndx != index)
			continue;

		/* if we match get the data from the table and return */
		memcpy( &s->pgp, tmp_pgp, sizeof(Elf32_Pgp) );
		return 1;
	}

	return 0;
}

static int 
dump_elf( dump_session_t *s )
{
	int ret=-1;

	ES_PRINT (NORM, "%s: ELF section summary\n", s->file);
	ES_PRINT (NORM, "  %3s  %-13s  %-9s  %-10s  %s\n",  
			"scn", "type", "size", "test", "name");

	/* */
	s->scn = NULL;
	while ((s->shdr = elf32_getshdr ( 
				s->scn = elf_nextscn (s->elf, s->scn)))) {

		int found, ndx;
		Elf32_Word type, size;
		const char *tname, *sname;
		char type_number[16], test_result[32];

		/* this is the index of this section */
		ndx = elf_ndxscn(s->scn);

		/* get the string of the type of this entry */
		type = s->shdr->sh_type;
		tname = elf_sht_string (type);
		/* if the type name is unknown print the hex number */
		if (!tname) {
			tname = type_number;
			sprintf (type_number, "0x%08x", type);
		}

		/* get the string name of the section */
		sname = elf_strptr (s->elf, s->ehdr->e_shstrndx,
				s->shdr->sh_name);

		/* get the data structure, for the length */
		s->data = elf_getdata (s->scn, NULL);
		size = s->data?s->data->d_size:0;

		/* locate the section in the .pgptab table */
		found = pgptab_find_section (s, ndx);
		if (!found) {
			strcpy (test_result, "-");
		} else if (s->pgp.pt_type != ELF_PT_SCN) {
			snprintf (test_result, 31, "type!=SCN");
		} else if (s->pgp.pt_size != size) {
			snprintf (test_result, 31, "size!=%d", s->pgp.pt_size);
		} else {
			strcpy (test_result, "OK");
		}

		/* print what we know */
		ES_PRINT (NORM, "  %3d  %-13s  %-9d  %-10s  %s\n", ndx,
				tname, size, test_result, sname?sname:"");
	}

	ret=0;

	return ret;
}


int 
do_elfdump( const char *file, int fd )
{
	int ret;
	dump_session_t session;

	ES_PRINT(DEBUG,"elfdump( '%s', %d )...\n"
			"\tverbose = %d\n"
			"\tforce   = %d\n"
			"\tkeyname = %s\n"
			"\tkeyring = %s\n"
			"\talgname = %s\n",
			file, fd,
			opts->verbose, opts->force, opts->keyname, 
			opts->keyring, opts->algname );

	memset(&session, 0, sizeof(dump_session_t));
	session.file = file;
	session.fd = fd;

	ret = init_process_elf( &session );

	if( ! ret )
		ret = dump_pgptab( &session );

	if( ! ret )
		ret = dump_pgpsig( &session );

	if( ! ret )
		ret = dump_elf( &session );

	elf_end(session.elf);

	return ret; 
}

