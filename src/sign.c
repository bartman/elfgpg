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
#include <gpgme.h>
#include <termios.h>
#include <string.h>
#include <stdlib.h>

#include "options.h"
#include "sign.h"
#include "elfgpg.h"
#include "elfhelp.h"
#include "elfstrings.h"

typedef struct sign_session_s 
{
	/* current read state */
	u_int32_t tab_index;
	u_int32_t scn_offset;
	int read_cb_eof;

	/* file being processed */
	const char *file;
	int fd;
	gpgme_ctx_t gpgme_ctx;

	void *pgptab_head; /* allocated buffer start */
	void *pgptab_tail; /* points to next byte to be used */
	size_t pgptab_len; /* lenght of the allocated buffer */

	/* the .pgptab and .pgpsig sections, headers and data */
	Elf_Scn *pgptab_scn, *pgpsig_scn;
	Elf_Data *pgptab_data, *pgpsig_data;
	Elf_Data fake_data;

	/* entry in the .pgptab */
	Elf32_Pgp pgp; 

	/* processing variables */
	Elf *elf;

	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;

	Elf32_Shdr *shdr;
	Elf_Data *data;
	Elf_Scn *scn;

	/* had to generate the new sections */
	int new_sections;

	/* the signature buffer */
	size_t slen;
	char sig[4096];	
}
sign_session_t;

static int 
linelen (const char *s)
{
	int i;
	for (i = 0; *s && *s != '\n'; s++, i++)
		;
	return i;
}


static char pass[1024] = {0,};

static gpgme_error_t
passphrase_cb (void *hook, const char *uid_hint, const char *passphrase_info,
		int prev_was_bad, int fd)
{
	struct termios term;
	static struct termios termsave;
	const char *cmd=NULL, *uid=NULL, *info=NULL;

fprintf(stderr, "%s: uid_hint = %s\n", __FUNCTION__, uid_hint);
fprintf(stderr, "%s: passphrase_info = %s\n", __FUNCTION__, passphrase_info);

	if( !passphrase_info ) {
		/* this is the second callback meant for releasing 
		 * resources, but we want to keep it to the very end of 
		 * the signing process */
		return GPG_ERR_CANCELED;
	}

	ES_PRINT(DEBUG,"%s: getting password\n", __PRETTY_FUNCTION__);

	/* get the description parts 
	 * [ code borowed from Sylpheed; thanks to Werner Koch <wk@gnupg.org> ]
	 */
	cmd = passphrase_info;
	uid = strchr (cmd, '\n');
	if (uid) {
		info = strchr (++uid, '\n');
		if (info )
			info++;
	}

	if (!uid)
		uid = "[no user id]";
	if (!info)
		info = "";

	/* now figure out if this is a retry or first attempt */
	if( strncmp(cmd,"TRY_AGAIN",9)==0 ) {
		fprintf(stderr, "Bad passphrase!  Try again...\n\n");
		pass[0] = 0;

	}else if( strncmp(cmd,"ENTER",5)==0 ) {
		if( pass[0] ) {
			goto return_password;
		}
	}

	/* must get a password... */
	fprintf(stderr, "Key Id: %.*s\n", linelen(uid), uid);
	fprintf(stderr, "Info:   %.*s\n", linelen(info), info);
	fprintf(stderr, "Enter passphrase:");
	fflush(stderr);

	/* disable echo */
	if( tcgetattr(fileno(stdin), &termsave) ) {
		ES_PRINT(ERROR,"tcgetattr() failed: %s\n", strerror(errno) );
		return GPG_ERR_CANCELED;
	}
	term = termsave;
	term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	if( tcsetattr( fileno(stdin), TCSAFLUSH, &term ) ) {
		ES_PRINT(ERROR,"tcsetattr() failed: %s\n", strerror(errno) );
		return GPG_ERR_CANCELED;
	}

	/* get the string */
	if( !fgets(pass, sizeof(pass)-1, stdin) ) {
		ES_PRINT(ERROR,"passphrase_cb: %s\n",strerror(errno));
		return GPG_ERR_CANCELED;
	}

	/* reset echo */
	if( tcsetattr(fileno(stdin), TCSAFLUSH, &termsave) ) {
		ES_PRINT(ERROR,"tcsetattr() failed: %s\n", strerror(errno) );
		return GPG_ERR_CANCELED;
	}

	fprintf(stderr, "\n");

return_password:
	if (write(fd, pass, strlen(pass)) < 0)
		return GPG_ERR_CANCELED;
	return GPG_ERR_NO_ERROR;
}

static int
configure_gpg( gpgme_ctx_t *ctx )
{
	gpgme_error_t err;

	ES_PRINT(DEBUG,"%s: gpgme configuration\n", __PRETTY_FUNCTION__);

	err = gpgme_new(ctx);
	if( err ) {
		ES_PRINT(ERROR, "gpgme_new: %s\n", gpgme_strerror(err));
		return -1;
	}

	if ( !getenv("GPG_AGENT_INFO") )
		gpgme_set_passphrase_cb ( *ctx, passphrase_cb, NULL );

	gpgme_set_textmode(*ctx,1);
	gpgme_set_armor(*ctx,0);

	return 0;
}


static int
pgptab_add( sign_session_t *s, Elf32_Pgp *p )
{
	int err = 0;
	char *name = "";

	ES_PRINT(DEBUG,"%s: inserting pgptab entry\n", __PRETTY_FUNCTION__);

	if( p->pt_type == ELF_PT_SCN )
		if( !(name = elf_strptr(s->elf, s->ehdr->e_shstrndx, 
						s->shdr->sh_name)) )
			name = "<name>";

	ES_PRINT(DEBUG, "pgptab_add: '%s' [%s/%d/%d]\n",
			name,
			(p->pt_type == ELF_PT_EHDR)?"EHDR"
			:((p->pt_type == ELF_PT_PHDR)?"PHDR"
				:((p->pt_type == ELF_PT_SCN)?"SCN":"???")),
			p->pt_size, p->pt_shndx);

	if( !s->pgptab_head ) {
		s->pgptab_len = 1024;
		s->pgptab_head = (void*)malloc( s->pgptab_len );
		if( !s->pgptab_head ) {
			ES_PRINT(ERROR, "pgptab_add: %s\n", strerror(errno));
			err = 1;
			goto bail;
		}
		s->pgptab_tail = s->pgptab_head;
	}

	if( ( s->pgptab_tail + sizeof(Elf32_Pgp) ) >
			( s->pgptab_head + s->pgptab_len ) ) {
		void *oldbuf = s->pgptab_head;
		size_t newlen = s->pgptab_len * 2;
		void *newbuf = (void*)malloc( newlen );
		if( !newbuf ) {
			ES_PRINT(ERROR, "pgptab_add: %s\n", strerror(errno));
			err = 1;
			goto bail;
		}

		memcpy( newbuf, oldbuf, s->pgptab_len );
		s->pgptab_head = newbuf;
		free(oldbuf);
	}

	memcpy( s->pgptab_tail, p, sizeof( Elf32_Pgp ) );
	s->pgptab_tail += sizeof( Elf32_Pgp );

bail:
	return err;
}

static ssize_t elf_data_read (void* opaque, void *buff, size_t blen);
static struct gpgme_data_cbs elf_data = {
	.read = elf_data_read,
	.write = NULL,
	.seek = NULL,
	.release = NULL,
};

static ssize_t
elf_data_read (void* opaque, void *buff, size_t blen)
{
	sign_session_t *s = (void*)opaque;
	int eof;	/* 1 if there is no more data to read */
	void *src_ptr, *dst_ptr;
	size_t src_len, dst_len;
	const char *tname, *sname;
	char type_number[16];
	int ndx;

	ES_PRINT(DEBUG, "%s(%p, %p, %"PRIuMAX")\n",
			__PRETTY_FUNCTION__, opaque, buff, blen);

	dst_ptr = buff;
	dst_len = blen;

	if( (eof = s->read_cb_eof) )
		goto bail;

more:
	if( !s->scn_offset ) {
		/* means that we need to fetch the next pgp entry from 
		 * .pgptab */
		long pgp_offset = s->tab_index * sizeof(Elf32_Pgp);

		ES_PRINT(DEBUG, "read_elf_cb: !offset: new section %d\n", 
				s->tab_index);

		if( (pgp_offset+sizeof(Elf32_Pgp)) > s->pgptab_data->d_size ) {
			ES_PRINT(DEBUG,"%s: got to the end of .pgptab\n", 
					s->file);
			s->read_cb_eof = 1;
			goto bail;

		}
		memcpy( &s->pgp, s->pgptab_data->d_buf + pgp_offset, 
				sizeof(Elf32_Pgp) );

		ES_PRINT(DEBUG, "read_elf_cb: pgptab[%d] = { %d, %d, %d }\n",
				s->tab_index, s->pgp.pt_type, s->pgp.pt_size, 
				s->pgp.pt_shndx);

		switch( s->pgp.pt_type ) {
		case ELF_PT_EHDR:
			/* we got an elf header */
			s->data = &s->fake_data;
			s->data->d_buf = (void*)s->ehdr;
			s->data->d_size = s->pgp.pt_size;

			ES_PRINT(INFO,"  %-7s  %-13s  %5d  %s\n", 
					"EHDR", "", s->pgp.pt_size, "");
			break;

		case ELF_PT_PHDR:
			/* get got a program header */
			s->data = &s->fake_data;
			s->data->d_buf = (void*)s->phdr;
			s->data->d_size = s->pgp.pt_size;

			ES_PRINT(INFO,"  %-7s  %-13s  %5d  %s\n", 
					"PHDR", "", s->pgp.pt_size, "");
			break;

		case ELF_PT_SCN:
			/* this is the section index */
			ndx = s->pgp.pt_shndx;

			/* we know the section number, get the section & header */
			s->scn = elf_getscn(s->elf, ndx);
			if( !(s->shdr = elf32_getshdr(s->scn)) ) { 
				ES_PRINT(ERROR,"%s: shndx=%d: %s\n", s->file, 
						ndx, elf_errmsg(-1));
				eof = s->read_cb_eof = 1;
				goto bail;
			}

			/* make sure we have a type for this section */
			tname = elf_sht_string (s->shdr->sh_type);
			if (!tname) {
				tname = type_number;
				sprintf (type_number, "0x%08x", 
						s->shdr->sh_type);
			}

			/* get the name of the elf section we are looking at */
			sname = elf_strptr(s->elf, s->ehdr->e_shstrndx, 
					s->shdr->sh_name);

			/* now get the data for that section */
			if( !(s->data = elf_getdata(s->scn, NULL)) ) {
				ES_PRINT(ERROR,"%s: get data %s\n", s->file, 
						elf_errmsg(-1));
				eof = s->read_cb_eof = 1;
				goto bail;
			}

			ES_PRINT(INFO,"  SCN %-3d  %-13s  %5"PRIuMAX"  %s\n", 
					ndx, tname, s->data->d_size, sname);
			break;

		default:
			ES_PRINT(ERROR,"%s: invalid .pgptab entry type "
					"at index %d\n",
					s->file, s->pgp.pt_shndx);
			eof = s->read_cb_eof = 1;
			goto bail;
		}
	}

	src_ptr = s->data->d_buf + s->scn_offset;
	src_len = s->data->d_size - s->scn_offset;
	if( !src_len ) 
		goto bail;

	ES_PRINT(DEBUG,"read_elf_cb: have data @ %p of len %"PRIuMAX" bytes\n",
			src_ptr, src_len);

	/* test to see if all the current data block can be submitted */
	if( src_len <= dst_len ) {
		if (s->data->d_buf) {
			/* if we have a src pointer then copy */
			memcpy ( dst_ptr, src_ptr, src_len );
		} else {
			/* otherwise we clear -- probably a .bss section */
			memset ( dst_ptr, 0, src_len );
		}
		/* move buffer pointer/size to after new addition */
		dst_ptr += src_len;
		dst_len -= src_len;
		/* prep for next call */
		s->scn_offset = 0;
		s->tab_index ++;

		if( !s->read_cb_eof && dst_len > 32 )
			goto more;

	} else {
		if (s->data->d_buf) {
			/* if we have a src pointer then copy */
			memcpy ( dst_ptr, src_ptr, dst_len );
		} else {
			/* otherwise we clear -- probably a .bss section */
			memset ( dst_ptr, 0, dst_len );
		}
		/* prep for next call */
		s->scn_offset += dst_len;
	}

bail:
	ES_PRINT(DEBUG,"read_elf_cb: returns %d\n",
			eof);
	return eof;
}


/* open_elf_file does just that opens s->fd as s->elf for read/write access */
static int
open_elf_file( sign_session_t *s )
{
	int err;

	ES_PRINT(DEBUG,"%s: opening file as elf\n", __PRETTY_FUNCTION__);

	s->elf = elf_begin( s->fd, ELF_C_RDWR, NULL );
	switch( elf_kind(s->elf) ) {
	case ELF_K_ELF:
		ES_PRINT(DEBUG, "%s: ELF file format detected\n", s->file);

		s->phdr = NULL;
		err = 1;

		/* get Elf and Program Headers */
		if( !(s->ehdr = elf32_getehdr(s->elf)) ) {
			ES_PRINT(ERROR, "%s: %s\n", s->file, elf_errmsg(-1));

		} else if ( s->ehdr->e_phnum 
				&& !(s->phdr = elf32_getphdr(s->elf)) ) {
			ES_PRINT(ERROR, "%s: %s\n", s->file, elf_errmsg(-1));

		} else {
			err = 0;
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


/* prepare_elfgpg_sections makes sure that .pgptab and .pgpsig sections
* exist in elf object -- if they do not then the object is updated 
* (not the file); the sign_session_t *s pgp{tab,sig}_{scn,tab} are also
* updated appropriately; */
static int
prepare_elfgpg_sections( sign_session_t *s )
{
	int err = 1;

	/* assume we don't need a second pass */
	s->new_sections = 0;

	ES_PRINT(DEBUG, "%s: locating the .pgptab section\n", 
			__PRETTY_FUNCTION__);

	if( (s->pgptab_scn = elf_findscn(s->elf, ".pgptab")) ) {
		ES_PRINT(DEBUG, "    ^^ .pgptab section exists\n");
		/* section exists, get the data */
		if( !(s->pgptab_data = elf_getdata(s->pgptab_scn,NULL)) ) {
			ES_PRINT(ERROR, "%s: elf_getdata .pgptab: %s\n", 
					s->file, elf_errmsg(-1));
			goto bail;
		}

	} else {  
		ES_PRINT(DEBUG, "    ^^ .pgptab section will be created\n");
		/* create a new table entry for .pgptab */  
		if( !(s->pgptab_scn = create_section( s->elf, SHT_PGPTAB, 
						".pgptab" )) ) {
			ES_PRINT(ERROR, "%s: create_section .pgptab: %s\n", 
					s->file, 
					elf_errmsg(-1));
			goto bail;
		}

		/* create data for the section */
		if( !(s->pgptab_data = elf_newdata(s->pgptab_scn)) ) {
			ES_PRINT(ERROR, "%s: elf_newdata .pgptab: %s\n", 
					s->file, elf_errmsg(-1));
			goto bail;
		}

		/* creating sections means we need a second pass */
		s->new_sections++;
	}

	/* update the object to include this table */
	s->pgptab_data->d_align = 1;
	s->pgptab_data->d_size = s->ehdr->e_shnum * sizeof(Elf32_Pgp);
	s->pgptab_data->d_type = ELF_T_BYTE;
	s->pgptab_data->d_buf = s->pgptab_head;

	ES_PRINT(DEBUG, "%s: elf_update .pgptab...\n", s->file);
	ES_PRINT(DEBUG, "%s: ->d_align = %"PRIuMAX"\n", s->file, 
			s->pgptab_data->d_align);
	ES_PRINT(DEBUG, "%s: ->d_size = %"PRIuMAX"\n", s->file, 
			s->pgptab_data->d_size);
	ES_PRINT(DEBUG, "%s: ->d_type = %d\n", s->file, 
			s->pgptab_data->d_type);
	ES_PRINT(DEBUG, "%s: ->d_buf = %p\n", s->file, 
			s->pgptab_data->d_buf);

	if( elf_update( s->elf, ELF_C_NULL ) == -1 ) {
		ES_PRINT(ERROR, "elf_update: %s\n", elf_errmsg(-1));
		goto bail;
	}

	ES_PRINT(DEBUG, "%s: locating the .pgpsig section\n", 
			__PRETTY_FUNCTION__);

	if( (s->pgpsig_scn = elf_findscn( s->elf, ".pgpsig" )) ) {
		ES_PRINT(DEBUG, "    ^^ .pgpsig section exists\n");
		/* section exists, get the data */
		if( !(s->pgpsig_data = elf_getdata(s->pgpsig_scn,NULL)) ) {
			ES_PRINT(ERROR, "%s: elf_getdata .pgpsig: %s\n", 
					s->file, elf_errmsg(-1));
			goto bail;
		}

	} else {
		ES_PRINT(DEBUG, "    ^^ .pgpsig section will be created\n");
		/* create a new section entry for .pgpsig */
		if( !(s->pgpsig_scn = create_section( s->elf, SHT_PGPSIG, 
						".pgpsig" )) ) {
			ES_PRINT(ERROR, "%s: create_section .pgpsig: %s\n", 
					s->file, 
					elf_errmsg(-1));
			goto bail;
		}

		/* create data for the section */
		if( !(s->pgpsig_data = elf_newdata(s->pgpsig_scn)) ) {    
			ES_PRINT(ERROR, "%s: elf_newdata: %s\n", s->file, 
					elf_errmsg(-1));
			goto bail;
		}

		/* creating sections means we need a second pass */
		s->new_sections++;
	}

	/* update the elf file to include this structure */
	s->pgpsig_data->d_align = 1;
	s->pgpsig_data->d_size = 65; /* is this large enough for any sig? */
	s->pgpsig_data->d_type = ELF_T_BYTE;
	s->pgpsig_data->d_buf = s->sig;

	ES_PRINT(DEBUG, "%s: elf_update .pgpsig...\n", s->file);
	ES_PRINT(DEBUG, "%s: ->d_align = %"PRIuMAX"\n", s->file, 
			s->pgptab_data->d_align);
	ES_PRINT(DEBUG, "%s: ->d_size = %"PRIuMAX"\n", s->file, 
			s->pgptab_data->d_size);
	ES_PRINT(DEBUG, "%s: ->d_type = %d\n", s->file, 
			s->pgptab_data->d_type);
	ES_PRINT(DEBUG, "%s: ->d_buf = %p\n", s->file, 
			s->pgptab_data->d_buf);

	if( elf_update( s->elf, ELF_C_NULL ) == -1 ) {
		ES_PRINT(ERROR, "%s: elf_update: %s\n", s->file, 
				elf_errmsg(-1));
		err = -1;
		goto bail;
	}

	/* no error */
	err = 0;
bail:
	return err;
}


/* generate_pgptab
* expects that the pgptab section was already created; this fn fills the 
* contents of the section data and updates the elf object (not disk file) */
static int
generate_pgptab( sign_session_t *s )
{
	int err = -1;
	Elf32_Pgp pgp;

	ES_PRINT(INFO,"%s: generating .pgptab entires...\n", s->file);
	ES_PRINT(INFO,"  %-7s  %-13s  %5s  %s\n", 
			"entry", "type", "size", "name");

	/* first add the elf header */
	pgp.pt_type = ELF_PT_EHDR;
	pgp.pt_size = sizeof(*(s->ehdr));
	pgp.pt_shndx = -1;
	pgptab_add( s, &pgp );

	ES_PRINT(INFO,"+ %-7s  %-13s  %5d  %s\n", 
			"EHDR", "", pgp.pt_size, "");

	/* second add the program header */
	pgp.pt_type = ELF_PT_PHDR;
	pgp.pt_size = sizeof(*(s->phdr));
	pgp.pt_shndx = -1;
	pgptab_add( s, &pgp );

	ES_PRINT(INFO,"+ %-7s  %-13s  %5d  %s\n", 
			"PHDR", "", pgp.pt_size, "");

	/* finally add all of the sections */
	s->scn=NULL;
	while((s->shdr = elf32_getshdr(s->scn = elf_nextscn(s->elf,s->scn)))) {
		const char *tname, *sname;
		char type_number[16];
		int ndx;

		/* this is the section index */
		ndx = elf_ndxscn(s->scn);

		/* make sure we have a type for this section */
		tname = elf_sht_string (s->shdr->sh_type);
		if (!tname) {
			tname = type_number;
			sprintf (type_number, "0x%08x", s->shdr->sh_type);
		}
		
		/* get the name of the elf section we are looking at */
		sname = elf_strptr(s->elf, s->ehdr->e_shstrndx, 
				s->shdr->sh_name);

		/* only look at interesting sections */
		if( !sname || s->shdr->sh_type == SHT_NULL ) {
				//|| s->shdr->sh_type == SHT_NOBITS ) {
			ES_PRINT(INFO,"  SCN %-3d  %-13s  %5s  %-10s    -- "
					"skipping null section\n", ndx,
					tname, "", sname?sname:"");
			continue;
		}
		/* skip over the .pgptab and .pgpsig sections */
		if( s->shdr->sh_type >= SHT_LOUSER 
				&& s->shdr->sh_type <= SHT_HIUSER ) {
			if( !strcmp( sname, ".pgptab" ) 
					|| !strcmp( sname, ".pgpsig" ) ) {
				ES_PRINT(INFO,"  SCN %-3d  %-13s  %5s  %-10s"
					"    -- skipping internal section\n", 
					ndx, tname, "", sname);
				continue;
			}
		}
		/* get the data info structure */
		if( !(s->data = elf_getdata(s->scn,NULL)) ) {
			ES_PRINT(INFO,"  SCN %-3d  %-13s  %5s  %s\n", 
					ndx, tname, "", sname);
			continue;
		}

		ES_PRINT(INFO,"+ SCN %-3d  %-13s  %5"PRIuMAX"  %s\n", 
				ndx, tname, s->data->d_size, sname);

		/* compose and append the pgptab entry */
		pgp.pt_type = ELF_PT_SCN;
		pgp.pt_size = s->data->d_size;
		pgp.pt_shndx = elf_ndxscn(s->scn);
		pgptab_add( s, &pgp );
	}

	/* update the object to include this table */
	s->pgptab_data->d_align = 1;
	s->pgptab_data->d_size = s->pgptab_tail - s->pgptab_head;
	s->pgptab_data->d_type = ELF_T_BYTE;
	s->pgptab_data->d_buf = s->pgptab_head;

	if( elf_update( s->elf, ELF_C_NULL ) == -1 ) {
		ES_PRINT(ERROR, "elf_update: %s\n", elf_errmsg(-1));
		goto bail;
	}

	/* success */
	err = 0;
bail:
	return err;
}


/* generate_pgptab
* expects that the pgptab section was already created; this fn fills the 
* contents of the section data and updates the elf object (not disk file) */
static int
generate_pgpsig( sign_session_t *s )
{
	int ret=-1;
	gpgme_error_t err;
	gpgme_data_t in, out;
	size_t oslen;

	/* start processing creating the .pgptab at elf header */
	s->tab_index = 0;
	s->scn_offset = 0;

	ES_PRINT(INFO,"%s: generating .pgpsig section...\n", s->file);
	ES_PRINT(INFO,"  %-7s  %-13s  %5s  %s\n", 
			"entry", "type", "size", "name");

	err = gpgme_data_new_from_cbs (&in, &elf_data, s);
	if( err ) {
		ES_PRINT(ERROR, "gpgme_data_new: %s\n", gpgme_strerror(err));
		goto bail;
	}

	err = gpgme_data_new( &out );
	if( err ) {
		ES_PRINT(ERROR, "gpgme_data_new: %s\n", gpgme_strerror(err));
		goto bail;
	}

	err = gpgme_op_sign (s->gpgme_ctx, in, out, GPGME_SIG_MODE_DETACH);
	if( err ) {
		ES_PRINT(ERROR, "gpgme_op_sign: %s\n", gpgme_strerror(err));
		goto bail;
	}

	oslen = s->slen = sizeof(s->sig);
	err = gpgme_data_read (out, s->sig, oslen);
	if( err ) {
		if( oslen==s->slen ) {
			ES_PRINT(ERROR, "sign_gpg: signature buffer was "
					"too short\n");
			goto bail;
		} else if ( err!=GPG_ERR_EOF ) {
			ES_PRINT(ERROR, "gpgme_data_read: %s\n", 
					gpgme_strerror(err));
			goto bail;
		}
	} else {
		ES_PRINT(INFO, "%s: sig %"PRIuMAX" bytes\n", s->file, s->slen);
	}

	s->pgpsig_data->d_align = 1;
	s->pgpsig_data->d_size = s->slen;
	s->pgpsig_data->d_type = ELF_T_BYTE;
	s->pgpsig_data->d_buf = s->sig;

	if( elf_update( s->elf, ELF_C_NULL ) == -1 ) {
		ES_PRINT(ERROR, "elf_update: %s\n", elf_errmsg(-1));
		err = -1;
		goto bail;
	}

	ret=0;
bail:
	gpgme_data_release(in);
	gpgme_data_release(out);
	return ret;
}


/* commit all changes made to the elf objects to the file that was opened 
* earlier */
static int
commit_elf_to_file( sign_session_t *s )
{
	int err = 0;

	ES_PRINT(DEBUG, "%s: writing changes to disk\n", __PRETTY_FUNCTION__);
	if( elf_update( s->elf, ELF_C_WRITE ) == -1 ) {
		ES_PRINT(ERROR, "elf_update: %s\n", elf_errmsg(-1));
		err = -1;
	}

	return err;
}


/* entry point to the module */
int 
do_elfsign( const char *file, int fd )
{
	int ret;
	int loop = 0;
	sign_session_t session;
	gpgme_ctx_t gpgme_ctx;

	ES_PRINT(DEBUG,"elfsign( '%s', %d )...\n"
			"\tverbose = %d\n"
			"\tforce   = %d\n"
			"\tkeyname = %s\n"
			"\tkeyring = %s\n"
			"\talgname = %s\n",
			file, fd,
			opts->verbose, opts->force, opts->keyname, 
			opts->keyring, opts->algname );

	memset(&session, 0, sizeof(sign_session_t));
	session.file = file;
	session.fd = fd;

	ret = configure_gpg( &gpgme_ctx );
	if (ret) {
		ES_PRINT (ERROR, "%s: failed to init libgpgme\n", file);
		goto bail;
	}

	/* store the gpgme contxt in the session */
	session.gpgme_ctx = gpgme_ctx;

again:
	ret = open_elf_file( &session );
	if (ret) {
		ES_PRINT (ERROR, "%s: failed to open file\n", file);
		goto bail;
	}

	ret = prepare_elfgpg_sections( &session );
	if (ret) {
		ES_PRINT (ERROR, "%s: failed to prepare sections\n", file);
		goto bail;
	}

	ret = generate_pgptab( &session );
	if (ret) {
		ES_PRINT (ERROR, "%s: failed to generate .pgptab\n", file);
		goto bail;
	}

	ret = generate_pgpsig( &session );
	if (ret) {
		ES_PRINT (ERROR, "%s: failed to generate .pgpsig\n", file);
		goto bail;
	}

	if( !ret && session.new_sections ) {

		ret = commit_elf_to_file( &session );
		if( ret ) {
			ES_PRINT (ERROR, "%s: failed to commit new sections\n", 
					file);
			goto bail;
		}

		/* finalize the elf file */
		elf_end(session.elf);

		/* reset the structure and put back the values we need */
		memset(&session, 0, sizeof(sign_session_t));
		session.file = file;
		session.fd = fd;
		session.gpgme_ctx = gpgme_ctx;

		if (++loop < 2) {
			ES_PRINT(INFO, "%s: created pgp sections; "
					"string pass %d\n", file, loop);

			goto again;
		}

		ES_PRINT(ERROR, "%s: internal error; endless loop detected\n",
				file);
		ret = -EFAULT;
	}

	ret = commit_elf_to_file( &session );
	if( ret ) {
		ES_PRINT (ERROR, "%s: failed to commit elf file\n", file);
		goto bail;
	}

	/* success */
	ES_PRINT(NORM, "%s: signed\n", file);

bail:
	elf_end(session.elf);
	gpgme_release( gpgme_ctx );

	if( session.pgptab_head )
		free( session.pgptab_head );

	return ret; 
}
