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
#include <stdlib.h>

#include "ep_session.h"

#include "options.h"
#include "verify.h"
#include "elfgpg.h"
#include "elfhelp.h"
#include "elfstrings.h"

typedef struct verify_session_s 
{
	elfgpg_session_t	*elfgpg_session;

	/* context for gpgme */
	gpgme_ctx_t 		gpgme_ctx;

	/* how far are we in the read */
	u_int32_t tab_index;
	u_int32_t scn_offset;
	int read_cb_eof;

	/* entry in the .pgptab */
	Elf32_Pgp pgp; 

	/* section currently being processed by the read callback */
	Elf32_Shdr *shdr;
	Elf_Data *data;
	Elf_Scn *scn;

	/* fake data for data pointer */
	Elf_Data fake_data;
}
verify_session_t;


static int
configure_gpg( gpgme_ctx_t *ctx )
{
	gpgme_error_t err;

	err = gpgme_new(ctx);
	if( err ) {
		ES_PRINT(ERROR, "gpgme_new: %s\n", gpgme_strerror(err));
		return -1;
	}

	gpgme_set_textmode(*ctx,1);
	gpgme_set_armor(*ctx,0);

	return 0;
}


static void
print_short_sig_stat ( verify_session_t *s, gpgme_verify_result_t result,
		gpgme_error_t verify_error)
{
	const char *id=NULL, *alg=NULL, *name=NULL, 
			*email=NULL, *note=NULL;
	gpgme_key_t key;
	int rc;

	key = gpgme_signers_enum(s->gpgme_ctx, 0);
	if (key) {
		id    = key->chain_id;
		if (key->subkeys)
			alg   = gpgme_pubkey_algo_name(key->subkeys->pubkey_algo);
		if (key->uids) {
			name  = key->uids->name;
			email = key->uids->email;
			note  = key->uids->comment;
		}
	}

	rc = ES_PRINT(INFO,"%-*s %-8s %s %s (%s) <%s>\n",
			opts->file_name_max, s->elfgpg_session->file, 
			gpg_strerror(verify_error),
			id, name, note, email);

	/* will show a less verbose output */
	if( !(rc) ) {
		const char *fmt, *val;
		if( email ) {
			fmt = "%-*s %-8s <%s>\n";
			val = email;
		} else {
			fmt = "%-*s %-8s %s\n";
			val = id;
		}
		ES_PRINT(NORM, fmt,
				opts->file_name_max, s->elfgpg_session->file, 
				gpg_strerror(verify_error),
				val);
	}
}


static void
print_verbose_sig_stat (verify_session_t *s, gpgme_verify_result_t result,
		gpgme_error_t verify_error)
{
	int idx;
	gpgme_key_t key;

	ES_PRINT(DEBUG, "print_verbose_sig_stat: dumping status...\n");

	for(idx=0; (key = gpgme_signers_enum(s->gpgme_ctx, idx)); idx++) {
		ES_PRINT(INFO, "sig %d: status: %s\n",
				idx,
				gpg_strerror(verify_error));
		ES_PRINT(INFO, "sig %d: fpr/keyid=`%s' %s <%s>\n",
				idx, key->chain_id,
				key->uids->name,
				key->uids->email);
	}
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
	verify_session_t *s = (void*)opaque;
	elfgpg_session_t *es = s->elfgpg_session;
	int eof;	/* 1 if there is no more data to read */
	void *src_ptr, *dst_ptr;
	size_t src_len, dst_len;
	const char *tname, *sname;
	char type_number[16];
	int ndx;

	ES_PRINT(DEBUG, "%s(%p, %p, %"PRIuMAX"\n",
			__PRETTY_FUNCTION__, opaque, buff, blen);

	dst_ptr = buff;
	dst_len = blen;

	if( (eof = s->read_cb_eof) )
		goto bail;

more:
	if( !s->scn_offset ) {
		/* means that we need to fetch the next pgp 
		 * entry from .pgptab */
		long pgp_offset = s->tab_index * sizeof(Elf32_Pgp);

		ES_PRINT(DEBUG, "read_elf_cb: !offset: new section %d\n", 
				s->tab_index);

		if( (pgp_offset+sizeof(Elf32_Pgp)) > es->pgptab_data->d_size ) {
			ES_PRINT(DEBUG,"%s: got to the end of .pgptab\n", 
					es->file);
			s->read_cb_eof = 1;
			goto bail;

		}
		memcpy( &s->pgp, es->pgptab_data->d_buf + pgp_offset, 
				sizeof(Elf32_Pgp) );

		ES_PRINT(DEBUG, "read_elf_cb: pgptab[%d] = { %d, %d, %d }\n",
				s->tab_index, s->pgp.pt_type, s->pgp.pt_size, 
				s->pgp.pt_shndx);

		switch( s->pgp.pt_type ) {
		case ELF_PT_EHDR:
			/* we got an elf header */
			s->data = &s->fake_data;
			s->data->d_buf = (void*)es->ehdr;
			s->data->d_size = s->pgp.pt_size;
		
			ES_PRINT(INFO,"  %-7s  %-13s  %5d  %s\n", 
					"EHDR", "", s->pgp.pt_size, "");
			break;

		case ELF_PT_PHDR:
			/* get got a program header */
			s->data = &s->fake_data;
			s->data->d_buf = (void*)es->phdr;
			s->data->d_size = s->pgp.pt_size;

			ES_PRINT(INFO,"  %-7s  %-13s  %5d  %s\n", 
					"PHDR", "", s->pgp.pt_size, "");
			break;

		case ELF_PT_SCN:
			/* this is the section index */
			ndx = s->pgp.pt_shndx;

			/* we know the section number, get the section & header */
			s->scn = elf_getscn(es->elf, ndx);
			if( !(s->shdr = elf32_getshdr(s->scn)) ) { 
				ES_PRINT(ERROR,"%s: shndx=%d: %s\n", es->file, 
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
			sname = elf_strptr(es->elf, es->ehdr->e_shstrndx, 
					s->shdr->sh_name);

			/* now get the data for that section */
			if( !(s->data = elf_getdata(s->scn, NULL)) ) {
				ES_PRINT(ERROR,"%s: get data %s\n", es->file, 
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
					es->file, s->pgp.pt_shndx);
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
	ES_PRINT(DEBUG,"read_elf_cb: returns %d\n", eof);
	return eof;
}


static int
init_process_elf( verify_session_t *s )
{
	int err;
	elfgpg_session_t *es = s->elfgpg_session;

	es->elf = elf_begin( es->fd, ELF_C_READ, NULL );
	switch( elf_kind(es->elf) ) {
	case ELF_K_ELF:
		ES_PRINT(DEBUG, "%s: ELF file format detected\n", es->file);

		es->phdr = NULL;
		err = 1;

		/* get Elf Program Headers then the scn/shdr/data for the tab/sig scns */
		if( !(es->ehdr = elf32_getehdr(es->elf)) ) {
			ES_PRINT(ERROR, "%s: %s\n", es->file, elf_errmsg(-1));

		} else if ( es->ehdr->e_phnum 
				&& !(es->phdr = elf32_getphdr(es->elf)) ) {
			ES_PRINT(ERROR, "%s: %s\n", es->file, elf_errmsg(-1));

		} else if ( !(es->pgptab_hdr = elf32_getshdr( es->pgptab_scn 
					= elf_findscn(es->elf, ".pgptab"))) ) {
			if ( elf_errno() ) {
				ES_PRINT(ERROR, "%s: find .pgptab: %s\n", 
						es->file, elf_errmsg(-1));
			} else {
				ES_PRINT(NORM, "%-*s %-8s\n", 
						opts->file_name_max, es->file,
						gpgme_strerror(
							GPGME_SIG_STAT_NOSIG));
			}

		} else if ( !(es->pgptab_data = elf_getdata(es->pgptab_scn, 
						NULL)) ) {
			ES_PRINT(ERROR, "%s: data .pgptab: %s\n", es->file, 
					elf_errmsg(-1));

		} else if ( !(es->pgpsig_hdr = elf32_getshdr( es->pgpsig_scn 
					= elf_findscn(es->elf, ".pgpsig"))) ) {
			if ( elf_errno() ) {
				ES_PRINT(ERROR, "%s: find .pgpsig: %s\n", 
						es->file, elf_errmsg(-1));
			} else {
				ES_PRINT(NORM, "%-*s %-8s\n", 
						opts->file_name_max, es->file,
						gpgme_strerror(
							GPGME_SIG_STAT_NOSIG));
			}

		} else if ( !(es->pgpsig_data = elf_getdata(es->pgpsig_scn, 
						NULL)) ) {
			ES_PRINT(ERROR, "%s: data .pgpsig: %s\n", es->file, 
					elf_errmsg(-1));

		} else {
			err = 0;
		}
		break;

	case ELF_K_AR:
		err = 1;
		ES_PRINT(ERROR, "%s: elf_kind of ELF_K_AR is not supported\n", 
				es->file);
		break;

	default:
		err = 1;
		ES_PRINT(ERROR, "%s: file format not recognized", es->file);
		break;
	}

	return err;
}


static int 
process_elf( verify_session_t *s )
{
	int ret=-1;
	gpgme_error_t err;
	gpgme_data_t sig, data;
	gpgme_verify_result_t result;
	elfgpg_session_t *es = s->elfgpg_session;

	/* start processing the .pgptab at the first entry */
	s->tab_index = 0;
	s->scn_offset = 0;

	ES_PRINT(INFO,"%s: validating .pgptab entires...\n", es->file);
	ES_PRINT(INFO,"  %-7s  %-13s  %5s  %s\n", 
			"entry", "type", "size", "name");

	err = gpgme_data_new_from_cbs (&data, &elf_data, s);
	if( err ) {
		ES_PRINT(ERROR, "gpgme_data_new_with_read_cb: %s\n", 
				gpgme_strerror(err));
		goto bail;
	}

	ES_PRINT(DEBUG, "process_elf: creating sig gpgme data object\n");

	ES_PRINT(DEBUG, "process_elf: sig is of size %"PRIuMAX"\n",
			es->pgpsig_data->d_size);
	err = gpgme_data_new_from_mem( &sig, es->pgpsig_data->d_buf,
			es->pgpsig_data->d_size, 0 );
	if( err ) {
		ES_PRINT(ERROR, "gpgme_data_new_from_mem: %s\n", 
				gpgme_strerror(err));
		goto bail;
	}

	ES_PRINT(DEBUG, "process_elf: calling gpgme_op_verify\n");

	err = gpgme_op_verify (s->gpgme_ctx, sig, NULL, data);
	if( err ) {
		ES_PRINT(ERROR, "gpgme_op_verify: %s\n", 
				gpgme_strerror(err));
		goto bail;
	}

	result = gpgme_op_verify_result (s->gpgme_ctx);

	print_short_sig_stat( s, result, err );
	if( ES_SHOW(DEBUG) )
		print_verbose_sig_stat( s, result, err );

	ret=0;
bail: 
#if defined(AVOID_GPGME_CALLBACK)
	if( big_buffer_ptr )
		free(big_buffer_ptr);
#endif

	gpgme_data_release(sig);
	gpgme_data_release(data);

	return ret;
}


int 
do_elfverify( const char *file, int fd )
{
	int ret;
	elfgpg_session_t elfgpg_session;
	verify_session_t session;

	ES_PRINT(DEBUG,"elfverify( '%s', %d )...\n"
			"\tverbose = %d\n"
			"\tforce   = %d\n"
			"\tkeyname = %s\n"
			"\tkeyring = %s\n"
			"\talgname = %s\n",
			file, fd,
			opts->verbose, opts->force, opts->keyname, 
			opts->keyring, opts->algname );

	memset(&elfgpg_session, 0, sizeof(elfgpg_session_t));
	elfgpg_session.file = file;
	elfgpg_session.fd = fd;

	memset(&session, 0, sizeof(verify_session_t));
	session.elfgpg_session = &elfgpg_session;

	ret = configure_gpg( &session.gpgme_ctx );

	if( ! ret )
		ret = init_process_elf( &session );

	if( ! ret )
		ret = process_elf( &session );

	elf_end(elfgpg_session.elf);
	gpgme_release( session.gpgme_ctx );

	return ret; 
}
