/****************************************************************************
* 
* $Id: verify.c,v 1.1.1.1 2001/07/10 00:20:14 bartron Exp $
* 
* Copyright (C) 2001 Bart Trojanowski <bart@jukie.net>
*
* This file is a part of the elfverify utility
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
* 
*****************************************************************************/

#include <libelf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gpgme.h>
#include <termios.h>
#include <stdlib.h>

#include "options.h"
#include "verify.h"
#include "elfpgp.h"
#include "elfhelp.h"

typedef struct verify_session_s 
{
  const char *file;
  int fd;
  GpgmeCtx ctx;

  /* how far are we in the read */
  u_int32_t tab_index;
  u_int32_t scn_offset;
  int read_cb_eof;

  /* elf processing variables */
  Elf *elf;
  
  Elf32_Ehdr *ehdr;
  Elf32_Phdr *phdr;

  /* the two section worth preloading */
  Elf32_Shdr *pgptab_hdr, *pgpsig_hdr;
  Elf_Scn *pgptab_scn, *pgpsig_scn;
  Elf_Data *pgptab_data, *pgpsig_data;
  Elf_Data fake_data;

  /* entry in the .pgptab */
  Elf32_Pgp pgp; 

  /* section currently being processed by the read callback */
  Elf32_Shdr *shdr;
  Elf_Data *data;
  Elf_Scn *scn;
}
verify_session_t;


static int
configure_gpg( GpgmeCtx *ctx )
{
  GpgmeError err;

  err = gpgme_new(ctx);
  if( err ) {
    ES_PRINT(ERROR, "gpgme_new: %s\n", gpgme_strerror(err));
    return -1;
  }
  
  gpgme_set_textmode(*ctx,1);
  gpgme_set_armor(*ctx,0);

  return 0;
}


static const char *
verify_status_string (GpgmeSigStat status)
{
    const char *s = "?";

    switch ( status ) {
      case GPGME_SIG_STAT_NONE:
        s = "None";
        break;
      case GPGME_SIG_STAT_NOSIG:
        s = "No sig";
        break;
      case GPGME_SIG_STAT_GOOD:
        s = "Good";
        break;
      case GPGME_SIG_STAT_BAD:
        s = "Bad";
        break;
      case GPGME_SIG_STAT_NOKEY:
        s = "No key";
        break;
      case GPGME_SIG_STAT_ERROR:
        s = "Error";
        break;
      case GPGME_SIG_STAT_DIFF:
        s = ">1 sig";
        break;
      default:
	ES_PRINT(ERROR, "%s: unhandled status of %d\n", __PRETTY_FUNCTION__,
			status);
	break;
    }
    return s;
}


static void
print_short_sig_stat ( verify_session_t *s, GpgmeSigStat stat )
{
  const char *id, *alg, *caps, *name, *email, *note;
  GpgmeKey key;
  int rc;

  if( !(gpgme_get_sig_key( s->ctx, 0, &key)) ) {
    id    = gpgme_key_get_string_attr( key, GPGME_ATTR_KEYID, NULL, 0 );
    alg   = gpgme_key_get_string_attr( key, GPGME_ATTR_ALGO, NULL, 0 );
    caps  = gpgme_key_get_string_attr( key, GPGME_ATTR_KEY_CAPS, NULL, 0 );
    name  = gpgme_key_get_string_attr( key, GPGME_ATTR_NAME, NULL, 0 );
    email = gpgme_key_get_string_attr( key, GPGME_ATTR_EMAIL, NULL, 0 );
    note  = gpgme_key_get_string_attr( key, GPGME_ATTR_COMMENT, NULL, 0 );
  }

  rc = ES_PRINT(INFO,"%-*s %-8s %s %s (%s) <%s>\n",
  	  opts->file_name_max, s->file, 
	  verify_status_string(stat),
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
	opts->file_name_max, s->file, 
	verify_status_string(stat),
	val);
  }
}


static void
print_verbose_sig_stat ( verify_session_t *s, GpgmeSigStat status )
{
  const char *ss;
  time_t created;
  int idx;
  GpgmeKey key;

  ES_PRINT(DEBUG, "process_elf: dumping status...\n");
  
  for(idx=0;(ss=gpgme_get_sig_status(s->ctx, idx, &status, &created)); idx++) {
    ES_PRINT(INFO, "sig %d: created: %lu status: %s\n", 
	idx, (unsigned long)created, verify_status_string(status) );
    ES_PRINT(INFO, "sig %d: fpr/keyid=`%s'\n", idx, ss );
    if ( !gpgme_get_sig_key (s->ctx, idx, &key) ) {
      char *p = gpgme_key_get_as_xml ( key );
      ES_PRINT(INFO,"sig %d: key object:\n%s\n", idx, p );
      free (p);
      gpgme_key_release (key);
    }
  }
}


static int
read_elf_cb( void* opaque, char *buff, size_t blen, size_t* bused )
{
  verify_session_t *s = (void*)opaque;
  int eof;	/* 1 if there is no more data to read */
  void *src_ptr, *dst_ptr;
  size_t src_len, dst_len;

  ES_PRINT(DEBUG, "%s(%p, %p, %d, %p)\n",
		  __PRETTY_FUNCTION__, opaque, buff, blen, bused );
  
  dst_ptr = buff;
  dst_len = blen;
  *bused = 0;

  if( (eof = s->read_cb_eof) )
    goto bail;

 more:
  if( !s->scn_offset ) {
    /* means that we need to fetch the next pgp entry from .pgptab */
    long pgp_offset = s->tab_index * sizeof(Elf32_Pgp);
    
    ES_PRINT(DEBUG, "read_elf_cb: !offset: new section %d\n", s->tab_index);

    if( (pgp_offset+sizeof(Elf32_Pgp)) > s->pgptab_data->d_size ) {
      ES_PRINT(DEBUG,"%s: got to the end of .pgptab\n", s->file);
      s->read_cb_eof = 1;
      goto bail;
      
    }
    memcpy( &s->pgp, s->pgptab_data->d_buf + pgp_offset, sizeof(Elf32_Pgp) );

    ES_PRINT(DEBUG, "read_elf_cb: pgptab[%d] = { %d, %d, %d }\n",
	s->tab_index, s->pgp.pt_type, s->pgp.pt_size, s->pgp.pt_shndx);
    
    switch( s->pgp.pt_type ) {
     case ELF_PT_EHDR:
       /* we got an elf header */
       s->data = &s->fake_data;
       s->data->d_buf = (void*)s->ehdr;
       s->data->d_size = s->pgp.pt_size;
       ES_PRINT(DEBUG,"READ: EHDR %8d bytes\n", s->data->d_size);
       break;

     case ELF_PT_PHDR:
       /* get got a program header */
       s->data = &s->fake_data;
       s->data->d_buf = (void*)s->phdr;
       s->data->d_size = s->pgp.pt_size;
       ES_PRINT(DEBUG,"READ: PHDR %8d bytes\n", s->data->d_size);
       break;

     case ELF_PT_SCN:
       /* we know the section number, get the section & header */
       s->scn = elf_getscn(s->elf, s->pgp.pt_shndx);
       if( !(s->shdr = elf32_getshdr(s->scn)) ) { 
   	 ES_PRINT(ERROR,"%s: shndx=%d: %s\n", s->file, s->pgp.pt_shndx,
   	     elf_errmsg(-1));
   	 eof = s->read_cb_eof = 1;
   	 goto bail;
       }
       
       /* now get the data for that section */
       if( !(s->data = elf_getdata(s->scn, NULL)) ) {
   	 ES_PRINT(ERROR,"%s: get data %s\n", s->file, elf_errmsg(-1));
   	 eof = s->read_cb_eof = 1;
   	 goto bail;
       }
       ES_PRINT(DEBUG,"READ: %d %8d bytes\n", s->pgp.pt_shndx, s->data->d_size);
       break;

     default:
       ES_PRINT(ERROR,"%s: invalid .pgptab entry type at index %d\n",
	   s->file, s->pgp.pt_shndx);
       eof = s->read_cb_eof = 1;
       goto bail;
    }
  }

  src_ptr = s->data->d_buf + s->scn_offset;
  src_len = s->data->d_size - s->scn_offset;
  if( !src_len ) 
    goto bail;

  ES_PRINT(DEBUG,"read_elf_cb: have data @ %p of len %d bytes\n",
      src_ptr, src_len);

  /* test to see if all the current data block can be submitted */
  if( src_len <= dst_len ) {
    memcpy( dst_ptr, src_ptr, src_len );
    *bused += src_len;
    /* move buffer pointer/size to after new addition */
    dst_ptr += src_len;
    dst_len -= src_len;
    /* prep for next call */
    s->scn_offset = 0;
    s->tab_index ++;

    if( !s->read_cb_eof && dst_len > 32 )
      goto more;
  
  } else {
    memcpy( dst_ptr, src_ptr, dst_len );
    *bused += dst_len;
    /* prep for next call */
    s->scn_offset += dst_len;
  }
  
 bail:
  ES_PRINT(DEBUG,"read_elf_cb: returns %d, bytes used set to %d\n",
      eof, *bused);
  return eof;
}


static int
init_process_elf( verify_session_t *s )
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
     
     } else if ( s->ehdr->e_phnum && !(s->phdr = elf32_getphdr(s->elf)) ) {
       ES_PRINT(ERROR, "%s: %s\n", s->file, elf_errmsg(-1));
     
     } else if ( !(s->pgptab_hdr = elf32_getshdr(
	     s->pgptab_scn = elf_findscn(s->elf, ".pgptab"))) ) {
       if ( elf_errno() ) {
          ES_PRINT(ERROR, "%s: find .pgptab: %s\n", s->file, elf_errmsg(-1));
       } else {
          ES_PRINT(NORM, "%-*s %-8s\n", opts->file_name_max, s->file,
			  verify_status_string (GPGME_SIG_STAT_NOSIG));
       }
       
     } else if ( !(s->pgptab_data = elf_getdata(s->pgptab_scn, NULL)) ) {
       ES_PRINT(ERROR, "%s: data .pgptab: %s\n", s->file, elf_errmsg(-1));
       
     } else if ( !(s->pgpsig_hdr = elf32_getshdr(
	     s->pgpsig_scn = elf_findscn(s->elf, ".pgpsig"))) ) {
       if ( elf_errno() ) {
          ES_PRINT(ERROR, "%s: find .pgpsig: %s\n", s->file, elf_errmsg(-1));
       } else {
          ES_PRINT(NORM, "%-*s %-8s\n", opts->file_name_max, s->file,
			  verify_status_string (GPGME_SIG_STAT_NOSIG));
       }
       
     } else if ( !(s->pgpsig_data = elf_getdata(s->pgpsig_scn, NULL)) ) {
       ES_PRINT(ERROR, "%s: data .pgpsig: %s\n", s->file, elf_errmsg(-1));
       
     } else {
       err = 0;
     }
     break;

   case ELF_K_AR:
     err = 1;
     ES_PRINT(ERROR, "%s: elf_kind of ELF_K_AR is not supported\n", s->file);
     break;

   default:
     err = 1;
     ES_PRINT(ERROR, "%s: file format not recognized", s->file);
     break;
  }
  
  return err;
}


static int 
process_elf( verify_session_t *s )
{
  int ret=-1;
  GpgmeError err;
  GpgmeData sig, data;
  GpgmeSigStat status;
  
  /* start processing the .pgptab at the first entry */
  s->tab_index = 0;
  s->scn_offset = 0;

  ES_PRINT(DEBUG, "process_elf: creating data gpgme data object\n");
  
  err = gpgme_data_new_with_read_cb ( &data, read_elf_cb, s );
  if( err ) {
    ES_PRINT(ERROR, "gpgme_data_new_with_read_cb: %s\n", gpgme_strerror(err));
    goto bail;
  }
  
  ES_PRINT(DEBUG, "process_elf: creating sig gpgme data object\n");

  ES_PRINT(DEBUG, "process_elf: sig is of size %d\n",s->pgpsig_data->d_size);
  err = gpgme_data_new_from_mem( &sig, s->pgpsig_data->d_buf,
     s->pgpsig_data->d_size, 0 );
  if( err ) {
    ES_PRINT(ERROR, "gpgme_data_new_from_mem: %s\n", gpgme_strerror(err));
    goto bail;
  }

  ES_PRINT(DEBUG, "process_elf: calling gpgme_op_verify\n");

  err = gpgme_op_verify (s->ctx, sig, data, &status);
  if( err ) {
    ES_PRINT(ERROR, "gpgme_op_verify: %s\n", gpgme_strerror(err));
    goto bail;
  }  

  print_short_sig_stat( s, status );
  if( ES_SHOW(DEBUG) )
    print_verbose_sig_stat( s, status );

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
  
  memset(&session, 0, sizeof(verify_session_t));
  session.file = file;
  session.fd = fd;
  
  ret = configure_gpg( &session.ctx );
  
  if( ! ret )
    ret = init_process_elf( &session );
  
  if( ! ret )
    ret = process_elf( &session );

  elf_end(session.elf);
  gpgme_release( session.ctx );
  
  return ret; 
}


/****************************************************************************
* 
* $Log: verify.c,v $
* Revision 1.1.1.1  2001/07/10 00:20:14  bartron
* initial import
*
* 
*****************************************************************************/
