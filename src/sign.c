/****************************************************************************
* 
* $Id: sign.c,v 1.1.1.1 2001/07/10 00:20:14 bartron Exp $
* 
* Copyright (C) 2001 Bart Trojanowski <bart@jukie.net>
*
* This file is a part of the elfpgp utility
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
#include <string.h>
#include <stdlib.h>

#include "options.h"
#include "sign.h"
#include "elfpgp.h"
#include "elfhelp.h"

typedef struct sign_session_s 
{
  /* current read state */
  u_int32_t tab_index;
  u_int32_t scn_offset;
  int read_cb_eof;

  /* file being processed */
  const char *file;
  int fd;
  GpgmeCtx ctx;

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
  
static const char *
passphrase_cb ( void *opaque, const char *desc, void **r_hd )
{
  struct termios term;
  static struct termios termsave;
  const char *cmd=NULL, *uid=NULL, *info=NULL;

  if( !desc ) {
    /* this is the second callback meant for releasing resources, but
    * we want to keep it to the very end of the signing process */
    return NULL;
  }
  
  ES_PRINT(DEBUG,"%s: getting password\n", __PRETTY_FUNCTION__);
  
  /* get the description parts 
  * [ code borowed from Sylpheed; thanks to Werner Koch <wk@gnupg.org> ]
  */
  cmd = desc;
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
    if( pass[0] ) 
      return pass;
  }
  
  /* must get a password... */
  fprintf(stderr, "Key Id: %.*s\n", linelen(uid), uid);
  fprintf(stderr, "Info:   %.*s\n", linelen(info), info);
  fprintf(stderr, "Enter passphrase:");
  fflush(stderr);

  /* disable echo */
  if( tcgetattr(fileno(stdin), &termsave) ) {
    ES_PRINT(ERROR,"tcgetattr() failed: %s\n", strerror(errno) );
    return NULL;
  }
  term = termsave;
  term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  if( tcsetattr( fileno(stdin), TCSAFLUSH, &term ) ) {
    ES_PRINT(ERROR,"tcsetattr() failed: %s\n", strerror(errno) );
    return NULL;
  }
 
  /* get the string */
  if( !fgets(pass, sizeof(pass)-1, stdin) ) {
    ES_PRINT(ERROR,"passphrase_cb: %s\n",strerror(errno));
    return NULL;
  }

  /* reset echo */
  if( tcsetattr(fileno(stdin), TCSAFLUSH, &termsave) ) {
    ES_PRINT(ERROR,"tcsetattr() failed: %s\n", strerror(errno) );
    return NULL;
  }

  fprintf(stderr, "\n");
  
  return pass; 
}

static int
configure_gpg( GpgmeCtx *ctx )
{
  GpgmeError err;

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
  char *name;
  
  ES_PRINT(DEBUG,"%s: inserting pgptab entry\n", __PRETTY_FUNCTION__);
  
  if( p->pt_type == ELF_PT_SCN )
    if( !(name = elf_strptr(s->elf, s->ehdr->e_shstrndx, s->shdr->sh_name)) )
      name = "<name>";

  ES_PRINT(DEBUG, "pgptab_add: %s [%s/%d/%d]\n",
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


static int
read_elf_cb( void* opaque, char *buff, size_t blen, size_t* bused )
{
  sign_session_t *s = (void*)opaque;
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
     
     } else if ( s->ehdr->e_phnum && !(s->phdr = elf32_getphdr(s->elf)) ) {
       ES_PRINT(ERROR, "%s: %s\n", s->file, elf_errmsg(-1));
       
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


/* prepare_elfpgp_sections makes sure that .pgptab and .pgpsig sections
* exist in elf object -- if they do not then the object is updated 
* (not the file); the sign_session_t *s pgp{tab,sig}_{scn,tab} are also
* updated appropriately; */
static int
prepare_elfpgp_sections( sign_session_t *s )
{
  int err = 1;

  ES_PRINT(DEBUG, "%s: locating the .pgptab section\n", __PRETTY_FUNCTION__);

  if( (s->pgptab_scn = elf_findscn(s->elf, ".pgptab")) ) {
    /* section exists, get the data */
    if( !(s->pgptab_data = elf_getdata(s->pgptab_scn,NULL)) ) {
      ES_PRINT(ERROR, "%s: elf_getdata: %s\n", s->file, elf_errmsg(-1));
      goto bail;
    }

  } else {  
    /* create a new table entry for .pgptab */  
    if( !(s->pgptab_scn = create_section( s->elf, SHT_PGPTAB, ".pgptab" )) ) {
      ES_PRINT(ERROR, "create_section: failed to create .pgptab\n");
      goto bail;
    }
    
    /* create data for the section */
    if( !(s->pgptab_data = elf_newdata(s->pgptab_scn)) ) {
      ES_PRINT(ERROR, "elf_newdata: %s\n", elf_errmsg(-1));
      goto bail;
    }
  }
  
  /* update the object to include this table */
  s->pgptab_data->d_align = 1;
  s->pgptab_data->d_size = s->ehdr->e_shnum * sizeof(Elf32_Pgp);
  s->pgptab_data->d_type = ELF_T_BYTE;
  s->pgptab_data->d_buf = s->pgptab_head;
  
  if( elf_update( s->elf, ELF_C_NULL ) == -1 ) {
    ES_PRINT(ERROR, "elf_update: %s\n", elf_errmsg(-1));
    goto bail;
  }

  ES_PRINT(DEBUG, "%s: locating the .pgpsig section\n", __PRETTY_FUNCTION__);

  if( (s->pgpsig_scn = elf_findscn( s->elf, ".pgpsig" )) ) {
    /* section exists, get the data */
    if( !(s->pgpsig_data = elf_getdata(s->pgpsig_scn,NULL)) ) {
      ES_PRINT(ERROR, "%s: elf_getdata: %s\n", s->file, elf_errmsg(-1));
      goto bail;
    }

  } else {
    /* create a new section entry for .pgpsig */
    if( !(s->pgpsig_scn = create_section( s->elf, SHT_PGPSIG, ".pgpsig" )) ) {
      ES_PRINT(ERROR, "create_section: failed to crete .pgpsig\n");
      goto bail;
    }
    
    /* create data for the section */
    if( !(s->pgpsig_data = elf_newdata(s->pgpsig_scn)) ) {    
      ES_PRINT(ERROR, "elf_newdata: %s\n", elf_errmsg(-1));
      goto bail;
    }
  }

  /* update the elf file to include this structure */
  s->pgpsig_data->d_align = 1;
  s->pgpsig_data->d_size = 65;
  s->pgpsig_data->d_type = ELF_T_BYTE;
  s->pgpsig_data->d_buf = s->sig;
  
  if( elf_update( s->elf, ELF_C_NULL ) == -1 ) {
    ES_PRINT(ERROR, "elf_update: %s\n", elf_errmsg(-1));
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
  
  ES_PRINT(DEBUG,"%s: generating .pgptab\n", __PRETTY_FUNCTION__);
  
  /* first add the elf header */
  pgp.pt_type = ELF_PT_EHDR;
  pgp.pt_size = sizeof(*(s->ehdr));
  pgptab_add( s, &pgp );

  /* second add the program header */
  pgp.pt_type = ELF_PT_PHDR;
  pgp.pt_size = sizeof(*(s->phdr));
  pgptab_add( s, &pgp );

  /* finally add all of the sections */
  s->scn=NULL;
  while( (s->shdr = elf32_getshdr( s->scn = elf_nextscn(s->elf,s->scn) ) ) ) {
    char *name = elf_strptr(s->elf, s->shdr->sh_link, s->shdr->sh_name);
    if( !name || s->shdr->sh_type == SHT_NULL
	|| s->shdr->sh_type == SHT_NOBITS )
      continue;
    if( s->shdr->sh_type >= SHT_LOUSER && s->shdr->sh_type <= SHT_HIUSER )
      if( !strcmp( name, ".pgptab" ) || !strcmp( name, ".pgpsig" ) )
	continue;
    if( !(s->data = elf_getdata(s->scn,NULL)) )
      continue;
    
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
  GpgmeError err;
  GpgmeData in, out;
  size_t oslen;

  ES_PRINT(DEBUG, "%s: generating pgp signature\n", __PRETTY_FUNCTION__);

  /* start processing creating the .pgptab at elf header */
  s->tab_index = 0;
  s->scn_offset = 0;

  err = gpgme_data_new_with_read_cb ( &in, read_elf_cb, s );
  if( err ) {
    ES_PRINT(ERROR, "gpgme_data_new: %s\n", gpgme_strerror(err));
    goto bail;
  }
  
  err = gpgme_data_new( &out );
  if( err ) {
    ES_PRINT(ERROR, "gpgme_data_new: %s\n", gpgme_strerror(err));
    goto bail;
  }

  err = gpgme_op_sign (s->ctx, in, out, GPGME_SIG_MODE_DETACH);
  if( err ) {
    ES_PRINT(ERROR, "gpgme_op_sign: %s\n", gpgme_strerror(err));
    goto bail;
  }

  oslen = s->slen = sizeof(s->sig);
  err = gpgme_data_read ( out, s->sig, oslen, &s->slen );
  if( err ) {
    if( oslen==s->slen ) {
      ES_PRINT(ERROR, "sign_gpg: signature buffer was too short\n");
      goto bail;
    } else if ( err!=GPGME_EOF ) {
      ES_PRINT(ERROR, "gpgme_data_read: %s\n", gpgme_strerror(err));
      goto bail;
    }
  } else {
    ES_PRINT(NORM, "%s: sig %d bytes\n", s->file, s->slen);
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
  sign_session_t session;
  
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
  
  ret = configure_gpg( &session.ctx );
  
  if( !ret )
    ret = open_elf_file( &session );
      
  if( !ret )
    ret = prepare_elfpgp_sections( &session );
  
  if( !ret )
    ret = generate_pgptab( &session );
  
  if( !ret )
    ret = generate_pgpsig( &session );
  
  if( !ret )
    ret = commit_elf_to_file( &session );

  elf_end(session.elf);
  gpgme_release( session.ctx );
  
  if( session.pgptab_head )
    free( session.pgptab_head );

  return ret; 
}


/****************************************************************************
* 
* $Log: sign.c,v $
* Revision 1.1.1.1  2001/07/10 00:20:14  bartron
* initial import
*
* 
*****************************************************************************/
