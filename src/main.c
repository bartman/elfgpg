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

#define COPYRIGHT "(C) 2001-2003 Bart Trojanowski <bart@jukie.net>"

#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <libelf.h>
#include <getopt.h>

#include "debug.h"
#include "options.h"
#include "sign.h"
#include "verify.h"
#include "dump.h"

elfsign_options_t *opts;

static struct option long_options[12] =
{
	{"sign",    0, 0, 's'},
	{"verify",  0, 0, 'c'},
	{"dump",    0, 0, 'd'},
	{"quiet",   0, 0, 'q'},
	{"verbose", 0, 0, 'v'},
	{"force",   0, 0, 'f'},
	{"version", 0, 0, 'V'},
	{"help",    0, 0, 'h'},
	{"key",     1, 0, 'k'},
	{"keyring", 1, 0, 'r'},
	{"algname", 1, 0, 'a'},
	{0,0,0,0}
};

static int
dump_version( void )
{
	printf(PACKAGE " v" VERSION " - " COPYRIGHT"\n");
	return 0;
}

static int
dump_help( const char * name )
{
	printf(PACKAGE " v" VERSION " - " COPYRIGHT"\n");
	printf("\nSyntax:  %s [command] [options] file(s)\n", name);
	printf("\ncommands:\n"
	" -s, --sign                  append or replace signature\n"
	" -c, --verify                verify signature\n"
	" -d, --dump                  list signature info\n"
	" -h, --help                  what you are reading now\n"
	" -V, --version               print version info\n"
	"\noptions:\n"
	" -q, --quiet                 be more quiet\n"
	" -v, --verbose               be more verbose\n"
	" -f, --force                 ignore some errors\n"
	" -k, --key <name>            specify a key to use\n"
	" -r, --keyring <file>        specify the location of the keyring\n"
	" -a, --algname <name>        specify the algorithm for hashing\n"
	);
	return 0;
}

static int 
process_options( int argc, char *const *argv )
{
	int ret, len;

	ES_PRINT(DEBUG,"Processing options...\n");

	len = strlen(argv[0]);
	if( len>=7 && strncmp( argv[0]+len-7, "elfsign", 8 ) == 0 ) {
		ES_PRINT(DEBUG,"operation = SIGN\n");
		opts->operation = SIGN;

	} else if( len>=8 && strncmp( argv[0]+len-8, "elfverify", 10 ) == 0 ) {
		ES_PRINT(DEBUG,"operation = VERIFY\n");
		opts->operation = VERIFY;

	}

	ret=1;
	for(;;) {
		int c, option_index;

		c = getopt_long ( argc, (char * const *)argv, "scqvfVhk:r:a:",
				long_options, &option_index );

		switch( c ) {
		case 's':
			opts->operation = SIGN;
			ES_PRINT(DEBUG,"operation = SIGN\n");
			break;

		case 'c':
			opts->operation = VERIFY;
			ES_PRINT(DEBUG,"operation = VERIFY\n");
			break;

		case 'd':
			opts->operation = DUMP;
			ES_PRINT(DEBUG,"operation = DUMP\n");
			break;

		case 'q':
			opts->verbose --;
			ES_PRINT(DEBUG,"verbosity lowered (%d)\n", 
					opts->verbose);
			break;

		case 'v':
			opts->verbose ++;
			ES_PRINT(DEBUG,"verbosity raised (%d)\n", 
					opts->verbose);
			break;

		case 'f':
			opts->force = 1;
			ES_PRINT(DEBUG,"force flag set\n");
			break;

		case 'V':
			ES_PRINT(DEBUG,"version requested\n");
			dump_version();
			exit(0);
			break;

		case 'h':
			ES_PRINT(DEBUG,"help requested\n");
			dump_help(argv[0]);
			exit(0);
			break;

		case 'k':
			ES_PRINT(DEBUG,"keyname set to %s\n",optarg);
			opts->keyname = optarg;
			break;

		case 'r':
			ES_PRINT(DEBUG,"keyring set to %s\n",optarg);
			opts->keyring = optarg;
			break;

		case 'a':
			ES_PRINT(DEBUG,"algorithm set to %s\n",optarg);
			opts->algname = optarg;
			break;

		default:
			goto scan_finished;
		}

		/* count number of processed options */
		ret = optind;
	}

scan_finished:
	ES_PRINT(DEBUG,"option scan complete, rest should be files.\n");

	if( opts->operation == NONE ) {
		ES_PRINT(ERROR,"Need to specify --sign or --verify "
				"operation\n");
		return -1;
	}

	return ret;
}

int
test_file( const char *file, int fd, int mode )
{
	static int uid=-1, gid, euid, egid;
	int ret=-1;
	struct stat st;

	ES_PRINT(DEBUG,"testing file %s\n",file);

	if(uid==-1) { 
		uid = getuid();
		gid = getgid();
		euid = geteuid();
		egid = getegid();
	}

	errno=0;
	if( ( ret = fstat(fd, &st) ) ) {
		ES_PRINT(ERROR,"%s: %s\n", file, strerror(errno));
		if( !opts->force ) goto bail;

	} else {
		/* fail on the next goto bail */
		ret = -1;

		if( !( st.st_mode & S_IFREG ) ) {
			ES_PRINT(ERROR,"%s: not a regular file\n", file);
			if( !opts->force ) goto bail;

		} else if( !( euid == 0 ) ) {
			/* test to see if this file can be read/written 
			 * by us */
			int good = 0;

			if( st.st_uid == uid || st.st_uid == euid ) {
				/* user mode required */
				unsigned int um = mode << 6;
				ES_PRINT(DEBUG,"%s: testing owner\n",file);
				if( (st.st_mode & um) == um )
					good++;
			}

			if( st.st_gid == gid || st.st_gid == egid ) {
				/* group mode required */
				unsigned int gm = mode << 3;
				ES_PRINT(DEBUG,"%s: testing group\n",file);
				if( (st.st_mode & gm) == gm )
					good++;
			}

			if( !good ) {
				/* other mode required */
				unsigned int om = mode;
				ES_PRINT(DEBUG,"%s: testing other\n",file);
				if( (st.st_mode & om) == om )
					good++;
			}

			if( !good ) {
				ES_PRINT(ERROR, "%s: insufficien access "
						"on file\n", file);
				if( !opts->force ) goto bail;
			}
		}
	}

	ret = 0;

bail:
	return ret;
}

int
main( int argc, char **argv )
{
	int i, ret, t_mode, o_mode, first, count;
	elfsign_options_t local_options;
	int(*proc_fn)(const char* name, int fd);

	ret = 0; 
	if( argc == 1 ) {
		dump_help(argv[0]);
		goto bail;
	}

	/* initialize the global reference */ 
	opts = &local_options;
	init_options();

	ret = 1;
	first = process_options(argc, argv);
	if( first<=0 ) goto bail;

	switch( opts->operation ) {
	case SIGN:
		o_mode  = O_RDWR;
		t_mode  = S_IROTH|S_IWOTH;
		proc_fn = do_elfsign;
		break;

	case VERIFY:
		o_mode  = O_RDONLY;
		t_mode  = S_IROTH;
		proc_fn = do_elfverify;
		break;

	case DUMP:
		o_mode  = O_RDONLY;
		t_mode  = S_IROTH;
		proc_fn = do_elfdump;
		break;

	default:
		ret = EINVAL;
		goto bail;
	}

	count = argc - first;
	if( count <= 0 ) {
		ES_PRINT(ERROR,"no files specified to %s\n",
				(opts->operation==SIGN)?"sign":"verify");
		ret = ENOENT;
		goto bail;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		ES_PRINT(ERROR, "%s: %s\n", argv[0], elf_errmsg(-1));
	}    

	ES_PRINT(DEBUG,"processing %d files...\n",count);
	for(i=0;i<count;i++) {
		const char * file;
		size_t file_name_len;
		file = argv[first+i];
		file_name_len = strlen (file);
		if ( opts->file_name_max < file_name_len )
			opts->file_name_max = file_name_len;
	}
	opts->file_name_max += 2;

	for(i=0;i<count;i++) {
		const char * file;
		int fd;

		file = argv[first+i];
		ES_PRINT(DEBUG,"file[%d] = %s\n",i,file);

		if( !file[0] ) {
			ES_PRINT(ERROR, "%s: invalid filename\n", file);
			ret = ENOENT;
			goto bail;
		}

		errno=0;
		if( (fd=open( file, o_mode ))<0 ) {
			ES_PRINT(ERROR, "%s: %s\n", file, strerror(errno));
			ret = fd;
			goto bail;
		}

		if( (ret=test_file( file, fd, t_mode ))<0 )
			goto bail;

		if( (ret=proc_fn( file, fd ))<0 )
			goto bail;

		close( fd );
	}

bail:
	if( ret ) {
		ES_PRINT(WARN, "\ntry %s --help for more information\n", 
				argv[0]);
	}
	exit( ret );
}

