/*
 * Copyright (c) 2003 by SOMA Networks, Inc.
 * All rights reserved.
 *
 * This material is proprietary to SOMA Networks, Inc. and,
 * in addition to the above mentioned Copyright, may be
 * subject to protection under other intellectual property
 * regimes, including patents, trade secrets, designs and/or
 * trademarks.
 *
 * Any use of this material for any purpose, except with an
 * express license from SOMA Networks, Inc. is strictly
 * prohibited.
 */

#ident "@(#)ccommenter.vim 1.3      03/02/27 SOMA Networks"

#ifndef ELFSIGN_ELFSTRINGS_H
#define ELFSIGN_ELFSTRINGS_H

/* converts an elf section header type to a string of it's name */
extern const char * elf_sht_string (int sh_type);

#endif
