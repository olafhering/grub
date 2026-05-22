/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2026  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_TSS2_UTIL_HEADER
#define GRUB_TSS2_UTIL_HEADER 1

#include <grub/err.h>
#include <tss2_types.h>

extern grub_err_t grub_tss2_hash_name_to_id (const char *name, TPM_ALG_ID_t *id);
extern grub_err_t grub_tss2_hash_id_to_digest_size (TPM_ALG_ID_t id, grub_size_t *size);
extern const char *grub_tss2_hash_id_to_name (TPM_ALG_ID_t id);

#endif /* GRUB_TSS2_UTIL_HEADER */
