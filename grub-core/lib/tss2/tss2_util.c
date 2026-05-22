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

#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/misc.h>
#include <grub/mm.h>

#include <tss2_util.h>

typedef struct
{
  const char *name;
  TPM_ALG_ID_t id;
  grub_size_t digest_size;
} tpm2_hash_info_t;

static const tpm2_hash_info_t hash_alg_table[] = {
  { "sha1",   TPM_ALG_SHA1,   TPM_SHA1_DIGEST_SIZE   },
  { "sha256", TPM_ALG_SHA256, TPM_SHA256_DIGEST_SIZE },
  { "sha384", TPM_ALG_SHA384, TPM_SHA384_DIGEST_SIZE },
  { "sha512", TPM_ALG_SHA512, TPM_SHA512_DIGEST_SIZE },
  { NULL }
};

grub_err_t
grub_tss2_hash_name_to_id (const char *name, TPM_ALG_ID_t *id)
{
  grub_size_t i;

  for (i = 0; hash_alg_table[i].name != NULL; i++)
    {
      if (grub_strcasecmp (name, hash_alg_table[i].name) == 0)
	{
	  *id = hash_alg_table[i].id;
	  return GRUB_ERR_NONE;
	}
    }

  return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("unknown hash algorithm '%s'"), name);
}

grub_err_t
grub_tss2_hash_id_to_digest_size (TPM_ALG_ID_t id, grub_size_t *size)
{
  grub_size_t i;

  for (i = 0; hash_alg_table[i].name != NULL; i++)
    {
      if (id == hash_alg_table[i].id)
	{
	  *size = hash_alg_table[i].digest_size;
	  return GRUB_ERR_NONE;
	}
    }

  return grub_error (GRUB_ERR_BAD_ARGUMENT,
		     N_("unknown hash algorithm id 0x%04x"), (unsigned) id);
}

const char *
grub_tss2_hash_id_to_name (TPM_ALG_ID_t id)
{
  grub_size_t i;

  for (i = 0; hash_alg_table[i].name != NULL; i++)
    if (id == hash_alg_table[i].id)
      return hash_alg_table[i].name;

  return NULL;
}
