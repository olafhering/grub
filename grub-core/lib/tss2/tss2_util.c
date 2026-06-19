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

#include <tpm2_cmd.h>
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
  { NULL, 0, 0 }
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

grub_err_t
grub_tss2_read_pcrs (grub_uint32_t pcr_bitmask, TPM_ALG_ID_t alg_id,
		     TPM2B_DIGEST_t digests[TPM_MAX_PCRS])
{
  TPML_PCR_SELECTION_t remaining = {0};
  TPML_PCR_SELECTION_t returned_sel;
  TPML_DIGEST_t values;
  grub_size_t expected_size;
  grub_uint32_t k;
  grub_uint8_t i;
  grub_uint8_t byte, bit;
  grub_uint8_t prev0, prev1, prev2;
  TPM_RC_t rc;
  grub_err_t err;

  err = grub_tss2_hash_id_to_digest_size (alg_id, &expected_size);
  if (err != GRUB_ERR_NONE)
    return err;

  grub_memset (digests, 0, sizeof (TPM2B_DIGEST_t) * TPM_MAX_PCRS);

  remaining.count = 1;
  remaining.pcrSelections[0].hash = alg_id;
  remaining.pcrSelections[0].sizeOfSelect = TPM_PCR_SELECT_MAX;
  for (i = 0; i < TPM_MAX_PCRS; i++)
    if (pcr_bitmask & (1u << i))
      TPMS_PCR_SELECTION_SelectPCR (&remaining.pcrSelections[0], i);

  while (remaining.pcrSelections[0].pcrSelect[0] ||
	 remaining.pcrSelections[0].pcrSelect[1] ||
	 remaining.pcrSelections[0].pcrSelect[2])
    {
      grub_memset (&returned_sel, 0, sizeof (returned_sel));
      grub_memset (&values, 0, sizeof (values));
      k = 0;

      rc = grub_tpm2_pcr_read (NULL, &remaining, NULL, &returned_sel, &values, NULL);
      if (rc != TPM_RC_SUCCESS)
	return grub_error (GRUB_ERR_BAD_DEVICE,
			   N_("TPM2_PCR_Read failed: status=0x%x"), rc);

      if (values.count == 0 ||
	  returned_sel.count == 0 ||
	  returned_sel.pcrSelections[0].sizeOfSelect == 0)
	return grub_error (GRUB_ERR_BAD_DEVICE,
			   N_("TPM2_PCR_Read returned no digests"));

      prev0 = remaining.pcrSelections[0].pcrSelect[0];
      prev1 = remaining.pcrSelections[0].pcrSelect[1];
      prev2 = remaining.pcrSelections[0].pcrSelect[2];

      for (i = 0; i < TPM_MAX_PCRS && k < values.count; i++)
	{
	  byte = i / 8;
	  bit = 1u << (i % 8);

	  if (!(returned_sel.pcrSelections[0].pcrSelect[byte] & bit))
	    continue;

	  if (values.digests[k].size != expected_size)
	    return grub_error (GRUB_ERR_BAD_DEVICE,
			       N_("unexpected digest size for PCR %d"), i);

	  digests[i] = values.digests[k++];
	  remaining.pcrSelections[0].pcrSelect[byte] &= ~bit;
	}

      /* Ensure that the TPM device returns non-redundant PCR digests. */
      if (remaining.pcrSelections[0].pcrSelect[0] == prev0 &&
	  remaining.pcrSelections[0].pcrSelect[1] == prev1 &&
	  remaining.pcrSelections[0].pcrSelect[2] == prev2)
	return grub_error (GRUB_ERR_BAD_DEVICE,
			   N_("TPM2_PCR_Read made no progress; aborting"));
    }

  return GRUB_ERR_NONE;
}
