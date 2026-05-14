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

#include <grub/dl.h>
#include <grub/efi/efi.h>
#include <grub/err.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/tpm.h>

#include <tcg2.h>
#include <tss2_util.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define TPM_PCR_BITMASK_ALL ((1u << GRUB_TPM_MAX_PCRS) - 1)

/* GUID for GRUB PCR snapshot EFI variables. */
#define GRUB_PCR_SNAPSHOT_GUID \
  { 0x7ce323f2, 0xb841, 0x4d30, { 0xa0, 0xe9, 0x54, 0x74, 0xa7, 0x6c, 0x9a, 0x3f } }

typedef enum {
  OPTION_EFIVAR = 0,
  OPTION_BANK,
} tpm_record_pcrs_options_t;

static const struct grub_arg_option tpm_record_pcrs_options[] =
  {
    {
      .longarg  = "efivar",
      .shortarg = 'E',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("The EFI variable to publish the PCRs to (default GrubPcrSnapshot)"),
    },

    {
      .longarg  = "bank",
      .shortarg = 'b',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("The PCR bank to record (sha1, sha256, sha384, sha512; default sha256)"),
    },

    {0, 0, 0, 0, 0, 0}
  };

static bool
tpm_record_parse_pcr_index (const char *word, const char **end_ret, grub_uint32_t *index)
{
  const char *end;
  grub_uint64_t raw;

  if (!grub_isdigit (word[0]))
    return false;

  raw = grub_strtoul (word, &end, 10);
  if (raw >= GRUB_TPM_MAX_PCRS)
    return false;
  *index = (grub_uint32_t)raw;

  *end_ret = end;
  return true;
}

static grub_err_t
tpm_record_parse_pcr_list (const char *arg, grub_uint32_t *bitmask)
{
  const char *word, *end;
  grub_uint32_t index, last_index = 0;

  if (!grub_strcmp (arg, "all"))
    {
      *bitmask = TPM_PCR_BITMASK_ALL;
      return GRUB_ERR_NONE;
    }

  word = arg;
  while (1)
    {
      if (tpm_record_parse_pcr_index (word, &end, &index) == false)
	goto bad_pcr_index;

      if (*end == '-')
	{
          if (tpm_record_parse_pcr_index (end + 1, &end, &last_index) == false || last_index < index)
	    goto bad_pcr_index;

	  while (index <= last_index)
	    *bitmask |= (1u << (index++));
	}
      else
	*bitmask |= (1u << index);

      if (*end == '\0')
	break;

      if (*end != ',')
	goto bad_pcr_index;

      word = end + 1;
    }

  return GRUB_ERR_NONE;

bad_pcr_index:
  return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("cannot parse PCR list \"%s\""), arg);
}

static grub_err_t
tpm_snapshot_pcrs (grub_uint32_t pcr_bitmask, const TPM_ALG_ID_t alg_id, void **buffer_ret, grub_size_t *size_ret)
{
  TPM2B_DIGEST_t digests[TPM_MAX_PCRS];
  TPM2B_DIGEST_t *d;
  const char *algo;
  char *buffer, *tmp;
  grub_size_t size = 4096;
  grub_size_t wpos = 0;
  grub_size_t need;
  grub_uint16_t k;
  grub_uint8_t pcr;
  grub_err_t err;

  algo = grub_tss2_hash_id_to_name (alg_id);
  if (algo == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Unknown Hash Algorithm ID: 0x%x"), alg_id);

  buffer = grub_malloc (size);
  if (buffer == NULL)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("Not enough memory when dumping PCR registers"));

  err = grub_tss2_read_pcrs (pcr_bitmask, alg_id, digests);
  if (err != GRUB_ERR_NONE)
    {
      grub_free (buffer);
      return err;
    }

  for (pcr = 0; pcr < GRUB_TPM_MAX_PCRS; ++pcr)
    {
      d = &digests[pcr];

      if (!(pcr_bitmask & (1u << pcr)))
	continue;

      /* We need room for the PCR index, 2 spaces, newline, NUL. 16 should be enough. */
      need = 16 + grub_strlen (algo) + 2 * d->size;
      if (wpos + need > size)
	{
	  tmp = grub_realloc (buffer, size + need);
	  if (tmp == NULL)
	    {
	      grub_free (buffer);
	      return grub_error (GRUB_ERR_OUT_OF_MEMORY, N_("Not enough memory when dumping PCR registers"));
	    }
	  buffer = tmp;
	  size = size + need;
	}

      wpos += grub_snprintf (buffer + wpos, size - wpos, "%02d %s ", pcr, algo);

      for (k = 0; k < d->size; ++k)
	wpos += grub_snprintf (buffer + wpos, size - wpos, "%02x", d->buffer[k]);

      buffer[wpos++] = '\n';
      buffer[wpos] = '\0';
    }

  *buffer_ret = buffer;
  *size_ret = wpos;

  return GRUB_ERR_NONE;
}

/*
 * Preserve current PCR values and record them to an EFI variable
 */
static grub_err_t
tpm_write_pcrs_to_efi (void *data, grub_size_t size, const char *var_name)
{
  grub_guid_t guid = GRUB_PCR_SNAPSHOT_GUID;
  grub_err_t rc;

  rc = grub_efi_set_variable_with_attributes (var_name, &guid, data, size,
					      GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS | GRUB_EFI_VARIABLE_RUNTIME_ACCESS);

  return rc;
}

static grub_err_t
tpm_record_pcrs (grub_extcmd_context_t ctxt, int argc, char **args)
{
  struct grub_arg_list *state = ctxt->state;
  grub_uint32_t pcr_bitmask = 0;
  const char *efivar;
  TPM_ALG_ID_t alg_id = TPM_ALG_SHA256;
  void *buffer = NULL;
  grub_size_t tcg2_size;
  grub_size_t size = 0;
  int n;
  grub_err_t err;

  /* To prevent error: unable to read PCR from TPM, if no TPM device available */
  if (grub_tcg2_get_max_output_size (&tcg2_size) != GRUB_ERR_NONE)
    {
      grub_dprintf ("tpm", "tpm_record_pcrs: no TCG2 protocol, skipping\n");
      grub_errno = GRUB_ERR_NONE;
      return GRUB_ERR_NONE;
    }

  efivar = "GrubPcrSnapshot";
  if (state[OPTION_EFIVAR].set)
    {
      if (grub_strlen (state[OPTION_EFIVAR].arg) <= 30)
	efivar = state[OPTION_EFIVAR].arg;
      else
	grub_printf (N_("EFI variable name exceeds 30 characters. Falling back to GrubPcrSnapshot.\n"));
    }

  if (state[OPTION_BANK].set)
    {
      err = grub_tss2_hash_name_to_id (state[OPTION_BANK].arg, &alg_id);
      if (err != GRUB_ERR_NONE)
	return err;
    }

  if (argc == 0)
    pcr_bitmask = TPM_PCR_BITMASK_ALL;
  else
    {
      for (n = 0; n < argc; ++n)
	{
	  err = tpm_record_parse_pcr_list (args[n], &pcr_bitmask);
	  if (err != GRUB_ERR_NONE)
	    return err;
	}
    }

  err = tpm_snapshot_pcrs (pcr_bitmask, alg_id, &buffer, &size);
  if (err != GRUB_ERR_NONE)
    goto out;

  if (size == 0)
    {
      err = grub_error (GRUB_ERR_READ_ERROR, N_("Empty PCR reading"));
      goto out;
    }

  err = tpm_write_pcrs_to_efi (buffer, size, efivar);
  if (err != GRUB_ERR_NONE)
    goto out;

out:
  grub_free (buffer);

  return err;
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT (tpm_record_pcrs)
{
  cmd = grub_register_extcmd ("tpm_record_pcrs", tpm_record_pcrs, 0,
			      N_("LIST_OF_PCRS"),
			      N_("Snapshot one or more PCR values and record them in an EFI variable."),
			      tpm_record_pcrs_options);
}

GRUB_MOD_FINI (tpm_record_pcrs)
{
  grub_unregister_extcmd (cmd);
}
