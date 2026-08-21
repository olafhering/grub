/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2025  Free Software Foundation, Inc.
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
 *
 *  Core TPCM support code.
 */

#include <grub/err.h>
#include <grub/verify.h>
#include <grub/dl.h>
#include <grub/efi/tpcm.h>
#include <grub/misc.h>
#include <grub/mm.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_tpcm_verify_init (grub_file_t io, enum grub_file_type type, void **context,
                       enum grub_verify_flags *flags)
{
    char *file_context;

    file_context = grub_xasprintf ("%d|%s", (type & GRUB_FILE_TYPE_MASK),
                                   io->name);
    if (file_context == NULL)
        return grub_errno;

    *context = file_context;
    *flags |= GRUB_VERIFY_FLAGS_SINGLE_CHUNK;

    return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpcm_verify_write (void *context, void *buf , grub_size_t size)
{
    return grub_tpcm_measure_memory (context, (grub_addr_t)buf, size);
}

static void
grub_tpcm_verify_close (void *context)
{
    grub_free (context);
}

static grub_err_t
grub_tpcm_verify_string (char *str, enum grub_verify_string_type type)
{
    const char *prefix = NULL;
    char *description, *context = NULL;
    grub_err_t status;

    switch (type)
    {
    case GRUB_VERIFY_KERNEL_CMDLINE:
      prefix = "kernel_cmdline: ";
      break;
    case GRUB_VERIFY_MODULE_CMDLINE:
      prefix = "module_cmdline: ";
      break;
    case GRUB_VERIFY_COMMAND:
      prefix = "grub_cmd: ";
      break;
    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }

    context = grub_zalloc (grub_strlen (str) + grub_strlen (prefix) + 1 + 4);  /* 4 for type */
    if (context == NULL)
        return grub_errno;

    grub_snprintf (context, 4, "%d|", type);
    description = context + grub_strlen (context);
    grub_memcpy (description, prefix, grub_strlen (prefix));
    grub_memcpy (description + grub_strlen (prefix), str, grub_strlen (str) + 1);

    status = grub_tpcm_measure_memory (context, (grub_addr_t)str, grub_strlen (str));

    grub_free (context);

    return status;
}

struct grub_file_verifier grub_tpcm_verifier = {
    .name = "tpcm",
    /* Measurement only, so it can run on the final buffer. */
    .in_place = true,
    .init  = grub_tpcm_verify_init,
    .write = grub_tpcm_verify_write,
    .close = grub_tpcm_verify_close,
    .verify_string = grub_tpcm_verify_string,
};

GRUB_MOD_INIT (tpcm)
{
    grub_verifier_register (&grub_tpcm_verifier);
}

GRUB_MOD_FINI (tpcm)
{
    grub_verifier_unregister (&grub_tpcm_verifier);
}
