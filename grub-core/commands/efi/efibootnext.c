/* efibootnext.c - Set EFI BootNext variable from GRUB. */
/*
 *  GRUB EFI bootnext command.
 *  Copyright (C) 2012  Free Software Foundation, Inc.
 *  Copyright (C) 2026  Thomas Grainger <tagrain@gmail.com>
 *
 *  Based on grub-core/commands/efi/efifwsetup.c
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
 *  Provides the `bootnext' command to set the UEFI BootNext NVRAM variable.
 *  This lets a GRUB menu entry hand control to a different EFI boot option
 *  for one boot only, without touching BootOrder.  Use the `reboot' command
 *  afterwards to trigger the boot immediately.
 *
 *  Usage (from grub.cfg or the GRUB shell):
 *
 *    bootnext 0003          # set BootNext to Boot0003
 *    bootnext 0x0003        # same, with 0x prefix
 *    bootnext 0003; reboot  # set BootNext to Boot0003 and reboot
 */

#include <grub/charset.h>
#include <grub/command.h>
#include <grub/dl.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_cmd_bootnext (grub_command_t cmd __attribute__ ((unused)),
                   int argc, char **args)
{
  grub_guid_t global = GRUB_EFI_GLOBAL_VARIABLE_GUID;
  /* "Boot" + 4 hex digits + NUL.  */
  char varname[sizeof ("Boot####")];
  /* EFI_LOAD_OPTION header: UINT32 Attributes; UINT16 FilePathListLength.  */
  const grub_size_t hdr = sizeof (grub_efi_uint32_t) + sizeof (grub_efi_uint16_t);
  grub_uint16_t entry;
  unsigned long parsed;
  grub_efi_status_t efi_status;
  grub_err_t status;
  const char *end;
  void *option = NULL;
  grub_size_t option_size = 0;
  grub_uint8_t *label = NULL;

  if (argc != 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("exactly one hex boot entry number required"));

  parsed = grub_strtoul (args[0], &end, 16);
  if (grub_errno != GRUB_ERR_NONE)
    return grub_errno;
  if (end == args[0] || *end != '\0')
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("invalid boot entry number `%s'"), args[0]);

  if (parsed > 0xffff)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       N_("boot entry number `0x%lx' out of range"),
                       parsed);

  entry = (grub_uint16_t) parsed;
  grub_snprintf (varname, sizeof (varname), "Boot%04X", (unsigned) entry);

  /*
   * The target boot entry must already exist: pointing BootNext at a
   * Boot#### the firmware does not know about would silently do nothing
   * on the next boot.  This is just another validation before the set,
   * so as with the checks above NVRAM is left untouched on failure.
   */
  efi_status = grub_efi_get_variable (varname, &global, &option_size, &option);
  if (efi_status != GRUB_EFI_SUCCESS || option == NULL)
    {
      grub_free (option);
      return grub_error (GRUB_ERR_BAD_ARGUMENT,
                         N_("no such boot entry `%s'"), varname);
    }

  /*
   * Best-effort decode of the entry's description (the label the
   * firmware boot menu shows).  A present but malformed/undecodable
   * entry is not fatal: BootNext is still set, just without a label.
   * EFI_LOAD_OPTION is: UINT32 Attributes; UINT16 FilePathListLength;
   * CHAR16 Description[] (NUL-terminated); ...
   */
  if (option_size > hdr)
    {
      grub_size_t max = (option_size - hdr) / sizeof (grub_efi_char16_t);
      grub_efi_char16_t *desc;
      grub_size_t len = 0;

      /*
       * The description sits at a byte offset inside the variable buffer
       * and is not guaranteed to be grub_efi_char16_t aligned, so copy
       * it out into an aligned buffer rather than casting in place.
       */
      desc = grub_malloc ((max + 1) * sizeof (*desc));
      if (desc != NULL)
        {
          grub_memcpy (desc, (grub_uint8_t *) option + hdr,
                       max * sizeof (*desc));

          while (len < max && desc[len] != 0)
            len++;

          label = grub_malloc (len * GRUB_MAX_UTF8_PER_UTF16 + 1);
          if (label != NULL)
            *grub_utf16_to_utf8 (label, desc, len) = '\0';

          grub_free (desc);
        }
    }

  /*
   * The label decode above is best-effort; do not let a failed malloc
   * leak grub_errno into the caller when BootNext is set successfully.
   */
  grub_errno = GRUB_ERR_NONE;

  status = grub_efi_set_variable ("BootNext", &global,
                                  &entry, sizeof (entry));
  if (status != GRUB_ERR_NONE)
    {
      grub_free (label);
      grub_free (option);
      return status;
    }

  if (label != NULL && *label != '\0')
    grub_printf ("BootNext set to %s: %s\n", varname, label);
  else
    grub_printf ("BootNext set to %s\n", varname);

  grub_free (label);
  grub_free (option);

  return GRUB_ERR_NONE;
}

static grub_command_t cmd;

GRUB_MOD_INIT (efibootnext)
{
  cmd = grub_register_command ("bootnext", grub_cmd_bootnext,
                               N_("[0x]XXXX"),
                               N_("Set EFI BootNext to Boot####."));
}

GRUB_MOD_FINI (efibootnext)
{
  grub_unregister_command (cmd);
}
