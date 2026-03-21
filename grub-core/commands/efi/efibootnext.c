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

#include <grub/command.h>
#include <grub/dl.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/misc.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_err_t
grub_cmd_bootnext (grub_command_t cmd __attribute__ ((unused)),
                   int argc, char **args)
{
  grub_guid_t global = GRUB_EFI_GLOBAL_VARIABLE_GUID;
  grub_uint16_t entry;
  unsigned long parsed;
  grub_err_t status;
  const char *end;

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

  status = grub_efi_set_variable ("BootNext", &global,
                                  &entry, sizeof (entry));
  if (status != GRUB_ERR_NONE)
    return status;

  grub_printf ("BootNext set to Boot%04X\n", (unsigned) entry);

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
