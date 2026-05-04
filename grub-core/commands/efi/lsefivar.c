/* efivar.c - dump runtime uefi variables. */
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
#include <grub/misc.h>
#include <grub/charset.h>
#include <grub/extcmd.h>
#include <grub/efi/efi.h>
#include <grub/efi/api.h>
#include <grub/lib/hexdump.h>

GRUB_MOD_LICENSE ("GPLv3+");

static const struct grub_arg_option options[] =
{
       {0, 'l', 0, N_("Dump variable contents"), 0, 0},
       {0, 0, 0, 0, 0, 0}
};

static void
dump_variable_data(const char *variable_name, grub_guid_t *variable_guid)
{
    grub_efi_status_t status;
    grub_efi_uint32_t attributes;
    grub_size_t data_size;
    void *data;

    attributes = 0;

    status = grub_efi_get_variable_with_attributes (variable_name, variable_guid,
                                                   &data_size, &data, &attributes);
    if (status != GRUB_EFI_SUCCESS)
        return;

    grub_puts_ (N_("Attributes:"));
    if (attributes & GRUB_EFI_VARIABLE_NON_VOLATILE)
        grub_puts_ (N_("\tNon-Volatile"));
    if (attributes & GRUB_EFI_VARIABLE_BOOTSERVICE_ACCESS)
        grub_puts_ (N_("\tBoot Service Access"));
    if (attributes & GRUB_EFI_VARIABLE_RUNTIME_ACCESS)
        grub_puts_ (N_("\tRuntime Service Access"));

    grub_puts_ (N_("Value:"));
    hexdump (0, data, data_size);
    grub_free (data);
}

static grub_err_t
dump_efi_variables(grub_efi_boolean_t dump_variable_content)
{
    grub_efi_status_t status;
    grub_efi_runtime_services_t *r;
    grub_efi_uintn_t variable_name_size;
    grub_efi_uintn_t buffer_size;
    grub_efi_char16_t *variable_name;
    grub_uint8_t *variable_name_string = NULL;
    grub_guid_t vendor_guid;

    grub_memset (&vendor_guid, 0, sizeof (grub_guid_t));
    buffer_size = 512;
    r = grub_efi_system_table->runtime_services;

    variable_name = grub_calloc (buffer_size, 1);
    if (variable_name == NULL)
       return grub_errno;
    *variable_name = 0; /* Start with empty string */

    while (1)
    {
        variable_name_size = buffer_size;
        status = r->get_next_variable_name (&variable_name_size, variable_name, &vendor_guid);
        if (status == GRUB_EFI_BUFFER_TOO_SMALL)
        {
            grub_efi_char16_t *tmp;
            /* According to UEFI VariableNameSize is parameter of in/out.
              That means it recieves buffer size on input and returns the size
              of enumerated variable on output, so we should treat differently. */
            buffer_size = variable_name_size;
            tmp = grub_realloc (variable_name, buffer_size);
            if (tmp == NULL)
            {
                grub_free (variable_name);
                return grub_errno;
            }
            variable_name = tmp;
            continue;
        }

        if (status == GRUB_EFI_NOT_FOUND)
            break;
        else if (status != GRUB_EFI_SUCCESS)
        {
            grub_free (variable_name);
            return GRUB_ERR_INVALID_COMMAND;
        }

        variable_name_string = grub_calloc ((variable_name_size / sizeof (grub_efi_char16_t)) + 1, 
                                            GRUB_MAX_UTF8_PER_UTF16);
        if (variable_name_string == NULL)
        {
            grub_free (variable_name);
            return grub_errno;
        }
        *grub_utf16_to_utf8 (variable_name_string, variable_name, variable_name_size) = '\0';
        grub_printf ("%pG-%s\n", &vendor_guid, variable_name_string);
        if (dump_variable_content)
            dump_variable_data ((char*)variable_name_string, &vendor_guid);

        grub_free (variable_name_string);
    }

    grub_free (variable_name);
    return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_lsefivar (grub_extcmd_context_t ctxt,
                int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
    if (ctxt->state[0].set)
        return dump_efi_variables (true); /* true: dump variables and contents*/
 
    return dump_efi_variables (false); /* false: do not dump variable contents*/
}

static grub_extcmd_t cmd;

GRUB_MOD_INIT(lsefivar)
{
    cmd = grub_register_extcmd_lockdown ("lsefivar", grub_cmd_lsefivar, 0, N_("[-l]"), N_("Display UEFI variables."), options);
}
GRUB_MOD_FINI(lsefivar)
{
    grub_unregister_extcmd (cmd);
}
