/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013,2019 Free Software Foundation, Inc.
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

/* Contains portions derived from efibootmgr, licensed as follows:
 *
 *  Copyright (C) 2001-2004 Dell, Inc. <Matt_Domsch@dell.com>
 *  Copyright 2015-2016 Red Hat, Inc. <pjones@redhat.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include <config.h>

#ifdef HAVE_EFIVAR

#include <grub/util/install.h>
#include <grub/emu/hostdisk.h>
#include <grub/util/misc.h>
#include <grub/list.h>
#include <grub/misc.h>
#include <grub/emu/exec.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <efiboot.h>
#include <efivar.h>

struct efi_variable {
  struct efi_variable *next;
  struct efi_variable **prev;
  char *name;
  efi_guid_t guid;
  uint8_t *data;
  size_t data_size;
  uint32_t attributes;
  int num;
};

/* Boot option attributes.  */
#define LOAD_OPTION_ACTIVE 0x00000001

/* GUIDs.  */
#define BLKX_UNKNOWN_GUID \
  EFI_GUID (0x47c7b225, 0xc42a, 0x11d2, 0x8e57, 0x00, 0xa0, 0xc9, 0x69, \
	    0x72, 0x3b)

/* Log all errors recorded by libefivar/libefiboot.  */
static void
show_efi_errors (void)
{
  int i;
  int saved_errno = errno;

  for (i = 0; ; ++i)
    {
      char *filename, *function, *message = NULL;
      int line, error = 0, rc;

      rc = efi_error_get (i, &filename, &function, &line, &message, &error);
      if (rc < 0)
	/* Give up.  The caller is going to log an error anyway.  */
	break;
      if (rc == 0)
	/* No more errors.  */
	break;
      grub_util_warn ("%s: %s: %s", function, message, strerror (error));
    }

  efi_error_clear ();
  errno = saved_errno;
}

static struct efi_variable *
new_efi_variable (void)
{
  struct efi_variable *new = xmalloc (sizeof (*new));
  memset (new, 0, sizeof (*new));
  return new;
}

static struct efi_variable *
new_boot_variable (void)
{
  struct efi_variable *new = new_efi_variable ();
  new->guid = EFI_GLOBAL_GUID;
  new->attributes = EFI_VARIABLE_NON_VOLATILE |
		    EFI_VARIABLE_BOOTSERVICE_ACCESS |
		    EFI_VARIABLE_RUNTIME_ACCESS;
  return new;
}

static void
free_efi_variable (struct efi_variable *entry)
{
  if (entry)
    {
      free (entry->name);
      free (entry->data);
      free (entry);
    }
}

static int
read_efi_variable (const char *name, struct efi_variable **entry)
{
  struct efi_variable *new = new_efi_variable ();
  int rc;

  rc = efi_get_variable (EFI_GLOBAL_GUID, name,
			 &new->data, &new->data_size, &new->attributes);
  if (rc < 0)
    {
      free_efi_variable (new);
      new = NULL;
    }

  if (new)
    {
      /* Latest Apple firmware sets the high bit which appears invalid
	 to the Linux kernel if we write it back, so let's zero it out if it
	 is set since it would be invalid to set it anyway.  */
      new->attributes = new->attributes & ~(1 << 31);

      new->name = xstrdup (name);
      new->guid = EFI_GLOBAL_GUID;
    }

  *entry = new;
  return rc;
}

/* Set an EFI variable, but only if it differs from the current value.
   Some firmware implementations are liable to fill up flash space if we set
   variables unnecessarily, so try to keep write activity to a minimum. */
static int
set_efi_variable (const char *name, struct efi_variable *entry)
{
  struct efi_variable *old = NULL;
  int rc = 0;

  read_efi_variable (name, &old);
  efi_error_clear ();
  if (old && old->attributes == entry->attributes &&
      old->data_size == entry->data_size &&
      memcmp (old->data, entry->data, entry->data_size) == 0)
    grub_util_info ("skipping unnecessary update of EFI variable %s", name);
  else
    {
      rc = efi_set_variable (EFI_GLOBAL_GUID, name,
			     entry->data, entry->data_size, entry->attributes,
			     0644);
      if (rc < 0)
	grub_util_warn (_("Cannot set EFI variable %s"), name);
    }
  free_efi_variable (old);
  return rc;
}

static int
cmpvarbyname (const void *p1, const void *p2)
{
  const struct efi_variable *var1 = *(const struct efi_variable **)p1;
  const struct efi_variable *var2 = *(const struct efi_variable **)p2;
  return strcmp (var1->name, var2->name);
}

static int
read_boot_variables (struct efi_variable **varlist)
{
  int rc;
  efi_guid_t *guid = NULL;
  char *name = NULL;
  struct efi_variable **newlist = NULL;
  int nentries = 0;
  int i;

  while ((rc = efi_get_next_variable_name (&guid, &name)) > 0)
    {
      const char *snum = name + sizeof ("Boot") - 1;
      struct efi_variable *var = NULL;
      unsigned int num;

      if (memcmp (guid, &efi_guid_global, sizeof (efi_guid_global)) != 0 ||
	  strncmp (name, "Boot", sizeof ("Boot") - 1) != 0 ||
	  !grub_isxdigit (snum[0]) || !grub_isxdigit (snum[1]) ||
	  !grub_isxdigit (snum[2]) || !grub_isxdigit (snum[3]))
	continue;

      rc = read_efi_variable (name, &var);
      if (rc < 0)
	break;

      if (sscanf (var->name, "Boot%04X-%*s", &num) == 1 && num < 65536)
	var->num = num;

      newlist = xrealloc (newlist, (++nentries) * sizeof (*newlist));
      newlist[nentries - 1] = var;
    }
  if (rc == 0 && newlist)
    {
      qsort (newlist, nentries, sizeof (*newlist), cmpvarbyname);
      for (i = nentries - 1; i >= 0; --i)
	grub_list_push (GRUB_AS_LIST_P (varlist), GRUB_AS_LIST (newlist[i]));
    }
  else if (newlist)
    {
      for (i = 0; i < nentries; ++i)
	free_efi_variable (newlist[i]);
      free (newlist);
    }
  return rc;
}

#define GET_ORDER(data, i) \
  ((uint16_t) ((data)[(i) * 2]) + ((data)[(i) * 2 + 1] << 8))
#define SET_ORDER(data, i, num) \
  do { \
    (data)[(i) * 2] = (num) & 0xFF; \
    (data)[(i) * 2 + 1] = ((num) >> 8) & 0xFF; \
  } while (0)

static void
remove_from_boot_order (struct efi_variable *order, uint16_t num)
{
  unsigned int old_i, new_i;

  /* We've got an array (in order->data) of the order.  Squeeze out any
     instance of the entry we're deleting by shifting the remainder down.  */
  for (old_i = 0, new_i = 0;
       old_i < order->data_size / sizeof (uint16_t);
       ++old_i)
    {
      uint16_t old_num = GET_ORDER (order->data, old_i);
      if (old_num != num)
	{
	  if (new_i != old_i)
	    SET_ORDER (order->data, new_i, old_num);
	  ++new_i;
	}
    }

  order->data_size = new_i * sizeof (uint16_t);
}

static void
add_to_boot_order (struct efi_variable *order, uint16_t num)
{
  int i;
  size_t new_data_size;
  uint8_t *new_data;

  /* Check whether this entry is already in the boot order.  If it is, leave
     it alone.  */
  for (i = 0; i < order->data_size / sizeof (uint16_t); ++i)
    if (GET_ORDER (order->data, i) == num)
      return;

  new_data_size = order->data_size + sizeof (uint16_t);
  new_data = xmalloc (new_data_size);
  SET_ORDER (new_data, 0, num);
  memcpy (new_data + sizeof (uint16_t), order->data, order->data_size);
  free (order->data);
  order->data = new_data;
  order->data_size = new_data_size;
}

static int
find_free_boot_num (struct efi_variable *entries)
{
  int num_vars = 0, i;
  struct efi_variable *entry;

  FOR_LIST_ELEMENTS (entry, entries)
    ++num_vars;

  if (num_vars == 0)
    return 0;

  /* O(n^2), but n is small and this is easy. */
  for (i = 0; i < num_vars; ++i)
    {
      int found = 0;
      FOR_LIST_ELEMENTS (entry, entries)
	{
	  if (entry->num == i)
	    {
	      found = 1;
	      break;
	    }
	}
      if (!found)
	return i;
    }

  return i;
}

static int
get_edd_version (void)
{
  efi_guid_t blkx_guid = BLKX_UNKNOWN_GUID;
  uint8_t *data = NULL;
  size_t data_size = 0;
  uint32_t attributes;
  efidp_header *path;
  int rc;

  rc = efi_get_variable (blkx_guid, "blk0", &data, &data_size, &attributes);
  if (rc < 0)
    return rc;

  path = (efidp_header *) data;
  if (path->type == 2 && path->subtype == 1)
    return 3;
  return 1;
}

static struct efi_variable *
make_boot_variable (int num, const char *disk, int part, const char *loader,
		    const char *label)
{
  struct efi_variable *entry = new_boot_variable ();
  uint32_t options;
  uint32_t edd10_devicenum;
  ssize_t dp_needed, loadopt_needed;
  efidp dp = NULL;

  options = EFIBOOT_ABBREV_HD;
  switch (get_edd_version ()) {
    case 1:
      options = EFIBOOT_ABBREV_EDD10;
      break;
    case 3:
      options = EFIBOOT_ABBREV_NONE;
      break;
  }

  /* This may not be the right disk; but it's probably only an issue on very
     old hardware anyway. */
  edd10_devicenum = 0x80;

  dp_needed = efi_generate_file_device_path_from_esp (NULL, 0, disk, part,
						      loader, options,
						      edd10_devicenum);
  if (dp_needed < 0)
    goto err;

  dp = xmalloc (dp_needed);
  dp_needed = efi_generate_file_device_path_from_esp ((uint8_t *) dp,
						      dp_needed, disk, part,
						      loader, options,
						      edd10_devicenum);
  if (dp_needed < 0)
    goto err;

  loadopt_needed = efi_loadopt_create (NULL, 0, LOAD_OPTION_ACTIVE,
				       dp, dp_needed, (unsigned char *) label,
				       NULL, 0);
  if (loadopt_needed < 0)
    goto err;
  entry->data_size = loadopt_needed;
  entry->data = xmalloc (entry->data_size);
  loadopt_needed = efi_loadopt_create (entry->data, entry->data_size,
				       LOAD_OPTION_ACTIVE, dp, dp_needed,
				       (unsigned char *) label, NULL, 0);
  if (loadopt_needed < 0)
    goto err;

  entry->name = xasprintf ("Boot%04X", num);
  entry->num = num;

  return entry;

err:
  free_efi_variable (entry);
  free (dp);
  return NULL;
}

int
grub_install_efivar_register_efi (grub_device_t efidir_grub_dev,
				  const char *efifile_path,
				  const char *efi_distributor)
{
  const char *efidir_disk;
  int efidir_part;
  struct efi_variable *entries = NULL, *entry;
  struct efi_variable *order;
  int entry_num = -1;
  int rc;

  efidir_disk = grub_util_biosdisk_get_osdev (efidir_grub_dev->disk);
  efidir_part = efidir_grub_dev->disk->partition ? efidir_grub_dev->disk->partition->number + 1 : 1;

#ifdef __linux__
  /*
   * Linux uses efivarfs (mounted on /sys/firmware/efi/efivars) to access the
   * EFI variable store. Some legacy systems may still use the deprecated
   * efivars interface (accessed through /sys/firmware/efi/vars). Where both
   * are present, libefivar will use the former in preference, so attempting
   * to load efivars will not interfere with later operations.
   */
  grub_util_exec_redirect_all ((const char * []){ "modprobe", "efivars", NULL },
			       NULL, NULL, "/dev/null");
#endif

  if (!efi_variables_supported ())
    {
      grub_util_warn ("%s",
		      _("EFI variables are not supported on this system."));
      /* Let the user continue.  Perhaps they can still arrange to boot GRUB
         manually.  */
      return 0;
    }

  rc = read_boot_variables (&entries);
  if (rc < 0)
    {
      grub_util_warn ("%s", _("Cannot read EFI Boot* variables"));
      goto err;
    }
  rc = read_efi_variable ("BootOrder", &order);
  if (rc < 0)
    {
      order = new_boot_variable ();
      order->name = xstrdup ("BootOrder");
      efi_error_clear ();
    }

  /* Delete old entries from the same distributor.  */
  FOR_LIST_ELEMENTS (entry, entries)
    {
      efi_load_option *load_option = (efi_load_option *) entry->data;
      const char *label;

      if (entry->num < 0)
	continue;
      label = (const char *) efi_loadopt_desc (load_option, entry->data_size);
      if (strcasecmp (label, efi_distributor) != 0)
	continue;

      /* To avoid problems with some firmware implementations, reuse the first
         matching variable we find rather than deleting and recreating it.  */
      if (entry_num == -1)
	entry_num = entry->num;
      else
	{
	  grub_util_info ("deleting superfluous EFI variable %s (%s)",
			  entry->name, label);
	  rc = efi_del_variable (EFI_GLOBAL_GUID, entry->name);
	  if (rc < 0)
	    {
	      grub_util_warn (_("Cannot delete EFI variable %s"), entry->name);
	      goto err;
	    }
	}

      remove_from_boot_order (order, (uint16_t) entry->num);
    }

  if (entry_num == -1)
    entry_num = find_free_boot_num (entries);
  entry = make_boot_variable (entry_num, efidir_disk, efidir_part,
			      efifile_path, efi_distributor);
  if (!entry)
    goto err;

  grub_util_info ("setting EFI variable %s", entry->name);
  rc = set_efi_variable (entry->name, entry);
  if (rc < 0)
    goto err;

  add_to_boot_order (order, (uint16_t) entry_num);

  grub_util_info ("setting EFI variable BootOrder");
  rc = set_efi_variable ("BootOrder", order);
  if (rc < 0)
    goto err;

  return 0;

err:
  show_efi_errors ();
  return errno;
}

#endif /* HAVE_EFIVAR */
