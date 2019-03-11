/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2013 Free Software Foundation, Inc.
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

#include <config.h>

#include <grub/util/install.h>
#include <grub/util/misc.h>
#include <grub/misc.h>
#include <grub/i18n.h>
#include <grub/emu/exec.h>
#include <sys/types.h>
#include <string.h>

static char *
get_ofpathname (const char *dev)
{
  size_t alloced = 4096;
  char *ret = xmalloc (alloced);
  size_t offset = 0;
  int fd;
  pid_t pid;

  pid = grub_util_exec_pipe ((const char * []){ "ofpathname", dev, NULL }, &fd);
  if (!pid)
    goto fail;

  FILE *fp = fdopen (fd, "r");
  if (!fp)
    goto fail;

  while (!feof (fp))
    {
      size_t r;
      if (alloced == offset)
       {
         alloced *= 2;
         ret = xrealloc (ret, alloced);
       }
      r = fread (ret + offset, 1, alloced - offset, fp);
      offset += r;
    }

  if (offset > 0 && ret[offset - 1] == '\n')
    offset--;
  if (offset > 0 && ret[offset - 1] == '\r')
    offset--;
  if (alloced == offset)
    {
      alloced++;
      ret = xrealloc (ret, alloced);
    }
  ret[offset] = '\0';

  fclose (fp);

  return ret;

 fail:
  grub_util_error (_("couldn't find IEEE1275 device path for %s.\nYou will have to set `boot-device' variable manually"),
		   dev);
}

int
grub_install_register_efi (grub_device_t efidir_grub_dev,
			   const char *efifile_path,
			   const char *efi_distributor)
{
#ifdef HAVE_EFIVAR
  return grub_install_efivar_register_efi (efidir_grub_dev, efifile_path,
					   efi_distributor);
#else
  grub_util_error ("%s",
		   _("GRUB was not built with efivar support; "
		     "cannot register EFI boot entry"));
#endif
}

void
grub_install_register_ieee1275 (int is_prep, const char *install_device,
				int partno, const char *relpath)
{
  char *boot_device;

  if (grub_util_exec_redirect_null ((const char * []){ "ofpathname", "--version", NULL }))
    {
      /* TRANSLATORS: This message is shown when required executable `%s'
	 isn't found.  */
      grub_util_error (_("%s: not found"), "ofpathname");
    }

  /* Get the Open Firmware device tree path translation.  */
  if (!is_prep)
    {
      char *ptr;
      char *ofpath;
      const char *iptr;

      ofpath = get_ofpathname (install_device);
      boot_device = xmalloc (strlen (ofpath) + 1
			     + sizeof ("XXXXXXXXXXXXXXXXXXXX")
			     + 1 + strlen (relpath) + 1);
      ptr = grub_stpcpy (boot_device, ofpath);
      *ptr++ = ':';
      grub_snprintf (ptr, sizeof ("XXXXXXXXXXXXXXXXXXXX"), "%d",
		     partno);
      ptr += strlen (ptr);
      *ptr++ = ',';
      for (iptr = relpath; *iptr; iptr++, ptr++)
	{
	  if (*iptr == '/')
	    *ptr = '\\';
	  else
	    *ptr = *iptr;
	}
      *ptr = '\0';
    }
  else
    boot_device = get_ofpathname (install_device);

  if (strcmp (grub_install_get_default_powerpc_machtype (), "chrp_ibm") == 0)
    {
      char *arg = xasprintf ("boot-device=%s", boot_device);
      if (grub_util_exec ((const char * []){ "nvram",
	  "--update-config", arg, NULL }))
	{
	  char *cmd = xasprintf ("setenv boot-device %s", boot_device);
	  grub_util_error (_("`nvram' failed. \nYou will have to set `boot-device' variable manually.  At the IEEE1275 prompt, type:\n  %s\n"),
			   cmd);
	  free (cmd);
	}
      free (arg);
    }
  else
    {
      if (grub_util_exec ((const char * []){ "nvsetenv", "boot-device",
	      boot_device, NULL }))
	{
	  char *cmd = xasprintf ("setenv boot-device %s", boot_device);
	  grub_util_error (_("`nvsetenv' failed. \nYou will have to set `boot-device' variable manually.  At the IEEE1275 prompt, type:\n  %s\n"),
			   cmd);
	  free (cmd);
	}
    }

  free (boot_device);
}

void
grub_install_sgi_setup (const char *install_device,
			const char *imgfile, const char *destname)
{
  grub_util_exec ((const char * []){ "dvhtool", "-d",
	install_device, "--unix-to-vh", 
	imgfile, destname, NULL });
  grub_util_warn ("%s", _("You will have to set `SystemPartition' and `OSLoader' manually."));
}
