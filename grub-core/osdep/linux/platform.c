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
#include <grub/emu/config.h>
#include <grub/emu/exec.h>
#include <grub/emu/misc.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/utsname.h>

static int
is_not_empty_directory (const char *dir)
{
  DIR *d;
  struct dirent *de;

  d = opendir (dir);
  if (!d)
    return 0;
  while ((de = readdir (d)))
    {
      if (strcmp (de->d_name, ".") == 0
	  || strcmp (de->d_name, "..") == 0)
	continue;
      closedir (d);
      return 1;
    }

  closedir (d);
  return 0;
}

static int
is_64_kernel (void)
{
  struct utsname un;

  if (uname (&un) < 0)
    return 0;

  return strcmp (un.machine, "x86_64") == 0;
}

static int
read_platform_size (void)
{
  FILE *fp;
  char *buf = NULL;
  size_t len = 0;
  int ret = 0;

  /* Newer kernels can tell us directly about the size of the
   * underlying firmware - let's see if that interface is there. */
  fp = grub_util_fopen ("/sys/firmware/efi/fw_platform_size", "r");
  if (fp != NULL)
  {
    if (getline (&buf, &len, fp) >= 3) /* 2 digits plus newline */
      {
	if (strncmp (buf, "32", 2) == 0)
	  ret = 32;
	else if (strncmp (buf, "64", 2) == 0)
	  ret = 64;
      }
    free (buf);
    fclose (fp);
  }

  if (ret == 0)
    {
      /* Unrecognised - fall back to matching the kernel size
       * instead */
      if (is_64_kernel ())
	ret = 64;
      else
	ret = 32;
    }

  return ret;
}

const char *
grub_install_get_default_x86_platform (void)
{ 
  /*
     On Linux, we need the efivars kernel modules.
     If no EFI is available this module just does nothing
     besides a small hello and if we detect efi we'll load it
     anyway later. So it should be safe to
     try to load it here.
   */
  grub_util_exec_redirect_all ((const char * []){ "modprobe", "efivars", NULL },
			       NULL, NULL, "/dev/null");

  grub_util_info ("Looking for /sys/firmware/efi ..");
  if (is_not_empty_directory ("/sys/firmware/efi"))
    {
      const char *pkglibdir = grub_util_get_pkglibdir ();
      const char *platform;
      char *pd;
      int found;

      grub_util_info ("...found");
      if (read_platform_size() == 64)
	platform = "x86_64-efi";
      else
	platform = "i386-efi";

      pd = grub_util_path_concat (2, pkglibdir, platform);
      found = grub_util_is_directory (pd);
      free (pd);
      if (found)
	return platform;
      else
	grub_util_info ("... but %s platform not available", platform);
    }

  grub_util_info ("... not found. Looking for /proc/device-tree ..");
  if (is_not_empty_directory ("/proc/device-tree"))
    {
      grub_util_info ("...found");
      return "i386-ieee1275";
    }

  grub_util_info ("... not found");
  return "i386-pc";
}

const char *
grub_install_get_default_powerpc_machtype (void)
{
  FILE *fp;
  char *buf = NULL;
  size_t len = 0;
  const char *machtype = "generic";

  fp = grub_util_fopen ("/proc/cpuinfo", "r");
  if (! fp)
    return machtype;

  while (getline (&buf, &len, fp) > 0)
    {
      if (strncmp (buf, "pmac-generation",
		   sizeof ("pmac-generation") - 1) == 0)
	{
	  if (strstr (buf, "NewWorld"))
	    {
	      machtype = "pmac_newworld";
	      break;
	    }
	  if (strstr (buf, "OldWorld"))
	    {
	      machtype = "pmac_oldworld";
	      break;
	    }
	}

      if (strncmp (buf, "motherboard", sizeof ("motherboard") - 1) == 0 &&
	  strstr (buf, "AAPL"))
	{
	  machtype = "pmac_oldworld";
	  break;
	}

      if (strncmp (buf, "machine", sizeof ("machine") - 1) == 0 &&
	  strstr (buf, "CHRP IBM"))
	{
	  if (strstr (buf, "qemu"))
	    {
	      machtype = "chrp_ibm_qemu";
	      break;
	    }
	  else
	    {
	      machtype = "chrp_ibm";
	      break;
	    }
	}

      if (strncmp (buf, "platform", sizeof ("platform") - 1) == 0)
	{
	  if (strstr (buf, "Maple"))
	    {
	      machtype = "maple";
	      break;
	    }
	  if (strstr (buf, "Cell"))
	    {
	      machtype = "cell";
	      break;
	    }
	}
    }

  free (buf);
  fclose (fp);
  return machtype;
}
