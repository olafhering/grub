/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2006,2007,2008,2009,2010,2011,2012,2013  Free Software Foundation, Inc.
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
#include <config-util.h>

#include <grub/emu/hostdisk.h>
#include <grub/emu/exec.h>
#include <grub/emu/config.h>
#include <grub/util/install.h>
#include <grub/util/misc.h>
#include <grub/list.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>

const char *
grub_util_get_config_filename (void)
{
  static char *value = NULL;
  if (!value)
    value = grub_util_path_concat (3, GRUB_SYSCONFDIR,
				   "default", "grub");
  return value;
}

const char *
grub_util_get_pkgdatadir (void)
{
  const char *ret = getenv ("pkgdatadir");
  if (ret)
    return ret;
  return GRUB_DATADIR "/" PACKAGE;
}

const char *
grub_util_get_pkglibdir (void)
{
  return GRUB_LIBDIR "/" PACKAGE;
}

const char *
grub_util_get_localedir (void)
{
  return LOCALEDIR;
}

struct cfglist
{
  struct cfglist *next;
  struct cfglist *prev;
  char *path;
};

void
grub_util_load_config (struct grub_util_config *cfg)
{
  pid_t pid;
  const char *argv[4];
  char *script = NULL, *ptr;
  const char *cfgfile, *iptr;
  char *cfgdir;
  grub_util_fd_dir_t d;
  struct cfglist *cfgpaths = NULL, *cfgpath, *next_cfgpath;
  int num_cfgpaths = 0;
  size_t len_cfgpaths = 0;
  char **sorted_cfgpaths = NULL;
  int i;
  FILE *f = NULL;
  int fd;
  const char *v;

  memset (cfg, 0, sizeof (*cfg));

  v = getenv ("GRUB_ENABLE_CRYPTODISK");
  if (v && v[0] == 'y' && v[1] == '\0')
    cfg->is_cryptodisk_enabled = 1;

  v = getenv ("GRUB_DISTRIBUTOR");
  if (v)
    cfg->grub_distributor = xstrdup (v);

  cfgfile = grub_util_get_config_filename ();
  if (grub_util_is_regular (cfgfile))
    {
      ++num_cfgpaths;
      len_cfgpaths += strlen (cfgfile) * 4 + sizeof (". ''; ") - 1;
    }

  cfgdir = xasprintf ("%s.d", cfgfile);
  d = grub_util_fd_opendir (cfgdir);
  if (d)
    {
      grub_util_fd_dirent_t de;

      while ((de = grub_util_fd_readdir (d)))
	{
	  const char *ext = strrchr (de->d_name, '.');

	  if (!ext || strcmp (ext, ".cfg") != 0)
	    continue;

	  cfgpath = xmalloc (sizeof (*cfgpath));
	  cfgpath->path = grub_util_path_concat (2, cfgdir, de->d_name);
	  grub_list_push (GRUB_AS_LIST_P (&cfgpaths), GRUB_AS_LIST (cfgpath));
	  ++num_cfgpaths;
	  len_cfgpaths += strlen (cfgpath->path) * 4 + sizeof (". ''; ") - 1;
	}
      grub_util_fd_closedir (d);
    }

  if (num_cfgpaths == 0)
    goto out;

  sorted_cfgpaths = xmalloc (num_cfgpaths * sizeof (*sorted_cfgpaths));
  i = 0;
  if (grub_util_is_regular (cfgfile))
    sorted_cfgpaths[i++] = xstrdup (cfgfile);
  FOR_LIST_ELEMENTS_SAFE (cfgpath, next_cfgpath, cfgpaths)
    {
      sorted_cfgpaths[i++] = cfgpath->path;
      free (cfgpath);
    }
  assert (i == num_cfgpaths);
  qsort (sorted_cfgpaths + 1, num_cfgpaths - 1, sizeof (*sorted_cfgpaths),
	 (int (*) (const void *, const void *)) strcmp);

  argv[0] = "sh";
  argv[1] = "-c";

  script = xmalloc (len_cfgpaths + 300);

  ptr = script;
  for (i = 0; i < num_cfgpaths; i++)
    {
      memcpy (ptr, ". '", 3);
      ptr += 3;
      for (iptr = sorted_cfgpaths[i]; *iptr; iptr++)
	{
	  if (*iptr == '\\')
	    {
	      memcpy (ptr, "'\\''", 4);
	      ptr += 4;
	      continue;
	    }
	  *ptr++ = *iptr;
	}
      memcpy (ptr, "'; ", 3);
      ptr += 3;
    }

  strcpy (ptr, "printf \"GRUB_ENABLE_CRYPTODISK=%s\\nGRUB_DISTRIBUTOR=%s\\n\" "
	  "\"$GRUB_ENABLE_CRYPTODISK\" \"$GRUB_DISTRIBUTOR\"");

  argv[2] = script;
  argv[3] = '\0';

  pid = grub_util_exec_pipe (argv, &fd);
  if (pid)
    f = fdopen (fd, "r");
  if (f)
    {
      grub_util_parse_config (f, cfg, 1);
      fclose (f);
    }
  if (pid)
    {
      close (fd);
      waitpid (pid, NULL, 0);
    }
  if (f)
    goto out;

  for (i = 0; i < num_cfgpaths; i++)
    {
      f = grub_util_fopen (sorted_cfgpaths[i], "r");
      if (f)
	{
	  grub_util_parse_config (f, cfg, 0);
	  fclose (f);
	}
      else
	grub_util_warn (_("cannot open configuration file `%s': %s"),
			cfgfile, strerror (errno));
    }

out:
  free (script);
  for (i = 0; i < num_cfgpaths; i++)
    free (sorted_cfgpaths[i]);
  free (sorted_cfgpaths);
  free (cfgdir);
}
