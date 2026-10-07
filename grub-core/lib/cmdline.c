/* cmdline.c - linux command line handling */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010  Free Software Foundation, Inc.
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

#include <grub/lib/cmdline.h>
#include <grub/misc.h>

static unsigned int
check_arg (char *c, int *has_space)
{
  unsigned int size = 0;

  while (*c)
    {
      if (*c == ' ')
	{
	  if (*has_space == 0)
	    {
	      *has_space = 1;
	      size += 2;
	    }
	}
      size++;
      c++;
    }

  /* For separator space or NULL.  */
  return size + 1;
}

unsigned int
grub_loader_cmdline_size (int argc, char *argv[])
{
  int i;
  int has_space;
  unsigned int size = 0;

  for (i = 0; i < argc; i++)
    {
      has_space = 0;
      size += check_arg (argv[i], &has_space);

    }

  return size ? size : 1;
}

grub_err_t
grub_create_loader_cmdline (int argc, char *argv[], char *buf,
			    grub_size_t size,
			    enum grub_verify_string_type type)
{
  int i, space;
  unsigned int arg_size;
  char *c, *orig_buf = buf;

  for (i = 0; i < argc; i++)
    {
      c = argv[i];
      space = 0;
      arg_size = check_arg (argv[i], &space);

      if (size < arg_size)
	break;

      size -= arg_size;

      if (space)
	*buf++ = '"';

      while (*c)
	{
	  *buf++ = *c++;
	}

      if (space)
	*buf++ = '"';

      if (i + 1 < argc)
   *buf++ = ' ';
    }

  *buf = '\0';

  return grub_verify_string (orig_buf, type);
}
