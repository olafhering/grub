/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010,2011,2012,2013  Free Software Foundation, Inc.
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

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <grub/util/install.h>
#include <grub/emu/misc.h>
#include <string.h>
#include <grub/time.h>
#include <signal.h>

int
grub_install_sync_fs_journal (const char *path)
{
  int fd;
  int ret;
  int need_retry = 0;
  grub_uint64_t start_time;

  sigset_t set, old_set;

  fd = open (path, O_RDONLY);
  if (fd == -1)
    return 1;

  /* Keep all blockable signals pending until the filesystem is thawed.  */
  sigfillset (&set);
  sigprocmask (SIG_BLOCK, &set, &old_set);

  start_time = grub_get_time_ms ();
  do {
    ret = ioctl (fd, FIFREEZE, 0);
  } while (ret == -1 && errno == EINTR && grub_get_time_ms () - start_time < 3000);

  if (ret < 0)
    {
      switch (errno)
	{
	case EBUSY:
	  need_retry = 1;
	  break;
	case EOPNOTSUPP:
	case ENOSYS:
	case EPERM:
	  break;
	default:
	  grub_util_warn ("Couldn't fsfreeze for %s: %s",
			  path,
			  strerror (errno));
	  break;
	}

      goto finish;
    }

  do {
    ret = ioctl (fd, FITHAW, 0);
  } while (ret == -1 && errno == EINTR);

  if (ret < 0)
    grub_util_warn ("Couldn't unfreeze for %s: %s", path, strerror (errno));

 finish:
  sigprocmask(SIG_SETMASK, &old_set, NULL);
  close (fd);
  return (need_retry ? 0 : 1);
}
