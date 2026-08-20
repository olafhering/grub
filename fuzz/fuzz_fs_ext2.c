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
 *
 *  Fuzz target: ext2/ext3/ext4 filesystem parser
 *
 */

#include <config-util.h>
#include <config.h>

#include <grub/device.h>
#include <grub/disk.h>
#include <grub/err.h>
#include <grub/fs.h>
#include <grub/misc.h>
#include <grub/mm.h>

#include <stddef.h>
#include <stdint.h>

#include "grub_fuzzing_platform.h"

int LLVMFuzzerInitialize (int *argc, char ***argv);
int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

int LLVMFuzzerInitialize (int *argc, char ***argv)
{
  fuzz_grub_init (argc, argv);
  return 0;
}

static int
dir_hook (const char                     *filename __attribute__ ((unused)),
          const struct grub_dirhook_info *info     __attribute__ ((unused)),
          void                           *data     __attribute__ ((unused)))
{
  return 0;
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  fuzz_disk_set_image (data, size);

  grub_fs_t fs;
  FOR_FILESYSTEMS (fs)
    if (grub_strcmp (fs->name, "ext2") == 0)
      break;

  if (!fs)
    {
      fuzz_grub_reset ();
      return 0;
    }

  grub_disk_t disk = grub_disk_open ("fuzzdev");
  if (!disk)
    {
      fuzz_grub_reset ();
      return 0;
    }

  struct grub_device dev = { .disk = disk, .net = NULL };

  fs->fs_dir (&dev, "/", dir_hook, NULL);
  grub_errno = GRUB_ERR_NONE;

  /*
   * Traverse a path whose first component may be a symlink so that
   * grub_fshelp_find_file calls grub_ext2_read_symlink via grub_ext2_dir.
   * A seed image containing "/link" as a symlink to a directory reaches
   * this; without one the lookup simply fails early.
   */
  fs->fs_dir (&dev, "/link", dir_hook, NULL);
  grub_errno = GRUB_ERR_NONE;

  if (fs->fs_label)
    {
      char *label = NULL;
      fs->fs_label (&dev, &label);
      grub_free (label);
      grub_errno = GRUB_ERR_NONE;
    }

  if (fs->fs_uuid)
    {
      char *uuid = NULL;
      fs->fs_uuid (&dev, &uuid);
      grub_free (uuid);
      grub_errno = GRUB_ERR_NONE;
    }

  grub_disk_close (disk);
  fuzz_grub_reset ();
  return 0;
}
