/* loopback.c - command to add loopback devices.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2006,2007  Free Software Foundation, Inc.
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
#include <grub/file.h>
#include <grub/disk.h>
#include <grub/mm.h>
#include <grub/extcmd.h>
#include <grub/i18n.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

struct grub_loopback
{
  char *devname;
  grub_file_t file;
  struct grub_loopback *next;
  unsigned long id;
  grub_uint64_t refcnt;
};

static struct grub_loopback *loopback_list;
static unsigned long last_id = 0;

static const struct grub_arg_option options[] =
  {
    /* TRANSLATORS: The disk is simply removed from the list of available ones,
       not wiped, avoid to scare user.  */
    {"delete", 'd', 0, N_("Delete the specified loopback drive."), 0, 0},
    {"decompress", 'D', 0, N_("Transparently decompress backing file."), 0, 0},
    {0, 0, 0, 0, 0, 0}
  };

/* Delete the loopback device NAME.  */
static grub_err_t
delete_loopback (const char *name)
{
  struct grub_loopback *dev;
  struct grub_loopback **prev;

  /* Search for the device.  */
  for (dev = loopback_list, prev = &loopback_list;
       dev;
       prev = &dev->next, dev = dev->next)
    if (grub_strcmp (dev->devname, name) == 0)
      break;

  if (! dev)
    return grub_error (GRUB_ERR_BAD_DEVICE, "device not found");

  if (dev->refcnt > 0)
    return grub_error (GRUB_ERR_STILL_REFERENCED, "device still referenced");
  /* Remove the device from the list.  */
  *prev = dev->next;

  grub_free (dev->devname);
  grub_file_close (dev->file);
  grub_free (dev);

  return 0;
}

/* The command to add and remove loopback devices.  */
static grub_err_t
grub_cmd_loopback (grub_extcmd_context_t ctxt, int argc, char **args)
{
  struct grub_arg_list *state = ctxt->state;
  grub_file_t file;
  enum grub_file_type type = GRUB_FILE_TYPE_LOOPBACK;
  struct grub_loopback *newdev;
  grub_err_t ret;

  if (argc < 1)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "device name required");

  /* Check if `-d' was used.  */
  if (state[0].set)
    return delete_loopback (args[0]);

  if (!state[1].set)
    type |= GRUB_FILE_TYPE_NO_DECOMPRESS;

  if (argc < 2)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));

  /* Check that a device with requested name does not already exist. */
  for (newdev = loopback_list; newdev; newdev = newdev->next)
    if (grub_strcmp (newdev->devname, args[0]) == 0)
      return grub_error (GRUB_ERR_BAD_ARGUMENT, "device name already exists");

  file = grub_file_open (args[1], type);
  if (! file)
    return grub_errno;

  /* Unable to replace it, make a new entry.  */
  newdev = grub_malloc (sizeof (struct grub_loopback));
  if (! newdev)
    goto fail;

  newdev->devname = grub_strdup (args[0]);
  if (! newdev->devname)
    {
      grub_free (newdev);
      goto fail;
    }

  newdev->file = file;
  newdev->id = last_id++;
  newdev->refcnt = 0;

  /* Add the new entry to the list.  */
  newdev->next = loopback_list;
  loopback_list = newdev;

  return 0;

fail:
  ret = grub_errno;
  grub_file_close (file);
  return ret;
}


static int
grub_loopback_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data,
		       grub_disk_pull_t pull)
{
  struct grub_loopback *d;
  if (pull != GRUB_DISK_PULL_NONE)
    return 0;
  for (d = loopback_list; d; d = d->next)
    {
      if (hook (d->devname, hook_data))
	return 1;
    }
  return 0;
}

static grub_err_t
grub_loopback_open (const char *name, grub_disk_t disk)
{
  struct grub_loopback *dev;

  for (dev = loopback_list; dev; dev = dev->next)
    if (grub_strcmp (dev->devname, name) == 0)
      break;

  if (! dev)
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "can't open device");

  if (grub_add (dev->refcnt, 1, &dev->refcnt))
    grub_fatal ("Reference count overflow");

  /* Use the filesize for the disk size, round up to a complete sector.  */
  if (dev->file->size != GRUB_FILE_SIZE_UNKNOWN)
    disk->total_sectors = ((dev->file->size + GRUB_DISK_SECTOR_SIZE - 1)
			   / GRUB_DISK_SECTOR_SIZE);
  else
    disk->total_sectors = GRUB_DISK_SIZE_UNKNOWN;
  /* Avoid reading more than 512M.  */
  disk->max_agglomerate = 1 << (29 - GRUB_DISK_SECTOR_BITS
				- GRUB_DISK_CACHE_BITS);

  disk->id = dev->id;

  disk->data = dev;

  return 0;
}

static void
grub_loopback_close (grub_disk_t disk)
{
  struct grub_loopback *dev = disk->data;

  if (grub_sub (dev->refcnt, 1, &dev->refcnt))
    grub_fatal ("Reference count underflow");
}

static grub_err_t
grub_loopback_read (grub_disk_t disk, grub_disk_addr_t sector,
		    grub_size_t size, char *buf)
{
  grub_file_t file = ((struct grub_loopback *) disk->data)->file;
  grub_off_t pos;

  grub_file_seek (file, sector << GRUB_DISK_SECTOR_BITS);

  grub_file_read (file, buf, size << GRUB_DISK_SECTOR_BITS);
  if (grub_errno)
    return grub_errno;

  /* In case there is more data read than there is available, in case
     of files that are not a multiple of GRUB_DISK_SECTOR_SIZE, fill
     the rest with zeros.  */
  pos = (sector + size) << GRUB_DISK_SECTOR_BITS;
  if (pos > file->size)
    {
      grub_size_t amount = pos - file->size;
      grub_memset (buf + (size << GRUB_DISK_SECTOR_BITS) - amount, 0, amount);
    }

  return 0;
}

static grub_err_t
grub_loopback_write (grub_disk_t disk __attribute ((unused)),
		     grub_disk_addr_t sector __attribute ((unused)),
		     grub_size_t size __attribute ((unused)),
		     const char *buf __attribute ((unused)))
{
  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		     "loopback write is not supported");
}

static struct grub_disk_dev grub_loopback_dev =
  {
    .name = "loopback",
    .id = GRUB_DISK_DEVICE_LOOPBACK_ID,
    .disk_iterate = grub_loopback_iterate,
    .disk_open = grub_loopback_open,
    .disk_close = grub_loopback_close,
    .disk_read = grub_loopback_read,
    .disk_write = grub_loopback_write,
    .next = 0
  };

static grub_extcmd_t cmd;

GRUB_MOD_INIT(loopback)
{
  cmd = grub_register_extcmd ("loopback", grub_cmd_loopback, 0,
			      N_("[-d] [-D] DEVICENAME FILE."),
			      /* TRANSLATORS: The file itself is not destroyed
				 or transformed into drive.  */
			      N_("Make a virtual drive from a file."), options);
  grub_disk_dev_register (&grub_loopback_dev);
}

GRUB_MOD_FINI(loopback)
{
  grub_unregister_extcmd (cmd);
  grub_disk_dev_unregister (&grub_loopback_dev);
}
