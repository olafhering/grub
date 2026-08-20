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
 *  GRUB Fuzzing Platform - in-memory disk device, subsystem init, and stubs.
 *
 *  Provides a "fuzzdev" disk device backed by the libFuzzer input buffer.
 *  grub_malloc/grub_free wrap libc malloc/free in EMU mode, so ASan sees
 *  all GRUB heap traffic without any extra stubs.
 */

#include <config-util.h>
#include <config.h>

#include <grub/crypto.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/emu/misc.h>
#include <grub/env.h>
#include <grub/env_private.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/util/misc.h>
#include <grub/verify.h>

int __wrap_grub_err_printf (const char *fmt __attribute__ ((unused)), ...);

void __wrap_grub_real_dprintf (const char *file __attribute__ ((unused)),
                               const char *function __attribute__ ((unused)),
                               int line __attribute__ ((unused)),
                               const char *condition __attribute__ ((unused)),
                               const char *fmt __attribute__ ((unused)), ...);

static void
fuzz_xputs_silent (const char *str __attribute__ ((unused)))
{
}

/*
 * Link-wrap (--wrap=grub_err_printf) redirects all callers to
 * grub_err_printf to this no-op stub for fuzz builds so the output
 * is not flooded with console traffic.
 */
int
__wrap_grub_err_printf (const char *fmt __attribute__ ((unused)), ...)
{
  return 0;
}

/*
 * grub_real_dprintf calls grub_debug_enabled() → grub_env_get("debug") →
 * grub_env_find() → grub_env_hashval(), which under libFuzzer's coverage
 * instrumentation (__sanitizer_cov_trace_const_cmp1) becomes extremely slow.
 * Redirect all dprintf calls to a no-op for fuzz builds.
 */
void
__wrap_grub_real_dprintf (const char *file __attribute__ ((unused)),
                          const char *function __attribute__ ((unused)),
                          int line __attribute__ ((unused)),
                          const char *condition __attribute__ ((unused)),
                          const char *fmt __attribute__ ((unused)), ...)
{
}

#include "grub_fuzzing_platform.h"

/* Global image buffer (set once per LLVMFuzzerTestOneInput call) */

static const uint8_t *fuzz_image_data = NULL;
static grub_size_t fuzz_image_size = 0;

/*
 * Optional minimum logical disk size, in bytes.  When greater than the input
 * size the disk is presented with this many bytes of capacity and reads past
 * the (smaller) input are zero-filled by fuzz_disk_read_cb.  This decouples
 * the on-disk geometry a filesystem expects from the size of the fuzz input,
 * so a small input can drive a filesystem that requires a large device while
 * keeping libFuzzer's per-exec cost low.  Default 0 ties the logical size to
 * the input size.
 */
static grub_size_t fuzz_image_min_size = 0;

void
fuzz_disk_set_image (const uint8_t *data, size_t size)
{
  fuzz_image_data = data;
  fuzz_image_size = (grub_size_t)size;
}

void
fuzz_disk_set_min_size (size_t bytes)
{
  fuzz_image_min_size = (grub_size_t)bytes;
}

/*
 * Logical capacity presented to GRUB: the larger of the input size and the
 * minimum size, rounded up to a whole sector so that the trailing partial
 * sector of the input can be read.
 */
static grub_size_t
fuzz_disk_logical_size (void)
{
  grub_size_t size = fuzz_image_size > fuzz_image_min_size ? fuzz_image_size
							     : fuzz_image_min_size;

  return ALIGN_UP (size, GRUB_DISK_SECTOR_SIZE);
}

/* "fuzzdev" disk device callbacks */

static int
fuzz_disk_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data,
                   grub_disk_pull_t pull)
{
  if (pull != GRUB_DISK_PULL_NONE)
    return 0;
  return hook ("fuzzdev", hook_data);
}

static grub_err_t
fuzz_disk_open (const char *name, grub_disk_t disk)
{
  if (grub_strcmp (name, "fuzzdev") != 0)
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "not a fuzz disk");
  disk->id = 1;

  /* Expose image as 512-byte sectors. */
  disk->log_sector_size = GRUB_DISK_SECTOR_BITS; /* 9 → 512 B/sector */
  disk->total_sectors = fuzz_disk_logical_size () >> GRUB_DISK_SECTOR_BITS;
  disk->data = NULL;
  return GRUB_ERR_NONE;
}

static void
fuzz_disk_close (grub_disk_t disk __attribute__ ((unused)))
{
}

/*
 * Device read callback.
 *
 * sector  — native sector number (512-byte units for this device)
 * size    — number of native sectors to read
 * buf     — output buffer; must hold (size * 512) bytes
 *
 * Reads are satisfied directly from fuzz_image_data.  GRUB's range check
 * only lets through reads within fuzz_disk_logical_size(), so the region
 * past the end of the image that reaches here is the padding of its last
 * sector and anything up to the size set with fuzz_disk_set_min_size().
 * That region is zero-filled.  Reads beyond the logical size fail in
 * grub_disk_read() with GRUB_ERR_OUT_OF_RANGE, as on a real disk.
 */
static grub_err_t
fuzz_disk_read_cb (grub_disk_t disk __attribute__ ((unused)),
                   grub_disk_addr_t sector, grub_size_t size, char *buf)
{
  grub_size_t bytes = size << GRUB_DISK_SECTOR_BITS; /* size * 512 */
  grub_size_t data_len = fuzz_image_size;
  grub_size_t byte_offset = (grub_size_t)sector << GRUB_DISK_SECTOR_BITS;

  if (byte_offset >= data_len)
    {
      grub_memset (buf, 0, bytes);
      return GRUB_ERR_NONE;
    }

  grub_size_t avail = data_len - byte_offset;

  if (avail >= bytes)
    grub_memcpy (buf, fuzz_image_data + byte_offset, bytes);
  else
    {
      grub_memcpy (buf, fuzz_image_data + byte_offset, avail);
      grub_memset (buf + avail, 0, bytes - avail);
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
fuzz_disk_write_cb (grub_disk_t      disk   __attribute__ ((unused)),
                    grub_disk_addr_t sector __attribute__ ((unused)),
                    grub_size_t      size   __attribute__ ((unused)),
                    const char      *buf    __attribute__ ((unused)))
{
  /* Writes are silently discarded; the image buffer is read-only. */
  return GRUB_ERR_NONE;
}

static struct grub_disk_dev fuzz_disk_dev =
  {
    .name         = "fuzzdev",
    .id           = GRUB_DISK_DEVICE_MEMDISK_ID,
    .disk_iterate = fuzz_disk_iterate,
    .disk_open    = fuzz_disk_open,
    .disk_close   = fuzz_disk_close,
    .disk_read    = fuzz_disk_read_cb,
    .disk_write   = fuzz_disk_write_cb,
    .next         = NULL,
  };

/* Stubs for symbols not present in the fuzz link libraries */

/*
 * grub_file_verifiers is defined in kern/verifiers.c, which is not compiled
 * into the EMU/fuzz build.  grub_verifier_register() (called from
 * GRUB_MOD_INIT(pgp)) appends to this list; start it as NULL.
 */
struct grub_file_verifier *grub_file_verifiers;

/*
 * Some modules calls grub_dl_load() to pull in other modules at runtime.
 * In the fuzz build those algorithms are linked statically; return NULL
 * (no module handle).  The caller resets grub_errno and continues.
 */
grub_dl_t
grub_dl_load (const char *name __attribute__ ((unused)))
{
  return NULL;
}

/*
 * Debug-logging helper used by rsa-common.c's PKCS padding functions.
 * Not present in libgcrypt-grub; provide a no-op stub.
 */
void _gcry_log_printmpi (const char *text, gcry_mpi_t mpi);
void
_gcry_log_printmpi (const char *text __attribute__ ((unused)),
                    gcry_mpi_t mpi __attribute__ ((unused)))
{
}

/* Public API */

/*
 * Stub: program-name and locale setup are unnecessary (and pull in gnulib's
 * progname.h which triggers -Wundef on ENABLE_RELOCATABLE under Clang).
 */
void
grub_util_host_init (int *argc __attribute__ ((unused)),
                     char ***argv __attribute__ ((unused)))
{
}

void
fuzz_grub_init (int *argc, char ***argv)
{
  grub_util_host_init (argc, argv);
  grub_xputs = fuzz_xputs_silent;
  /*
   * Initialize all linked-in GRUB modules (filesystems, partmaps, etc.).
   * grub_fstest_init.c (auto-generated by the build) defines grub_init_all.
   */
  grub_init_all ();
  grub_gcry_init_all ();
  /*
   * Register our in-memory disk after module init so module init functions
   * cannot accidentally open fuzzdev before fuzz_image_data is set.
   */
  grub_disk_dev_register (&fuzz_disk_dev);
}

void
fuzz_grub_reset (void)
{
  int i;

  grub_errno = GRUB_ERR_NONE;
  grub_disk_cache_invalidate_all ();

  /*
   * Clear user-set environment variables accumulated by grub_env_set()
   * during load_env iterations.  Without this the 13-bucket hash table in
   * grub_current_context grows without bound across fuzzer iterations,
   * making each grub_env_find() walk an ever-longer chain.
   *
   * Only variables without read/write hooks are removed.  Hook-registered
   * vars (e.g. "prefix", "root") are installed once by grub_init_all() and
   * must survive across iterations; grub_env_unset() on a hooked var
   * would set it to "" rather than remove it, which is harmless but
   * unnecessary, so we skip them.
   *
   * The iteration saves p->next before calling grub_env_unset() because
   * grub_env_remove() modifies the linked list in place.
   */
  for (i = 0; i < HASHSZ; i++)
    {
      struct grub_env_var *p = grub_current_context->vars[i];
      while (p)
        {
          struct grub_env_var *next = p->next;
          if (!p->read_hook && !p->write_hook)
            grub_env_unset (p->name);
          p = next;
        }
    }
}
