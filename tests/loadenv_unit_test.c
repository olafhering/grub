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

/*
 * Native unit test for the environment block engine in grub-core/lib/envblk.c,
 * which is compiled into the loadenv module and implements the on-disk format
 * that the load_env / save_env / list_env commands read and write.  It builds
 * an environment block in memory and exercises open/validate, set (append,
 * in-place overwrite both longer and shorter, out-of-space), value escaping of
 * '\\' and newline, iterate, and delete.  Being a native unit test it links
 * the code directly, so it also gives ASan/UBSan coverage of this parser.
 *
 * The command/file/disk layer in loadenv.c itself (notably save_env's
 * block-list writes to a real device) is outside the scope of a native test
 * and is better exercised by a grub-shell functional test.
 */

#include <grub/lib/envblk.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/test.h>
#include <grub/types.h>

#define SIG     GRUB_ENVBLK_SIGNATURE
#define SIGLEN  (sizeof (SIG) - 1)

/*
 * Build a fresh, empty environment block of the given size: the signature
 * followed by '#' padding.  grub_envblk_open() takes ownership of the buffer
 * (grub_envblk_close() frees it).
 */
static grub_envblk_t
make_block (grub_size_t size)
{
  char *buf = grub_malloc (size);

  if (!buf)
    return 0;
  grub_memcpy (buf, SIG, SIGLEN);
  grub_memset (buf + SIGLEN, '#', size - SIGLEN);
  return grub_envblk_open (buf, size);
}

/* Iterate helper: capture the value of a named variable (strdup'd). */
struct find_ctx
{
  const char *want;
  char *got;
};

static int
find_hook (const char *name, const char *value, void *data)
{
  struct find_ctx *c = data;

  if (grub_strcmp (name, c->want) == 0)
    {
      c->got = grub_strdup (value);
      return 1; /* stop */
    }
  return 0;
}

/* Return a strdup'd copy of NAME's value, or NULL if absent.  Caller frees. */
static char *
value_of (grub_envblk_t e, const char *name)
{
  struct find_ctx c = { name, 0 };

  grub_envblk_iterate (e, &c, find_hook);
  return c.got;
}

static int
count_hook (const char *name __attribute__ ((unused)),
            const char *value __attribute__ ((unused)), void *data)
{
  (*(int *) data)++;
  return 0;
}

static int
count_entries (grub_envblk_t e)
{
  int n = 0;

  grub_envblk_iterate (e, &n, count_hook);
  return n;
}

/* Assert NAME has VALUE in E. */
static void
expect (grub_envblk_t e, const char *name, const char *value,
        const char *label)
{
  char *v = value_of (e, name);

  grub_test_assert (v != NULL, "%s: variable `%s' not found", label, name);
  if (v)
    {
      grub_test_assert (grub_strcmp (v, value) == 0,
                        "%s: `%s' = `%s', want `%s'", label, name, v, value);
      grub_free (v);
    }
}

static void
loadenv_test (void)
{
  grub_envblk_t e;
  char *v;

  /* A buffer that does not start with the signature must be rejected. */
  {
    char *bad = grub_malloc (64);
    grub_memset (bad, 'x', 64);
    grub_errno = GRUB_ERR_NONE;
    grub_test_assert (grub_envblk_open (bad, 64) == 0,
                      "open accepted a buffer without the signature");
    grub_free (bad);
    grub_errno = GRUB_ERR_NONE;
  }

  /* A valid empty block opens and has no entries. */
  e = make_block (1024);
  grub_test_assert (e != NULL, "open rejected a valid empty block");
  grub_test_assert (count_entries (e) == 0, "empty block has entries");
  grub_test_assert (grub_envblk_size (e) == 1024, "size mismatch");
  grub_test_assert (grub_envblk_buffer (e) != NULL, "buffer is NULL");

  /* Append two variables. */
  grub_test_assert (grub_envblk_set (e, "color", "blue") == 1, "set color");
  grub_test_assert (grub_envblk_set (e, "shape", "round") == 1, "set shape");
  grub_test_assert (count_entries (e) == 2, "expected two entries");
  expect (e, "color", "blue", "append");
  expect (e, "shape", "round", "append");

  /* A variable that was never set is absent. */
  v = value_of (e, "missing");
  grub_test_assert (v == NULL, "found a variable that was never set");
  grub_free (v);

  /*
   * Overwrite in place with a longer value, then a shorter one; the
   * neighbouring variable must stay intact across the memmoves.
   */
  grub_test_assert (grub_envblk_set (e, "color", "ultraviolet") == 1,
                    "overwrite color (longer)");
  expect (e, "color", "ultraviolet", "overwrite-longer");
  expect (e, "shape", "round", "overwrite-longer");

  grub_test_assert (grub_envblk_set (e, "color", "red") == 1,
                    "overwrite color (shorter)");
  expect (e, "color", "red", "overwrite-shorter");
  expect (e, "shape", "round", "overwrite-shorter");
  grub_test_assert (count_entries (e) == 2,
                    "entry count changed on overwrite");

  /*
   * Values containing '\\' and '\n' are escaped on write and restored on
   * iterate.
   */
  grub_test_assert (grub_envblk_set (e, "path", "a\\b") == 1, "set backslash");
  expect (e, "path", "a\\b", "escape-backslash");
  grub_test_assert (grub_envblk_set (e, "multi", "x\ny") == 1, "set newline");
  expect (e, "multi", "x\ny", "escape-newline");

  /* Delete: removed variable is gone, the rest remain. */
  grub_envblk_delete (e, "color");
  v = value_of (e, "color");
  grub_test_assert (v == NULL, "deleted variable still present");
  grub_free (v);
  expect (e, "shape", "round", "after-delete");
  expect (e, "path", "a\\b", "after-delete");

  /* Deleting a non-existent variable is a no-op. */
  grub_envblk_delete (e, "nonexistent");
  expect (e, "shape", "round", "delete-noop");

  grub_envblk_close (e);

  /*
   * Out-of-space: a tiny block with little free room rejects a value that does
   * not fit (returns 0) but accepts one that does.
   */
  e = make_block (SIGLEN + 16);
  grub_test_assert (e != NULL, "open rejected a small block");
  grub_test_assert (grub_envblk_set (e, "k", "0123456789012345") == 0,
                    "set succeeded despite insufficient space");
  grub_test_assert (count_entries (e) == 0, "failed set left an entry behind");
  grub_test_assert (grub_envblk_set (e, "k", "ok") == 1,
                    "set of a fitting value failed");
  expect (e, "k", "ok", "small-block");
  grub_envblk_close (e);
}

GRUB_UNIT_TEST ("loadenv_unit_test", loadenv_test);
