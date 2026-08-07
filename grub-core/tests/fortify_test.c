/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2026 Free Software Foundation, Inc.
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
 * Functional test for the fortified copy and formatting functions in
 * include/grub/misc.h. Built with TARGET_CFLAGS, so -Os, which is the
 * only one of the two fortify test builds where the object-size builtins
 * can see through an allocator call. The body is shared with the host
 * unit test in tests/fortify_unit_test.c.
 *
 * This module also carries the fortify_overflow command, which is what
 * tests/fortify_abort_test.in drives; see below.
 */

#include <grub/command.h>
#include <grub/dl.h>

#include "fortify_test.h"

GRUB_MOD_LICENSE ("GPLv3+");

#ifdef GRUB_OBJECT_SIZE
static grub_command_t cmd_fortify_overflow;

/*
 * Deliberately overflows a local buffer, so that
 * tests/fortify_abort_test.in test it.
 *
 * Registered only when the checks are actually compiled in. Without them
 * this would just corrupt the stack, which is not worth doing on purpose
 * even in a module that never leaves a test image.
 */
static grub_err_t
grub_cmd_fortify_overflow (grub_command_t cmd __attribute__ ((unused)),
			   int argc __attribute__ ((unused)),
			   char **args __attribute__ ((unused)))
{
  char buf[8];
  grub_size_t n;

  /*
   * This variable uses volatile so that the complier does not flag it
   * during compilation. A constant would be caught by
   * GRUB_FORTIFY_STATIC_CHECK() and this file would fail to build, which
   * is correct behavior but not what is being tested here.
   */
  n = fortify_test_dynamic_size / 4;	/* 16, twice the size of buf */

  grub_memcpy (buf, "0123456789abcdef", n);

  /* Not reached: the copy above has to have called grub_fatal(). */
  grub_printf ("fortify_overflow: check did not fire, buf=%s\n", buf);

  return GRUB_ERR_NONE;
}
#endif /* GRUB_OBJECT_SIZE */

GRUB_MOD_INIT (fortify_test)
{
  grub_test_register ("fortify_test", fortify_test);
#ifdef GRUB_OBJECT_SIZE
  cmd_fortify_overflow =
    grub_register_command ("fortify_overflow", grub_cmd_fortify_overflow, 0,
			   "Overflow a buffer to exercise the fortify check.");
#endif
}

GRUB_MOD_FINI (fortify_test)
{
#ifdef GRUB_OBJECT_SIZE
  grub_unregister_command (cmd_fortify_overflow);
#endif
  grub_test_unregister ("fortify_test");
}
