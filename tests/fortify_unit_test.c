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
 * Host unit test for the fortified copy and formatting functions in
 * include/grub/misc.h; runs under "make check" without needing qemu. The
 * body is shared with the functional test in
 * grub-core/tests/fortify_test.c, which is the one that covers the heap
 * cases: HOST_CFLAGS carry no -O flag, and the object-size builtins
 * cannot fold an allocator call at -O0. What this build does add is the
 * wrappers exercised with the optimiser unable to fold the checks away.
 */

#include "../grub-core/tests/fortify_test.h"

GRUB_MOD_LICENSE ("GPLv3+");

GRUB_UNIT_TEST ("fortify_test", fortify_test);
