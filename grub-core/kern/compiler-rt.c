/* compiler-rt.c - compiler helpers. */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010-2014  Free Software Foundation, Inc.
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

#include <grub/misc.h>
#include <grub/compiler-rt.h>

#if defined (__powerpc__)

union component64
{
  grub_uint64_t full;
  struct
  {
#ifdef GRUB_CPU_WORDS_BIGENDIAN
    grub_uint32_t high;
    grub_uint32_t low;
#else
    grub_uint32_t low;
    grub_uint32_t high;
#endif
  };
};

/* Based on libgcc2.c from gcc suite.  */
grub_uint64_t
__lshrdi3 (grub_uint64_t u, int b)
{
  if (b == 0)
    return u;

  const union component64 uu = {.full = u};
  const int bm = 32 - b;
  union component64 w;

  if (bm <= 0)
    {
      w.high = 0;
      w.low = (grub_uint32_t) uu.high >> -bm;
    }
  else
    {
      const grub_uint32_t carries = (grub_uint32_t) uu.high << bm;

      w.high = (grub_uint32_t) uu.high >> b;
      w.low = ((grub_uint32_t) uu.low >> b) | carries;
    }

  return w.full;
}

/* Based on libgcc2.c from gcc suite.  */
grub_uint64_t
__ashrdi3 (grub_uint64_t u, int b)
{
  if (b == 0)
    return u;

  const union component64 uu = {.full = u};
  const int bm = 32 - b;
  union component64 w;

  if (bm <= 0)
    {
      /* w.high = 1..1 or 0..0 */
      w.high = uu.high >> (32 - 1);
      w.low = uu.high >> -bm;
    }
  else
    {
      const grub_uint32_t carries = (grub_uint32_t) uu.high << bm;

      w.high = uu.high >> b;
      w.low = ((grub_uint32_t) uu.low >> b) | carries;
    }

  return w.full;
}

/* Based on libgcc2.c from gcc suite.  */
grub_uint64_t
__ashldi3 (grub_uint64_t u, int b)
{
  if (b == 0)
    return u;

  const union component64 uu = {.full = u};
  const int bm = 32 - b;
  union component64 w;

  if (bm <= 0)
    {
      w.low = 0;
      w.high = (grub_uint32_t) uu.low << -bm;
    }
  else
    {
      const grub_uint32_t carries = (grub_uint32_t) uu.low >> bm;

      w.low = (grub_uint32_t) uu.low << b;
      w.high = ((grub_uint32_t) uu.high << b) | carries;
    }

  return w.full;
}

/* Based on libgcc2.c from gcc suite.  */
int
__ucmpdi2 (grub_uint64_t a, grub_uint64_t b)
{
  union component64 ac, bc;
  ac.full = a;
  bc.full = b;

  if (ac.high < bc.high)
    return 0;
  else if (ac.high > bc.high)
    return 2;

  if (ac.low < bc.low)
    return 0;
  else if (ac.low > bc.low)
    return 2;
  return 1;
}

/* Based on libgcc2.c from gcc suite.  */
grub_uint32_t
__bswapsi2 (grub_uint32_t u)
{
  return ((((u) & 0xff000000) >> 24)
	  | (((u) & 0x00ff0000) >>  8)
	  | (((u) & 0x0000ff00) <<  8)
	  | (((u) & 0x000000ff) << 24));
}

/* Based on libgcc2.c from gcc suite.  */
grub_uint64_t
__bswapdi2 (grub_uint64_t u)
{
  return ((((u) & 0xff00000000000000ull) >> 56)
	  | (((u) & 0x00ff000000000000ull) >> 40)
	  | (((u) & 0x0000ff0000000000ull) >> 24)
	  | (((u) & 0x000000ff00000000ull) >>  8)
	  | (((u) & 0x00000000ff000000ull) <<  8)
	  | (((u) & 0x0000000000ff0000ull) << 24)
	  | (((u) & 0x000000000000ff00ull) << 40)
	  | (((u) & 0x00000000000000ffull) << 56));
}

#endif
