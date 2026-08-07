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
 * Shared body for the two fortify tests, which differ only in how they
 * register themselves: grub-core/tests/fortify_test.c is the functional
 * test (built with TARGET_CFLAGS, so -Os) and tests/fortify_unit_test.c
 * is the host unit test (built with HOST_CFLAGS, which carry no -O flag
 * at all). Running both is deliberate -- see fortify_test_object_size().
 *
 * Nothing in here may actually overflow a buffer. A tripped check calls
 * grub_fatal(), which in the functional test kills the whole run and in
 * the host unit test hangs: grub_abort()'s "press any key" branch is
 * guarded by #ifndef GRUB_UTIL, so under GRUB_UTIL it always runs, and
 * grub_getkey() spins forever on an empty grub_term_inputs. The abort
 * path therefore is not covered here. Neither is the compile-time
 * escalation in GRUB_FORTIFY_STATIC_CHECK(), which by construction needs
 * a compilation that fails -- though the exact-fit cases below do assert
 * one half of it, since they are all compile-time constants and so must
 * *not* trip it.
 */

#ifndef GRUB_FORTIFY_TEST_HEADER
#define GRUB_FORTIFY_TEST_HEADER 1

#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/test.h>
#include <grub/types.h>

/*
 * Opaque to the optimiser, so an allocation sized from it is genuinely
 * dynamic rather than a constant the compiler folds behind our back.
 */
static volatile grub_size_t fortify_test_dynamic_size = 64;

/*
 * Tier 1: the canary.
 *
 * The fortify checks are silent when the destination's size comes back
 * unknowable -- they compile to nothing and the build stays clean. So a
 * toolchain change that stops the builtins folding would disable the
 * hardening with no other symptom. These assertions are what notices.
 *
 * Deliberately loose for the heap cases: assert only that the size is
 * knowable, not what it is. A future compiler declining to track some
 * pattern is not a GRUB bug and should not block a build; a compiler
 * that has stopped tracking allocations altogether is.
 */
static void
fortify_test_object_size (void)
{
#ifdef GRUB_OBJECT_SIZE
  struct
  {
    char head[8];
    char tail[24];
  } obj;
  char stack[16];

  /* A local array is knowable at any optimisation level. */
  grub_test_assert (GRUB_OBJECT_SIZE0 (stack) == sizeof (stack),
		    "whole-object size of a local array is %llu, expected %llu",
		    (unsigned long long) GRUB_OBJECT_SIZE0 (stack),
		    (unsigned long long) sizeof (stack));
  grub_test_assert (GRUB_OBJECT_SIZE (stack) == sizeof (stack),
		    "subobject size of a local array is %llu, expected %llu",
		    (unsigned long long) GRUB_OBJECT_SIZE (stack),
		    (unsigned long long) sizeof (stack));

  /*
   * The two flavours have to differ on a struct member, or the split
   * between them is not doing anything: the subobject flavour sees just
   * the member, the whole-object flavour sees the rest of the struct
   * too. mem* relies on the latter being the looser of the two.
   */
  grub_test_assert (GRUB_OBJECT_SIZE (obj.tail) == sizeof (obj.tail),
		    "subobject size of a struct member is %llu, expected %llu",
		    (unsigned long long) GRUB_OBJECT_SIZE (obj.tail),
		    (unsigned long long) sizeof (obj.tail));
  grub_test_assert (GRUB_OBJECT_SIZE0 (obj.tail) >= sizeof (obj.tail),
		    "whole-object size of a struct member is %llu, "
		    "expected at least %llu",
		    (unsigned long long) GRUB_OBJECT_SIZE0 (obj.tail),
		    (unsigned long long) sizeof (obj.tail));

#ifdef __OPTIMIZE__
  /*
   * Tracking a size through an alloc_size()-annotated allocator needs
   * the optimiser -- at -O0 neither builtin folds an allocator call, so
   * these run in the functional test (-Os) and are skipped in the host
   * unit test, whose HOST_CFLAGS carry no -O flag. That is the reason
   * both tests exist rather than just one.
   */
  {
    grub_size_t n = fortify_test_dynamic_size;
    char *cbuf = grub_malloc (32);
    char *dbuf = grub_malloc (n);

    if (cbuf == NULL || dbuf == NULL)
      {
	grub_test_assert (0, "out of memory");
	grub_free (cbuf);
	grub_free (dbuf);
	return;
      }

    /* Both builtins can size an allocation made with a constant. */
    grub_test_assert (GRUB_OBJECT_SIZE0 (cbuf) != (grub_size_t) -1,
		      "constant-sized heap allocation is not tracked; "
		      "fortification of it has silently become a no-op");

#ifdef HAVE_BUILTIN_DYNAMIC_OBJECT_SIZE
    /*
     * Only the dynamic builtin can size an allocation whose length is a
     * runtime value, which is the whole reason for preferring it: a
     * length parsed out of on-disk or on-wire data feeding grub_malloc()
     * and then bounding the copies after it. If this stops holding, the
     * hardening that matters is gone.
     *
     * Guarded because a compiler without the dynamic builtin is a
     * supported configuration, not a fault -- configure falls back to
     * the plain one, for which this correctly comes back unknowable.
     * Asserting it unconditionally would fail the test on every GCC
     * before 12 and every clang before 9, for a build that is behaving
     * exactly as intended.
     */
    grub_test_assert (GRUB_OBJECT_SIZE0 (dbuf) != (grub_size_t) -1,
		      "dynamically-sized heap allocation is not tracked; "
		      "fortification of it has silently become a no-op");
#endif

    grub_free (cbuf);
    grub_free (dbuf);
  }
#endif /* __OPTIMIZE__ */
#endif /* GRUB_OBJECT_SIZE */
}

/*
 * Tier 2: behavioural equivalence.
 *
 * grub_strcpy() and grub_stpcpy() are the only two that do not delegate
 * once the destination size is known -- the fortified forms are separate
 * implementations of the copy. Their results and, for stpcpy, their
 * return value have to match the originals exactly. A local array is
 * knowable at -O0 too, so these run in both builds.
 */
static void
fortify_test_copy_semantics (void)
{
  char dest[16];
  char *ret;

  grub_memset (dest, 'X', sizeof (dest));
  ret = grub_strcpy (dest, "hello");
  grub_test_assert (ret == dest, "grub_strcpy did not return dest");
  grub_test_assert (grub_strcmp (dest, "hello") == 0,
		    "grub_strcpy copied \"%s\", expected \"hello\"", dest);
  grub_test_assert (dest[5] == '\0', "grub_strcpy did not terminate");
  grub_test_assert (dest[6] == 'X',
		    "grub_strcpy wrote past the terminating NUL");

  grub_memset (dest, 'X', sizeof (dest));
  ret = grub_stpcpy (dest, "hello");
  grub_test_assert (ret == dest + 5,
		    "grub_stpcpy returned dest+%llu, expected dest+5",
		    (unsigned long long) (ret - dest));
  grub_test_assert (*ret == '\0',
		    "grub_stpcpy did not return a pointer to the NUL");
  grub_test_assert (grub_strcmp (dest, "hello") == 0,
		    "grub_stpcpy copied \"%s\", expected \"hello\"", dest);
  grub_test_assert (dest[6] == 'X',
		    "grub_stpcpy wrote past the terminating NUL");

  /* The empty string: the NUL is written, nothing else is. */
  grub_memset (dest, 'X', sizeof (dest));
  ret = grub_stpcpy (dest, "");
  grub_test_assert (ret == dest, "grub_stpcpy(\"\") did not return dest");
  grub_test_assert (*ret == '\0', "grub_stpcpy(\"\") did not write the NUL");
  grub_test_assert (dest[1] == 'X', "grub_stpcpy(\"\") wrote too much");

  /*
   * The return value is used to chain appends throughout the tree, so
   * check it composes rather than just that it points somewhere right.
   */
  grub_memset (dest, 'X', sizeof (dest));
  ret = grub_stpcpy (dest, "ab");
  ret = grub_stpcpy (ret, "cd");
  ret = grub_stpcpy (ret, "ef");
  grub_test_assert (grub_strcmp (dest, "abcdef") == 0,
		    "chained grub_stpcpy produced \"%s\", expected \"abcdef\"",
		    dest);
  grub_test_assert (ret == dest + 6,
		    "chained grub_stpcpy ended at dest+%llu, expected dest+6",
		    (unsigned long long) (ret - dest));

  /* A copy that exactly fills the destination must still terminate. */
  grub_memset (dest, 'X', sizeof (dest));
  ret = grub_strcpy (dest, "0123456789abcde");
  grub_test_assert (grub_strlen (dest) == 15,
		    "exactly-filling grub_strcpy produced length %llu, "
		    "expected 15", (unsigned long long) grub_strlen (dest));
  grub_test_assert (dest[15] == '\0',
		    "exactly-filling grub_strcpy did not terminate");
}

static int
fortify_test_vsnprintf (const char *fmt, ...)
{
  char buf[8];
  va_list ap;
  int ret;

  /*
   * buf has to be local to the function that calls grub_vsnprintf(): a
   * destination arriving as a parameter is unknowable to the builtins
   * and the check would compile away, testing nothing.
   */
  va_start (ap, fmt);
  ret = grub_vsnprintf (buf, sizeof (buf), fmt, ap);
  va_end (ap);

  grub_test_assert (grub_strcmp (buf, "0123456") == 0,
		    "grub_vsnprintf produced \"%s\", expected \"0123456\"",
		    buf);

  return ret;
}

/*
 * Tier 3: the boundary.
 *
 * Every fortified function, called with a length exactly equal to the
 * destination's size. None of these may trip. An off-by-one turning the
 * check from "n > size" into "n >= size" would abort on every one of
 * them -- and since the lengths here are compile-time constants, in an
 * optimised build it would not even get that far: GRUB_FORTIFY_STATIC_
 * CHECK() would fail the build. Either way this catches it.
 *
 * The second half repeats the same calls with the length laundered
 * through a volatile, so that the runtime comparison is exercised too
 * rather than folded away.
 */
static void
fortify_test_exact_fit (void)
{
  char buf[8];
  grub_size_t n;

  grub_memcpy (buf, "01234567", 8);
  grub_test_assert (buf[7] == '7', "exact-fit grub_memcpy did not copy");

  grub_memmove (buf, "01234567", 8);
  grub_test_assert (buf[7] == '7', "exact-fit grub_memmove did not copy");

  grub_memset (buf, 'z', 8);
  grub_test_assert (buf[7] == 'z', "exact-fit grub_memset did not fill");

  grub_strcpy (buf, "0123456");
  grub_test_assert (grub_strcmp (buf, "0123456") == 0,
		    "exact-fit grub_strcpy produced \"%s\"", buf);

  grub_stpcpy (buf, "0123456");
  grub_test_assert (grub_strcmp (buf, "0123456") == 0,
		    "exact-fit grub_stpcpy produced \"%s\"", buf);

  grub_memset (buf, 'z', 8);
  grub_strncpy (buf, "0123456", 8);
  grub_test_assert (grub_strcmp (buf, "0123456") == 0,
		    "exact-fit grub_strncpy produced \"%s\"", buf);

  grub_test_assert (grub_strlcpy (buf, "0123456", 8) == 7,
		    "exact-fit grub_strlcpy returned the wrong length");
  grub_test_assert (grub_strcmp (buf, "0123456") == 0,
		    "exact-fit grub_strlcpy produced \"%s\"", buf);

  grub_snprintf (buf, 8, "%s", "0123456");
  grub_test_assert (grub_strcmp (buf, "0123456") == 0,
		    "exact-fit grub_snprintf produced \"%s\"", buf);

  fortify_test_vsnprintf ("%s", "0123456");

  /* Now with a length the compiler cannot fold, so the check is real. */
  n = fortify_test_dynamic_size / 8;	/* 8 */

  grub_memcpy (buf, "01234567", n);
  grub_test_assert (buf[7] == '7',
		    "exact-fit runtime-length grub_memcpy did not copy");

  grub_memmove (buf, "abcdefgh", n);
  grub_test_assert (buf[7] == 'h',
		    "exact-fit runtime-length grub_memmove did not copy");

  grub_memset (buf, 'q', n);
  grub_test_assert (buf[7] == 'q',
		    "exact-fit runtime-length grub_memset did not fill");

  grub_memset (buf, 'z', sizeof (buf));
  grub_strncpy (buf, "0123456", (int) n);
  grub_test_assert (grub_strcmp (buf, "0123456") == 0,
		    "exact-fit runtime-length grub_strncpy produced \"%s\"",
		    buf);

  grub_test_assert (grub_strlcpy (buf, "0123456", n) == 7,
		    "exact-fit runtime-length grub_strlcpy returned the "
		    "wrong length");

  grub_snprintf (buf, n, "%s", "0123456");
  grub_test_assert (grub_strcmp (buf, "0123456") == 0,
		    "exact-fit runtime-length grub_snprintf produced \"%s\"",
		    buf);

  /* A length comfortably under the size must be untouched as well. */
  grub_memset (buf, 'z', sizeof (buf));
  grub_memcpy (buf, "ab", n / 4);
  grub_test_assert (buf[2] == 'z', "short grub_memcpy wrote too much");
}

static void
fortify_test (void)
{
  fortify_test_object_size ();
  fortify_test_copy_semantics ();
  fortify_test_exact_fit ();
}

#endif /* ! GRUB_FORTIFY_TEST_HEADER */
