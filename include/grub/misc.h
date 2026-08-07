/* misc.h - prototypes for misc functions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2005,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
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

#ifndef GRUB_MISC_HEADER
#define GRUB_MISC_HEADER	1

#include <stdarg.h>
#include <grub/types.h>
#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/compiler.h>

#define ALIGN_UP(addr, align) \
	(((addr) + (typeof (addr)) (align) - 1) & ~((typeof (addr)) (align) - 1))
#define ALIGN_UP_OVERHEAD(addr, align) ((-(addr)) & ((typeof (addr)) (align) - 1))
#define ALIGN_DOWN(addr, align) \
	((addr) & ~((typeof (addr)) (align) - 1))
#define ARRAY_SIZE(array) (sizeof (array) / sizeof (array[0]))
#define COMPILE_TIME_ASSERT(cond) switch (0) { case 1: case !(cond): ; }

#define grub_dprintf(condition, ...) grub_real_dprintf(GRUB_FILE, __FUNCTION__, __LINE__, condition, __VA_ARGS__)

void *EXPORT_FUNC(grub_memmove) (void *dest, const void *src, grub_size_t n);
char *EXPORT_FUNC(grub_strcpy) (char *dest, const char *src);

static inline char *
grub_strncpy (char *dest, const char *src, int c)
{
  char *p = dest;

  while ((*p++ = *src++) != '\0' && --c)
    ;

  return dest;
}

static inline char *
grub_stpcpy (char *dest, const char *src)
{
  char *d = dest;
  const char *s = src;

  do
    *d++ = *s;
  while (*s++ != '\0');

  return d - 1;
}

static inline grub_size_t
grub_strlcpy (char *dest, const char *src, grub_size_t size)
{
  char *d = dest;
  grub_size_t res = 0;
  /*
   * We do not subtract one from size here to avoid dealing with underflowing
   * the value, which is why to_copy is always checked to be greater than one
   * throughout this function.
   */
  grub_size_t to_copy = size;

  /* Copy size - 1 bytes to dest. */
  if (to_copy > 1)
    while ((*d++ = *src++) != '\0' && ++res && --to_copy > 1)
      ;

  /*
   * NUL terminate if size != 0. The previous step may have copied a NUL byte
   * if it reached the end of the string, but we know dest[size - 1] must always
   * be a NUL byte.
   */
  if (size != 0)
    dest[size - 1] = '\0';

  /* If there is still space in dest, but are here, we reached the end of src. */
  if (to_copy > 1)
    return res;

  /*
   * If we haven't reached the end of the string, iterate through to determine
   * the strings total length.
   */
  while (*src++ != '\0' && ++res)
   ;

  return res;
}

static inline void *
grub_memcpy (void *dest, const void *src, grub_size_t n)
{
  return grub_memmove (dest, src, n);
}

#if defined(__x86_64__) && !defined (GRUB_UTIL)
#if defined (__MINGW32__) || defined (__CYGWIN__) || defined (__MINGW64__)
#define GRUB_ASM_ATTR __attribute__ ((sysv_abi))
#else
#define GRUB_ASM_ATTR
#endif
#endif

int EXPORT_FUNC(grub_memcmp) (const void *s1, const void *s2, grub_size_t n);
int EXPORT_FUNC(grub_strcmp) (const char *s1, const char *s2);
int EXPORT_FUNC(grub_strncmp) (const char *s1, const char *s2, grub_size_t n);

char *EXPORT_FUNC(grub_strchr) (const char *s, int c);
char *EXPORT_FUNC(grub_strrchr) (const char *s, int c);
int EXPORT_FUNC(grub_strword) (const char *s, const char *w);

char *EXPORT_FUNC(grub_strtok_r) (char *s, const char *delim, char **save_ptr);
char *EXPORT_FUNC(grub_strtok) (char *s, const char *delim);

/* Copied from gnulib.
   Written by Bruno Haible <bruno@clisp.org>, 2005. */
static inline char *
grub_strstr (const char *haystack, const char *needle)
{
  /* Be careful not to look at the entire extent of haystack or needle
     until needed.  This is useful because of these two cases:
       - haystack may be very long, and a match of needle found early,
       - needle may be very long, and not even a short initial segment of
       needle may be found in haystack.  */
  if (*needle != '\0')
    {
      /* Speed up the following searches of needle by caching its first
	 character.  */
      char b = *needle++;

      for (;; haystack++)
	{
	  if (*haystack == '\0')
	    /* No match.  */
	    return 0;
	  if (*haystack == b)
	    /* The first character matches.  */
	    {
	      const char *rhaystack = haystack + 1;
	      const char *rneedle = needle;

	      for (;; rhaystack++, rneedle++)
		{
		  if (*rneedle == '\0')
		    /* Found a match.  */
		    return (char *) haystack;
		  if (*rhaystack == '\0')
		    /* No match.  */
		    return 0;
		  if (*rhaystack != *rneedle)
		    /* Nothing in this round.  */
		    break;
		}
	    }
	}
    }
  else
    return (char *) haystack;
}

int EXPORT_FUNC(grub_isspace) (int c);

static inline int
grub_isprint (int c)
{
  return (c >= ' ' && c <= '~');
}

static inline int
grub_iscntrl (int c)
{
  return (c >= 0x00 && c <= 0x1F) || c == 0x7F;
}

static inline int
grub_isalpha (int c)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static inline int
grub_islower (int c)
{
  return (c >= 'a' && c <= 'z');
}

static inline int
grub_isupper (int c)
{
  return (c >= 'A' && c <= 'Z');
}

static inline int
grub_isgraph (int c)
{
  return (c >= '!' && c <= '~');
}

static inline int
grub_isdigit (int c)
{
  return (c >= '0' && c <= '9');
}

static inline int
grub_isxdigit (int c)
{
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static inline int
grub_isalnum (int c)
{
  return grub_isalpha (c) || grub_isdigit (c);
}

static inline int
grub_tolower (int c)
{
  if (c >= 'A' && c <= 'Z')
    return c - 'A' + 'a';

  return c;
}

static inline int
grub_toupper (int c)
{
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 'A';

  return c;
}

static inline int
grub_strcasecmp (const char *s1, const char *s2)
{
  while (*s1 && *s2)
    {
      if (grub_tolower ((grub_uint8_t) *s1)
	  != grub_tolower ((grub_uint8_t) *s2))
	break;

      s1++;
      s2++;
    }

  return (int) grub_tolower ((grub_uint8_t) *s1)
    - (int) grub_tolower ((grub_uint8_t) *s2);
}

static inline int
grub_strncasecmp (const char *s1, const char *s2, grub_size_t n)
{
  if (n == 0)
    return 0;

  while (*s1 && *s2 && --n)
    {
      if (grub_tolower ((grub_uint8_t) *s1)
	  != grub_tolower ((grub_uint8_t) *s2))
	break;

      s1++;
      s2++;
    }

  return (int) grub_tolower ((grub_uint8_t) *s1)
    - (int) grub_tolower ((grub_uint8_t) *s2);
}

/*
 * Do a case insensitive compare of two UUID strings by ignoring all dashes.
 * Note that the parameter n, is the number of significant characters to
 * compare, where significant characters are any except the dash.
 */
static inline int
grub_uuidcasecmp (const char *uuid1, const char *uuid2, grub_size_t n)
{
  if (n == 0)
    return 0;

  while (*uuid1 && *uuid2 && --n)
    {
      /* Skip forward to non-dash on both UUIDs. */
      while ('-' == *uuid1)
        ++uuid1;

      while ('-' == *uuid2)
        ++uuid2;

      if (grub_tolower ((grub_uint8_t) *uuid1) != grub_tolower ((grub_uint8_t) *uuid2))
	break;

      uuid1++;
      uuid2++;
    }

  return (int) grub_tolower ((grub_uint8_t) *uuid1) - (int) grub_tolower ((grub_uint8_t) *uuid2);
}

/*
 * Note that these differ from the C standard's definitions of strtol,
 * strtoul(), and strtoull() by the addition of two const qualifiers on the end
 * pointer, which make the declaration match the *semantic* requirements of
 * their behavior.  This means that instead of:
 *
 *  char *s = "1234 abcd";
 *  char *end;
 *  unsigned long l;
 *
 *  l = grub_strtoul(s, &end, 10);
 *
 * We must one of:
 *
 *  const char *end;
 *  ... or ...
 *  l = grub_strtoul(s, (const char ** const)&end, 10);
 */
unsigned long EXPORT_FUNC(grub_strtoul) (const char * restrict str, const char ** const restrict end, int base);
unsigned long long EXPORT_FUNC(grub_strtoull) (const char * restrict str, const char ** const restrict end, int base);

static inline long
grub_strtol (const char * restrict str, const char ** const restrict end, int base)
{
  int negative = 0;
  unsigned long long magnitude;

  while (*str && grub_isspace (*str))
    str++;

  if (*str == '-')
    {
      negative = 1;
      str++;
    }

  magnitude = grub_strtoull (str, end, base);
  if (negative)
    {
      if (magnitude > (unsigned long) GRUB_LONG_MAX + 1)
        {
          grub_error (GRUB_ERR_OUT_OF_RANGE, N_("overflow is detected"));
          return GRUB_LONG_MIN;
        }
      return -((long) magnitude);
    }
  else
    {
      if (magnitude > GRUB_LONG_MAX)
        {
          grub_error (GRUB_ERR_OUT_OF_RANGE, N_("overflow is detected"));
          return GRUB_LONG_MAX;
        }
      return (long) magnitude;
    }
}

char *EXPORT_FUNC(grub_strdup) (const char *s) WARN_UNUSED_RESULT;
char *EXPORT_FUNC(grub_strndup) (const char *s, grub_size_t n) WARN_UNUSED_RESULT;
void *EXPORT_FUNC(grub_memset) (void *s, int c, grub_size_t n);
grub_size_t EXPORT_FUNC(grub_strlen) (const char *s) WARN_UNUSED_RESULT;

/*
 * Fortified grub_memcpy/grub_memmove/grub_memset and the string copy
 * helpers: when the destination's size is knowable at the call site -- a
 * local array or a fixed-size struct field, anything whose declaration
 * the compiler can still see, which rules out a pointer received as a
 * plain argument from another function -- catch a would-be overflow
 * instead of silently corrupting adjacent memory. This is GRUB's
 * equivalent of glibc's _FORTIFY_SOURCE.
 *
 * The size also tracks forward from an alloc_size()-annotated allocator
 * (see mm.h), so a grub_malloc()-then-memcpy() in one function is
 * covered too. With __builtin_dynamic_object_size() -- preferred, and
 * used whenever the compiler has it, which is exactly what distinguishes
 * _FORTIFY_SOURCE=3 from =2 -- that holds even when the allocation
 * length is a runtime value rather than a constant, which is the case
 * that matters here: an on-disk or on-wire length field feeding
 * grub_malloc() and then bounding the copies that follow. Plain
 * __builtin_object_size() can only fold to a compile-time constant, so
 * it silently yields "unknown" for those and the check disappears.
 *
 * Either builtin stops at the same boundary: once a pointer crosses a
 * real (non-inlined) function call as a plain pointer argument, the size
 * becomes unknowable and these macros are a no-op -- they expand to the
 * plain, unchecked call, exactly as if fortification were unavailable.
 *
 * Two object-size flavours, following glibc's split exactly.
 * GRUB_OBJECT_SIZE0() is the whole enclosing object and is what the mem*
 * functions use: writing into a struct member and deliberately running
 * on into the rest of the object is a legitimate and common idiom in
 * this codebase's on-disk-format parsers, and the stricter flavour would
 * abort on it. GRUB_OBJECT_SIZE() is the closest surrounding subobject,
 * and is what the string functions use, matching glibc again.
 */
#if defined (GRUB_BUILD)
/*
 * Deliberately left unfortified. The host-side tools built with
 * GRUB_BUILD (build-grub-mkfont and friends) run on the build machine to
 * generate data files, never on the boot path, and they don't link
 * kern/misc.c, so grub_fatal() isn't even available to them.
 */
#elif defined (HAVE_BUILTIN_DYNAMIC_OBJECT_SIZE)
#define GRUB_OBJECT_SIZE(ptr)  __builtin_dynamic_object_size ((ptr), 1)
#define GRUB_OBJECT_SIZE0(ptr) __builtin_dynamic_object_size ((ptr), 0)
#elif defined (HAVE_BUILTIN_OBJECT_SIZE)
#define GRUB_OBJECT_SIZE(ptr)  __builtin_object_size ((ptr), 1)
#define GRUB_OBJECT_SIZE0(ptr) __builtin_object_size ((ptr), 0)
#endif

#ifdef GRUB_OBJECT_SIZE

/*
 * When the length and the destination size both fold to constants the
 * overflow is provable without running anything, so fail the build
 * rather than wait for a boot to hit it -- the same escalation glibc
 * makes with __warndecl(). The mechanism is that a call to an
 * error-attributed function is only diagnosed if it survives to the end
 * of optimisation, so the dead branch has to be foldable; with the
 * optimiser off nothing folds and every call site would trip it, hence
 * the __OPTIMIZE__ guard.
 *
 * This has to be evaluated in the macro, at the call site.
 * __builtin_constant_p() cannot see a value that has already been passed
 * into a function as a parameter, not even an always_inline one.
 */
#if defined (__OPTIMIZE__) && defined (HAVE_ATTRIBUTE_ERROR)
extern void grub_fortify_overflow (void)
  __attribute__ ((__error__ ("buffer overflow detected: length exceeds the size of the destination")));
#define GRUB_FORTIFY_STATIC_CHECK(n, size)				\
  ((__builtin_constant_p (n) && __builtin_constant_p (size)		\
    && (grub_size_t) (size) != (grub_size_t) -1				\
    && (grub_size_t) (n) > (grub_size_t) (size))			\
   ? grub_fortify_overflow () : (void) 0)
#else
#define GRUB_FORTIFY_STATIC_CHECK(n, size) ((void) 0)
#endif

/*
 * A destination size of (grub_size_t) -1 is the builtins' "unknowable"
 * answer, not a 16-exabyte buffer, so it always passes.
 */
static inline void
grub_fortify_check (const char *func, grub_size_t n, grub_size_t size)
{
  if (size != (grub_size_t) -1 && n > size)
    grub_fatal ("buffer overflow detected in %s (%" PRIuGRUB_SIZE " > %"
		PRIuGRUB_SIZE ")", func, n, size);
}

static inline void *
grub_fortify_memcpy (void *dest, const void *src, grub_size_t n,
		      grub_size_t dest_size)
{
  grub_fortify_check ("grub_memcpy", n, dest_size);
  return (grub_memcpy) (dest, src, n);
}
#define grub_memcpy(dest, src, n)					\
  (GRUB_FORTIFY_STATIC_CHECK ((n), GRUB_OBJECT_SIZE0 ((dest))),		\
   grub_fortify_memcpy ((dest), (src), (n), GRUB_OBJECT_SIZE0 ((dest))))

static inline void *
grub_fortify_memmove (void *dest, const void *src, grub_size_t n,
		       grub_size_t dest_size)
{
  grub_fortify_check ("grub_memmove", n, dest_size);
  return (grub_memmove) (dest, src, n);
}
#define grub_memmove(dest, src, n)					\
  (GRUB_FORTIFY_STATIC_CHECK ((n), GRUB_OBJECT_SIZE0 ((dest))),		\
   grub_fortify_memmove ((dest), (src), (n), GRUB_OBJECT_SIZE0 ((dest))))

static inline void *
grub_fortify_memset (void *s, int c, grub_size_t n, grub_size_t s_size)
{
  grub_fortify_check ("grub_memset", n, s_size);
  return (grub_memset) (s, c, n);
}
#define grub_memset(s, c, n)						\
  (GRUB_FORTIFY_STATIC_CHECK ((n), GRUB_OBJECT_SIZE0 ((s))),		\
   grub_fortify_memset ((s), (c), (n), GRUB_OBJECT_SIZE0 ((s))))

/*
 * grub_strcpy and grub_stpcpy have no length argument, so unlike the
 * three above these can't just be a pre-call bounds check: they have to
 * do the bounded copy themselves once dest_size is known, the same way
 * glibc's __strcpy_chk()/__stpcpy_chk() do. No static check either, for
 * the same reason -- there is no length to fold.
 */
static inline char *
grub_fortify_strcpy (char *dest, const char *src, grub_size_t dest_size)
{
  grub_size_t i;

  if (dest_size == (grub_size_t) -1)
    return (grub_strcpy) (dest, src);

  for (i = 0; i < dest_size; i++)
    {
      dest[i] = src[i];
      if (src[i] == '\0')
	return dest;
    }

  grub_fatal ("buffer overflow detected in grub_strcpy (dest size %"
	      PRIuGRUB_SIZE ")", dest_size);
}
#define grub_strcpy(dest, src) \
  grub_fortify_strcpy ((dest), (src), GRUB_OBJECT_SIZE ((dest)))

/* Returns a pointer to the terminating NUL, as grub_stpcpy does. */
static inline char *
grub_fortify_stpcpy (char *dest, const char *src, grub_size_t dest_size)
{
  grub_size_t i;

  if (dest_size == (grub_size_t) -1)
    return (grub_stpcpy) (dest, src);

  for (i = 0; i < dest_size; i++)
    {
      dest[i] = src[i];
      if (src[i] == '\0')
	return dest + i;
    }

  grub_fatal ("buffer overflow detected in grub_stpcpy (dest size %"
	      PRIuGRUB_SIZE ")", dest_size);
}
#define grub_stpcpy(dest, src) \
  grub_fortify_stpcpy ((dest), (src), GRUB_OBJECT_SIZE ((dest)))

/*
 * grub_strncpy writes at most c bytes, so c is the length to check. It
 * is an int rather than a grub_size_t: a negative count makes the copy
 * run unbounded, so the cast deliberately turns that into a very large
 * length and trips the check.
 */
static inline char *
grub_fortify_strncpy (char *dest, const char *src, int c,
		      grub_size_t dest_size)
{
  grub_fortify_check ("grub_strncpy", (grub_size_t) c, dest_size);
  return (grub_strncpy) (dest, src, c);
}
#define grub_strncpy(dest, src, c)					\
  (GRUB_FORTIFY_STATIC_CHECK ((c), GRUB_OBJECT_SIZE ((dest))),		\
   grub_fortify_strncpy ((dest), (src), (c), GRUB_OBJECT_SIZE ((dest))))

static inline grub_size_t
grub_fortify_strlcpy (char *dest, const char *src, grub_size_t size,
		      grub_size_t dest_size)
{
  grub_fortify_check ("grub_strlcpy", size, dest_size);
  return (grub_strlcpy) (dest, src, size);
}
#define grub_strlcpy(dest, src, size)					\
  (GRUB_FORTIFY_STATIC_CHECK ((size), GRUB_OBJECT_SIZE ((dest))),	\
   grub_fortify_strlcpy ((dest), (src), (size), GRUB_OBJECT_SIZE ((dest))))

#endif /* GRUB_OBJECT_SIZE */

/* Replace all `ch' characters of `input' with `with' and copy the
   result into `output'; return EOS address of `output'. */
static inline char *
grub_strchrsub (char *output, const char *input, char ch, const char *with)
{
  while (*input)
    {
      if (*input == ch)
	{
	  grub_strcpy (output, with);
	  output += grub_strlen (with);
	  input++;
	  continue;
	}
      *output++ = *input++;
    }
  *output = '\0';
  return output;
}

extern void (*EXPORT_VAR (grub_xputs)) (const char *str);

static inline int
grub_puts (const char *s)
{
  const char nl[2] = "\n";
  grub_xputs (s);
  grub_xputs (nl);

  return 1;	/* Cannot fail.  */
}

int EXPORT_FUNC(grub_puts_) (const char *s);
int EXPORT_FUNC(grub_debug_enabled) (const char *condition);
void EXPORT_FUNC(grub_real_dprintf) (const char *file,
				     const char *function,
                                     const int line,
                                     const char *condition,
                                     const char *fmt, ...) __attribute__ ((format (GNU_PRINTF, 5, 6)));
int EXPORT_FUNC(grub_printf) (const char *fmt, ...) __attribute__ ((format (GNU_PRINTF, 1, 2)));
int EXPORT_FUNC(grub_printf_) (const char *fmt, ...) __attribute__ ((format (GNU_PRINTF, 1, 2)));
int EXPORT_FUNC(grub_vprintf) (const char *fmt, va_list args);
int EXPORT_FUNC(grub_snprintf) (char *str, grub_size_t n, const char *fmt, ...)
     __attribute__ ((format (GNU_PRINTF, 3, 4)));
int EXPORT_FUNC(grub_vsnprintf) (char *str, grub_size_t n, const char *fmt,
				 va_list args);

#ifdef GRUB_OBJECT_SIZE
/*
 * Fortified grub_snprintf/grub_vsnprintf: these already bound their own
 * writes to n, so what is checked is that the caller's idea of the
 * destination's size agrees with the compiler's -- catching the classic
 * sizeof() applied to the wrong buffer, or to a pointer. Same check as
 * glibc's __snprintf_chk(). These have to come after the declarations
 * above, hence the separate block.
 */
#define grub_snprintf(str, n, ...)					\
  (GRUB_FORTIFY_STATIC_CHECK ((n), GRUB_OBJECT_SIZE ((str))),		\
   grub_fortify_check ("grub_snprintf", (n), GRUB_OBJECT_SIZE ((str))),	\
   (grub_snprintf) ((str), (n), __VA_ARGS__))

#define grub_vsnprintf(str, n, fmt, args)				\
  (GRUB_FORTIFY_STATIC_CHECK ((n), GRUB_OBJECT_SIZE ((str))),		\
   grub_fortify_check ("grub_vsnprintf", (n), GRUB_OBJECT_SIZE ((str))), \
   (grub_vsnprintf) ((str), (n), (fmt), (args)))
#endif /* GRUB_OBJECT_SIZE */
char *EXPORT_FUNC(grub_xasprintf) (const char *fmt, ...)
     __attribute__ ((format (GNU_PRINTF, 1, 2))) WARN_UNUSED_RESULT;
char *EXPORT_FUNC(grub_xvasprintf) (const char *fmt, va_list args) WARN_UNUSED_RESULT;

void EXPORT_FUNC(grub_exit) (void) __attribute__ ((noreturn));
void EXPORT_FUNC(grub_abort) (void) __attribute__ ((noreturn));
grub_uint64_t EXPORT_FUNC(grub_divmod64) (grub_uint64_t n,
					  grub_uint64_t d,
					  grub_uint64_t *r);

extern bool EXPORT_FUNC(grub_is_cli_disabled) (void);
extern bool EXPORT_FUNC(grub_is_cli_need_auth) (void);
extern void EXPORT_FUNC(grub_cli_set_auth_needed) (void);

/* Must match softdiv group in gentpl.py.  */
#if !defined(GRUB_MACHINE_EMU) && (defined(__arm__) || defined(__ia64__) || \
    (defined(__riscv) && (__riscv_xlen == 32))) || defined(__mips__)
#define GRUB_DIVISION_IN_SOFTWARE 1
#else
#define GRUB_DIVISION_IN_SOFTWARE 0
#endif

/* Some division functions need to be in kernel if compiler generates calls
   to them. Otherwise we still need them for consistent tests but they go
   into a separate module.  */
#if GRUB_DIVISION_IN_SOFTWARE
#define EXPORT_FUNC_IF_SOFTDIV EXPORT_FUNC
#else
#define EXPORT_FUNC_IF_SOFTDIV(x) x
#endif

grub_int64_t
EXPORT_FUNC_IF_SOFTDIV(grub_divmod64s) (grub_int64_t n,
					grub_int64_t d,
					grub_int64_t *r);

grub_uint32_t
EXPORT_FUNC_IF_SOFTDIV (grub_divmod32) (grub_uint32_t n,
					grub_uint32_t d,
					grub_uint32_t *r);

grub_int32_t
EXPORT_FUNC_IF_SOFTDIV (grub_divmod32s) (grub_int32_t n,
					 grub_int32_t d,
					 grub_int32_t *r);

/* Inline functions.  */

static inline char *
grub_memchr (const void *p, int c, grub_size_t len)
{
  const char *s = (const char *) p;
  const char *e = s + len;

  for (; s < e; s++)
    if (*s == c)
      return (char *) s;

  return 0;
}


static inline unsigned int
grub_abs (int x)
{
  if (x < 0)
    return (unsigned int) (-x);
  else
    return (unsigned int) x;
}

/* Reboot the machine.  */
#if defined (GRUB_MACHINE_EMU) || defined (GRUB_MACHINE_QEMU_MIPS) || \
    defined (GRUB_MACHINE_EFI)
void EXPORT_FUNC(grub_reboot) (void) __attribute__ ((noreturn));
#else
void grub_reboot (void) __attribute__ ((noreturn));
#endif

#ifdef GRUB_MACHINE_PCBIOS
/* Halt the system, using APM if possible. If NO_APM is true, don't
 * use APM even if it is available.  */
void grub_halt (int no_apm) __attribute__ ((noreturn));
#elif defined (__mips__) && !defined (GRUB_MACHINE_EMU)
void EXPORT_FUNC (grub_halt) (void) __attribute__ ((noreturn));
#else
void grub_halt (void) __attribute__ ((noreturn));
#endif

#ifdef GRUB_MACHINE_EMU
/* Flag to check if module loading is available.  */
extern const int EXPORT_VAR(grub_no_modules);
#else
#define grub_no_modules 0
#endif

static inline void
grub_error_save (struct grub_error_saved *save)
{
  grub_memcpy (save->errmsg, grub_errmsg, sizeof (save->errmsg));
  save->grub_errno = grub_errno;
  grub_errno = GRUB_ERR_NONE;
}

static inline void
grub_error_load (const struct grub_error_saved *save)
{
  grub_memcpy (grub_errmsg, save->errmsg, sizeof (grub_errmsg));
  grub_errno = save->grub_errno;
}

/*
 * grub_printf_fmt_checks() a fmt string for printf() against an expected
 * format. It is intended for cases where the fmt string could come from
 * an outside source and cannot be trusted.
 *
 * While expected fmt accepts a printf() format string it should be kept
 * as simple as possible. The printf() format strings with positional
 * parameters are NOT accepted, neither for fmt nor for fmt_expected.
 *
 * The fmt is accepted if it has equal or less arguments than fmt_expected
 * and if the type of all arguments match.
 *
 * Returns GRUB_ERR_NONE if fmt is acceptable.
 */
grub_err_t EXPORT_FUNC (grub_printf_fmt_check) (const char *fmt, const char *fmt_expected);

#if BOOT_TIME_STATS
struct grub_boot_time
{
  struct grub_boot_time *next;
  grub_uint64_t tp;
  const char *file;
  int line;
  char *msg;
};

extern struct grub_boot_time *EXPORT_VAR(grub_boot_time_head);

void EXPORT_FUNC(grub_real_boot_time) (const char *file,
				       const int line,
				       const char *fmt, ...) __attribute__ ((format (GNU_PRINTF, 3, 4)));
#define grub_boot_time(...) grub_real_boot_time(GRUB_FILE, __LINE__, __VA_ARGS__)
#else
#define grub_boot_time(...)
#endif

#define grub_max(a, b) (((a) > (b)) ? (a) : (b))
#define grub_min(a, b) (((a) < (b)) ? (a) : (b))

#define grub_log2ull(n) (GRUB_TYPE_BITS (grub_uint64_t) - __builtin_clzll (n) - 1)

grub_ssize_t
EXPORT_FUNC(grub_utf8_to_utf16_alloc) (const char *str8, grub_uint16_t **utf16_msg, grub_uint16_t **last_position);

#endif /* ! GRUB_MISC_HEADER */
