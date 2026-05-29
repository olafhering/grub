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
 * Benchmark and correctness test for grub_memmove.
 *
 * Run from the GRUB shell:
 *   insmod memmove_bench
 *   memmove_bench [LOOPS]
 *
 * Output reports throughput (MiB/s) per buffer size and scenario.
 * grub_memmove is exercised across four alignment combinations (non-overlapping),
 * two byte-offset overlap configurations (forward and backward, byte-copy path),
 * and two word-offset overlap configurations (forward and backward, word-copy
 * path), covering all copy paths.  When LOOPS > 1, each loop's results are
 * printed followed by averages.
 */

#include <grub/command.h>
#include <grub/dl.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/time.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

/*
 * Maximum single-copy size; drives the allocation. 1 MiB is large enough
 * to exceed typical L2 caches and stress main-memory bandwidth.
 */
#define MAX_BUF_SIZE  (1U * 1024U * 1024U)

/*
 * Iteration counts chosen so each cell produces a measurable elapsed time
 * (several ms) even on a fast EFI machine with grub_get_time_ms() resolution,
 * while keeping the full run under ~60 s on a slow machine.
 */
static const struct
{
  const char *label;
  grub_size_t  size;
  unsigned int iters;
} cases[] =
{
  { "    8 B",         8, 2000000 },
  { "   16 B",        16, 2000000 },
  { "   24 B",        24, 2000000 },
  { "   32 B",        32, 2000000 },
  { "   64 B",        64, 1000000 },
  { "  128 B",       128, 1000000 },
  { "  256 B",       256,  500000 },
  { "  512 B",       512,  500000 },
  { "  1 KiB",      1024,  200000 },
  { "  2 KiB",      2048,  200000 },
  { "  4 KiB",      4096,  100000 },
  { "  8 KiB",      8192,  100000 },
  { " 16 KiB",     16384,   50000 },
  { " 32 KiB",     32768,   50000 },
  { " 64 KiB",     65536,   10000 },
  { "128 KiB",    131072,   10000 },
  { "256 KiB",    262144,    5000 },
  { "512 KiB",    524288,    5000 },
  { "  1 MiB",   1048576,    1000 },
};

static const char * const scenarios[] =
{
  "non-overlap: aligned src,   aligned dst",
  "non-overlap: unaligned src, unaligned dst",
  "non-overlap: unaligned src, aligned dst",
  "non-overlap: aligned src,   unaligned dst",
  "overlap fwd byte: dst=buf+0, src=buf+1",
  "overlap bwd byte: dst=buf+1, src=buf+0",
  "overlap fwd word: dst=buf+0, src=buf+WORD",
  "overlap bwd word: dst=buf+WORD, src=buf+0",
  "overlap fwd unaligned word: dst=buf+1, src=buf+1+WORD",
  "overlap bwd unaligned word: dst=buf+1+WORD, src=buf+1",
};

/*
 * mbps_sum accumulates MiB/s across loops for one scenario;
 * mbps_cnt counts how many loops produced a measurable elapsed time.
 */
static void
run_bench (const char *scenario,
	   grub_uint8_t *dst, grub_uint8_t *src,
	   grub_uint64_t *mbps_sum, unsigned int *mbps_cnt)
{
  grub_uint64_t start, elapsed;
  grub_uint64_t bytes;
  grub_uint64_t mbps;
  grub_uint64_t r;
  grub_size_t i;
  unsigned int j;

  grub_printf (" [%s]\n", scenario);

  for (i = 0; i < ARRAY_SIZE (cases); i++)
    {
      start = grub_get_time_ms ();
      for (j = 0; j < cases[i].iters; j++)
	grub_memmove (dst, src, cases[i].size);
      elapsed = grub_get_time_ms () - start;

      bytes = (grub_uint64_t) cases[i].size * cases[i].iters;

      if (elapsed > 0)
	{
	  mbps = grub_divmod64 (bytes * 1000ULL, elapsed * 1024ULL * 1024ULL, &r);
	  mbps_sum[i] += mbps;
	  mbps_cnt[i]++;
	  grub_printf ("  %s  %6"PRIuGRUB_UINT64_T" ms   %6"PRIuGRUB_UINT64_T" MiB/s\n",
		       cases[i].label, elapsed, mbps);
	}
      else
	grub_printf ("  %s  <1 ms  (too fast to measure)\n", cases[i].label);
    }
}

typedef struct {
  grub_uint8_t *dst;
  grub_uint8_t *src;
} test_pair_t;

#define ALIGN_MASK (sizeof (grub_addr_t) - 1)
#define MAKE_ALIGN(addr) ((grub_uint8_t *) (((grub_addr_t) (addr) + ALIGN_MASK) & ~(grub_addr_t) ALIGN_MASK))

static void
memmove_bench (unsigned int loops)
{
  grub_uint8_t *src_raw, *dst_raw, *ov_raw;
  grub_uint8_t *src_al, *dst_al;
  grub_uint8_t *src_un, *dst_un;
  grub_uint8_t *ov_al;
  grub_uint8_t *ov_un;
  test_pair_t pairs[ARRAY_SIZE (scenarios)];
  grub_uint64_t sum[ARRAY_SIZE (scenarios)][ARRAY_SIZE (cases)] = {0};
  unsigned int cnt[ARRAY_SIZE (scenarios)][ARRAY_SIZE (cases)] = {0};
  grub_size_t i;
  unsigned int l, s;
  grub_uint64_t avg, r;

  /* +16 gives room to align the base pointer and still have +1 headroom.  */
  src_raw = grub_malloc (MAX_BUF_SIZE + 16);
  dst_raw = grub_malloc (MAX_BUF_SIZE + 16);
  ov_raw  = grub_malloc (MAX_BUF_SIZE + 16);

  if (src_raw == NULL || dst_raw == NULL || ov_raw == NULL)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, "grub_malloc failed");
      goto out;
    }

  /* Round up to the next alignment boundary.  */
  src_al = MAKE_ALIGN (src_raw);
  dst_al = MAKE_ALIGN (dst_raw);
  ov_al  = MAKE_ALIGN (ov_raw);

  /* One byte off from the aligned pointer guarantees misalignment.  */
  src_un = src_al + 1;
  dst_un = dst_al + 1;
  ov_un  = ov_al  + 1;

  /* Buffer pairs for each scenario (indices match scenarios[]).  */
  pairs[0].dst = dst_al;
  pairs[0].src = src_al;

  pairs[1].dst = dst_un;
  pairs[1].src = src_un;

  pairs[2].dst = dst_al;
  pairs[2].src = src_un;

  pairs[3].dst = dst_un;
  pairs[3].src = src_al;

  pairs[4].dst = ov_al;
  pairs[4].src = ov_al + 1;

  pairs[5].dst = ov_al + 1;
  pairs[5].src = ov_al;

  /*
   * Word-offset overlap: offset equals sizeof(grub_addr_t) so both pointers
   * share the same alignment modulo ALIGN_MASK, enabling the word-copy path.
   */
  pairs[6].dst = ov_al;
  pairs[6].src = ov_al + sizeof (grub_addr_t);

  pairs[7].dst = ov_al + sizeof (grub_addr_t);
  pairs[7].src = ov_al;

  /*
   * Unaligned word-offset overlap: same word-copy path as above, but both
   * pointers start 1 byte past an 8-byte boundary.  Analogous to the
   * non-overlap "unaligned src, unaligned dst" regression case.
   */
  pairs[8].dst = ov_un;
  pairs[8].src = ov_un + sizeof (grub_addr_t);

  pairs[9].dst = ov_un + sizeof (grub_addr_t);
  pairs[9].src = ov_un;

  /* Initialise src_al with a known pattern; src_un = src_al+1 follows.  */
  for (i = 0; i < MAX_BUF_SIZE; i++)
    src_al[i] = (grub_uint8_t) (i & 0xff);

  /* ----- Correctness: grub_memmove (non-overlapping) ----- */
  grub_memset (dst_al, 0, MAX_BUF_SIZE);
  grub_memmove (dst_al, src_al, MAX_BUF_SIZE);
  if (grub_memcmp (dst_al, src_al, MAX_BUF_SIZE) != 0)
    {
      grub_error (GRUB_ERR_BUG, "correctness failure: aligned src, aligned dst");
      goto out;
    }

  grub_memset (dst_un, 0, MAX_BUF_SIZE - 1);
  grub_memmove (dst_un, src_un, MAX_BUF_SIZE - 1);
  if (grub_memcmp (dst_un, src_un, MAX_BUF_SIZE - 1) != 0)
    {
      grub_error (GRUB_ERR_BUG, "correctness failure: unaligned src, unaligned dst");
      goto out;
    }

  grub_memset (dst_al, 0, MAX_BUF_SIZE);
  grub_memmove (dst_al, src_un, MAX_BUF_SIZE - 1);
  if (grub_memcmp (dst_al, src_un, MAX_BUF_SIZE - 1) != 0)
    {
      grub_error (GRUB_ERR_BUG, "correctness failure: unaligned src, aligned dst");
      goto out;
    }

  grub_memset (dst_un, 0, MAX_BUF_SIZE - 1);
  grub_memmove (dst_un, src_al, MAX_BUF_SIZE - 1);
  if (grub_memcmp (dst_un, src_al, MAX_BUF_SIZE - 1) != 0)
    {
      grub_error (GRUB_ERR_BUG, "correctness failure: aligned src, unaligned dst");
      goto out;
    }

  /* ----- Correctness: grub_memmove (overlapping) ----- */

  /*
   * Forward overlap (d < s): shift the buffer left by 1.
   * After the call ov_al[i] must equal the original ov_al[i+1] = (i+1)&0xff.
   */
  for (i = 0; i < MAX_BUF_SIZE; i++)
    ov_al[i] = (grub_uint8_t) (i & 0xff);

  grub_memmove (ov_al, ov_al + 1, MAX_BUF_SIZE - 1);

  for (i = 0; i < MAX_BUF_SIZE - 1; i++)
    if (ov_al[i] != (grub_uint8_t) ((i + 1) & 0xff))
      {
	grub_error (GRUB_ERR_BUG,
		    "memmove overlap fwd failure at byte %"PRIuGRUB_SIZE": got 0x%02x want 0x%02"PRIxGRUB_SIZE,
		    i, ov_al[i], ((i + 1) & 0xff));
	goto out;
      }

  /*
   * Backward overlap (d > s): shift the buffer right by 1.
   * After the call ov_al[i+1] must equal the original ov_al[i] = i&0xff.
   */
  for (i = 0; i < MAX_BUF_SIZE; i++)
    ov_al[i] = (grub_uint8_t) (i & 0xff);

  grub_memmove (ov_al + 1, ov_al, MAX_BUF_SIZE - 1);

  for (i = 1; i < MAX_BUF_SIZE; i++)
    if (ov_al[i] != (grub_uint8_t) ((i - 1) & 0xff))
      {
	grub_error (GRUB_ERR_BUG,
		    "memmove overlap bwd failure at byte %"PRIuGRUB_SIZE": got 0x%02x want 0x%02"PRIxGRUB_SIZE,
		    i, ov_al[i], ((i - 1) & 0xff));
	goto out;
      }

  /*
   * Forward word-aligned overlap (d < s, offset = sizeof(grub_addr_t)):
   * both pointers are aligned, so __memmove_fwd uses word-sized copies.
   * Shift the buffer left by WORD; ov_al[i] must equal (i+WORD)&0xff.
   */
  for (i = 0; i < MAX_BUF_SIZE; i++)
    ov_al[i] = (grub_uint8_t) (i & 0xff);

  grub_memmove (ov_al, ov_al + sizeof (grub_addr_t), MAX_BUF_SIZE - sizeof (grub_addr_t));

  for (i = 0; i < MAX_BUF_SIZE - sizeof (grub_addr_t); i++)
    if (ov_al[i] != (grub_uint8_t) ((i + sizeof (grub_addr_t)) & 0xff))
      {
	grub_error (GRUB_ERR_BUG,
		    "memmove overlap fwd word failure at byte %"PRIuGRUB_SIZE": got 0x%02x want 0x%02"PRIxGRUB_SIZE,
		    i, ov_al[i], ((i + sizeof (grub_addr_t)) & 0xff));
	goto out;
      }

  /*
   * Backward word-aligned overlap (d > s, offset = sizeof(grub_addr_t)):
   * both pointers are aligned, so __memmove_bwd uses word-sized copies.
   * Shift the buffer right by WORD; ov_al[i+WORD] must equal i&0xff.
   */
  for (i = 0; i < MAX_BUF_SIZE; i++)
    ov_al[i] = (grub_uint8_t) (i & 0xff);

  grub_memmove (ov_al + sizeof (grub_addr_t), ov_al, MAX_BUF_SIZE - sizeof (grub_addr_t));

  for (i = sizeof (grub_addr_t); i < MAX_BUF_SIZE; i++)
    if (ov_al[i] != (grub_uint8_t) ((i - sizeof (grub_addr_t)) & 0xff))
      {
	grub_error (GRUB_ERR_BUG,
		    "memmove overlap bwd word failure at byte %"PRIuGRUB_SIZE": got 0x%02x want 0x%02"PRIxGRUB_SIZE,
		    i, ov_al[i], ((i - sizeof (grub_addr_t)) & 0xff));
	goto out;
      }

  /*
   * Forward unaligned word-offset overlap (d < s, d=ov_un, s=ov_un+WORD):
   * both pointers share the same alignment modulo WORD (offset 1), so the
   * word-copy path activates after a 1-byte alignment step — analogous to
   * the non-overlap "unaligned src, unaligned dst" regression case.
   * Shift the buffer left by WORD; ov_un[i] must equal (i+1+WORD)&0xff.
   */
  for (i = 0; i < MAX_BUF_SIZE; i++)
    ov_al[i] = (grub_uint8_t) (i & 0xff);

  grub_memmove (ov_un, ov_un + sizeof (grub_addr_t),
		MAX_BUF_SIZE - 1 - sizeof (grub_addr_t));

  for (i = 0; i < MAX_BUF_SIZE - 1 - sizeof (grub_addr_t); i++)
    if (ov_un[i] != (grub_uint8_t) ((i + 1 + sizeof (grub_addr_t)) & 0xff))
      {
	grub_error (GRUB_ERR_BUG,
		    "memmove overlap fwd unaligned word failure at byte %"PRIuGRUB_SIZE": got 0x%02x want 0x%02"PRIxGRUB_SIZE,
		    i, ov_un[i], ((i + 1 + sizeof (grub_addr_t)) & 0xff));
	goto out;
      }

  /*
   * Backward unaligned word-offset overlap (d > s, d=ov_un+WORD, s=ov_un):
   * both pointers share the same alignment modulo WORD (offset 1), so the
   * word-copy path activates after a 1-byte alignment step.
   * Shift the buffer right by WORD; ov_un[i+WORD] must equal (i+1)&0xff.
   */
  for (i = 0; i < MAX_BUF_SIZE; i++)
    ov_al[i] = (grub_uint8_t) (i & 0xff);

  grub_memmove (ov_un + sizeof (grub_addr_t), ov_un,
		MAX_BUF_SIZE - 1 - sizeof (grub_addr_t));

  for (i = sizeof (grub_addr_t); i < MAX_BUF_SIZE - 1; i++)
    if (ov_un[i] != (grub_uint8_t) ((i + 1 - sizeof (grub_addr_t)) & 0xff))
      {
	grub_error (GRUB_ERR_BUG,
		    "memmove overlap bwd unaligned word failure at byte %"PRIuGRUB_SIZE": got 0x%02x want 0x%02"PRIxGRUB_SIZE,
		    i, ov_un[i], ((i + 1 - sizeof (grub_addr_t)) & 0xff));
	goto out;
      }

  /* ----- Benchmarks: grub_memmove ----- */

  /*
   * Scenarios 0-3 use separate src/dst allocations (non-overlapping).
   * Scenarios 4-5 use a 1-byte offset (byte-copy path: alignment check fails).
   * Scenarios 6-7 use a WORD-byte offset (word-copy path: alignment check passes).
   * Scenarios 8-9 use a WORD-byte offset from an unaligned base (word-copy path
   * after 1-byte alignment step: analogous to "unaligned src, unaligned dst").
   */
  grub_printf ("grub_memmove benchmark\n");

  for (l = 0; l < loops; l++)
    {
      if (loops > 1)
	grub_printf ("--- loop %u/%u ---\n", l + 1, loops);
      for (s = 0; s < ARRAY_SIZE (scenarios); s++)
	run_bench (scenarios[s], pairs[s].dst, pairs[s].src, sum[s], cnt[s]);
    }

  if (loops > 1)
    {
      grub_printf ("--- averages over %u loops ---\n", loops);
      for (s = 0; s < ARRAY_SIZE (scenarios); s++)
	{
	  grub_printf (" [%s]\n", scenarios[s]);
	  for (i = 0; i < ARRAY_SIZE (cases); i++)
	    if (cnt[s][i] > 0)
	      {
		avg = grub_divmod64 (sum[s][i], cnt[s][i], &r);
		grub_printf ("  %s  %6"PRIuGRUB_UINT64_T" MiB/s (avg)\n",
			     cases[i].label, avg);
	      }
	    else
	      grub_printf ("  %s  Not measurable\n", cases[i].label);
	}
    }

out:
  grub_free (src_raw);
  grub_free (dst_raw);
  grub_free (ov_raw);
}

static grub_command_t cmd;

static grub_err_t
grub_cmd_memmove_bench (grub_command_t command __attribute__ ((unused)),
			int argc, char **args)
{
  unsigned int loops = 1;
  const char *end;
  unsigned long val;

  if (argc >= 1)
    {
      val = grub_strtoul (args[0], &end, 10);
      if (grub_errno != GRUB_ERR_NONE)
	return grub_errno;
      if (*end != '\0')
	return grub_error (GRUB_ERR_BAD_ARGUMENT, "invalid loop count `%s'", args[0]);
      if (val == 0)
	return grub_error (GRUB_ERR_BAD_ARGUMENT, "loop count must be >= 1");
      loops = (unsigned int) val;
    }

  memmove_bench (loops);
  return grub_errno;
}

GRUB_MOD_INIT (memmove_bench)
{
  cmd = grub_register_command ("memmove_bench", grub_cmd_memmove_bench,
			       "[LOOPS]",
			       "Benchmark grub_memmove.");
}

GRUB_MOD_FINI (memmove_bench)
{
  grub_unregister_command (cmd);
}
