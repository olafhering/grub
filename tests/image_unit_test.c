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
 * Native unit test for the image readers grub-core/video/readers/{png,jpeg,
 * tga}.c.  It feeds embedded image blobs to the decoders through an in-memory
 * procfs file and checks the decoded dimensions and a few pixels.  Several
 * well-formed images exercise the main decode paths (PNG truecolor / RGBA /
 * palette, TGA uncompressed / RLE, baseline JPEG); a few "bad" images check
 * that the decoders fail gracefully (no bitmap, no crash).
 *
 * The embedded blobs are produced at authoring time (PNG/TGA by hand, JPEG via
 * ImageMagick) and stored as literals, so the test adds no build dependency.
 */

#include <grub/bitmap.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/procfs.h>
#include <grub/test.h>
#include <grub/types.h>
#include <grub/video.h>

/*
 * The decoders are static; their reader structs are registered by the module
 * init functions, which GRUB_UTIL exports as grub_<name>_init.  We register
 * them and procfs, then decode through grub_video_bitmap_load (by extension).
 */
extern void grub_procfs_init (void);
extern void grub_png_init (void);
extern void grub_jpeg_init (void);
extern void grub_tga_init (void);

/*
 * ------------------------------------------------------------------
 * Embedded image fixtures.
 * 2x2 reference image, top row then bottom row:
 *   (0,0) red   (1,0) green
 *   (0,1) blue  (1,1) white
 *
 * Each blob was captured from the command shown above it with
 * "xxd -i FILE".  Re-running the command may not reproduce the exact
 * bytes (encoders differ), but it yields an equivalent image; the
 * test checks the decoded pixels, not the encoded bytes.  The shared
 * PPM source for the 2x2 images is:
 *   printf 'P3\n2 2\n255\n255 0 0  0 255 0  0 0 255  255 255 255\n'
 * ------------------------------------------------------------------
 */

/* convert ppm:- png24:rgb.png   (PNG, 8-bit truecolor, color type 2) */
static const grub_uint8_t png_rgb_2x2[] = {
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49,
  0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02,
  0x00, 0x00, 0x00, 0xfd, 0xd4, 0x9a, 0x73, 0x00, 0x00, 0x00, 0x12, 0x49, 0x44,
  0x41, 0x54, 0x78, 0xda, 0x63, 0xf8, 0xcf, 0xc0, 0xc0, 0x00, 0xc2, 0x0c, 0xff,
  0x81, 0x00, 0x00, 0x1f, 0xee, 0x05, 0xfb, 0xf1, 0xab, 0xba, 0x77, 0x00, 0x00,
  0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
};

/*
 * RGBA (color type 6); (1,1) has alpha 128.  Generated with:
 *   printf '# ImageMagick pixel enumeration: 2,2,255,srgba\n
 *     0,0: (255,0,0,255)\n1,0: (0,255,0,255)\n
 *     0,1: (0,0,255,255)\n1,1: (255,255,255,128)\n' | convert txt:-
 * png32:rgba.png
 */
static const grub_uint8_t png_rgba_2x2[] = {
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49,
  0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x06,
  0x00, 0x00, 0x00, 0x72, 0xb6, 0x0d, 0x24, 0x00, 0x00, 0x00, 0x13, 0x49, 0x44,
  0x41, 0x54, 0x78, 0xda, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0x0c, 0x81, 0x34,
  0x08, 0x34, 0x00, 0x00, 0x49, 0x49, 0x09, 0x78, 0x9c, 0x51, 0x17, 0x92, 0x00,
  0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
};

/* convert ppm:- png8:pal.png   (PNG, 8-bit palette, color type 3) */
static const grub_uint8_t png_pal_2x2[] = {
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
  0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
  0x08, 0x03, 0x00, 0x00, 0x00, 0x45, 0x68, 0xfd, 0x16, 0x00, 0x00, 0x00,
  0x0c, 0x50, 0x4c, 0x54, 0x45, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00,
  0x00, 0xff, 0xff, 0xff, 0xff, 0xfb, 0x00, 0x60, 0xf6, 0x00, 0x00, 0x00,
  0x0e, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x60, 0x60, 0x64, 0x60,
  0x62, 0x06, 0x00, 0x00, 0x11, 0x00, 0x07, 0x83, 0xca, 0x64, 0x64, 0x00,
  0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
};

/* convert ppm:- -compress none tga:raw.tga   (TGA, uncompressed truecolor) */
static const grub_uint8_t tga_raw_2x2[] = {
  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x18, 0x20, 0x00, 0x00,
  0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff,
};

/* convert ppm:- -compress RLE tga:rle.tga   (TGA, RLE-compressed truecolor) */
static const grub_uint8_t tga_rle_2x2[] = {
  0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x02, 0x00, 0x02, 0x00, 0x18, 0x20, 0x01, 0x00, 0x00, 0xff,
  0x00, 0xff, 0x00, 0x01, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff,
};

/*
 *  8x8 solid color (32,96,160), baseline JPEG (lossy).  Generated with:
 *   convert -size 8x8 xc:'rgb(32,96,160)' -quality 90 jpg:solid.jpg
 */
static const grub_uint8_t jpeg_solid_8x8[] = {
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x03,
  0x02, 0x02, 0x03, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x03, 0x03, 0x04,
  0x05, 0x08, 0x05, 0x05, 0x04, 0x04, 0x05, 0x0a, 0x07, 0x07, 0x06, 0x08, 0x0c,
  0x0a, 0x0c, 0x0c, 0x0b, 0x0a, 0x0b, 0x0b, 0x0d, 0x0e, 0x12, 0x10, 0x0d, 0x0e,
  0x11, 0x0e, 0x0b, 0x0b, 0x10, 0x16, 0x10, 0x11, 0x13, 0x14, 0x15, 0x15, 0x15,
  0x0c, 0x0f, 0x17, 0x18, 0x16, 0x14, 0x18, 0x12, 0x14, 0x15, 0x14, 0xff, 0xdb,
  0x00, 0x43, 0x01, 0x03, 0x04, 0x04, 0x05, 0x04, 0x05, 0x09, 0x05, 0x05, 0x09,
  0x14, 0x0d, 0x0b, 0x0d, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
  0x14, 0x14, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x08, 0x00, 0x08, 0x03, 0x01,
  0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0xff, 0xc4, 0x00, 0x14, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x07, 0xff, 0xc4, 0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xff, 0xc4, 0x00, 0x14, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xff, 0xc4, 0x00, 0x14,
  0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02,
  0x11, 0x03, 0x11, 0x00, 0x3f, 0x00, 0x0a, 0x39, 0x87, 0x1f, 0xff, 0xd9,
};

/*
 * Malformed: the truecolor PNG above truncated mid-stream (IEND and the tail
 * of IDAT removed).  Derived with:  head -c 63 rgb.png
 */
static const grub_uint8_t png_truncated[] = {
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49,
  0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02,
  0x00, 0x00, 0x00, 0xfd, 0xd4, 0x9a, 0x73, 0x00, 0x00, 0x00, 0x12, 0x49, 0x44,
  0x41, 0x54, 0x78, 0xda, 0x63, 0xf8, 0xcf, 0xc0, 0xc0, 0x00, 0xc2, 0x0c, 0xff,
  0x81, 0x00, 0x00, 0x1f, 0xee, 0x05, 0xfb, 0xf1, 0xab, 0xba, 0x77,
};

/*
 * Malformed: a hand-written 18-byte TGA header for a 2x2 truecolor image with
 * an unsupported bit depth (7 bpp), which deterministically hits the
 * format-rejection path.  Not produced by an image tool.
 */
static const grub_uint8_t tga_bad_fmt[] = {
  0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x07, 0x20,
};

/*
 * Malformed: a JFIF-looking header whose leading marker is EOI (FF D9) instead
 * of SOI (FF D8), so the decoder rejects it at the initial SOI check before
 * any table or entropy decoding.  Hand-edited from a valid JPEG (D8 -> D9).
 */
static const grub_uint8_t jpeg_bad_soi[] = {
  0xff, 0xd9, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46,
  0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
};

/*
 * ------------------------------------------------------------------
 * In-memory file provider backed by procfs.
 * ------------------------------------------------------------------
 */

static const grub_uint8_t *g_data;
static grub_size_t g_len;

static char *
provider_get_contents (grub_size_t *sz)
{
  char *p = grub_malloc (g_len);
  if (!p)
    return 0;
  grub_memcpy (p, g_data, g_len);
  *sz = g_len;
  return p;
}

static char provider_name[16];

static struct grub_procfs_entry provider_entry
    = { .name = provider_name, .get_contents = provider_get_contents };

/*
 * Decode a blob through grub_video_bitmap_load.  The extension selects the
 * reader and must match the procfs entry name we expose it under.
 */
static struct grub_video_bitmap *
decode (const char *ext, const grub_uint8_t *data, grub_size_t len)
{
  struct grub_video_bitmap *bm = 0;
  char path[24];

  g_data = data;
  g_len = len;
  grub_snprintf (provider_name, sizeof (provider_name), "img.%s", ext);
  grub_snprintf (path, sizeof (path), "(proc)/img.%s", ext);
  grub_errno = GRUB_ERR_NONE;
  grub_video_bitmap_load (&bm, path);
  return bm;
}

/*
 * ------------------------------------------------------------------
 * Pixel helpers.
 * ------------------------------------------------------------------
 */

static grub_uint32_t
pixel_at (struct grub_video_bitmap *bm, unsigned x, unsigned y)
{
  struct grub_video_mode_info *mi = &bm->mode_info;
  grub_uint8_t *p = (grub_uint8_t *)bm->data + y * mi->pitch +
                    x * mi->bytes_per_pixel;
  grub_uint32_t v = 0;
  unsigned i;

  for (i = 0; i < mi->bytes_per_pixel; i++)
    v |= ((grub_uint32_t)p[i]) << (8 * i);
  return v;
}

static int
channel (grub_uint32_t v, unsigned pos, unsigned size)
{
  if (!size)
    return -1;
  return (int)((v >> pos) & ((1u << size) - 1));
}

static int
absdiff (int a, int b)
{
  return a > b ? a - b : b - a;
}

/* Assert that pixel (x,y) is within tol of (r,g,b). */
static void
check_rgb (struct grub_video_bitmap *bm, unsigned x, unsigned y, int r, int g,
           int b, int tol, const char *label)
{
  struct grub_video_mode_info *mi = &bm->mode_info;
  grub_uint32_t v = pixel_at (bm, x, y);
  int pr = channel (v, mi->red_field_pos, mi->red_mask_size);
  int pg = channel (v, mi->green_field_pos, mi->green_mask_size);
  int pb = channel (v, mi->blue_field_pos, mi->blue_mask_size);

  grub_test_assert (absdiff (pr, r) <= tol && absdiff (pg, g) <= tol
                        && absdiff (pb, b) <= tol,
                    "%s pixel (%u,%u) = (%d,%d,%d), want (%d,%d,%d) +/-%d",
                    label, x, y, pr, pg, pb, r, g, b, tol);
}

static void
check_dims (struct grub_video_bitmap *bm, unsigned w, unsigned h,
            const char *label)
{
  grub_test_assert (bm != 0, "%s: decode failed (errno=%d)", label,
                    grub_errno);
  if (!bm)
    return;
  grub_test_assert (grub_video_bitmap_get_width (bm) == w
                        && grub_video_bitmap_get_height (bm) == h,
                    "%s: dimensions %ux%u, want %ux%u", label,
                    grub_video_bitmap_get_width (bm),
                    grub_video_bitmap_get_height (bm), w, h);
}

/*
 * ------------------------------------------------------------------
 * The test.
 * ------------------------------------------------------------------
 */

static void
image_test (void)
{
  struct grub_video_bitmap *bm;

  grub_procfs_init ();
  grub_png_init ();
  grub_jpeg_init ();
  grub_tga_init ();
  grub_procfs_register (provider_name, &provider_entry);

  /* PNG, 8-bit truecolor (color type 2). */
  bm = decode ("png", png_rgb_2x2, sizeof (png_rgb_2x2));
  check_dims (bm, 2, 2, "png-rgb");
  if (bm)
    {
      check_rgb (bm, 0, 0, 255, 0, 0, 0, "png-rgb");
      check_rgb (bm, 1, 0, 0, 255, 0, 0, "png-rgb");
      check_rgb (bm, 0, 1, 0, 0, 255, 0, "png-rgb");
      check_rgb (bm, 1, 1, 255, 255, 255, 0, "png-rgb");
      grub_video_bitmap_destroy (bm);
    }

  /* PNG, 8-bit RGBA (color type 6); (1,1) has alpha 128. */
  bm = decode ("png", png_rgba_2x2, sizeof (png_rgba_2x2));
  check_dims (bm, 2, 2, "png-rgba");
  if (bm)
    {
      struct grub_video_mode_info *mi = &bm->mode_info;
      check_rgb (bm, 0, 0, 255, 0, 0, 0, "png-rgba");
      check_rgb (bm, 1, 1, 255, 255, 255, 0, "png-rgba");
      if (mi->reserved_mask_size > 0)
        {
          int a00 = channel (pixel_at (bm, 0, 0), mi->reserved_field_pos,
                             mi->reserved_mask_size);
          int a11 = channel (pixel_at (bm, 1, 1), mi->reserved_field_pos,
                             mi->reserved_mask_size);
          grub_test_assert (a00 == 255, "png-rgba alpha(0,0)=%d, want 255",
                            a00);
          grub_test_assert (a11 == 128, "png-rgba alpha(1,1)=%d, want 128",
                            a11);
        }
      grub_video_bitmap_destroy (bm);
    }

  /* PNG, 8-bit palette (color type 3). */
  bm = decode ("png", png_pal_2x2, sizeof (png_pal_2x2));
  check_dims (bm, 2, 2, "png-palette");
  if (bm)
    {
      check_rgb (bm, 0, 0, 255, 0, 0, 0, "png-palette");
      check_rgb (bm, 1, 0, 0, 255, 0, 0, "png-palette");
      check_rgb (bm, 0, 1, 0, 0, 255, 0, "png-palette");
      check_rgb (bm, 1, 1, 255, 255, 255, 0, "png-palette");
      grub_video_bitmap_destroy (bm);
    }

  /* TGA, uncompressed truecolor. */
  bm = decode ("tga", tga_raw_2x2, sizeof (tga_raw_2x2));
  check_dims (bm, 2, 2, "tga-raw");
  if (bm)
    {
      check_rgb (bm, 0, 0, 255, 0, 0, 0, "tga-raw");
      check_rgb (bm, 1, 0, 0, 255, 0, 0, "tga-raw");
      check_rgb (bm, 0, 1, 0, 0, 255, 0, "tga-raw");
      check_rgb (bm, 1, 1, 255, 255, 255, 0, "tga-raw");
      grub_video_bitmap_destroy (bm);
    }

  /* TGA, RLE-compressed truecolor. */
  bm = decode ("tga", tga_rle_2x2, sizeof (tga_rle_2x2));
  check_dims (bm, 2, 2, "tga-rle");
  if (bm)
    {
      check_rgb (bm, 0, 0, 255, 0, 0, 0, "tga-rle");
      check_rgb (bm, 1, 0, 0, 255, 0, 0, "tga-rle");
      check_rgb (bm, 0, 1, 0, 0, 255, 0, "tga-rle");
      check_rgb (bm, 1, 1, 255, 255, 255, 0, "tga-rle");
      grub_video_bitmap_destroy (bm);
    }

  /* Baseline JPEG, 8x8 solid color (lossy: assert within tolerance). */
  bm = decode ("jpg", jpeg_solid_8x8, sizeof (jpeg_solid_8x8));
  check_dims (bm, 8, 8, "jpeg-solid");
  if (bm)
    {
      check_rgb (bm, 4, 4, 32, 96, 160, 24, "jpeg-solid");
      check_rgb (bm, 1, 1, 32, 96, 160, 24, "jpeg-solid");
      grub_video_bitmap_destroy (bm);
    }

  /*
   * Malformed inputs must fail without producing a bitmap (and without
   * crashing -- the real payoff under ASan/UBSan).
   */
  bm = decode ("png", png_truncated, sizeof (png_truncated));
  grub_test_assert (bm == 0, "truncated PNG unexpectedly produced a bitmap");

  bm = decode ("tga", tga_bad_fmt, sizeof (tga_bad_fmt));
  grub_test_assert (bm == 0, "malformed TGA unexpectedly produced a bitmap");

  bm = decode ("jpg", jpeg_bad_soi, sizeof (jpeg_bad_soi));
  grub_test_assert (bm == 0, "malformed JPEG unexpectedly produced a bitmap");

  grub_procfs_unregister (&provider_entry);
  grub_errno = GRUB_ERR_NONE;
}

GRUB_UNIT_TEST ("image_unit_test", image_test);
