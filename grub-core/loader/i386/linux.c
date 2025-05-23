/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2006,2007,2008,2009,2010  Free Software Foundation, Inc.
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

#include <grub/loader.h>
#include <grub/memory.h>
#include <grub/normal.h>
#include <grub/file.h>
#include <grub/disk.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/types.h>
#include <grub/dl.h>
#include <grub/mm.h>
#include <grub/term.h>
#include <grub/cpu/linux.h>
#include <grub/video.h>
#include <grub/video_fb.h>
#include <grub/command.h>
#include <grub/i386/relocator.h>
#include <grub/i18n.h>
#include <grub/lib/cmdline.h>
#include <grub/linux.h>
#include <grub/machine/kernel.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

#ifdef GRUB_MACHINE_PCBIOS
#include <grub/i386/pc/vesa_modes_table.h>
#endif

#ifdef GRUB_MACHINE_EFI
#include <grub/efi/efi.h>
#include <grub/efi/sb.h>
#define HAS_VGA_TEXT 0
#define DEFAULT_VIDEO_MODE "auto"
#define ACCEPTS_PURE_TEXT 0
#elif defined (GRUB_MACHINE_IEEE1275)
#include <grub/ieee1275/ieee1275.h>
#define HAS_VGA_TEXT 0
#define DEFAULT_VIDEO_MODE "text"
#define ACCEPTS_PURE_TEXT 1
#else
#include <grub/i386/pc/vbe.h>
#include <grub/i386/pc/console.h>
#define HAS_VGA_TEXT 1
#define DEFAULT_VIDEO_MODE "text"
#define ACCEPTS_PURE_TEXT 1
#endif

static grub_dl_t my_mod;

static grub_size_t linux_mem_size;
static int loaded;
static void *prot_mode_mem;
static grub_addr_t prot_mode_target;
static void *initrd_mem;
static grub_addr_t initrd_mem_target;
static grub_size_t prot_init_space;
static struct grub_relocator *relocator = NULL;
static void *efi_mmap_buf;
static grub_size_t maximal_cmdline_size;
static struct linux_kernel_params linux_params;
static char *linux_cmdline;
#ifdef GRUB_MACHINE_EFI
static grub_efi_uintn_t efi_mmap_size;
#else
static const grub_size_t efi_mmap_size = 0;
#endif

/* FIXME */
#if 0
struct idt_descriptor
{
  grub_uint16_t limit;
  void *base;
} GRUB_PACKED;

static struct idt_descriptor idt_desc =
  {
    0,
    0
  };
#endif

static inline grub_size_t
page_align (grub_size_t size)
{
  return (size + (1 << 12) - 1) & (~((1 << 12) - 1));
}

/* Helper for find_mmap_size.  */
static int
count_hook (grub_uint64_t addr __attribute__ ((unused)),
	    grub_uint64_t size __attribute__ ((unused)),
	    grub_memory_type_t type __attribute__ ((unused)), void *data)
{
  grub_size_t *count = data;

  (*count)++;
  return 0;
}

/* Find the optimal number of pages for the memory map. */
static grub_size_t
find_mmap_size (void)
{
  grub_size_t count = 0, mmap_size;

  grub_mmap_iterate (count_hook, &count);

  mmap_size = count * sizeof (struct grub_boot_e820_entry);

  /* Increase the size a bit for safety, because GRUB allocates more on
     later.  */
  mmap_size += (1 << 12);

  return page_align (mmap_size);
}

static void
free_pages (void)
{
  grub_relocator_unload (relocator);
  relocator = NULL;
  prot_mode_mem = initrd_mem = 0;
  prot_mode_target = initrd_mem_target = 0;
}

/* Allocate pages for the real mode code and the protected mode code
   for linux as well as a memory map buffer.  */
static grub_err_t
allocate_pages (grub_size_t prot_size, grub_size_t *align,
		grub_size_t min_align, int relocatable,
		grub_uint64_t preferred_address)
{
  grub_err_t err;

  if (prot_size == 0)
    prot_size = 1;

  prot_size = page_align (prot_size);

  /* Initialize the memory pointers with NULL for convenience.  */
  free_pages ();

  relocator = grub_relocator_new ();
  if (!relocator)
    {
      err = grub_errno;
      goto fail;
    }

  /* FIXME: Should request low memory from the heap when this feature is
     implemented.  */

  {
    grub_relocator_chunk_t ch;
    if (relocatable)
      {
	err = grub_relocator_alloc_chunk_align (relocator, &ch,
						preferred_address,
						preferred_address,
						prot_size, 1,
						GRUB_RELOCATOR_PREFERENCE_LOW,
						1);
	for (; err && *align + 1 > min_align; (*align)--)
	  {
	    grub_errno = GRUB_ERR_NONE;
	    err = grub_relocator_alloc_chunk_align (relocator, &ch, 0x1000000,
						    UP_TO_TOP32 (prot_size),
						    prot_size, 1 << *align,
						    GRUB_RELOCATOR_PREFERENCE_LOW,
						    1);
	  }
	if (err)
	  goto fail;
      }
    else
      err = grub_relocator_alloc_chunk_addr (relocator, &ch,
					     preferred_address,
					     prot_size);
    if (err)
      goto fail;
    prot_mode_mem = get_virtual_current_address (ch);
    prot_mode_target = get_physical_target_address (ch);
  }

  grub_dprintf ("linux", "prot_mode_mem = %p, prot_mode_target = %lx, prot_size = %x\n",
                prot_mode_mem, (unsigned long) prot_mode_target,
		(unsigned) prot_size);
  return GRUB_ERR_NONE;

 fail:
  free_pages ();
  return err;
}

static grub_err_t
grub_e820_add_region (struct grub_boot_e820_entry *e820_entry, int *e820_num,
                      grub_uint64_t start, grub_uint64_t size,
                      grub_uint32_t type)
{
  int n = *e820_num;

  if ((n > 0) && (e820_entry[n - 1].addr + e820_entry[n - 1].size == start) &&
      (e820_entry[n - 1].type == type))
    e820_entry[n - 1].size += size;
  else
    {
      e820_entry[n].addr = start;
      e820_entry[n].size = size;
      e820_entry[n].type = type;
      (*e820_num)++;
    }
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_linux_setup_video (struct linux_kernel_params *params)
{
  struct grub_video_mode_info mode_info;
  void *framebuffer;
  grub_err_t err;
  grub_video_driver_id_t driver_id;
  const char *gfxlfbvar = grub_env_get ("gfxpayloadforcelfb");

  driver_id = grub_video_get_driver_id ();

  if (driver_id == GRUB_VIDEO_DRIVER_NONE)
    return 1;

  err = grub_video_get_info_and_fini (&mode_info, &framebuffer);

  if (err)
    {
      grub_errno = GRUB_ERR_NONE;
      return 1;
    }

  params->screen_info.lfb_width = mode_info.width;
  params->screen_info.lfb_height = mode_info.height;
  params->screen_info.lfb_depth = mode_info.bpp;
  params->screen_info.lfb_linelength = mode_info.pitch;

  params->screen_info.lfb_base = (grub_size_t) framebuffer;

#if defined (GRUB_MACHINE_EFI) && defined (__x86_64__)
  params->screen_info.ext_lfb_base = (grub_size_t) (((grub_uint64_t)(grub_size_t) framebuffer) >> 32);
  params->screen_info.capabilities |= VIDEO_CAPABILITY_64BIT_BASE;
#endif

  params->screen_info.lfb_size = ALIGN_UP (params->screen_info.lfb_linelength * params->screen_info.lfb_height, 65536);

  params->screen_info.red_size = mode_info.red_mask_size;
  params->screen_info.red_pos = mode_info.red_field_pos;
  params->screen_info.green_size = mode_info.green_mask_size;
  params->screen_info.green_pos = mode_info.green_field_pos;
  params->screen_info.blue_size = mode_info.blue_mask_size;
  params->screen_info.blue_pos = mode_info.blue_field_pos;
  params->screen_info.rsvd_size = mode_info.reserved_mask_size;
  params->screen_info.rsvd_pos = mode_info.reserved_field_pos;

  if (gfxlfbvar && (gfxlfbvar[0] == '1' || gfxlfbvar[0] == 'y'))
    params->screen_info.orig_video_isVGA = GRUB_VIDEO_LINUX_TYPE_SIMPLE;
  else
    {
      switch (driver_id)
	{
	case GRUB_VIDEO_DRIVER_VBE:
	  params->screen_info.lfb_size >>= 16;
	  params->screen_info.orig_video_isVGA = GRUB_VIDEO_LINUX_TYPE_VESA;
	  break;

	case GRUB_VIDEO_DRIVER_EFI_UGA:
	case GRUB_VIDEO_DRIVER_EFI_GOP:
	  params->screen_info.orig_video_isVGA = GRUB_VIDEO_LINUX_TYPE_EFIFB;
	  break;

	  /* FIXME: check if better id is available.  */
	case GRUB_VIDEO_DRIVER_SM712:
	case GRUB_VIDEO_DRIVER_SIS315PRO:
	case GRUB_VIDEO_DRIVER_VGA:
	case GRUB_VIDEO_DRIVER_CIRRUS:
	case GRUB_VIDEO_DRIVER_BOCHS:
	case GRUB_VIDEO_DRIVER_RADEON_FULOONG2E:
	case GRUB_VIDEO_DRIVER_RADEON_YEELOONG3A:
	case GRUB_VIDEO_DRIVER_IEEE1275:
	case GRUB_VIDEO_DRIVER_COREBOOT:
	  /* Make gcc happy. */
	case GRUB_VIDEO_DRIVER_XEN:
	case GRUB_VIDEO_DRIVER_SDL:
	case GRUB_VIDEO_DRIVER_NONE:
	case GRUB_VIDEO_ADAPTER_CAPTURE:
	  params->screen_info.orig_video_isVGA = GRUB_VIDEO_LINUX_TYPE_SIMPLE;
	  break;
	}
    }

#ifdef GRUB_MACHINE_PCBIOS
  /* VESA packed modes may come with zeroed mask sizes, which need
     to be set here according to DAC Palette width.  If we don't,
     this results in Linux displaying a black screen.  */
  if (driver_id == GRUB_VIDEO_DRIVER_VBE && mode_info.bpp <= 8)
    {
      struct grub_vbe_info_block controller_info;
      int status;
      int width = 8;

      status = grub_vbe_bios_get_controller_info (&controller_info);

      if (status == GRUB_VBE_STATUS_OK &&
	  (controller_info.capabilities & GRUB_VBE_CAPABILITY_DACWIDTH))
	status = grub_vbe_bios_set_dac_palette_width (&width);

      if (status != GRUB_VBE_STATUS_OK)
	/* 6 is default after mode reset.  */
	width = 6;

      params->screen_info.red_size = params->screen_info.green_size
	= params->screen_info.blue_size = width;
      params->screen_info.rsvd_size = 0;
    }
#endif

  return GRUB_ERR_NONE;
}

/* Context for grub_linux_boot.  */
struct grub_linux_boot_ctx
{
  grub_addr_t real_mode_target;
  grub_size_t real_size;
  struct linux_kernel_params *params;
  int e820_num;
};

/* Helper for grub_linux_boot.  */
static int
grub_linux_boot_mmap_find (grub_uint64_t addr, grub_uint64_t size,
			   grub_memory_type_t type, void *data)
{
  struct grub_linux_boot_ctx *ctx = data;

  /* We must put real mode code in the traditional space.  */
  if (type != GRUB_MEMORY_AVAILABLE || addr > 0x90000)
    return 0;

  if (addr + size < 0x10000)
    return 0;

  if (addr < 0x10000)
    {
      size += addr - 0x10000;
      addr = 0x10000;
    }

  if (addr + size > 0x90000)
    size = 0x90000 - addr;

  if (ctx->real_size + efi_mmap_size > size)
    return 0;

  grub_dprintf ("linux", "addr = %lx, size = %x, need_size = %x\n",
		(unsigned long) addr,
		(unsigned) size,
		(unsigned) (ctx->real_size + efi_mmap_size));
  ctx->real_mode_target = ((addr + size) - (ctx->real_size + efi_mmap_size));
  return 1;
}

/* GRUB types conveniently match E820 types.  */
static int
grub_linux_boot_mmap_fill (grub_uint64_t addr, grub_uint64_t size,
			   grub_memory_type_t type, void *data)
{
  struct grub_linux_boot_ctx *ctx = data;

  if (grub_e820_add_region (ctx->params->e820_table, &ctx->e820_num,
			    addr, size, type))
    return 1;

  return 0;
}

static grub_err_t
grub_linux_boot (void)
{
  grub_err_t err = 0;
  const char *modevar;
  char *tmp;
  struct grub_relocator32_state state;
  void *real_mode_mem;
  struct grub_linux_boot_ctx ctx = {
    .real_mode_target = 0
  };
  grub_size_t mmap_size;
  grub_size_t cl_offset;

#ifdef GRUB_MACHINE_IEEE1275
  {
    const char *bootpath;
    grub_ssize_t len;

    bootpath = grub_env_get ("root");
    if (bootpath)
      grub_ieee1275_set_property (grub_ieee1275_chosen,
				  "bootpath", bootpath,
				  grub_strlen (bootpath) + 1,
				  &len);
    linux_params.olpc_ofw_header.ofw_magic = GRUB_LINUX_OFW_SIGNATURE;
    linux_params.olpc_ofw_header.ofw_version = 1;
    linux_params.olpc_ofw_header.cif_handler = (grub_uint32_t) grub_ieee1275_entry_fn;
    linux_params.olpc_ofw_header.irq_desc_table = 0;
  }
#endif

  modevar = grub_env_get ("gfxpayload");

  /* Now all graphical modes are acceptable.
     May change in future if we have modes without framebuffer.  */
  if (modevar && *modevar != 0)
    {
      tmp = grub_xasprintf ("%s;" DEFAULT_VIDEO_MODE, modevar);
      if (! tmp)
	return grub_errno;
#if ACCEPTS_PURE_TEXT
      err = grub_video_set_mode (tmp, 0, 0);
#else
      err = grub_video_set_mode (tmp, GRUB_VIDEO_MODE_TYPE_PURE_TEXT, 0);
#endif
      grub_free (tmp);
    }
  else       /* We can't go back to text mode from coreboot fb.  */
#ifdef GRUB_MACHINE_COREBOOT
    if (grub_video_get_driver_id () == GRUB_VIDEO_DRIVER_COREBOOT)
      err = GRUB_ERR_NONE;
    else
#endif
      {
#if ACCEPTS_PURE_TEXT
	err = grub_video_set_mode (DEFAULT_VIDEO_MODE, 0, 0);
#else
	err = grub_video_set_mode (DEFAULT_VIDEO_MODE,
				 GRUB_VIDEO_MODE_TYPE_PURE_TEXT, 0);
#endif
      }

  if (err)
    {
      grub_print_error ();
      grub_puts_ (N_("Booting in blind mode"));
      grub_errno = GRUB_ERR_NONE;
    }

  if (grub_linux_setup_video (&linux_params))
    {
#if defined (GRUB_MACHINE_PCBIOS) || defined (GRUB_MACHINE_COREBOOT) || defined (GRUB_MACHINE_QEMU)
      linux_params.screen_info.orig_video_isVGA = GRUB_VIDEO_LINUX_TYPE_TEXT;
      linux_params.screen_info.orig_video_mode = 0x3;
#else
      linux_params.screen_info.orig_video_isVGA = 0;
      linux_params.screen_info.orig_video_mode = 0;
      linux_params.screen_info.orig_video_cols = 0;
      linux_params.screen_info.orig_video_lines = 0;
#endif
    }


#ifndef GRUB_MACHINE_IEEE1275
  if (linux_params.screen_info.orig_video_isVGA == GRUB_VIDEO_LINUX_TYPE_TEXT)
#endif
    {
      grub_term_output_t term;
      int found = 0;
      FOR_ACTIVE_TERM_OUTPUTS(term)
	if (grub_strcmp (term->name, "vga_text") == 0
	    || grub_strcmp (term->name, "console") == 0
	    || grub_strcmp (term->name, "ofconsole") == 0)
	  {
	    struct grub_term_coordinate pos = grub_term_getxy (term);
	    linux_params.screen_info.orig_x = pos.x;
	    linux_params.screen_info.orig_y = pos.y;
	    linux_params.screen_info.orig_video_cols = grub_term_width (term);
	    linux_params.screen_info.orig_video_lines = grub_term_height (term);
	    found = 1;
	    break;
	  }
      if (!found)
	{
	  linux_params.screen_info.orig_x = 0;
	  linux_params.screen_info.orig_y = 0;
	  linux_params.screen_info.orig_video_cols = 80;
	  linux_params.screen_info.orig_video_lines = 25;
	}
    }

#ifdef GRUB_KERNEL_USE_RSDP_ADDR
  linux_params.acpi_rsdp_addr = grub_le_to_cpu64 (grub_rsdp_addr);
#endif

  mmap_size = find_mmap_size ();
  /* Make sure that each size is aligned to a page boundary.  */
  cl_offset = ALIGN_UP (mmap_size + sizeof (linux_params), 4096);
  if (cl_offset < ((grub_size_t) linux_params.hdr.setup_sects << GRUB_DISK_SECTOR_BITS))
    cl_offset = ALIGN_UP ((grub_size_t) (linux_params.hdr.setup_sects
					 << GRUB_DISK_SECTOR_BITS), 4096);
  ctx.real_size = ALIGN_UP (cl_offset + maximal_cmdline_size, 4096);

#ifdef GRUB_MACHINE_EFI
  efi_mmap_size = grub_efi_find_mmap_size ();
  if (efi_mmap_size == 0)
    return grub_errno;
#endif

  grub_dprintf ("linux", "real_size = %x, mmap_size = %x\n",
		(unsigned) ctx.real_size, (unsigned) mmap_size);

#ifdef GRUB_MACHINE_EFI
  grub_efi_mmap_iterate (grub_linux_boot_mmap_find, &ctx, 1);
  if (! ctx.real_mode_target)
    grub_efi_mmap_iterate (grub_linux_boot_mmap_find, &ctx, 0);
#else
  grub_mmap_iterate (grub_linux_boot_mmap_find, &ctx);
#endif
  grub_dprintf ("linux", "real_mode_target = %lx, real_size = %x, efi_mmap_size = %x\n",
                (unsigned long) ctx.real_mode_target,
		(unsigned) ctx.real_size,
		(unsigned) efi_mmap_size);

  if (! ctx.real_mode_target)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY, "cannot allocate real mode pages");

  {
    grub_relocator_chunk_t ch;
    grub_size_t sz;

    if (grub_add (ctx.real_size, efi_mmap_size, &sz))
      return GRUB_ERR_OUT_OF_RANGE;

    err = grub_relocator_alloc_chunk_addr (relocator, &ch,
					   ctx.real_mode_target, sz);
    if (err)
     return err;
    real_mode_mem = get_virtual_current_address (ch);
  }
  efi_mmap_buf = (grub_uint8_t *) real_mode_mem + ctx.real_size;

  grub_dprintf ("linux", "real_mode_mem = %p\n",
                real_mode_mem);

  ctx.params = real_mode_mem;

  *ctx.params = linux_params;
  ctx.params->hdr.cmd_line_ptr = ctx.real_mode_target + cl_offset;
  grub_memcpy ((char *) ctx.params + cl_offset, linux_cmdline,
	       maximal_cmdline_size);

  grub_dprintf ("linux", "code32_start = %x\n",
		(unsigned) ctx.params->hdr.code32_start);

  ctx.e820_num = 0;
  if (grub_mmap_iterate (grub_linux_boot_mmap_fill, &ctx))
    return grub_errno;
  ctx.params->e820_entries = ctx.e820_num;

#ifdef GRUB_MACHINE_EFI
  {
    grub_efi_uintn_t efi_desc_size;
    grub_size_t efi_mmap_target;
    grub_efi_uint32_t efi_desc_version;

    ctx.params->secure_boot = grub_efi_get_secureboot ();

    err = grub_efi_finish_boot_services (&efi_mmap_size, efi_mmap_buf, NULL,
					 &efi_desc_size, &efi_desc_version);
    if (err)
      return err;

    /* Note that no boot services are available from here.  */
    efi_mmap_target = ctx.real_mode_target
      + ((grub_uint8_t *) efi_mmap_buf - (grub_uint8_t *) real_mode_mem);
    /* Pass EFI parameters.  */
    if (grub_le_to_cpu16 (ctx.params->hdr.version) >= 0x0208)
      {
	ctx.params->efi_info.v0208.efi_memdesc_size = efi_desc_size;
	ctx.params->efi_info.v0208.efi_memdesc_version = efi_desc_version;
	ctx.params->efi_info.v0208.efi_memmap = efi_mmap_target;
	ctx.params->efi_info.v0208.efi_memmap_size = efi_mmap_size;

#ifdef __x86_64__
	ctx.params->efi_info.v0208.efi_memmap_hi = (efi_mmap_target >> 32);
#endif
      }
    else if (grub_le_to_cpu16 (ctx.params->hdr.version) >= 0x0206)
      {
	ctx.params->efi_info.v0206.efi_memdesc_size = efi_desc_size;
	ctx.params->efi_info.v0206.efi_memdesc_version = efi_desc_version;
	ctx.params->efi_info.v0206.efi_memmap = efi_mmap_target;
	ctx.params->efi_info.v0206.efi_memmap_size = efi_mmap_size;
      }
    else if (grub_le_to_cpu16 (ctx.params->hdr.version) >= 0x0204)
      {
	ctx.params->efi_info.v0204.efi_memdesc_size = efi_desc_size;
	ctx.params->efi_info.v0204.efi_memdesc_version = efi_desc_version;
	ctx.params->efi_info.v0204.efi_memmap = efi_mmap_target;
	ctx.params->efi_info.v0204.efi_memmap_size = efi_mmap_size;
      }
  }
#endif

#if defined (__x86_64__) && defined (GRUB_MACHINE_EFI)
  if (grub_le_to_cpu16 (ctx.params->hdr.version) >= 0x020c &&
      (linux_params.hdr.xloadflags & LINUX_X86_XLF_KERNEL_64) != 0)
    {
      struct grub_relocator64_efi_state state64;

      state64.rsi = ctx.real_mode_target;
      state64.rip = ctx.params->hdr.code32_start + LINUX_X86_STARTUP64_OFFSET;
      return grub_relocator64_efi_boot (relocator, state64);
    }
#endif

  /* FIXME.  */
  /*  asm volatile ("lidt %0" : : "m" (idt_desc)); */
  state.ebp = state.edi = state.ebx = 0;
  state.esi = ctx.real_mode_target;
  state.esp = ctx.real_mode_target;
  state.eip = ctx.params->hdr.code32_start;
  return grub_relocator32_boot (relocator, state, 0);
}

static grub_err_t
grub_linux_unload (void)
{
  grub_dl_unref (my_mod);
  loaded = 0;
  grub_free (linux_cmdline);
  linux_cmdline = 0;
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_cmd_linux (grub_command_t cmd __attribute__ ((unused)),
		int argc, char *argv[])
{
  grub_file_t file = 0;
  struct linux_i386_kernel_header lh;
  grub_uint8_t setup_sects;
  grub_size_t real_size, prot_size, prot_file_size;
  grub_ssize_t len;
  int i;
  grub_size_t align, min_align;
  int relocatable;
  grub_uint64_t preferred_address = GRUB_LINUX_BZIMAGE_ADDR;

  grub_dl_ref (my_mod);

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  file = grub_file_open (argv[0], GRUB_FILE_TYPE_LINUX_KERNEL);
  if (! file)
    goto fail;

  if (grub_file_read (file, &lh, sizeof (lh)) != sizeof (lh))
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
		    argv[0]);
      goto fail;
    }

  if (lh.boot_flag != grub_cpu_to_le16_compile_time (0xaa55))
    {
      grub_error (GRUB_ERR_BAD_OS, "invalid magic number");
      goto fail;
    }

  if (lh.setup_sects > GRUB_LINUX_MAX_SETUP_SECTS)
    {
      grub_error (GRUB_ERR_BAD_OS, "too many setup sectors");
      goto fail;
    }

  /* FIXME: 2.03 is not always good enough (Linux 2.4 can be 2.03 and
     still not support 32-bit boot.  */
  if (lh.header != grub_cpu_to_le32_compile_time (GRUB_LINUX_I386_MAGIC_SIGNATURE)
      || grub_le_to_cpu16 (lh.version) < 0x0203)
    {
      grub_error (GRUB_ERR_BAD_OS, "version too old for 32-bit boot"
#ifdef GRUB_MACHINE_PCBIOS
		  " (try with `linux16')"
#endif
		  );
      goto fail;
    }

  if (! (lh.loadflags & GRUB_LINUX_FLAG_BIG_KERNEL))
    {
      grub_error (GRUB_ERR_BAD_OS, "zImage doesn't support 32-bit boot"
#ifdef GRUB_MACHINE_PCBIOS
		  " (try with `linux16')"
#endif
		  );
      goto fail;
    }

  if (grub_le_to_cpu16 (lh.version) >= 0x0206)
    maximal_cmdline_size = grub_le_to_cpu32 (lh.cmdline_size) + 1;
  else
    maximal_cmdline_size = 256;

  if (maximal_cmdline_size < 128)
    maximal_cmdline_size = 128;

  setup_sects = lh.setup_sects;

  /* If SETUP_SECTS is not set, set it to the default (4).  */
  if (! setup_sects)
    setup_sects = GRUB_LINUX_DEFAULT_SETUP_SECTS;

  real_size = setup_sects << GRUB_DISK_SECTOR_BITS;
  prot_file_size = grub_file_size (file) - real_size - GRUB_DISK_SECTOR_SIZE;

  if (grub_le_to_cpu16 (lh.version) >= 0x205
      && lh.kernel_alignment != 0
      && ((lh.kernel_alignment - 1) & lh.kernel_alignment) == 0)
    {
      for (align = 0; align < 32; align++)
	if (grub_le_to_cpu32 (lh.kernel_alignment) & (1 << align))
	  break;
      relocatable = lh.relocatable;
    }
  else
    {
      align = 0;
      relocatable = 0;
    }

  if (grub_le_to_cpu16 (lh.version) >= 0x020a)
    {
      min_align = lh.min_alignment;
      prot_size = grub_le_to_cpu32 (lh.init_size);
      prot_init_space = page_align (prot_size);
      if (relocatable)
	preferred_address = grub_le_to_cpu64 (lh.pref_address);
    }
  else
    {
      min_align = align;
      prot_size = prot_file_size;
      /* Usually, the compression ratio is about 50%.  */
      prot_init_space = page_align (prot_size) * 3;
    }

  if (allocate_pages (prot_size, &align,
		      min_align, relocatable,
		      preferred_address))
    goto fail;

  grub_memset (&linux_params, 0, sizeof (linux_params));

  /*
   * The Linux 32-bit boot protocol defines the setup header end
   * to be at 0x202 + the byte value at 0x201.
   */
  len = 0x202 + *((char *) &lh.jump + 1);

  /* Verify the struct is big enough so we do not write past the end. */
  if (len > (char *) &linux_params.edd_mbr_sig_buffer - (char *) &linux_params) {
    grub_error (GRUB_ERR_BAD_OS, "Linux setup header too big");
    goto fail;
  }

  grub_memcpy (&linux_params.hdr.setup_sects, &lh.setup_sects, len - 0x1F1);

  /* We've already read lh so there is no need to read it second time. */
  len -= sizeof(lh);

  if ((len > 0) &&
      (grub_file_read (file, (char *) &linux_params + sizeof (lh), len) != len))
    {
      if (!grub_errno)
	grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
		    argv[0]);
      goto fail;
    }

  linux_params.hdr.code32_start = prot_mode_target + lh.code32_start - GRUB_LINUX_BZIMAGE_ADDR;
  linux_params.hdr.kernel_alignment = ((grub_uint32_t) 1 << align);
  linux_params.hdr.boot_flag = 0;
  linux_params.hdr.type_of_loader = GRUB_LINUX_BOOT_LOADER_TYPE;

  /* These two are used (instead of cmd_line_ptr) by older versions of Linux,
     and otherwise ignored.  */
  linux_params.screen_info.cl_magic = GRUB_LINUX_CL_MAGIC;
  linux_params.screen_info.cl_offset = 0x1000;

  linux_params.hdr.ramdisk_image = 0;
  linux_params.hdr.ramdisk_size = 0;

  linux_params.hdr.heap_end_ptr = GRUB_LINUX_HEAP_END_OFFSET;
  linux_params.hdr.loadflags |= GRUB_LINUX_FLAG_CAN_USE_HEAP;

  /* These are not needed to be precise, because Linux uses these values
     only to raise an error when the decompression code cannot find good
     space.  */
  linux_params.screen_info.ext_mem_k = ((32 * 0x100000) >> 10);
  linux_params.alt_mem_k = ((32 * 0x100000) >> 10);

  /* Ignored by Linux.  */
  linux_params.screen_info.orig_video_page = 0;

  /* Only used when `video_mode == 0x7', otherwise ignored.  */
  linux_params.screen_info.orig_video_ega_bx = 0;

  linux_params.screen_info.orig_video_points = 16; /* XXX */

#ifdef GRUB_MACHINE_EFI
#ifdef __x86_64__
  if (grub_le_to_cpu16 (linux_params.hdr.version) < 0x0208 &&
      ((grub_addr_t) grub_efi_system_table >> 32) != 0) {
    grub_errno = grub_error (GRUB_ERR_BAD_OS, "kernel does not support 64-bit addressing");
    goto fail;
  }
#endif

  if (grub_le_to_cpu16 (linux_params.hdr.version) >= 0x0208)
    {
      linux_params.efi_info.v0208.efi_loader_signature = GRUB_LINUX_EFI_SIGNATURE;
      linux_params.efi_info.v0208.efi_systab = (grub_uint32_t) (grub_addr_t) grub_efi_system_table;
#ifdef __x86_64__
      linux_params.efi_info.v0208.efi_systab_hi = (grub_uint32_t) ((grub_uint64_t) grub_efi_system_table >> 32);
#endif
    }
  else if (grub_le_to_cpu16 (linux_params.hdr.version) >= 0x0206)
    {
      linux_params.efi_info.v0206.efi_loader_signature = GRUB_LINUX_EFI_SIGNATURE;
      linux_params.efi_info.v0206.efi_systab = (grub_uint32_t) (grub_addr_t) grub_efi_system_table;
    }
  else if (grub_le_to_cpu16 (linux_params.hdr.version) >= 0x0204)
    {
      linux_params.efi_info.v0204.efi_loader_signature = GRUB_LINUX_EFI_SIGNATURE_0204;
      linux_params.efi_info.v0204.efi_systab = (grub_uint32_t) (grub_addr_t) grub_efi_system_table;
    }
#endif

  /* The other parameters are filled when booting.  */

  grub_file_seek (file, real_size + GRUB_DISK_SECTOR_SIZE);

  grub_dprintf ("linux", "bzImage, setup=0x%x, size=0x%x\n",
		(unsigned) real_size, (unsigned) prot_size);

  /* Look for memory size and video mode specified on the command line.  */
  linux_mem_size = 0;
  for (i = 1; i < argc; i++)
#ifdef GRUB_MACHINE_PCBIOS
    if (grub_memcmp (argv[i], "vga=", 4) == 0)
      {
	/* Video mode selection support.  */
	char *val = argv[i] + 4;
	unsigned vid_mode = GRUB_LINUX_VID_MODE_NORMAL;
	struct grub_vesa_mode_table_entry *linux_mode;
	grub_err_t err;
	char *buf;

	grub_dl_load ("vbe");

	if (grub_strcmp (val, "normal") == 0)
	  vid_mode = GRUB_LINUX_VID_MODE_NORMAL;
	else if (grub_strcmp (val, "ext") == 0)
	  vid_mode = GRUB_LINUX_VID_MODE_EXTENDED;
	else if (grub_strcmp (val, "ask") == 0)
	  {
	    grub_puts_ (N_("Legacy `ask' parameter no longer supported."));

	    /* We usually would never do this in a loader, but "vga=ask" means user
	       requested interaction, so it can't hurt to request keyboard input.  */
	    grub_wait_after_message ();

	    goto fail;
	  }
	else
	  vid_mode = (grub_uint16_t) grub_strtoul (val, 0, 0);

	switch (vid_mode)
	  {
	  case 0:
	  case GRUB_LINUX_VID_MODE_NORMAL:
	    grub_env_set ("gfxpayload", "text");
	    grub_printf_ (N_("%s is deprecated. "
			     "Use set gfxpayload=%s before "
			     "linux command instead.\n"),
			  argv[i], "text");
	    break;

	  case 1:
	  case GRUB_LINUX_VID_MODE_EXTENDED:
	    /* FIXME: support 80x50 text. */
	    grub_env_set ("gfxpayload", "text");
	    grub_printf_ (N_("%s is deprecated. "
			     "Use set gfxpayload=%s before "
			     "linux command instead.\n"),
			  argv[i], "text");
	    break;
	  default:
	    /* Ignore invalid values.  */
	    if (vid_mode < GRUB_VESA_MODE_TABLE_START ||
		vid_mode > GRUB_VESA_MODE_TABLE_END)
	      {
		grub_env_set ("gfxpayload", "text");
		/* TRANSLATORS: "x" has to be entered in, like an identifier,
		   so please don't use better Unicode codepoints.  */
		grub_printf_ (N_("%s is deprecated. VGA mode %d isn't recognized. "
				 "Use set gfxpayload=WIDTHxHEIGHT[xDEPTH] "
				 "before linux command instead.\n"),
			     argv[i], vid_mode);
		break;
	      }

	    linux_mode = &grub_vesa_mode_table[vid_mode
					       - GRUB_VESA_MODE_TABLE_START];

	    buf = grub_xasprintf ("%ux%ux%u,%ux%u",
				 linux_mode->width, linux_mode->height,
				 linux_mode->depth,
				 linux_mode->width, linux_mode->height);
	    if (! buf)
	      goto fail;

	    grub_printf_ (N_("%s is deprecated. "
			     "Use set gfxpayload=%s before "
			     "linux command instead.\n"),
			 argv[i], buf);
	    err = grub_env_set ("gfxpayload", buf);
	    grub_free (buf);
	    if (err)
	      goto fail;
	  }
      }
    else
#endif /* GRUB_MACHINE_PCBIOS */
    if (grub_memcmp (argv[i], "mem=", 4) == 0)
      {
	const char *val = argv[i] + 4;

	linux_mem_size = grub_strtoul (val, &val, 0);

	if (grub_errno)
	  {
	    grub_errno = GRUB_ERR_NONE;
	    linux_mem_size = 0;
	  }
	else
	  {
	    int shift = 0;

	    switch (grub_tolower (val[0]))
	      {
	      case 'g':
		shift += 10;
		/* FALLTHROUGH */
	      case 'm':
		shift += 10;
		/* FALLTHROUGH */
	      case 'k':
		shift += 10;
		/* FALLTHROUGH */
	      default:
		break;
	      }

	    /* Check an overflow.  */
	    if (linux_mem_size > (~0UL >> shift))
	      linux_mem_size = 0;
	    else
	      linux_mem_size <<= shift;
	  }
      }
    else if (grub_memcmp (argv[i], "quiet", sizeof ("quiet") - 1) == 0)
      {
	linux_params.hdr.loadflags |= GRUB_LINUX_FLAG_QUIET;
      }

  /* Create kernel command line.  */
  linux_cmdline = grub_zalloc (maximal_cmdline_size + 1);
  if (!linux_cmdline)
    goto fail;
  grub_memcpy (linux_cmdline, LINUX_IMAGE, sizeof (LINUX_IMAGE));
  {
    grub_err_t err;
    err = grub_create_loader_cmdline (argc, argv,
				      linux_cmdline
				      + sizeof (LINUX_IMAGE) - 1,
				      maximal_cmdline_size
				      - (sizeof (LINUX_IMAGE) - 1),
				      GRUB_VERIFY_KERNEL_CMDLINE);
    if (err)
      goto fail;
  }

  len = prot_file_size;
  if (grub_file_read (file, prot_mode_mem, len) != len && !grub_errno)
    grub_error (GRUB_ERR_BAD_OS, N_("premature end of file %s"),
		argv[0]);

  if (grub_errno == GRUB_ERR_NONE)
    {
      grub_loader_set (grub_linux_boot, grub_linux_unload,
		       0 /* set noreturn=0 in order to avoid grub_console_fini() */);
      loaded = 1;
    }

 fail:

  if (file)
    grub_file_close (file);

  if (grub_errno != GRUB_ERR_NONE)
    {
      grub_dl_unref (my_mod);
      loaded = 0;
    }

  return grub_errno;
}

static grub_err_t
grub_cmd_initrd (grub_command_t cmd __attribute__ ((unused)),
		 int argc, char *argv[])
{
  grub_size_t size = 0, aligned_size = 0;
  grub_addr_t addr_min, addr_max;
  grub_addr_t addr;
  grub_err_t err;
  struct grub_linux_initrd_context initrd_ctx = { 0, 0, 0 };

  if (argc == 0)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("filename expected"));
      goto fail;
    }

  if (! loaded)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("you need to load the kernel first"));
      goto fail;
    }

  if (grub_initrd_init (argc, argv, &initrd_ctx))
    goto fail;

  size = grub_get_initrd_size (&initrd_ctx);
  aligned_size = ALIGN_UP (size, 4096);

  /* Get the highest address available for the initrd.  */
  if (grub_le_to_cpu16 (linux_params.hdr.version) >= 0x0203)
    {
      addr_max = grub_cpu_to_le32 (linux_params.hdr.initrd_addr_max);

      /* XXX in reality, Linux specifies a bogus value, so
	 it is necessary to make sure that ADDR_MAX does not exceed
	 0x3fffffff.  */
      if (addr_max > GRUB_LINUX_INITRD_MAX_ADDRESS)
	addr_max = GRUB_LINUX_INITRD_MAX_ADDRESS;
    }
  else
    addr_max = GRUB_LINUX_INITRD_MAX_ADDRESS;

  if (linux_mem_size != 0 && linux_mem_size < addr_max)
    addr_max = linux_mem_size;

  /* Linux 2.3.xx has a bug in the memory range check, so avoid
     the last page.
     Linux 2.2.xx has a bug in the memory range check, which is
     worse than that of Linux 2.3.xx, so avoid the last 64kb.  */
  addr_max -= 0x10000;

  addr_min = (grub_addr_t) prot_mode_target + prot_init_space;

  /* Make sure the maximum address is able to store the initrd. */
  if (addr_max < aligned_size)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE,
                  N_("the size of initrd is bigger than addr_max"));
      goto fail;
    }

  /* Put the initrd as high as possible, 4KiB aligned.  */
  addr = (addr_max - aligned_size) & ~0xFFF;

  grub_dprintf ("linux",
                "Initrd at addr 0x%" PRIxGRUB_ADDR " which is expected in"
                " ranger 0x%" PRIxGRUB_ADDR " ~ 0x%" PRIxGRUB_ADDR "\n",
                addr, addr_min, addr_max);

  if (addr < addr_min)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, "the initrd is too big");
      goto fail;
    }

  {
    grub_relocator_chunk_t ch;
    err = grub_relocator_alloc_chunk_align (relocator, &ch,
					    addr_min, addr, aligned_size,
					    0x1000,
					    GRUB_RELOCATOR_PREFERENCE_HIGH,
					    1);
    if (err)
      goto fail;
    initrd_mem = get_virtual_current_address (ch);
    initrd_mem_target = get_physical_target_address (ch);
  }

  if (grub_initrd_load (&initrd_ctx, initrd_mem))
    goto fail;

  grub_dprintf ("linux", "Initrd (%p) at 0x%" PRIxGRUB_ADDR ", size=0x%" PRIxGRUB_SIZE "\n",
		initrd_mem, initrd_mem_target, size);

  linux_params.hdr.ramdisk_image = initrd_mem_target;
  linux_params.hdr.ramdisk_size = size;
  linux_params.hdr.root_dev = 0x0100; /* XXX */

 fail:
  grub_initrd_close (&initrd_ctx);

  return grub_errno;
}

#ifndef GRUB_MACHINE_EFI
static grub_command_t cmd_linux, cmd_initrd;

GRUB_MOD_INIT(linux)
{
  cmd_linux = grub_register_command ("linux", grub_cmd_linux,
				     0, N_("Load Linux."));
  cmd_initrd = grub_register_command ("initrd", grub_cmd_initrd,
				      0, N_("Load initrd."));
  my_mod = mod;
}

GRUB_MOD_FINI(linux)
{
  grub_unregister_command (cmd_linux);
  grub_unregister_command (cmd_initrd);
}
#else
extern grub_err_t __attribute__((alias("grub_cmd_linux")))
grub_cmd_linux_x86_legacy (grub_command_t cmd, int argc, char *argv[]);

extern grub_err_t __attribute__((alias("grub_cmd_initrd")))
grub_cmd_initrd_x86_legacy (grub_command_t cmd, int argc, char *argv[]);
#endif
