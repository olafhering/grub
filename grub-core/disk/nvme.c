/*
 *  GRUB  --  GRand Unified Bootloader
 *
 *  Copyright (C) 2019 secunet Security Networks AG
 *  Copyright (C) 2024  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Additionally this file can be distributed under 3-clause BSD license.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/dl.h>
#include <grub/disk.h>
#include <grub/mm.h>
#include <grub/time.h>
#include <grub/pci.h>
#include <grub/misc.h>
#include <grub/list.h>
#include <grub/loader.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define NVME_CC_EN	(1 <<  0)
#define NVME_CC_CSS	(0 <<  4)
#define NVME_CC_MPS	(0 <<  7)
#define NVME_CC_AMS	(0 << 11)
#define NVME_CC_SHN	(0 << 14)
#define NVME_CC_IOSQES	(6 << 16)
#define NVME_CC_IOCQES	(4 << 20)

#define NVME_QUEUE_SIZE 2
#define NVME_SQ_ENTRY_SIZE 64
#define NVME_CQ_ENTRY_SIZE 16

struct grub_nvme_mmio_reg
{
  /*  0 */ grub_uint64_t cap;
  /*  8 */ grub_uint32_t vs;
  /*  c */ grub_uint32_t intms;
  /* 10 */ grub_uint32_t intmc;
  /* 14 */ grub_uint32_t controller_config;
  /* 18 */ grub_uint32_t reserved1;
  /* 1c */ grub_uint32_t controller_status;
  /* 20 */ grub_uint32_t nssr;
  /* 24 */ grub_uint32_t aqa;
  /* 28 */ grub_uint64_t asq;
  /* 30 */ grub_uint64_t acq;
};

struct nvme_ident_block
{
  /*  0 */ grub_uint64_t nsze;
  /*  8 */ grub_uint64_t ncap;
  /* 10 */ grub_uint64_t nuse;
  /* 18 */ grub_uint8_t nsfeat;
  /* 19 */ grub_uint8_t nlbaf;
  /* 1a */ grub_uint8_t flbas;
  /* 1b */ grub_uint8_t mc;
  /* 1c */ grub_uint32_t fill[(0x80 - 0x1c) / 4];
  /* 80 */ grub_uint32_t lbaf[64];
};

struct grub_nvme_device
{
  struct grub_nvme_device *next;
  struct grub_nvme_device **prev;
  volatile struct grub_nvme_mmio_reg *regs;
  struct grub_pci_dma_chunk *prp_list;
  struct grub_pci_dma_chunk *sq_buffer;
  struct grub_pci_dma_chunk *cq_buffer;
  struct grub_pci_dma_chunk *ioc_buffer;
  struct grub_pci_dma_chunk *ios_buffer;
  struct grub_pci_dma_chunk *ident_buffer;
  grub_uint64_t total_sectors;
  int num, log_sector_size;

  struct {
    volatile void *base;
    volatile grub_uint32_t *bell;
    grub_uint16_t idx; // bool pos 0 or 1
    grub_uint16_t round; // bool round 0 or 1+0xd
  } queue[4];
};

struct nvme_s_queue_entry {
  grub_uint32_t dw[NVME_SQ_ENTRY_SIZE / sizeof (grub_uint32_t)];
};

struct nvme_c_queue_entry {
  grub_uint32_t dw[NVME_CQ_ENTRY_SIZE / sizeof (grub_uint32_t)];
};

static struct grub_nvme_device *grub_nvme_devices;
static int numdevs;

enum nvme_queue {
  NVME_ADMIN_QUEUE = 0,
  ads = 0,
  adc = 1,
  NVME_IO_QUEUE = 2,
  ios = 2,
  ioc = 3,
};

static int
nvme_cmd (struct grub_nvme_device *nvme, enum nvme_queue q, const struct nvme_s_queue_entry *cmd)
{
  int sq = q, cq = q+1;

  struct nvme_s_queue_entry *s_entry =
    &((struct nvme_s_queue_entry *)nvme->queue[sq].base)[nvme->queue[sq].idx];
  grub_memcpy (s_entry, cmd, NVME_SQ_ENTRY_SIZE);
  nvme->queue[sq].idx = (nvme->queue[sq].idx + 1) & (NVME_QUEUE_SIZE - 1);
  *nvme->queue[sq].bell = grub_cpu_to_le32 (nvme->queue[sq].idx);

  volatile struct nvme_c_queue_entry *c_entry =
    &((struct nvme_c_queue_entry *)nvme->queue[cq].base)[nvme->queue[cq].idx];
  grub_uint64_t endtime = grub_get_time_ms () + 100;
  while (((grub_le_to_cpu32 (*(volatile grub_uint32_t *)(&c_entry->dw[3])) >> 16) & 0x1)
	 == nvme->queue[cq].round)
    {
      if (grub_get_time_ms () > endtime)
	{
	  grub_dprintf ("nvme", "command timed out");
	  return -1;
	}
    }
  nvme->queue[cq].idx = (nvme->queue[cq].idx + 1) & (NVME_QUEUE_SIZE - 1);
  *nvme->queue[cq].bell = grub_cpu_to_le32 (nvme->queue[cq].idx);
  if (nvme->queue[cq].idx == 0)
    nvme->queue[cq].round = (nvme->queue[cq].round + 1) & 1;
  return grub_le_to_cpu32 (c_entry->dw[3]) >> 17;
}

static int
create_admin_queues (struct grub_nvme_device *nvme)
{
  grub_uint8_t cap_dstrd = (grub_le_to_cpu64 (nvme->regs->cap) >> 32) & 0xf;
  nvme->regs->aqa = grub_cpu_to_le32_compile_time ((NVME_QUEUE_SIZE - 1) << 16
						   | (NVME_QUEUE_SIZE - 1));

  nvme->sq_buffer = grub_memalign_dma32 (0x1000, NVME_SQ_ENTRY_SIZE * NVME_QUEUE_SIZE);
  if (!nvme->sq_buffer)
    {
      grub_dprintf ("nvme", "NVMe ERROR: Failed to allocated memory for admin submission queue\n");
      return -1;
    }
  grub_memset ((void *) grub_dma_get_virt (nvme->sq_buffer), 0, NVME_SQ_ENTRY_SIZE * NVME_QUEUE_SIZE);
  nvme->regs->asq = grub_cpu_to_le64 (grub_dma_get_phys (nvme->sq_buffer));

  nvme->queue[ads].base = grub_dma_get_virt (nvme->sq_buffer);
  nvme->queue[ads].bell = (volatile grub_uint32_t *) nvme->regs + 0x1000 / 4 + (ads * (1 << cap_dstrd));
  nvme->queue[ads].idx = 0;

  nvme->cq_buffer = grub_memalign_dma32 (0x1000, NVME_CQ_ENTRY_SIZE * NVME_QUEUE_SIZE);
  if (!nvme->cq_buffer)
    {
      grub_dprintf ("nvme", "NVMe ERROR: Failed to allocate memory for admin completion queue\n");
      grub_dma_free (nvme->sq_buffer);
      nvme->sq_buffer = NULL;
      return -1;
    }
  grub_memset ((void *) grub_dma_get_virt (nvme->cq_buffer), 0, NVME_CQ_ENTRY_SIZE * NVME_QUEUE_SIZE);
  nvme->regs->acq = grub_cpu_to_le64 (grub_dma_get_phys (nvme->cq_buffer));

  nvme->queue[adc].base = grub_dma_get_virt (nvme->cq_buffer);
  nvme->queue[adc].bell = (volatile grub_uint32_t *) nvme->regs + 0x1000 / 4 + (adc * (1 << cap_dstrd));
  nvme->queue[adc].idx = 0;
  nvme->queue[adc].round = 0;

  return 0;
}

static int create_io_submission_queue (struct grub_nvme_device *nvme)
{
  nvme->ios_buffer = grub_memalign_dma32 (0x1000, NVME_SQ_ENTRY_SIZE * NVME_QUEUE_SIZE);
  if (!nvme->ios_buffer)
    {
      grub_dprintf("nvme", "NVMe ERROR: Failed to allocate memory for io submission queue.\n");
      return -1;
    }
  grub_memset ((void *) grub_dma_get_virt (nvme->ios_buffer), 0, NVME_SQ_ENTRY_SIZE * NVME_QUEUE_SIZE);

  struct nvme_s_queue_entry e = {
    .dw[0]  = grub_cpu_to_le32_compile_time (0x01),
    .dw[6]  = grub_cpu_to_le32 (grub_dma_get_phys (nvme->ios_buffer)),
    .dw[10] = grub_cpu_to_le32_compile_time (((NVME_QUEUE_SIZE - 1) << 16) | ios >> 1),
    .dw[11] = grub_cpu_to_le32_compile_time ((1 << 16) | 1),
  };

  int res = nvme_cmd (nvme, NVME_ADMIN_QUEUE, &e);
  if (res) {
    grub_dprintf ("nvme", "NVMe ERROR: nvme_cmd returned with %i.\n", res);
    grub_dma_free (nvme->ios_buffer);
    nvme->ios_buffer = NULL;
    return res;
  }

  grub_uint8_t cap_dstrd = (grub_le_to_cpu64 (nvme->regs->cap) >> 32) & 0xf;
  nvme->queue[ios].base = nvme->ios_buffer;
  nvme->queue[ios].bell = (volatile grub_uint32_t *) nvme->regs + 0x1000 / 4 + (ios * (1 << cap_dstrd));
  nvme->queue[ios].idx = 0;
  return 0;
}

static int create_io_completion_queue (struct grub_nvme_device *nvme)
{
  nvme->ioc_buffer = grub_memalign_dma32 (0x1000, NVME_CQ_ENTRY_SIZE * NVME_QUEUE_SIZE);
  if (!nvme->ioc_buffer) {
    grub_dprintf ("nvme", "NVMe ERROR: Failed to allocate memory for io completion queue.\n");
    return -1;
  }
  grub_memset ((void *) grub_dma_get_virt (nvme->ioc_buffer), 0, NVME_CQ_ENTRY_SIZE * NVME_QUEUE_SIZE);

  const struct nvme_s_queue_entry e = {
    .dw[0]  = grub_cpu_to_le32_compile_time (0x05),
    .dw[6]  = grub_cpu_to_le32 (grub_dma_get_phys (nvme->ioc_buffer)),
    .dw[10] = grub_cpu_to_le32_compile_time (((NVME_QUEUE_SIZE - 1) << 16) | ioc >> 1),
    .dw[11] = grub_cpu_to_le32_compile_time (1),
  };

  int res = nvme_cmd (nvme, NVME_ADMIN_QUEUE, &e);
  if (res)
    {
      grub_dprintf ("nvme", "NVMe ERROR: nvme_cmd returned with %i.\n", res);
      grub_dma_free (nvme->ioc_buffer);
      nvme->ioc_buffer = NULL;
      return res;
    }

  grub_uint8_t cap_dstrd = (grub_le_to_cpu64 (nvme->regs->cap) >> 32) & 0xf;
  nvme->queue[ioc].base  = grub_dma_get_virt (nvme->ioc_buffer);
  nvme->queue[ioc].bell  = (volatile grub_uint32_t *) nvme->regs + 0x1000 / 4 + (ioc * (1 << cap_dstrd));
  nvme->queue[ioc].idx   = 0;
  nvme->queue[ioc].round = 0;

  return 0;
}

static int identify (struct grub_nvme_device *nvme)
{
  nvme->ident_buffer = grub_memalign_dma32 (0x1000, 0x1000);
  if (!nvme->ident_buffer) {
    grub_dprintf ("nvme", "NVMe ERROR: Failed to allocate ident buffer.\n");
    return -1;
  }
  grub_memset ((void *) grub_dma_get_virt (nvme->ident_buffer), 0, 0x1000);

  const struct nvme_s_queue_entry e = {
    .dw[0]  = grub_cpu_to_le32_compile_time (0x06),
    .dw[1]  = grub_cpu_to_le32_compile_time (0x01),
    .dw[2]  = 0x00,
    .dw[6]  = grub_cpu_to_le32 (grub_dma_get_phys (nvme->ident_buffer)),
    .dw[10] = 0x00,
  };

  int res = nvme_cmd (nvme, NVME_ADMIN_QUEUE, &e);
  if (res)
    {
      grub_dprintf ("nvme", "NVMe ERROR: nvme_cmd returned with %i.\n", res);
      grub_memset ((void *) grub_dma_get_virt (nvme->ident_buffer), 0, 0x1000);
      return res;
    }

  struct nvme_ident_block *nvme_ident = (void *) grub_dma_get_virt (nvme->ident_buffer);
  nvme->total_sectors = grub_le_to_cpu64 (nvme_ident->nsze);
  int selected_lbaf = nvme_ident->flbas & 0xf;
  nvme->log_sector_size = (grub_le_to_cpu32 (nvme_ident->lbaf[selected_lbaf]) >> 16) & 0xff;

  grub_dprintf ("nvme", "Detected disk with %lld sectors of 2^%d bytes each\n", (long long) nvme->total_sectors, nvme->log_sector_size);

  return 0;
}

static int delete_io_submission_queue (struct grub_nvme_device *nvme)
{
  const struct nvme_s_queue_entry e = {
    .dw[0]  = 0,
    .dw[10] = grub_cpu_to_le32_compile_time (ios >> 1),
  };

  int res = nvme_cmd (nvme, NVME_ADMIN_QUEUE, &e);

  grub_dma_free (nvme->ios_buffer);
  nvme->ios_buffer      = NULL;
  nvme->queue[ios].base = NULL;
  nvme->queue[ios].bell = NULL;
  nvme->queue[ios].idx  = 0;
  return res;
}

static int delete_io_completion_queue (struct grub_nvme_device *nvme)
{
  const struct nvme_s_queue_entry e = {
    .dw[0]  = grub_cpu_to_le32_compile_time (4),
    .dw[10] = grub_cpu_to_le32_compile_time (ioc >> 1),
  };

  int res = nvme_cmd (nvme, NVME_ADMIN_QUEUE, &e);
  grub_dma_free (nvme->ioc_buffer);
  nvme->ioc_buffer       = NULL;
  nvme->queue[ioc].base  = NULL;
  nvme->queue[ioc].bell  = NULL;
  nvme->queue[ioc].idx   = 0;
  nvme->queue[ioc].round = 0;
  return res;
}

static int
grub_nvme_pciinit (grub_pci_device_t dev,
		   grub_pci_id_t pciid __attribute__ ((unused)),
		   void *data __attribute__ ((unused)))
{
  grub_pci_address_t addr;
  grub_uint32_t class;
  grub_uint64_t bar;
  volatile struct grub_nvme_mmio_reg *mmio_reg;

  /* Read class.  */
  addr = grub_pci_make_address (dev, GRUB_PCI_REG_CLASS);
  class = grub_pci_read (addr);

  /* Check if this class ID matches that of a PCI NVMe Controller.  */
  if (class >> 8 != 0x010802)
    return 0;

  addr = grub_pci_make_address (dev, GRUB_PCI_REG_ADDRESS_REG0);

  bar = grub_pci_read (addr);

  if ((bar & (GRUB_PCI_ADDR_SPACE_MASK | GRUB_PCI_ADDR_MEM_TYPE_MASK
	      | GRUB_PCI_ADDR_MEM_PREFETCH))
      != (GRUB_PCI_ADDR_SPACE_MEMORY | GRUB_PCI_ADDR_MEM_TYPE_64))
    return 0;

  addr = grub_pci_make_address (dev, GRUB_PCI_REG_ADDRESS_REG1);

  bar |= ((grub_uint64_t) grub_pci_read (addr)) << 32;

  addr = grub_pci_make_address (dev, GRUB_PCI_REG_COMMAND);
  grub_pci_write_word (addr, grub_pci_read_word (addr)
		       | GRUB_PCI_COMMAND_MEM_ENABLED);

  mmio_reg = grub_pci_device_map_range (dev, bar & ~0xfULL, sizeof (*mmio_reg));
  grub_dprintf ("nvme", "dev: %x:%x.%x\n", dev.bus, dev.device, dev.function);

  if (!(grub_le_to_cpu64 (mmio_reg->cap) & (1LL << 37))) {
    grub_dprintf ("nvme", "nvme command set not supported\n");
    grub_pci_device_unmap_range (dev, mmio_reg, sizeof (*mmio_reg));
    return 0;
  }

  mmio_reg->controller_config = 0;

  struct grub_nvme_device *nvmedev = grub_zalloc (sizeof (*nvmedev));
  if (!nvmedev) {
    grub_pci_device_unmap_range (dev, mmio_reg, sizeof (*mmio_reg));
    return 0;
  }

  nvmedev->regs = mmio_reg;
  nvmedev->num = numdevs++;

  grub_int32_t max_timeout_ms = ((grub_le_to_cpu64 (mmio_reg->cap) >> 24) & 0xff) * 500;
  grub_int32_t timeout_ms = max_timeout_ms;
  while (1)
    {
      grub_uint8_t status = grub_le_to_cpu32 (mmio_reg->controller_status) & 0x3;
      if (status == 0x2)
	{
	  grub_dprintf ("nvme", "NVMe ERROR: Failed to disable controller. FATAL ERROR\n");
	  goto fail;
	}
      if (status == 0)
	break;
      if (timeout_ms < 0)
	{
	  grub_dprintf ("nvme", "NVMe ERROR: Failed to disable controller. Timeout.\n");
	  goto fail;
	}
      timeout_ms -= 10;
      grub_millisleep (10);
    }

  timeout_ms = max_timeout_ms;
  if (create_admin_queues (nvmedev))
    {
      grub_dprintf ("nvme", "NVMe ERROR: Failed to create admin queues. FATAL ERROR\n");
      goto fail;
    }

  mmio_reg->controller_config
    = grub_cpu_to_le32_compile_time (NVME_CC_EN | NVME_CC_CSS | NVME_CC_MPS | NVME_CC_AMS
				    | NVME_CC_SHN | NVME_CC_IOSQES | NVME_CC_IOCQES);
  while (1)
    {
      grub_uint8_t status = grub_le_to_cpu32 (mmio_reg->controller_status) & 0x3;
      if (status == 0x2) {
	grub_dprintf ("nvme", "NVMe ERROR: Failed to enable controller. FATAL ERROR\n");
	mmio_reg->controller_config = 0;
	goto fail;
      }
      if (status == 1)
	break;
      if (timeout_ms < 0) {
	grub_dprintf ("nvme", "NVMe ERROR: Failed to enable controller. Timeout.\n");
	mmio_reg->controller_config = 0;
	goto fail;
      }
      timeout_ms -= 10;
      grub_millisleep (10);
    }

  nvmedev->prp_list = grub_memalign_dma32 (0x1000, 0x1000);
  if (!nvmedev->prp_list) {
    mmio_reg->controller_config = 0;
    goto fail;
  }

  addr = grub_pci_make_address (dev, GRUB_PCI_REG_COMMAND);
  grub_pci_write_word (addr, grub_pci_read_word (addr) | GRUB_PCI_COMMAND_BUS_MASTER);

  if(create_io_completion_queue (nvmedev)
     || create_io_submission_queue (nvmedev)
     || identify (nvmedev)) {
    goto fail;
  } else {
    grub_list_push (GRUB_AS_LIST_P (&grub_nvme_devices),
		    GRUB_AS_LIST (nvmedev));
  }
  return 0;
 fail:
  {
    if (nvmedev->regs)
      grub_pci_device_unmap_range (dev, nvmedev->regs, sizeof (*nvmedev->regs));
    if (nvmedev->prp_list)
      grub_dma_free (nvmedev->prp_list);
    if (nvmedev->sq_buffer)
      grub_dma_free (nvmedev->sq_buffer);
    if (nvmedev->cq_buffer)
      grub_dma_free (nvmedev->cq_buffer);
    if (nvmedev->ioc_buffer)
      grub_dma_free (nvmedev->ioc_buffer);
    if (nvmedev->ios_buffer)
      grub_dma_free (nvmedev->ios_buffer);
    if (nvmedev->ident_buffer)
      grub_dma_free (nvmedev->ident_buffer);
    grub_free (nvmedev);
  }
  return 0;
}

static grub_err_t
grub_nvme_initialize (void)
{
  grub_pci_iterate (grub_nvme_pciinit, NULL);
  return grub_errno;
}

static grub_err_t
grub_nvme_fini_hw (int noreturn __attribute__ ((unused)))
{
  struct grub_nvme_device *dev;

  for (dev = grub_nvme_devices; dev; dev = dev->next)
    {
      delete_io_submission_queue (dev);
      delete_io_completion_queue (dev);
      dev->regs->controller_config = 0;
      /* TODO: wait for completition.  */
    }
  return GRUB_ERR_NONE;
}


static grub_err_t
grub_nvme_restore_hw (void)
{
  struct grub_nvme_device **pdev;

  for (pdev = &grub_nvme_devices; *pdev; pdev = &((*pdev)->next)) {
    (*pdev)->regs->controller_config
      = grub_cpu_to_le32_compile_time (NVME_CC_EN | NVME_CC_CSS | NVME_CC_MPS | NVME_CC_AMS
				       | NVME_CC_SHN | NVME_CC_IOSQES | NVME_CC_IOCQES);
    grub_int32_t timeout_ms = ((grub_le_to_cpu64 ((*pdev)->regs->cap) >> 24) & 0xff) * 500;

    while (1) {
      grub_uint8_t status = grub_le_to_cpu32 ((*pdev)->regs->controller_status) & 0x3;
      if (status == 0x2) {
	grub_dprintf ("nvme", "NVMe ERROR: Failed to restore controller. FATAL ERROR\n");
	return GRUB_ERR_BAD_DEVICE;
      }
      if (status == 1)
	break;
      if (timeout_ms < 0) {
	grub_dprintf ("nvme", "NVMe ERROR: Failed to enable controller. Timeout.\n");
	return GRUB_ERR_BAD_DEVICE;
      }
      timeout_ms -= 10;
      grub_millisleep (10);
    }

    (*pdev)->queue[ads].idx = 0;
    grub_memset((void *)grub_dma_get_virt((*pdev)->sq_buffer),
		0, NVME_SQ_ENTRY_SIZE * NVME_QUEUE_SIZE);

    (*pdev)->queue[adc].idx = 0;
    (*pdev)->queue[adc].round = 0;
    grub_memset((void *)grub_dma_get_virt((*pdev)->cq_buffer),
		0, NVME_CQ_ENTRY_SIZE * NVME_QUEUE_SIZE);

    if (create_io_completion_queue (*pdev)) {
      grub_dprintf ("nvme", "NVMe ERROR: Failed to create completion queue.\n");
      return GRUB_ERR_BAD_DEVICE;
    }
    if (create_io_submission_queue (*pdev)) {
      grub_dprintf ("nvme", "NVMe ERROR: Failed to create submission queue.\n");
      return GRUB_ERR_BAD_DEVICE;
    }
  }
  return GRUB_ERR_NONE;
}




static int
grub_nvme_iterate (grub_disk_dev_iterate_hook_t hook, void *hook_data,
		   grub_disk_pull_t pull)
{
  struct grub_nvme_device *dev;

  if (pull != GRUB_DISK_PULL_NONE)
    return 0;

  FOR_LIST_ELEMENTS (dev, grub_nvme_devices)
    {
      char devname[40];
      /* TODO: Other namespaces.  */
      grub_snprintf (devname, sizeof (devname),
		     "nvme%dn%d", dev->num, 1);
      if (hook (devname, hook_data))
	return 1;
    }

  return 0;
}

static grub_err_t
grub_nvme_open (const char *name, grub_disk_t disk)
{
  const char *rest;
  if (grub_memcmp (name, "nvme", 4) != 0 || !grub_isdigit (name[4]))
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "not an NVMe disk");
  int devnum = grub_strtoul (name + 4, &rest, 0);
  if (*rest != 'n')
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "not an NVMe disk");
  int namespace = grub_strtoul (rest + 1, 0, 0);

  struct grub_nvme_device *dev;

  FOR_LIST_ELEMENTS (dev, grub_nvme_devices)
    if (dev->num == devnum)
      {
	if (namespace != 1)
	  return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "unknown NVMe namespace");

	disk->total_sectors = dev->total_sectors;
	grub_disk_set_max_agglomerate (disk, 512);

	disk->log_sector_size = dev->log_sector_size;
	disk->id = (devnum << 8) | namespace;
	disk->data = dev;
	return 0;
      }

  return grub_error (GRUB_ERR_UNKNOWN_DEVICE, "unknown NVMe disk");
}

static void
grub_nvme_close (grub_disk_t disk)
{
  (void) disk;
}

static grub_err_t
nvme_readwrite (struct grub_nvme_device *dev, int namespace,
		grub_disk_addr_t sector, grub_size_t size, char *buf, int is_write)
{
  (void) namespace;

  if (size == 0)
    return 0;

  if (size > 512)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "overlong nvme read");

  /* This assumes virt == phys which is true on platforms where we support nvme.  */
  /* FIXME: perform proper address translation before enabling for other platforms.  */
  grub_uint64_t buffer_phys = (grub_addr_t) buf;

  struct nvme_s_queue_entry e = {
    .dw[0] = is_write ? grub_cpu_to_le32_compile_time (0x01) : grub_cpu_to_le32_compile_time (0x02),
    .dw[1] = grub_cpu_to_le32_compile_time (0x1),
    .dw[6] = grub_cpu_to_le32 ((grub_addr_t) buffer_phys),
    .dw[7] = grub_cpu_to_le32 ((grub_addr_t) (buffer_phys >> 32)),
    .dw[10] = grub_cpu_to_le32 (sector),
    .dw[11] = grub_cpu_to_le32 (sector >> 32),
    .dw[12] = grub_cpu_to_le32 (size - 1),
  };

  const grub_uint64_t start_page = buffer_phys >> 12;
  const grub_uint64_t end_page = (buffer_phys + (size << dev->log_sector_size) - 1) >> 12;
  if (end_page == start_page) {
    /* No page crossing, PRP2 is reserved */
  } else if (end_page == start_page + 1) {
    /* Crossing exactly one page boundary, PRP2 is second page */
    e.dw[8] = grub_cpu_to_le32 ((buffer_phys + 0x1000) & ~0xfff);
    e.dw[9] = grub_cpu_to_le32 ((buffer_phys + 0x1000) >> 32);
  } else {
    /* Use a single page as PRP list, PRP2 points to the list */
    unsigned int i;
    volatile grub_uint64_t *prp_list = grub_dma_get_virt(dev->prp_list);
    for (i = 0; i < end_page - start_page; ++i) {
      buffer_phys += 0x1000;
      prp_list[i] = buffer_phys & ~0xfff;
    }
    e.dw[8] = grub_cpu_to_le32 (grub_dma_get_phys(dev->prp_list));
  }

  int io_err = nvme_cmd (dev, ios, &e);
  if (io_err)
    return grub_error (GRUB_ERR_IO, "NVMe error %d", io_err);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_nvme_read (grub_disk_t disk, grub_disk_addr_t sector,
		grub_size_t size, char *buf)
{
  struct grub_nvme_device *dev = disk->data;
  int namespace = disk->id & 0xff;

  return nvme_readwrite (dev, namespace, sector, size, buf, 0);
}

static grub_err_t
grub_nvme_write (grub_disk_t disk, grub_disk_addr_t sector,
		 grub_size_t size, const char *buf)
{
  struct grub_nvme_device *dev = disk->data;
  int namespace = disk->id & 0xff;

  return nvme_readwrite (dev, namespace, sector, size, (char *)buf, 1);
}

static struct grub_disk_dev grub_nvme_dev =
  {
    .name = "nvme",
    .id = GRUB_DISK_DEVICE_NVME_ID,
    .disk_iterate = grub_nvme_iterate,
    .disk_open = grub_nvme_open,
    .disk_close = grub_nvme_close,
    .disk_read = grub_nvme_read,
    .disk_write = grub_nvme_write,
    .next = 0
  };



static struct grub_preboot *fini_hnd;

GRUB_MOD_INIT (nvme)
{
  grub_stop_disk_firmware ();

  /* NVMe initialization.  */
  grub_nvme_initialize ();

  grub_disk_dev_register (&grub_nvme_dev);

  fini_hnd = grub_loader_register_preboot_hook (grub_nvme_fini_hw,
						grub_nvme_restore_hw,
						GRUB_LOADER_PREBOOT_HOOK_PRIO_DISK);
}

GRUB_MOD_FINI (nvme)
{
  grub_nvme_fini_hw (0);
  grub_loader_unregister_preboot_hook (fini_hnd);

  grub_disk_dev_unregister (&grub_nvme_dev);
}
