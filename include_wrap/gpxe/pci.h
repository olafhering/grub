/*
 * Copyright © 2009 Vladimir 'phcoder' Serbinenko <phcoder@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */     

FILE_LICENCE ( BSD2 );

#ifndef _GPXE_PCI_H
#define _GPXE_PCI_H

#include <grub/pci.h>
#include <grub/time.h>

static inline grub_uint8_t
inb (grub_uint16_t port)
{
  return grub_inb (GRUB_MACHINE_PCI_IO_BASE + port);
}

static inline void
outb (grub_uint8_t data, grub_uint16_t port)
{
  return grub_outb (data, GRUB_MACHINE_PCI_IO_BASE + port);
}

static inline void
outw (grub_uint16_t data, grub_uint16_t port)
{
  return grub_outw (data, GRUB_MACHINE_PCI_IO_BASE + port);
}

static inline grub_uint16_t
inw (grub_uint16_t port)
{
  return grub_inw (GRUB_MACHINE_PCI_IO_BASE + port);
}

static inline void
outl (grub_uint32_t data, grub_uint16_t port)
{
  return grub_outw (data, GRUB_MACHINE_PCI_IO_BASE + port);
}

static inline grub_uint16_t
inl (grub_uint32_t port)
{
  return grub_inw (GRUB_MACHINE_PCI_IO_BASE + port);
}

static inline void
mdelay (unsigned delay)
{
  grub_millisleep (delay);
}

struct device
{
  grub_pci_device_t pci_dev;
};

struct pci_device
{
  struct device dev;

  grub_uint16_t ioaddr;
  grub_uint16_t vendor;
  grub_uint16_t device;

  int irq;

  void *priv;
};
struct pci_device_id
{
  grub_pci_id_t devid;
};
#define PCI_ROM(vendor, model, short_name, long_name, num) {.devid = ((vendor) | ((model) << 16))}
#define __pci_driver

struct pci_driver
{
  struct pci_device_id *ids;
  grub_size_t id_count;
  int (*probe) (struct pci_device *pci, const struct pci_device_id *id);
  void (*remove) (struct pci_device *pci);
  void (*irq) (struct nic *nic, int action);
};

#define PCI_VENDOR_ID_DAVICOM 0x0291
#define PCI_VENDOR_ID_WINBOND2 0x1050
#define PCI_VENDOR_ID_COMPEX 0x11f6
#define PCI_REVISION_ID 0x8
#define PCI_REVISION PCI_REVISION_ID 
#define PCI_BASE_ADDRESS_0 0x10
#define PCI_BASE_ADDRESS_1 0x14

#endif
