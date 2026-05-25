/*
 *  virtionet.c - Provide virtio-net driver for network interface
 *                support in a virtual environment such as Qemu.
 *                This was written to comply with virtio version
 *                1.x. This uses a virtio-pci interface.
 *
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2024  Free Software Foundation, Inc.
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
 *
 */

#include <grub/dl.h>
#include <grub/loader.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/net.h>
#include <grub/pci.h>
#include <grub/safemath.h>
#include <grub/time.h>
#include <grub/types.h>

GRUB_MOD_LICENSE ("GPLv3+");

/*  Driver Conformance Targets (per virtio spec 1.2):
 *   1. Clause 1 (virtio Driver)
 *   2. Clause 2 (virtio PCI Driver)
 *   3. Clause 5 (virtio Network Driver)
 *   4. Clause 46 (virtio Legacy) - Legacy Devices Not Supported
 *
 *  Limitations:
 *   1. Currently assumes byte order between Qemu (device) and
 *      GRUB (driver) over PCI is the same - may not work
 *      for big-endian devices or CPUs.
 *   2. Has been tested on i386-pc and x86_64-efi GRUB environments
 *      running on an x86_64 processor. Other platforms / CPUs may
 *      need additional testing.
 *   3. If additional "virtio" device support is added to GRUB in
 *      the future it may make sense to split some of the functions
 *      in this code out (such as for virtio queues, virtio PCI).
 *   4. Certainly isn't the fastest implementation of a virtio-net
 *      driver, but lays a groundwork for incremental improvement
 *      if needed. Some more complex (but faster) virtio-net features
 *      are not used for simplicity.
 *   5. This driver will support at most one virtio-net device.
 */

#define GRUB_ALIGN_4096 __attribute__ ((aligned (4096)))
#define GRUB_VIOPCI_MAX_BARS (6)
#define GRUB_VIO_BUFF_CNT (2048)
#define GRUB_VIONET_RX_Q_SEL (0)
#define GRUB_VIONET_TX_Q_SEL (1)

struct virtio_pci_cap_struct_t
{
  grub_uint8_t cap_vndr;
  grub_uint8_t cap_next;
  grub_uint8_t cap_len;
  grub_uint8_t cfg_type;
  grub_uint8_t bar;
  grub_uint8_t id;
  grub_uint8_t padding[2];
  grub_uint32_t offset;
  grub_uint32_t length;
} GRUB_PACKED;
typedef struct virtio_pci_cap_struct_t virtio_pci_cap_t;

#define GRUB_VIRTIO_PCI_CAP_COMMON_CFG 1
#define GRUB_VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define GRUB_VIRTIO_PCI_CAP_DEVICE_CFG 4

struct virtio_pci_common_cfg_struct_t
{
  grub_uint32_t device_feature_select_rw;
  grub_uint32_t device_feature_ro;
  grub_uint32_t driver_feature_select_rw;
  grub_uint32_t driver_feature_rw;
  grub_uint16_t config_msix_vector_rw;
  grub_uint16_t num_queues_ro;
  grub_uint8_t device_status_rw;
  grub_uint8_t config_generation_ro;
  grub_uint16_t queue_select_rw;
  grub_uint16_t queue_size_rw;
  grub_uint16_t queue_msix_vector_rw;
  grub_uint16_t queue_enable_rw;
  grub_uint16_t queue_notify_off_ro;
  grub_uint32_t queue_desc_lo_rw;
  grub_uint32_t queue_desc_hi_rw;
  grub_uint32_t queue_driver_lo_rw;
  grub_uint32_t queue_driver_hi_rw;
  grub_uint32_t queue_device_lo_rw;
  grub_uint32_t queue_device_hi_rw;
  grub_uint16_t queue_notify_data_ro;
  grub_uint16_t queue_reset_rw;
} GRUB_PACKED;
typedef struct virtio_pci_common_cfg_struct_t virtio_pci_common_cfg_t;

struct grub_virtio_net_config_struct_t
{
  grub_uint8_t mac[6];
  grub_uint16_t status;
  grub_uint16_t max_virtqueue_pairs;
  grub_uint16_t mtu;
  grub_uint32_t speed;
  grub_uint8_t duplex;
  grub_uint8_t rss_max_key_size;
  grub_uint16_t rss_max_indirection_table_length;
  grub_uint32_t supported_hash_types;
} GRUB_PACKED;

typedef struct grub_virtio_net_config_struct_t grub_virtio_net_config_t;

/* This marks a buffer as device write-only (otherwise device read-only). */
#define GRUB_VIRTQ_DESC_F_WRITE 2

/* 16 receiver buffers should be plenty for GRUB use. */
#define GRUB_VIO_Q_SZ (16)

struct virtq_desc
{
  grub_uint64_t addr;
  grub_uint32_t len;
  grub_uint16_t flags;
  grub_uint16_t next;
} GRUB_PACKED;

#define GRUB_VIRTQ_AVAIL_F_NO_INTERRUPT 1
struct virtq_avail
{
  grub_uint16_t flags;
  grub_uint16_t idx;
  grub_uint16_t ring[GRUB_VIO_Q_SZ];
  grub_uint16_t used_event; /* Only if VIRTIO_F_EVENT_IDX */
} GRUB_PACKED GRUB_ALIGN_4096;

struct virtq_used_elem
{
  grub_uint32_t id;
  grub_uint32_t len;
} GRUB_PACKED;

struct virtq_used
{
  grub_uint16_t flags;
  grub_uint16_t idx;
  struct virtq_used_elem ring[GRUB_VIO_Q_SZ];
  grub_uint16_t avail_event; /* Only if VIRTIO_F_EVENT_IDX */
} GRUB_PACKED GRUB_ALIGN_4096;

struct virtq
{
  struct virtq_desc desc[GRUB_VIO_Q_SZ];
  struct virtq_avail avail;
  struct virtq_used used;
};

static volatile grub_uint8_t rx_buff[GRUB_VIO_Q_SZ]
                                    [GRUB_VIO_BUFF_CNT] GRUB_ALIGN_4096;
static volatile grub_uint8_t tx_buff[GRUB_VIO_Q_SZ]
                                    [GRUB_VIO_BUFF_CNT] GRUB_ALIGN_4096;

static struct virtq virtq_rx;
static struct virtq virtq_tx;

struct grub_virtionetcard_data
{
  grub_pci_device_t pci_dev;
  volatile virtio_pci_common_cfg_t *pci_common;
  volatile grub_uint16_t *virtio_notify;
  grub_uint32_t virtio_notify_len;
  volatile grub_virtio_net_config_t *virtio_net_cfg;
  grub_uint32_t virtio_net_cfg_len;
  struct virtq *v_rx;
  grub_uint16_t v_rx_last_seen_used;
  grub_uint32_t rx_notify_idx;
  grub_uint32_t tx_notify_idx;
  struct virtq *v_tx;
  int card_found;
};

struct grub_virtio_net_hdr_struct_t
{
  grub_uint8_t flags;
  grub_uint8_t gso_type;
  grub_uint16_t hdr_len;
  grub_uint16_t gso_size;
  grub_uint16_t csum_start;
  grub_uint16_t csum_offset;
  grub_uint16_t num_buffers;
} GRUB_PACKED;

typedef struct grub_virtio_net_hdr_struct_t grub_virtio_net_hdr_t;

#define GRUB_VIRTIO_NET_DEVSTAT_ACKNOWLEDGE (1)
#define GRUB_VIRTIO_NET_DEVSTAT_DRIVER (2)
#define GRUB_VIRTIO_NET_DEVSTAT_FAILED (128)
#define GRUB_VIRTIO_NET_DEVSTAT_FEATURES_OK (8)
#define GRUB_VIRTIO_NET_DEVSTAT_DRIVER_OK (4)

/* Device has specific MAC address - bit 5 */
#define GRUB_VIRTIO_NET_F_MAC_L (1 << 5)
/* Modern driver - v1.0 and newer - bit 32 */
#define GRUB_VIRTIO_F_VERSION_1_U (1)

/* Vendor 1AF4 with device ID 1000 is a transitional network device. */
#define GRUB_VIRTIO_NET_TRANS_PCIID 0x10001AF4

/* Vendor 1AF4 with device ID 1041 is a regular network device. */
#define GRUB_VIRTIO_NET_PCIID 0x10411AF4

/* Perform a memory barrier to ensure transactions are complete. */
/* This is required by the specification in certain situations. */
#if defined(__x86_64__)
#define MB() asm volatile ("mfence; sfence;" ::: "memory")
#elif defined(__i386__)
#define MB() asm volatile ("lock; addl $0,0(%%esp)" ::: "memory")
#elif defined(__aarch64__) || defined(__arm__)
#define MB() asm volatile ("dsb sy" ::: "memory")
#else
/* No-op so code compiles. */
#define MB() do { } while (0);
#endif

/* Reset the virtio-net device */
static grub_err_t
grub_virtio_net_dev_reset (volatile virtio_pci_common_cfg_t *const net_dev)
{
  if (net_dev == NULL)
    {
      return GRUB_ERR_BAD_ARGUMENT;
    }

  /* Tell the virtio net device to reset. */
  net_dev->device_status_rw = 0;

  /* The virtio spec says to check that the device is done with
   *  reset by checking that device status is zero. In testing
   *  this appeared to happen "instantly" but allow up to one
   *  second for the device to finish just in case. */
  int count = 0;
  while (net_dev->device_status_rw != 0 && count < 20)
    {
      count++;
      grub_millisleep (50);
    }

  /* If the reset timed out, return an error indication that the
   * device may not have been reset correctly. */
  if (net_dev->device_status_rw != 0)
    return GRUB_ERR_TIMEOUT;
  else
    return GRUB_ERR_NONE;
}

/* Initialize the virtio queues. */
static void
grub_vio_q_setup (volatile virtio_pci_common_cfg_t *const net_dev,
                  const grub_uint16_t queue_sel,
                  const grub_uint16_t initial_flags,
                  volatile grub_uint8_t buff[GRUB_VIO_Q_SZ][GRUB_VIO_BUFF_CNT],
                  struct virtq *virtq,
                  struct virtq **v_q)
{

  /* Initialize virtual queues for the device. */
  for (int i = 0; i < GRUB_VIO_Q_SZ; i++)
    {
      virtq->desc[i].addr = (grub_addr_t)&buff[i];
      virtq->desc[i].len = GRUB_VIO_BUFF_CNT;
      virtq->desc[i].flags = initial_flags;

      virtq->avail.ring[i] = i;
    }

  virtq->avail.flags = GRUB_VIRTQ_AVAIL_F_NO_INTERRUPT;
  virtq->avail.idx = 0;

  virtq->used.flags = 0;
  virtq->used.idx = 0;

  *v_q = virtq;

  MB ();

  /* Setup the driver virtual queue */
  net_dev->queue_select_rw = queue_sel;
  net_dev->queue_size_rw = GRUB_VIO_Q_SZ;
  net_dev->queue_desc_lo_rw
      = (grub_uint32_t)((grub_addr_t)&virtq->desc[0] & 0xFFFFFFFFu);
  net_dev->queue_driver_lo_rw
      = (grub_uint32_t)((grub_addr_t)&virtq->avail & 0xFFFFFFFFu);
  net_dev->queue_device_lo_rw
      = (grub_uint32_t)((grub_addr_t)&virtq->used & 0xFFFFFFFFu);
#if GRUB_CPU_SIZEOF_VOID_P == 8
  net_dev->queue_desc_hi_rw
      = (grub_uint32_t)(((grub_addr_t)&virtq->desc[0] >> 32u) & 0xFFFFFFFFu);
  net_dev->queue_driver_hi_rw
      = (grub_uint32_t)(((grub_addr_t)&virtq->avail >> 32u) & 0xFFFFFFFFu);
  net_dev->queue_device_hi_rw
      = (grub_uint32_t)(((grub_addr_t)&virtq->used >> 32u) & 0xFFFFFFFFu);
#else  /* GRUB_CPU_SIZEOF_VOID_P != 8 */
  net_dev->queue_desc_hi_rw = 0;
  net_dev->queue_driver_hi_rw = 0;
  net_dev->queue_device_hi_rw = 0;
#endif /* GRUB_CPU_SIZEOF_VOID_P check */
  net_dev->queue_enable_rw = 1;

  MB ();

}

/*
 * Initialize the virtio-net device
 *
 * For required steps, reference virtio spec 1.2 section 3.1.1
 * "Driver Requirements: Device Initialization"
 */
static grub_err_t
grub_virtio_net_dev_init (volatile virtio_pci_common_cfg_t *const net_dev,
                          volatile grub_uint16_t *const virtio_notify,
                          const grub_uint32_t notify_len,
                          const grub_uint32_t notify_multiplier,
                          grub_uint32_t *rx_notify_idx,
                          grub_uint32_t *tx_notify_idx, struct virtq **v_rx,
                          struct virtq **v_tx)
{
  grub_err_t ret_code = GRUB_ERR_NONE;
  if (net_dev == NULL || virtio_notify == NULL || v_rx == NULL || v_tx == NULL)
    {
      grub_dprintf ("vnet", "param is null error");
      return GRUB_ERR_BAD_ARGUMENT;
    }

  if ((ret_code = grub_virtio_net_dev_reset (net_dev)) != GRUB_ERR_NONE)
    {
      grub_dprintf ("vnet", "grub_virtio_net_dev_reset error");
      return ret_code;
    }

  /* Driver has noticed the device. */
  net_dev->device_status_rw |= GRUB_VIRTIO_NET_DEVSTAT_ACKNOWLEDGE;

  MB ();

  /* Driver knows how to drive the device. */
  net_dev->device_status_rw |= GRUB_VIRTIO_NET_DEVSTAT_DRIVER;

  MB ();

  net_dev->device_feature_select_rw = 0;

  /* Read feature bits and write the subset of features we support*/
  grub_uint32_t dev_feat_0_31 = net_dev->device_feature_ro;
  net_dev->device_feature_select_rw = 1; /* Select dev feature 32 to 63 */

  grub_uint32_t dev_feat_32_63 = net_dev->device_feature_ro;
  grub_dprintf ("vnet", "dev features: %x %x\n", dev_feat_0_31,
                dev_feat_32_63);

  /* Check device feature vs. what we support in the driver. */
  if ((dev_feat_32_63 & GRUB_VIRTIO_F_VERSION_1_U)
      != GRUB_VIRTIO_F_VERSION_1_U)
    {
      grub_dprintf ("vnet", "error: legacy device not supported\n");
      net_dev->device_status_rw |= GRUB_VIRTIO_NET_DEVSTAT_FAILED;
      MB ();
      return GRUB_ERR_BAD_DEVICE;
    }
  else if ((dev_feat_0_31 & GRUB_VIRTIO_NET_F_MAC_L)
           != GRUB_VIRTIO_NET_F_MAC_L)
    {
      grub_dprintf ("vnet", "error: device does not support MAC reporting\n");
      net_dev->device_status_rw |= GRUB_VIRTIO_NET_DEVSTAT_FAILED;
      MB ();
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Set the negotiated features to the device. */
  net_dev->driver_feature_select_rw = 0;
  grub_uint32_t driver_features = GRUB_VIRTIO_NET_F_MAC_L;
  net_dev->driver_feature_rw = (dev_feat_0_31 & driver_features);

  net_dev->driver_feature_select_rw = 1;
  driver_features = GRUB_VIRTIO_F_VERSION_1_U;
  net_dev->driver_feature_rw = (dev_feat_32_63 & driver_features);

  /* Driver accepts features. */
  net_dev->device_status_rw |= GRUB_VIRTIO_NET_DEVSTAT_FEATURES_OK;

  MB ();

  if ((net_dev->device_status_rw & GRUB_VIRTIO_NET_DEVSTAT_FEATURES_OK)
      != GRUB_VIRTIO_NET_DEVSTAT_FEATURES_OK)
    {
      grub_dprintf ("vnet", "error: device did not accept features\n");
      net_dev->device_status_rw |= GRUB_VIRTIO_NET_DEVSTAT_FAILED;
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Initialize RX virtual queues for the device. */
  grub_vio_q_setup (net_dev, GRUB_VIONET_RX_Q_SEL, GRUB_VIRTQ_DESC_F_WRITE, rx_buff, &virtq_rx, v_rx);

  /* Initialize TX virtual queues for the device. */
  grub_vio_q_setup (net_dev, GRUB_VIONET_TX_Q_SEL, 0, tx_buff, &virtq_tx, v_tx);

  /* Tell the device that the buffers are ready. */
  (*v_rx)->avail.idx = GRUB_VIO_Q_SZ;

  MB ();

  net_dev->queue_select_rw = GRUB_VIONET_TX_Q_SEL;
  /* Device must present a notification cap length large enough to hold
   * the 16-bit notifier at notify_offs.  Use overflow-checking math so
   * a hostile device cannot wrap the multiply or the +2. */
  grub_uint32_t notify_offs;
  grub_uint32_t notify_end;
  if (grub_mul (net_dev->queue_notify_off_ro, notify_multiplier, &notify_offs)
      || grub_add (notify_offs, 2, &notify_end)
      || notify_end >= notify_len)
    {
      grub_dprintf ("vnet", "error: bad tx notify offset\n");
      net_dev->device_status_rw |= GRUB_VIRTIO_NET_DEVSTAT_FAILED;
      return GRUB_ERR_BAD_DEVICE;
    }
  *tx_notify_idx = notify_offs / sizeof (virtio_notify[0]);

  net_dev->queue_select_rw = GRUB_VIONET_RX_Q_SEL;
  if (grub_mul (net_dev->queue_notify_off_ro, notify_multiplier, &notify_offs)
      || grub_add (notify_offs, 2, &notify_end)
      || notify_end >= notify_len)
    {
      grub_dprintf ("vnet", "error: bad rx notify offset\n");
      net_dev->device_status_rw |= GRUB_VIRTIO_NET_DEVSTAT_FAILED;
      return GRUB_ERR_BAD_DEVICE;
    }
  *rx_notify_idx = notify_offs / sizeof (virtio_notify[0]);

  /* Everything is setup in the driver now. */
  net_dev->device_status_rw |= GRUB_VIRTIO_NET_DEVSTAT_DRIVER_OK;

  MB ();

  virtio_notify[*rx_notify_idx] = 0;
  MB ();

  return GRUB_ERR_NONE;
}

static struct grub_preboot *fini_hnd;

/*
 * Unmap any PCI ranges currently mapped in virtdata and NULL the
 * pointers.  Safe to call when only some of the ranges have been
 * mapped (e.g. on a partial init failure) or repeatedly.
 */
static void
grub_virtionet_unmap_all (struct grub_virtionetcard_data *virtdata)
{
  if (virtdata->pci_common != NULL)
    {
      grub_pci_device_unmap_range (virtdata->pci_dev, virtdata->pci_common,
                                   sizeof (virtio_pci_common_cfg_t));
      virtdata->pci_common = NULL;
    }
  if (virtdata->virtio_notify != NULL)
    {
      grub_pci_device_unmap_range (virtdata->pci_dev, virtdata->virtio_notify,
                                   virtdata->virtio_notify_len);
      virtdata->virtio_notify = NULL;
    }
  if (virtdata->virtio_net_cfg != NULL)
    {
      grub_pci_device_unmap_range (virtdata->pci_dev, virtdata->virtio_net_cfg,
                                   virtdata->virtio_net_cfg_len);
      virtdata->virtio_net_cfg = NULL;
    }
}

/*
 * Check if the given PCI(e) device is a virtio-net PCI device. If so, get
 * the processor side BAR addresses. The find the device PCI capability
 * registers, and then find the virtio PCI extended capability registers to
 * find the required info for initializing and using a virtio-net device.
 * If that succeeded, then map the extended capability info to RAM so they
 * can easily be accessed. Pass this needed information on to the virtio-net
 * init function.
 */
static int
grub_virtionet_pci_iter (grub_pci_device_t dev, grub_pci_id_t pciid,
                         void *data)
{
  grub_uint32_t val;
  grub_pci_address_t addr;
  int i;
  grub_uint32_t idx;
  struct grub_virtionetcard_data *virtdata
      = (struct grub_virtionetcard_data *)data;
  virtio_pci_cap_t virtio_pci_cap;
  virtio_pci_cap_t virtio_cfg_cap;
  virtio_pci_cap_t virtio_notify_cap;
  virtio_pci_cap_t virtio_net_dev_cap;
  /* Ensure our buffer is big enough with possible padding. */
  grub_uint32_t virtio_pci_buff[(sizeof(virtio_pci_cap_t) / 
                                sizeof(grub_uint32_t)) + 1];
  int ttl;
  grub_addr_t bar_addr[GRUB_VIOPCI_MAX_BARS];

  if (virtdata == NULL)
    {
      grub_error (GRUB_ERR_BUG, "virtdata is NULL.");
      grub_dprintf ("vnet", "Error: virtdata is NULL\n");
      return 0;
    }

  grub_memset (bar_addr, 0, sizeof (bar_addr));
  grub_memset (&virtio_pci_cap, 0, sizeof (virtio_pci_cap));

  /* If the device was already found, skip this one - we only
   * support one for now. */
  if (virtdata->card_found)
    {
      return 0;
    }

  /* If this is not a virtio-net device, just return. Note
   * that we support both "transitional" and regular IDs. */
  if ((pciid != GRUB_VIRTIO_NET_TRANS_PCIID)
      && (pciid != GRUB_VIRTIO_NET_PCIID))
    {
      virtdata->card_found = 0;
      return 0;
    }

  virtdata->card_found = 1;

  grub_dprintf ("vnet", "Found device OK %x\n", pciid);

  /* Look through the max. 6 PCI config regs for the BAR
   * addresses. Derive i (the BAR slot index) from reg at the top of each
   * iteration rather than incrementing a counter. A 64-bit BAR consumes
   * two consecutive register slots but represents one BAR; if i were
   * simply incremented once per loop iteration, the slots after a 64-bit
   * BAR would be indexed one too low, mismatching the bar field in virtio
   * PCI capability structures. */
  int reg = GRUB_PCI_REG_ADDRESSES;
  while (reg < GRUB_PCI_REG_CIS_POINTER)
    {
      grub_addr_t bar_tmp;
      i = (reg - GRUB_PCI_REG_ADDRESSES) / (int) sizeof (grub_uint32_t);
      addr = grub_pci_make_address (dev, reg);
      reg += sizeof (grub_uint32_t);
      bar_tmp = grub_pci_read (addr);

      if ((bar_tmp & GRUB_PCI_ADDR_SPACE_MASK) == GRUB_PCI_ADDR_SPACE_MEMORY)
        {
          if ((bar_tmp & GRUB_PCI_ADDR_MEM_TYPE_MASK)
              == GRUB_PCI_ADDR_MEM_TYPE_64)
            {
              /* A 64-bit BAR occupies two consecutive register slots.
               * Always advance past the high half so subsequent BARs
               * are indexed correctly, even on 32-bit hosts.  On a
               * 32-bit host the high half must be zero for the host
               * to address the BAR, so we ignore it. */
#if GRUB_CPU_SIZEOF_VOID_P == 8
              addr = grub_pci_make_address (dev, reg);
              bar_tmp |= ((grub_uint64_t)grub_pci_read (addr)) << 32;
#endif
              reg += sizeof (grub_uint32_t);
            }
          bar_addr[i] = (bar_tmp & GRUB_PCI_ADDR_MEM_MASK);
        }
    }

  /* Find the virtio_pci_cap capability (0x09). */
  grub_uint8_t pos = grub_pci_find_capability (dev, 0x09);
  if (pos <= GRUB_PCI_REG_CAP_POINTER)
    {
      grub_error (GRUB_ERR_BAD_DEVICE, "cap pointer invalid.");
      grub_dprintf ("vnet", "error: cap pointer invalid %x\n", pos);
      virtdata->card_found = 0;
      return 0;
    }

  /* Ensure we don't get stuck in an infinite loop if the
   * PCI linked list doesn't resolve as expected. */
  ttl = 48;
  bool got_cfg = false;
  bool got_notify = false;
  bool got_net_dev_cfg = false;
  bool got_all = false;
  grub_uint16_t notify_offset = 0;
  /* Look through the virtio-pci device extended capabilities to find the 
   * three structures required by this driver to get the BAR where the data 
   * is located and offset into the BAR.*/
  do
    {
      for (idx = 0; idx < (sizeof (virtio_pci_cap) / sizeof (grub_uint32_t));
           idx++)
        {
          addr = grub_pci_make_address (dev,
                                        pos + (idx * sizeof (grub_uint32_t)));
          val = grub_pci_read (addr);
          virtio_pci_buff[idx] = val;
        }
      grub_memcpy (&virtio_pci_cap, virtio_pci_buff, sizeof (virtio_pci_cap));

      if (virtio_pci_cap.cfg_type == GRUB_VIRTIO_PCI_CAP_COMMON_CFG)
        {
          got_cfg = true;
          grub_memcpy (&virtio_cfg_cap, &virtio_pci_cap,
                       sizeof (virtio_cfg_cap));
        }
      else if (virtio_pci_cap.cfg_type == GRUB_VIRTIO_PCI_CAP_NOTIFY_CFG)
        {
          notify_offset = (grub_uint16_t)pos + sizeof (virtio_pci_cap);
          got_notify = true;
          grub_memcpy (&virtio_notify_cap, &virtio_pci_cap,
                       sizeof (virtio_notify_cap));
        }
      else if (virtio_pci_cap.cfg_type == GRUB_VIRTIO_PCI_CAP_DEVICE_CFG)
        {
          got_net_dev_cfg = true;
          grub_memcpy (&virtio_net_dev_cap, &virtio_pci_cap,
                       sizeof (virtio_net_dev_cap));
        }
      got_all = got_cfg && got_notify && got_net_dev_cfg;

      pos = virtio_pci_cap.cap_next;
      ttl--;
    }
  while (((!got_all)) && (pos > GRUB_PCI_REG_CAP_POINTER) && (ttl > 0));

  if (!got_all)
    {
      grub_error (GRUB_ERR_BAD_DEVICE,
                  "virtio cfg, notify, or netdev cap not found.");
      virtdata->card_found = 0;
      return 0;
    }

  if ((virtio_cfg_cap.bar >= GRUB_VIOPCI_MAX_BARS) || 
      (virtio_notify_cap.bar >= GRUB_VIOPCI_MAX_BARS) ||
      (virtio_net_dev_cap.bar >= GRUB_VIOPCI_MAX_BARS) || 
      (bar_addr[virtio_cfg_cap.bar] == 0) ||
      (bar_addr[virtio_notify_cap.bar] == 0) ||
      (bar_addr[virtio_net_dev_cap.bar] == 0))
    {
      grub_error (GRUB_ERR_BAD_DEVICE, "virtio pci bar invalid.");
      virtdata->card_found = 0;
      return 0;
    }

  /* Enable MEM address spaces and set Bus Master */
  grub_pci_address_t rcaddr
      = grub_pci_make_address (dev, GRUB_PCI_REG_COMMAND);
  grub_pci_write_word (rcaddr, grub_pci_read_word (rcaddr)
                                   | GRUB_PCI_COMMAND_MEM_ENABLED
                                   | GRUB_PCI_COMMAND_BUS_MASTER);

  /* Save device and mapped lengths so teardown can call unmap correctly. */
  virtdata->pci_dev = dev;
  virtdata->virtio_notify_len = virtio_notify_cap.length;
  virtdata->virtio_net_cfg_len = virtio_net_dev_cap.length;

  virtdata->pci_common = grub_pci_device_map_range (
      dev, bar_addr[virtio_cfg_cap.bar] + virtio_cfg_cap.offset,
      sizeof (virtio_pci_common_cfg_t));

  if (virtdata->pci_common == NULL)
    {
      grub_error (GRUB_ERR_BAD_DEVICE, "virtio_pci_common_cfg is NULL.");
      virtdata->card_found = 0;
      return 0;
    }

  virtdata->virtio_notify = grub_pci_device_map_range (
      dev, bar_addr[virtio_notify_cap.bar] + virtio_notify_cap.offset,
      virtio_notify_cap.length);

  if (virtdata->virtio_notify == NULL)
    {
      grub_virtionet_unmap_all (virtdata);
      grub_error (GRUB_ERR_BAD_DEVICE, "virtio_notify is NULL.");
      virtdata->card_found = 0;
      return 0;
    }

  virtdata->virtio_net_cfg = grub_pci_device_map_range (
      dev, bar_addr[virtio_net_dev_cap.bar] + virtio_net_dev_cap.offset,
      virtio_net_dev_cap.length);

  if (virtdata->virtio_net_cfg == NULL)
    {
      grub_virtionet_unmap_all (virtdata);
      grub_error (GRUB_ERR_BAD_DEVICE, "virtio_net_cfg is NULL.");
      virtdata->card_found = 0;
      return 0;
    }

  rcaddr = grub_pci_make_address (dev, notify_offset);

  grub_uint32_t notify_off_multiplier = grub_pci_read (rcaddr);

  grub_err_t err =
    grub_virtio_net_dev_init (
      virtdata->pci_common, virtdata->virtio_notify,
      virtio_notify_cap.length, notify_off_multiplier,
      &virtdata->rx_notify_idx, &virtdata->tx_notify_idx, &virtdata->v_rx,
      &virtdata->v_tx);
  if (err != GRUB_ERR_NONE)
    {
      grub_error (err, "grub_virtio_net_dev_init error.");
      grub_virtionet_unmap_all (virtdata);
      virtdata->card_found = 0;
      return 0;
    }

  return 0;
}

/* Iterate through PCI(e) devices looking for virtio-net PCI devices */
static void
grub_virtionet_pci_scan (struct grub_virtionetcard_data *virtdata)
{
  grub_pci_iterate (grub_virtionet_pci_iter, virtdata);
  return;
}

static grub_err_t
grub_virtionet_restore_hw (void)
{
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_virtionet_open (struct grub_net_card *dev __attribute__ ((unused)))
{
  return GRUB_ERR_NONE;
}

static void
grub_virtionet_close (struct grub_net_card *dev __attribute__ ((unused)))
{
  return;
}

/* Write (transmit) data out the virtio-net device. */
static int
grub_virtionet_write (struct grub_virtionetcard_data *card,
                      grub_uint8_t *txbuf, grub_size_t txbufsize,
                      grub_ssize_t *actual)
{
  grub_uint32_t tx_len;

  if (card == NULL || card->v_tx == NULL || txbuf == NULL || actual == NULL)
    {
      grub_error (GRUB_ERR_BUG, "grub_virtionet_write NULL parameter.");
      return -1;
    }

  tx_len = txbufsize;

  /* Wait for a free TX descriptor.  The cast to grub_uint16_t gives correct
   * modular arithmetic across avail/used wraparound. */
  int count = 0;
  while ((grub_uint16_t)(card->v_tx->avail.idx - card->v_tx->used.idx)
         >= GRUB_VIO_Q_SZ && count < 20)
    {
      count++;
      grub_millisleep (50);
    }
  if ((grub_uint16_t)(card->v_tx->avail.idx - card->v_tx->used.idx)
      >= GRUB_VIO_Q_SZ)
    {
      grub_error (GRUB_ERR_IO, "virtionet: TX queue full");
      return -1;
    }

  grub_uint16_t avail_idx = card->v_tx->avail.idx % GRUB_VIO_Q_SZ;
  grub_addr_t tx_q_addr = (grub_addr_t)(card->v_tx->desc[avail_idx].addr);

  /* Limit size of message being sent (truncate) if too large. */
  if (tx_len + sizeof(grub_virtio_net_hdr_t) > GRUB_VIO_BUFF_CNT)
    tx_len = (GRUB_VIO_BUFF_CNT - sizeof (grub_virtio_net_hdr_t));

  grub_memset ((grub_uint8_t *)tx_q_addr, 0, sizeof (grub_virtio_net_hdr_t));
  grub_memcpy ((grub_uint8_t *)(tx_q_addr + sizeof (grub_virtio_net_hdr_t)),
               txbuf, tx_len);
  *actual = tx_len;
  card->v_tx->desc[avail_idx].flags = 0;
  card->v_tx->desc[avail_idx].len = tx_len + sizeof (grub_virtio_net_hdr_t);
  card->v_tx->avail.flags = GRUB_VIRTQ_AVAIL_F_NO_INTERRUPT;
  MB ();
  grub_uint16_t new_avail_idx = card->v_tx->avail.idx + 1;
  card->v_tx->avail.idx = new_avail_idx;
  MB ();
  card->virtio_notify[card->tx_notify_idx] = GRUB_VIONET_TX_Q_SEL;
  MB ();

  return 0;
}

/* Transmit data out the virtio-net device. */
static grub_err_t
grub_virtionet_send (struct grub_net_card *dev, struct grub_net_buff *pack)
{
  grub_ssize_t actual;
  int status;
  struct grub_virtionetcard_data *data = dev->data;
  grub_size_t len;

  len = (pack->tail - pack->data);
  if (len > dev->mtu)
    len = dev->mtu;

  grub_memcpy (dev->txbuf, pack->data, len);
  status = grub_virtionet_write (data, dev->txbuf, len, &actual);

  if (status)
    return grub_error (GRUB_ERR_IO, N_ ("couldn't send network packet"));
  return GRUB_ERR_NONE;
}

/* Read (receive) data in from the virtio-net device. */
static int
grub_virtionet_read (struct grub_virtionetcard_data *card, void *rcvbuf,
                     grub_size_t rcvbufsize, grub_ssize_t *actual)
{
  grub_uint32_t rx_len;

  if (card == NULL || card->v_rx == NULL || rcvbuf == NULL || actual == NULL)
    {
      grub_error (GRUB_ERR_BUG, "grub_virtionet_read NULL parameter.");
      return -1;
    }

  /* Store temporary (RAM local) versions of these values to avoid any
   * potential for them to change unexpected when checking multiple
   * times.
   */
  grub_uint16_t shdw_last_used = card->v_rx_last_seen_used;
  grub_uint16_t shadow_used = card->v_rx->used.idx;

  /* The device will indicate it "used" a receive buffer (or buffers)
   * by incrementing the used index by the number of buffers used.
   *
   * For us, this means new data was received, so process it.
   */
  if (shdw_last_used != shadow_used)
    {
      grub_uint16_t shdw_last_u_mod = shdw_last_used % GRUB_VIO_Q_SZ;
      /* Ensure we only copy at most receive buff size. */
      rx_len
          = grub_min (rcvbufsize, card->v_rx->used.ring[shdw_last_u_mod].len);

      grub_uint16_t desc_idx = card->v_rx->used.ring[shdw_last_u_mod].id % GRUB_VIO_Q_SZ;

      grub_addr_t rx_q_addr
          = (grub_addr_t)(card->v_rx->desc[desc_idx].addr);
      grub_memcpy (rcvbuf, (grub_uint8_t *)rx_q_addr, rx_len);
      *actual = rx_len;

      card->v_rx->desc[desc_idx].flags = GRUB_VIRTQ_DESC_F_WRITE;
      card->v_rx->avail.flags = GRUB_VIRTQ_AVAIL_F_NO_INTERRUPT;
      card->v_rx_last_seen_used++;
      card->v_rx->avail.ring[card->v_rx->avail.idx % GRUB_VIO_Q_SZ] = desc_idx;
      MB ();
      grub_uint16_t avail_idx = card->v_rx->avail.idx + 1;
      card->v_rx->avail.idx = avail_idx;
      MB ();
      card->virtio_notify[card->rx_notify_idx] = GRUB_VIONET_RX_Q_SEL;
      MB ();
    }
  else
    {
      /* No new data. */
      *actual = 0;
    }

  return 0;
}

/* Receive data from the virtio-net device. */
static struct grub_net_buff *
grub_virtionet_recv (struct grub_net_card *dev)
{
  grub_ssize_t actual = 0;
  int rc = 0;
  struct grub_virtionetcard_data *data = dev->data;
  struct grub_net_buff *nb;
  grub_ssize_t nb_size = 0;
  grub_uint8_t *data_ptr = NULL;
  grub_err_t err;

  rc = grub_virtionet_read (data, dev->rcvbuf, dev->rcvbufsize, &actual);

  if (actual <= 0 || rc < 0)
    return NULL;

  /* Although we don't use the virtio net hdr, check message size for
   * sanity... there should be some actual data too. */
  if (actual <= (grub_ssize_t)sizeof (grub_virtio_net_hdr_t))
    {
      grub_dprintf ("vnet", "error: rx too small min: %zi, got: %zi\n",
                    sizeof (grub_virtio_net_hdr_t), actual);
      return NULL;
    }

  /* Calculate amount of actual received data (without virtio header) */
  /* and then round up to the nearest 4 to ensure 4-byte alignment. */
  nb_size = (actual - sizeof (grub_virtio_net_hdr_t));
  nb = grub_netbuff_alloc (nb_size + 2);
  if (!nb)
    {
      grub_error (GRUB_ERR_BUG, "grub_virtionet_read nb alloc failure.");
      return NULL;
    }

  /* Reserve 2 bytes so that 2 + 14/18 bytes of ethernet header is divisible
     by 4. So that IP header is aligned on 4 bytes. */
  err = grub_netbuff_reserve (nb, 2);
  if (err != GRUB_ERR_NONE)
    {
      grub_error (GRUB_ERR_BUG, "grub_virtionet_read nb reserve failure.");
      grub_netbuff_free (nb);
      return NULL;
    }

  /* Copy the data after the virtio net hdr. */
  data_ptr = (grub_uint8_t *)dev->rcvbuf;
  grub_memcpy (nb->data, &(data_ptr[sizeof (grub_virtio_net_hdr_t)]), nb_size);

  if (grub_netbuff_put (nb, nb_size))
    {
      grub_error (GRUB_ERR_BUG, "grub_virtionet_read nb put failure.");
      grub_netbuff_free (nb);
      return NULL;
    }

  return nb;
}

struct grub_net_card_driver grub_virtionet_card_driver =
  {
    .open = grub_virtionet_open,
    .close = grub_virtionet_close,
    .send = grub_virtionet_send,
    .recv = grub_virtionet_recv
  };

struct grub_net_card grub_vionet_card =
  {
    .driver = &grub_virtionet_card_driver,
    .name = "virtionet"
  };

/* Close / cleanup / reset the virtio-net device. */
static grub_err_t
grub_virtionet_fini_hw (int noreturn __attribute__ ((unused)))
{
  grub_err_t ret_code = GRUB_ERR_NONE;
  
  struct grub_virtionetcard_data *virtdata
      = (struct grub_virtionetcard_data *)grub_vionet_card.data;

  if (virtdata == NULL || virtdata->pci_common == NULL)
    {
      grub_dprintf ("vnet", "grub_virtionet_fini_hw: pci_common is NULL\n");
      return GRUB_ERR_NONE;
    }

  ret_code = grub_virtio_net_dev_reset (virtdata->pci_common);
  if (ret_code != GRUB_ERR_NONE)
    grub_dprintf ("vnet", "grub_virtionet_fini_hw: dev reset error\n");

  /* Unmap PCI ranges and NULL pointers to prevent double-reset/unmap. */
  grub_virtionet_unmap_all (virtdata);

  return GRUB_ERR_NONE;
}

/* Module initialization for virtio-net */
GRUB_MOD_INIT (virtionet)
{
  struct grub_virtionetcard_data *virtdata;

  virtdata = grub_zalloc (sizeof (struct grub_virtionetcard_data));
  if (!virtdata)
    {
      grub_dprintf ("vnet", "virtdata alloc failure.\n");
      grub_print_error ();
      return;
    }

  grub_virtionet_pci_scan (virtdata);
  if (virtdata->card_found == 0)
    {
      grub_dprintf ("vnet", "card not found.\n");
      grub_print_error ();
      grub_free (virtdata);
      return;
    }

  grub_vionet_card.mtu = 1500;
  /* Get device MAC into the driver and set type. */
  grub_net_link_level_address_t lla;
  grub_memset (&lla, 0, sizeof (lla));
  grub_memcpy (&lla.mac, (grub_uint8_t *)virtdata->virtio_net_cfg->mac, 6);
  lla.type = GRUB_NET_LINK_LEVEL_PROTOCOL_ETHERNET;
  grub_vionet_card.default_address = lla;

  grub_vionet_card.txbufsize = ALIGN_UP (grub_vionet_card.mtu, 64) + 256;
  grub_vionet_card.rcvbufsize = ALIGN_UP (grub_vionet_card.mtu, 64) + 256;

  grub_vionet_card.txbuf = grub_malloc (grub_vionet_card.txbufsize);
  if (!grub_vionet_card.txbuf)
    {
      grub_print_error ();
      if (grub_virtio_net_dev_reset (virtdata->pci_common) != GRUB_ERR_NONE)
        grub_dprintf ("vnet", "virtionet init: dev reset error\n");
      grub_virtionet_unmap_all (virtdata);
      grub_free (virtdata);
      return;
    }

  grub_vionet_card.rcvbuf = grub_malloc (grub_vionet_card.rcvbufsize);
  if (!grub_vionet_card.rcvbuf)
    {
      grub_print_error ();
      if (grub_virtio_net_dev_reset (virtdata->pci_common) != GRUB_ERR_NONE)
        grub_dprintf ("vnet", "virtionet init: dev reset error\n");
      grub_free (grub_vionet_card.txbuf);
      grub_virtionet_unmap_all (virtdata);
      grub_free (virtdata);
      return;
    }
  grub_vionet_card.data = virtdata;
  grub_vionet_card.flags = 0;
  grub_vionet_card.idle_poll_delay_ms = 10;
  grub_net_card_register (&grub_vionet_card);

  /* Make sure the virtio device is reset so it stops accessing memory */
  /* before booting the loader target. */
  fini_hnd = grub_loader_register_preboot_hook (
      grub_virtionet_fini_hw, grub_virtionet_restore_hw,
      GRUB_LOADER_PREBOOT_HOOK_PRIO_DISK);

  if (fini_hnd == NULL) 
    grub_print_error();
}

/* Module cleanup function for virtio-net */
GRUB_MOD_FINI (virtionet)
{
  if (grub_vionet_card.data != NULL)
    {
      /* Stop the device from access our memory. */
      grub_virtionet_fini_hw (0);

      /* Cleanup things. */
      if (fini_hnd)
        grub_loader_unregister_preboot_hook (fini_hnd);
      grub_net_card_unregister (&grub_vionet_card);
      if (grub_vionet_card.rcvbuf != NULL)
        {
          grub_free (grub_vionet_card.rcvbuf);
          grub_vionet_card.rcvbuf = NULL;
        }
      if (grub_vionet_card.txbuf != NULL)
        {
          grub_free (grub_vionet_card.txbuf);
          grub_vionet_card.txbuf = NULL;
        }

      grub_free (grub_vionet_card.data);
      grub_vionet_card.data = NULL;
    }
}

