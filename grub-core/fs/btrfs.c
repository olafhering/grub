/* btrfs.c - B-tree file system.  */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010,2011,2012,2013  Free Software Foundation, Inc.
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
 * Tell zstd to expose functions that aren't part of the stable API, which
 * aren't safe to use when linking against a dynamic library. We vendor in a
 * specific zstd version, so we know what we're getting. We need these unstable
 * functions to provide our own allocator, which uses grub_malloc(), to zstd.
 */
#define ZSTD_STATIC_LINKING_ONLY

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/lib/crc.h>
#include <grub/deflate.h>
#include <minilzo.h>
#include <zstd.h>
#include <grub/i18n.h>
#include <grub/btrfs.h>
#include <grub/crypto.h>
#include <grub/diskfilter.h>
#include <grub/safemath.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define GRUB_BTRFS_SIGNATURE "_BHRfS_M"

/* From http://www.oberhumer.com/opensource/lzo/lzofaq.php
 * LZO will expand incompressible data by a little amount. I still haven't
 * computed the exact values, but I suggest using these formulas for
 * a worst-case expansion calculation:
 *
 * output_block_size = input_block_size + (input_block_size / 16) + 64 + 3
 *  */
#define GRUB_BTRFS_LZO_BLOCK_SIZE 4096
#define GRUB_BTRFS_LZO_BLOCK_MAX_CSIZE (GRUB_BTRFS_LZO_BLOCK_SIZE + \
				     (GRUB_BTRFS_LZO_BLOCK_SIZE / 16) + 64 + 3)

#define ZSTD_BTRFS_MAX_WINDOWLOG 17
#define ZSTD_BTRFS_MAX_INPUT     (1 << ZSTD_BTRFS_MAX_WINDOWLOG)

typedef grub_uint8_t grub_btrfs_checksum_t[0x20];
typedef grub_uint16_t grub_btrfs_uuid_t[8];

struct grub_btrfs_device
{
  grub_uint64_t device_id;
  grub_uint64_t size;
  grub_uint8_t dummy[0x62 - 0x10];
} GRUB_PACKED;

struct grub_btrfs_superblock
{
  grub_btrfs_checksum_t checksum;
  grub_btrfs_uuid_t uuid;
  grub_uint8_t dummy[0x10];
  grub_uint8_t signature[sizeof (GRUB_BTRFS_SIGNATURE) - 1];
  grub_uint64_t generation;
  grub_uint64_t root_tree;
  grub_uint64_t chunk_tree;
  grub_uint8_t dummy2[0x20];
  grub_uint64_t root_dir_objectid;
  grub_uint8_t dummy3[0x41];
  struct grub_btrfs_device this_device;
  char label[0x100];
  grub_uint8_t dummy4[0x100];
  grub_uint8_t bootstrap_mapping[0x800];
} GRUB_PACKED;

struct btrfs_header
{
  grub_btrfs_checksum_t checksum;
  grub_btrfs_uuid_t uuid;
  grub_uint64_t bytenr;
  grub_uint8_t dummy[0x28];
  grub_uint32_t nitems;
  grub_uint8_t level;
} GRUB_PACKED;

struct grub_btrfs_device_desc
{
  grub_device_t dev;
  grub_uint64_t id;
};

struct grub_btrfs_data
{
  struct grub_btrfs_superblock sblock;
  grub_uint64_t tree;
  grub_uint64_t inode;

  struct grub_btrfs_device_desc *devices_attached;
  unsigned n_devices_attached;
  unsigned n_devices_allocated;

  /* Cached extent data.  */
  grub_uint64_t extstart;
  grub_uint64_t extend;
  grub_uint64_t extino;
  grub_uint64_t exttree;
  grub_size_t extsize;
  struct grub_btrfs_extent_data *extent;
};

struct grub_btrfs_chunk_item
{
  grub_uint64_t size;
  grub_uint64_t dummy;
  grub_uint64_t stripe_length;
  grub_uint64_t type;
#define GRUB_BTRFS_CHUNK_TYPE_BITS_DONTCARE 0x07
#define GRUB_BTRFS_CHUNK_TYPE_SINGLE        0x00
#define GRUB_BTRFS_CHUNK_TYPE_RAID0         0x08
#define GRUB_BTRFS_CHUNK_TYPE_RAID1         0x10
#define GRUB_BTRFS_CHUNK_TYPE_DUPLICATED    0x20
#define GRUB_BTRFS_CHUNK_TYPE_RAID10        0x40
#define GRUB_BTRFS_CHUNK_TYPE_RAID5         0x80
#define GRUB_BTRFS_CHUNK_TYPE_RAID6         0x100
#define GRUB_BTRFS_CHUNK_TYPE_RAID1C3       0x200
#define GRUB_BTRFS_CHUNK_TYPE_RAID1C4       0x400
  grub_uint8_t dummy2[0xc];
  grub_uint16_t nstripes;
  grub_uint16_t nsubstripes;
} GRUB_PACKED;

struct grub_btrfs_chunk_stripe
{
  grub_uint64_t device_id;
  grub_uint64_t offset;
  grub_btrfs_uuid_t device_uuid;
} GRUB_PACKED;

struct grub_btrfs_leaf_node
{
  struct grub_btrfs_key key;
  grub_uint32_t offset;
  grub_uint32_t size;
} GRUB_PACKED;

struct grub_btrfs_internal_node
{
  struct grub_btrfs_key key;
  grub_uint64_t addr;
  grub_uint64_t dummy;
} GRUB_PACKED;

struct grub_btrfs_dir_item
{
  struct grub_btrfs_key key;
  grub_uint8_t dummy[8];
  grub_uint16_t m;
  grub_uint16_t n;
#define GRUB_BTRFS_DIR_ITEM_TYPE_REGULAR 1
#define GRUB_BTRFS_DIR_ITEM_TYPE_DIRECTORY 2
#define GRUB_BTRFS_DIR_ITEM_TYPE_SYMLINK 7
  grub_uint8_t type;
  char name[0];
} GRUB_PACKED;

struct grub_btrfs_leaf_descriptor
{
  unsigned depth;
  unsigned allocated;
  struct
  {
    grub_disk_addr_t addr;
    unsigned iter;
    unsigned maxiter;
    int leaf;
  } *data;
};

struct grub_btrfs_time
{
  grub_int64_t sec;
  grub_uint32_t nanosec;
} GRUB_PACKED;

struct grub_btrfs_inode
{
  grub_uint8_t dummy1[0x10];
  grub_uint64_t size;
  grub_uint8_t dummy2[0x70];
  struct grub_btrfs_time mtime;
} GRUB_PACKED;

struct grub_btrfs_extent_data
{
  grub_uint64_t dummy;
  grub_uint64_t size;
  grub_uint8_t compression;
  grub_uint8_t encryption;
  grub_uint16_t encoding;
  grub_uint8_t type;
  union
  {
    char inl[0];
    struct
    {
      grub_uint64_t laddr;
      grub_uint64_t compressed_size;
      grub_uint64_t offset;
      grub_uint64_t filled;
    };
  };
} GRUB_PACKED;

#define GRUB_BTRFS_EXTENT_INLINE 0
#define GRUB_BTRFS_EXTENT_REGULAR 1

#define GRUB_BTRFS_COMPRESSION_NONE 0
#define GRUB_BTRFS_COMPRESSION_ZLIB 1
#define GRUB_BTRFS_COMPRESSION_LZO  2
#define GRUB_BTRFS_COMPRESSION_ZSTD 3

#define GRUB_BTRFS_OBJECT_ID_CHUNK 0x100

static grub_disk_addr_t superblock_sectors[] = { 64 * 2, 64 * 1024 * 2,
  256 * 1048576 * 2, 1048576ULL * 1048576ULL * 2
};

static grub_err_t
grub_btrfs_read_logical (struct grub_btrfs_data *data,
			 grub_disk_addr_t addr, void *buf, grub_size_t size,
			 int recursion_depth);

static grub_err_t
read_sblock (grub_disk_t disk, struct grub_btrfs_superblock *sb)
{
  struct grub_btrfs_superblock sblock;
  unsigned i;
  grub_err_t err = GRUB_ERR_NONE;
  for (i = 0; i < ARRAY_SIZE (superblock_sectors); i++)
    {
      /* Don't try additional superblocks beyond device size.  */
      if (i && (grub_le_to_cpu64 (sblock.this_device.size)
		>> GRUB_DISK_SECTOR_BITS) <= superblock_sectors[i])
	break;
      err = grub_disk_read (disk, superblock_sectors[i], 0,
			    sizeof (sblock), &sblock);
      if (err == GRUB_ERR_OUT_OF_RANGE)
	break;

      if (grub_memcmp ((char *) sblock.signature, GRUB_BTRFS_SIGNATURE,
		       sizeof (GRUB_BTRFS_SIGNATURE) - 1) != 0)
	break;
      if (i == 0 || grub_le_to_cpu64 (sblock.generation)
	  > grub_le_to_cpu64 (sb->generation))
	grub_memcpy (sb, &sblock, sizeof (sblock));
    }

  if ((err == GRUB_ERR_OUT_OF_RANGE || !err) && i == 0)
    return grub_error (GRUB_ERR_BAD_FS, "not a Btrfs filesystem");

  if (err == GRUB_ERR_OUT_OF_RANGE)
    grub_errno = err = GRUB_ERR_NONE;

  return err;
}

static int
key_cmp (const struct grub_btrfs_key *a, const struct grub_btrfs_key *b)
{
  if (grub_le_to_cpu64 (a->object_id) < grub_le_to_cpu64 (b->object_id))
    return -1;
  if (grub_le_to_cpu64 (a->object_id) > grub_le_to_cpu64 (b->object_id))
    return +1;

  if (a->type < b->type)
    return -1;
  if (a->type > b->type)
    return +1;

  if (grub_le_to_cpu64 (a->offset) < grub_le_to_cpu64 (b->offset))
    return -1;
  if (grub_le_to_cpu64 (a->offset) > grub_le_to_cpu64 (b->offset))
    return +1;
  return 0;
}

static void
free_iterator (struct grub_btrfs_leaf_descriptor *desc)
{
  grub_free (desc->data);
}

static grub_err_t
check_btrfs_header (struct grub_btrfs_data *data, struct btrfs_header *header,
                    grub_disk_addr_t addr)
{
  if (grub_le_to_cpu64 (header->bytenr) != addr)
    {
      grub_dprintf ("btrfs", "btrfs_header.bytenr is not equal node addr\n");
      return grub_error (GRUB_ERR_BAD_FS,
			 "header bytenr is not equal node addr");
    }
  if (grub_memcmp (data->sblock.uuid, header->uuid, sizeof(grub_btrfs_uuid_t)))
    {
      grub_dprintf ("btrfs", "btrfs_header.uuid doesn't match sblock uuid\n");
      return grub_error (GRUB_ERR_BAD_FS,
			 "header uuid doesn't match sblock uuid");
    }
  return GRUB_ERR_NONE;
}

static grub_err_t
save_ref (struct grub_btrfs_leaf_descriptor *desc,
	  grub_disk_addr_t addr, unsigned i, unsigned m, int l)
{
  desc->depth++;
  if (desc->allocated < desc->depth)
    {
      void *newdata;
      grub_size_t sz;

      if (grub_mul (desc->allocated, 2, &desc->allocated) ||
	  grub_mul (desc->allocated, sizeof (desc->data[0]), &sz))
	return GRUB_ERR_OUT_OF_RANGE;

      newdata = grub_realloc (desc->data, sz);
      if (!newdata)
	return grub_errno;
      desc->data = newdata;
    }
  desc->data[desc->depth - 1].addr = addr;
  desc->data[desc->depth - 1].iter = i;
  desc->data[desc->depth - 1].maxiter = m;
  desc->data[desc->depth - 1].leaf = l;
  return GRUB_ERR_NONE;
}

static int
next (struct grub_btrfs_data *data,
      struct grub_btrfs_leaf_descriptor *desc,
      grub_disk_addr_t * outaddr, grub_size_t * outsize,
      struct grub_btrfs_key *key_out)
{
  grub_err_t err;
  struct grub_btrfs_leaf_node leaf;

  for (; desc->depth > 0; desc->depth--)
    {
      desc->data[desc->depth - 1].iter++;
      if (desc->data[desc->depth - 1].iter
	  < desc->data[desc->depth - 1].maxiter)
	break;
    }
  if (desc->depth == 0)
    return 0;
  while (!desc->data[desc->depth - 1].leaf)
    {
      struct grub_btrfs_internal_node node;
      struct btrfs_header head;

      err = grub_btrfs_read_logical (data, desc->data[desc->depth - 1].iter
				     * sizeof (node)
				     + sizeof (struct btrfs_header)
				     + desc->data[desc->depth - 1].addr,
				     &node, sizeof (node), 0);
      if (err)
	return -err;

      err = grub_btrfs_read_logical (data, grub_le_to_cpu64 (node.addr),
				     &head, sizeof (head), 0);
      if (err)
	return -err;
      check_btrfs_header (data, &head, grub_le_to_cpu64 (node.addr));

      save_ref (desc, grub_le_to_cpu64 (node.addr), 0,
		grub_le_to_cpu32 (head.nitems), !head.level);
    }
  err = grub_btrfs_read_logical (data, desc->data[desc->depth - 1].iter
				 * sizeof (leaf)
				 + sizeof (struct btrfs_header)
				 + desc->data[desc->depth - 1].addr, &leaf,
				 sizeof (leaf), 0);
  if (err)
    return -err;
  *outsize = grub_le_to_cpu32 (leaf.size);
  *outaddr = desc->data[desc->depth - 1].addr + sizeof (struct btrfs_header)
    + grub_le_to_cpu32 (leaf.offset);
  *key_out = leaf.key;
  return 1;
}

static grub_err_t
lower_bound (struct grub_btrfs_data *data,
	     const struct grub_btrfs_key *key_in,
	     struct grub_btrfs_key *key_out,
	     grub_uint64_t root,
	     grub_disk_addr_t *outaddr, grub_size_t *outsize,
	     struct grub_btrfs_leaf_descriptor *desc,
	     int recursion_depth)
{
  grub_disk_addr_t addr = grub_le_to_cpu64 (root);
  int depth = -1;

  if (desc)
    {
      desc->allocated = 16;
      desc->depth = 0;
      desc->data = grub_calloc (desc->allocated, sizeof (desc->data[0]));
      if (!desc->data)
	return grub_errno;
    }

  /* > 2 would work as well but be robust and allow a bit more just in case.
   */
  if (recursion_depth > 10)
    return grub_error (GRUB_ERR_BAD_FS, "too deep btrfs virtual nesting");

  grub_dprintf ("btrfs",
		"retrieving %" PRIxGRUB_UINT64_T
		" %x %" PRIxGRUB_UINT64_T "\n",
		key_in->object_id, key_in->type, key_in->offset);

  while (1)
    {
      grub_err_t err;
      struct btrfs_header head;

    reiter:
      depth++;
      /* FIXME: preread few nodes into buffer. */
      err = grub_btrfs_read_logical (data, addr, &head, sizeof (head),
				     recursion_depth + 1);
      if (err)
	return err;
      check_btrfs_header (data, &head, addr);
      addr += sizeof (head);
      if (head.level)
	{
	  unsigned i;
	  struct grub_btrfs_internal_node node, node_last;
	  int have_last = 0;
	  grub_memset (&node_last, 0, sizeof (node_last));
	  for (i = 0; i < grub_le_to_cpu32 (head.nitems); i++)
	    {
	      err = grub_btrfs_read_logical (data, addr + i * sizeof (node),
					     &node, sizeof (node),
					     recursion_depth + 1);
	      if (err)
		return err;

	      grub_dprintf ("btrfs",
			    "internal node (depth %d) %" PRIxGRUB_UINT64_T
			    " %x %" PRIxGRUB_UINT64_T "\n", depth,
			    node.key.object_id, node.key.type,
			    node.key.offset);

	      if (key_cmp (&node.key, key_in) == 0)
		{
		  err = GRUB_ERR_NONE;
		  if (desc)
		    err = save_ref (desc, addr - sizeof (head), i,
				    grub_le_to_cpu32 (head.nitems), 0);
		  if (err)
		    return err;
		  addr = grub_le_to_cpu64 (node.addr);
		  goto reiter;
		}
	      if (key_cmp (&node.key, key_in) > 0)
		break;
	      node_last = node;
	      have_last = 1;
	    }
	  if (have_last)
	    {
	      err = GRUB_ERR_NONE;
	      if (desc)
		err = save_ref (desc, addr - sizeof (head), i - 1,
				grub_le_to_cpu32 (head.nitems), 0);
	      if (err)
		return err;
	      addr = grub_le_to_cpu64 (node_last.addr);
	      goto reiter;
	    }
	  *outsize = 0;
	  *outaddr = 0;
	  grub_memset (key_out, 0, sizeof (*key_out));
	  if (desc)
	    return save_ref (desc, addr - sizeof (head), -1,
			     grub_le_to_cpu32 (head.nitems), 0);
	  return GRUB_ERR_NONE;
	}
      {
	unsigned i;
	struct grub_btrfs_leaf_node leaf, leaf_last;
	int have_last = 0;
	for (i = 0; i < grub_le_to_cpu32 (head.nitems); i++)
	  {
	    err = grub_btrfs_read_logical (data, addr + i * sizeof (leaf),
					   &leaf, sizeof (leaf),
					   recursion_depth + 1);
	    if (err)
	      return err;

	    grub_dprintf ("btrfs",
			  "leaf (depth %d) %" PRIxGRUB_UINT64_T
			  " %x %" PRIxGRUB_UINT64_T "\n", depth,
			  leaf.key.object_id, leaf.key.type, leaf.key.offset);

	    if (key_cmp (&leaf.key, key_in) == 0)
	      {
		grub_memcpy (key_out, &leaf.key, sizeof (*key_out));
		*outsize = grub_le_to_cpu32 (leaf.size);
		*outaddr = addr + grub_le_to_cpu32 (leaf.offset);
		if (desc)
		  return save_ref (desc, addr - sizeof (head), i,
				   grub_le_to_cpu32 (head.nitems), 1);
		return GRUB_ERR_NONE;
	      }

	    if (key_cmp (&leaf.key, key_in) > 0)
	      break;

	    have_last = 1;
	    leaf_last = leaf;
	  }

	if (have_last)
	  {
	    grub_memcpy (key_out, &leaf_last.key, sizeof (*key_out));
	    *outsize = grub_le_to_cpu32 (leaf_last.size);
	    *outaddr = addr + grub_le_to_cpu32 (leaf_last.offset);
	    if (desc)
	      return save_ref (desc, addr - sizeof (head), i - 1,
			       grub_le_to_cpu32 (head.nitems), 1);
	    return GRUB_ERR_NONE;
	  }
	*outsize = 0;
	*outaddr = 0;
	grub_memset (key_out, 0, sizeof (*key_out));
	if (desc)
	  return save_ref (desc, addr - sizeof (head), -1,
			   grub_le_to_cpu32 (head.nitems), 1);
	return GRUB_ERR_NONE;
      }
    }
}

/* Context for find_device.  */
struct find_device_ctx
{
  struct grub_btrfs_data *data;
  grub_uint64_t id;
  grub_device_t dev_found;
};

/* Helper for find_device.  */
static int
find_device_iter (const char *name, void *data)
{
  struct find_device_ctx *ctx = data;
  grub_device_t dev;
  grub_err_t err;
  struct grub_btrfs_superblock sb;

  dev = grub_device_open (name);
  if (!dev)
    return 0;
  if (!dev->disk)
    {
      grub_device_close (dev);
      return 0;
    }
  err = read_sblock (dev->disk, &sb);
  if (err == GRUB_ERR_BAD_FS)
    {
      grub_device_close (dev);
      grub_errno = GRUB_ERR_NONE;
      return 0;
    }
  if (err)
    {
      grub_device_close (dev);
      grub_print_error ();
      return 0;
    }
  if (grub_memcmp (ctx->data->sblock.uuid, sb.uuid, sizeof (sb.uuid)) != 0
      || sb.this_device.device_id != ctx->id)
    {
      grub_device_close (dev);
      return 0;
    }

  ctx->dev_found = dev;
  return 1;
}

static grub_device_t
find_device (struct grub_btrfs_data *data, grub_uint64_t id)
{
  struct find_device_ctx ctx = {
    .data = data,
    .id = id,
    .dev_found = NULL
  };
  unsigned i;

  for (i = 0; i < data->n_devices_attached; i++)
    if (id == data->devices_attached[i].id)
      return data->devices_attached[i].dev;

  grub_device_iterate (find_device_iter, &ctx);

  data->n_devices_attached++;
  if (data->n_devices_attached > data->n_devices_allocated)
    {
      void *tmp;
      grub_size_t sz;

      if (grub_mul (data->n_devices_attached, 2, &data->n_devices_allocated) ||
	  grub_add (data->n_devices_allocated, 1, &data->n_devices_allocated) ||
	  grub_mul (data->n_devices_allocated, sizeof (data->devices_attached[0]), &sz))
	goto fail;

      data->devices_attached = grub_realloc (tmp = data->devices_attached, sz);
      if (!data->devices_attached)
	{
	  data->devices_attached = tmp;

 fail:
	  if (ctx.dev_found)
	    grub_device_close (ctx.dev_found);
	  return NULL;
	}
    }
  data->devices_attached[data->n_devices_attached - 1].id = id;
  data->devices_attached[data->n_devices_attached - 1].dev = ctx.dev_found;
  return ctx.dev_found;
}

static grub_err_t
btrfs_read_from_chunk (struct grub_btrfs_data *data,
		       struct grub_btrfs_chunk_item *chunk,
		       grub_uint64_t stripen, grub_uint64_t stripe_offset,
		       int redundancy, grub_uint64_t csize,
		       void *buf)
{
    struct grub_btrfs_chunk_stripe *stripe;
    grub_disk_addr_t paddr;
    grub_device_t dev;
    grub_err_t err;

    stripe = (struct grub_btrfs_chunk_stripe *) (chunk + 1);
    /* Right now the redundancy handling is easy.
       With RAID5-like it will be more difficult.  */
    stripe += stripen + redundancy;

    paddr = grub_le_to_cpu64 (stripe->offset) + stripe_offset;

    grub_dprintf ("btrfs", "stripe %" PRIxGRUB_UINT64_T
		  " maps to 0x%" PRIxGRUB_UINT64_T "\n"
		  "reading paddr 0x%" PRIxGRUB_UINT64_T "\n",
		  stripen, stripe->offset, paddr);

    dev = find_device (data, stripe->device_id);
    if (!dev)
      {
	grub_dprintf ("btrfs",
		      "couldn't find a necessary member device "
		      "of multi-device filesystem\n");
	grub_errno = GRUB_ERR_NONE;
	return GRUB_ERR_READ_ERROR;
      }

    err = grub_disk_read (dev->disk, paddr >> GRUB_DISK_SECTOR_BITS,
			  paddr & (GRUB_DISK_SECTOR_SIZE - 1),
			  csize, buf);
    return err;
}

struct raid56_buffer {
  void *buf;
  int  data_is_valid;
};

static void
rebuild_raid5 (char *dest, struct raid56_buffer *buffers,
	       grub_uint64_t nstripes, grub_uint64_t csize)
{
  grub_uint64_t i;
  int first;

  for(i = 0; buffers[i].data_is_valid && i < nstripes; i++);

  if (i == nstripes)
    {
      grub_dprintf ("btrfs", "called rebuild_raid5(), but all disks are OK\n");
      return;
    }

  grub_dprintf ("btrfs", "rebuilding RAID 5 stripe #%" PRIuGRUB_UINT64_T "\n", i);

  for (i = 0, first = 1; i < nstripes; i++)
    {
      if (!buffers[i].data_is_valid)
	continue;

      if (first) {
	grub_memcpy(dest, buffers[i].buf, csize);
	first = 0;
      } else
	grub_crypto_xor (dest, dest, buffers[i].buf, csize);
    }
}

static grub_err_t
raid6_recover_read_buffer (void *data, int disk_nr,
			   grub_uint64_t addr __attribute__ ((unused)),
			   void *dest, grub_size_t size)
{
    struct raid56_buffer *buffers = data;

    if (!buffers[disk_nr].data_is_valid)
	return grub_errno = GRUB_ERR_READ_ERROR;

    grub_memcpy(dest, buffers[disk_nr].buf, size);

    return grub_errno = GRUB_ERR_NONE;
}

static void
rebuild_raid6 (struct raid56_buffer *buffers, grub_uint64_t nstripes,
               grub_uint64_t csize, grub_uint64_t parities_pos, void *dest,
               grub_uint64_t stripen)

{
  grub_raid6_recover_gen (buffers, nstripes, stripen, parities_pos,
                          dest, 0, csize, 0, raid6_recover_read_buffer);
}

static grub_err_t
raid56_read_retry (struct grub_btrfs_data *data,
		   struct grub_btrfs_chunk_item *chunk,
		   grub_uint64_t stripe_offset, grub_uint64_t stripen,
		   grub_uint64_t csize, void *buf, grub_uint64_t parities_pos)
{
  struct raid56_buffer *buffers;
  grub_uint64_t nstripes = grub_le_to_cpu16 (chunk->nstripes);
  grub_uint64_t chunk_type = grub_le_to_cpu64 (chunk->type);
  grub_err_t ret = GRUB_ERR_OUT_OF_MEMORY;
  grub_uint64_t i, failed_devices;

  buffers = grub_calloc (nstripes, sizeof (*buffers));
  if (!buffers)
    goto cleanup;

  for (i = 0; i < nstripes; i++)
    {
      buffers[i].buf = grub_zalloc (csize);
      if (!buffers[i].buf)
	goto cleanup;
    }

  for (failed_devices = 0, i = 0; i < nstripes; i++)
    {
      struct grub_btrfs_chunk_stripe *stripe;
      grub_disk_addr_t paddr;
      grub_device_t dev;
      grub_err_t err;

      /*
       * The struct grub_btrfs_chunk_stripe array lives
       * behind struct grub_btrfs_chunk_item.
       */
      stripe = (struct grub_btrfs_chunk_stripe *) (chunk + 1) + i;

      paddr = grub_le_to_cpu64 (stripe->offset) + stripe_offset;
      grub_dprintf ("btrfs", "reading paddr %" PRIxGRUB_UINT64_T
                    " from stripe ID %" PRIxGRUB_UINT64_T "\n",
                    paddr, stripe->device_id);

      dev = find_device (data, stripe->device_id);
      if (!dev)
	{
	  grub_dprintf ("btrfs", "stripe %" PRIuGRUB_UINT64_T " FAILED (dev ID %"
			PRIxGRUB_UINT64_T ")\n", i, stripe->device_id);
	  failed_devices++;
	  continue;
	}

      err = grub_disk_read (dev->disk, paddr >> GRUB_DISK_SECTOR_BITS,
			    paddr & (GRUB_DISK_SECTOR_SIZE - 1),
			    csize, buffers[i].buf);
      if (err == GRUB_ERR_NONE)
	{
	  buffers[i].data_is_valid = 1;
	  grub_dprintf ("btrfs", "stripe %" PRIuGRUB_UINT64_T " OK (dev ID %"
			PRIxGRUB_UINT64_T ")\n", i, stripe->device_id);
	}
      else
	{
	  grub_dprintf ("btrfs", "stripe %" PRIuGRUB_UINT64_T
			" READ FAILED (dev ID %" PRIxGRUB_UINT64_T ")\n",
			i, stripe->device_id);
	  failed_devices++;
	}
    }

  if (failed_devices > 1 && (chunk_type & GRUB_BTRFS_CHUNK_TYPE_RAID5))
    {
      grub_dprintf ("btrfs", "not enough disks for RAID 5: total %" PRIuGRUB_UINT64_T
		    ", missing %" PRIuGRUB_UINT64_T "\n",
		    nstripes, failed_devices);
      ret = GRUB_ERR_READ_ERROR;
      goto cleanup;
    }
  else if (failed_devices > 2 && (chunk_type & GRUB_BTRFS_CHUNK_TYPE_RAID6))
    {
      grub_dprintf ("btrfs", "not enough disks for RAID 6: total %" PRIuGRUB_UINT64_T
		    ", missing %" PRIuGRUB_UINT64_T "\n",
		    nstripes, failed_devices);
      ret = GRUB_ERR_READ_ERROR;
      goto cleanup;
    }
  else
    grub_dprintf ("btrfs", "enough disks for RAID 5: total %"
		  PRIuGRUB_UINT64_T ", missing %" PRIuGRUB_UINT64_T "\n",
		  nstripes, failed_devices);

  /* We have enough disks. So, rebuild the data. */
  if (chunk_type & GRUB_BTRFS_CHUNK_TYPE_RAID5)
    rebuild_raid5 (buf, buffers, nstripes, csize);
  else
    rebuild_raid6 (buffers, nstripes, csize, parities_pos, buf, stripen);

  ret = GRUB_ERR_NONE;
 cleanup:
  if (buffers)
    for (i = 0; i < nstripes; i++)
	grub_free (buffers[i].buf);
  grub_free (buffers);

  return ret;
}

static grub_err_t
grub_btrfs_read_logical (struct grub_btrfs_data *data, grub_disk_addr_t addr,
			 void *buf, grub_size_t size, int recursion_depth)
{
  while (size > 0)
    {
      grub_uint8_t *ptr;
      struct grub_btrfs_key *key;
      struct grub_btrfs_chunk_item *chunk;
      grub_uint64_t csize;
      grub_err_t err = 0;
      struct grub_btrfs_key key_out;
      int challoc = 0;
      struct grub_btrfs_key key_in;
      grub_size_t chsize;
      grub_disk_addr_t chaddr;

      grub_dprintf ("btrfs", "searching for laddr %" PRIxGRUB_UINT64_T "\n",
		    addr);
      for (ptr = data->sblock.bootstrap_mapping;
	   ptr < data->sblock.bootstrap_mapping
	   + sizeof (data->sblock.bootstrap_mapping)
	   - sizeof (struct grub_btrfs_key);)
	{
	  key = (struct grub_btrfs_key *) ptr;
	  if (key->type != GRUB_BTRFS_ITEM_TYPE_CHUNK)
	    break;
	  chunk = (struct grub_btrfs_chunk_item *) (key + 1);
	  grub_dprintf ("btrfs",
			"%" PRIxGRUB_UINT64_T " %" PRIxGRUB_UINT64_T " \n",
			grub_le_to_cpu64 (key->offset),
			grub_le_to_cpu64 (chunk->size));
	  if (grub_le_to_cpu64 (key->offset) <= addr
	      && addr < grub_le_to_cpu64 (key->offset)
	      + grub_le_to_cpu64 (chunk->size))
	    goto chunk_found;
	  ptr += sizeof (*key) + sizeof (*chunk)
	    + sizeof (struct grub_btrfs_chunk_stripe)
	    * grub_le_to_cpu16 (chunk->nstripes);
	}

      key_in.object_id = grub_cpu_to_le64_compile_time (GRUB_BTRFS_OBJECT_ID_CHUNK);
      key_in.type = GRUB_BTRFS_ITEM_TYPE_CHUNK;
      key_in.offset = grub_cpu_to_le64 (addr);
      err = lower_bound (data, &key_in, &key_out,
			 data->sblock.chunk_tree,
			 &chaddr, &chsize, NULL, recursion_depth);
      if (err)
	return err;
      key = &key_out;
      if (key->type != GRUB_BTRFS_ITEM_TYPE_CHUNK
	  || !(grub_le_to_cpu64 (key->offset) <= addr))
	return grub_error (GRUB_ERR_BAD_FS,
			   "couldn't find the chunk descriptor");

      if (!chsize)
	{
	  grub_dprintf ("btrfs", "zero-size chunk\n");
	  return grub_error (GRUB_ERR_BAD_FS,
			     "got an invalid zero-size chunk");
	}

      /*
       * The space being allocated for a chunk should at least be able to
       * contain one chunk item.
       */
      if (chsize < sizeof (struct grub_btrfs_chunk_item))
       {
         grub_dprintf ("btrfs", "chunk-size too small\n");
         return grub_error (GRUB_ERR_BAD_FS,
                            "got an invalid chunk size");
       }
      chunk = grub_malloc (chsize);
      if (!chunk)
	return grub_errno;

      challoc = 1;
      err = grub_btrfs_read_logical (data, chaddr, chunk, chsize,
				     recursion_depth);
      if (err)
	{
	  grub_free (chunk);
	  return err;
	}

    chunk_found:
      {
	grub_uint64_t stripen;
	grub_uint64_t stripe_offset;
	grub_uint64_t off = addr - grub_le_to_cpu64 (key->offset);
	grub_uint64_t chunk_stripe_length;
	grub_uint16_t nstripes;
	unsigned redundancy = 1;
	unsigned i, j;
	int is_raid56;
	grub_uint64_t parities_pos = 0;

        is_raid56 = !!(grub_le_to_cpu64 (chunk->type) &
		       (GRUB_BTRFS_CHUNK_TYPE_RAID5 |
		        GRUB_BTRFS_CHUNK_TYPE_RAID6));

	if (grub_le_to_cpu64 (chunk->size) <= off)
	  {
	    grub_dprintf ("btrfs", "no chunk\n");
	    return grub_error (GRUB_ERR_BAD_FS,
			       "couldn't find the chunk descriptor");
	  }

	nstripes = grub_le_to_cpu16 (chunk->nstripes) ? : 1;
	chunk_stripe_length = grub_le_to_cpu64 (chunk->stripe_length) ? : 512;
	grub_dprintf ("btrfs", "chunk 0x%" PRIxGRUB_UINT64_T
		      "+0x%" PRIxGRUB_UINT64_T
		      " (%d stripes (%d substripes) of %"
		      PRIxGRUB_UINT64_T ")\n",
		      grub_le_to_cpu64 (key->offset),
		      grub_le_to_cpu64 (chunk->size),
		      nstripes,
		      grub_le_to_cpu16 (chunk->nsubstripes),
		      chunk_stripe_length);

	switch (grub_le_to_cpu64 (chunk->type)
		& ~GRUB_BTRFS_CHUNK_TYPE_BITS_DONTCARE)
	  {
	  case GRUB_BTRFS_CHUNK_TYPE_SINGLE:
	    {
	      grub_uint64_t stripe_length;
	      grub_dprintf ("btrfs", "single\n");
	      stripe_length = grub_divmod64 (grub_le_to_cpu64 (chunk->size),
					     nstripes,
					     NULL);

	      /* For single, there should be exactly 1 stripe. */
	      if (grub_le_to_cpu16 (chunk->nstripes) != 1)
		{
		  grub_dprintf ("btrfs", "invalid RAID_SINGLE: nstripes != 1 (%u)\n",
				grub_le_to_cpu16 (chunk->nstripes));
		  return grub_error (GRUB_ERR_BAD_FS,
				     "invalid RAID_SINGLE: nstripes != 1 (%u)",
				      grub_le_to_cpu16 (chunk->nstripes));
		}
	      if (stripe_length == 0)
		stripe_length = 512;
	      stripen = grub_divmod64 (off, stripe_length, &stripe_offset);
	      csize = (stripen + 1) * stripe_length - off;
	      break;
	    }
	  case GRUB_BTRFS_CHUNK_TYPE_RAID1C4:
	    redundancy++;
	    /* fall through */
	  case GRUB_BTRFS_CHUNK_TYPE_RAID1C3:
	    redundancy++;
	    /* fall through */
	  case GRUB_BTRFS_CHUNK_TYPE_DUPLICATED:
	  case GRUB_BTRFS_CHUNK_TYPE_RAID1:
	    {
	      grub_dprintf ("btrfs", "RAID1 (copies: %d)\n", ++redundancy);
	      stripen = 0;
	      stripe_offset = off;
	      csize = grub_le_to_cpu64 (chunk->size) - off;

             /*
	      * Redundancy, and substripes only apply to RAID10, and there
	      * should be exactly 2 sub-stripes.
	      */
	     if (grub_le_to_cpu16 (chunk->nstripes) != redundancy)
               {
                 grub_dprintf ("btrfs", "invalid RAID1: nstripes != %u (%u)\n",
                               redundancy, grub_le_to_cpu16 (chunk->nstripes));
                 return grub_error (GRUB_ERR_BAD_FS,
                                    "invalid RAID1: nstripes != %u (%u)",
                                    redundancy, grub_le_to_cpu16 (chunk->nstripes));
               }
	      break;
	    }
	  case GRUB_BTRFS_CHUNK_TYPE_RAID0:
	    {
	      grub_uint64_t middle, high;
	      grub_uint64_t low;
	      grub_dprintf ("btrfs", "RAID0\n");
	      middle = grub_divmod64 (off,
				      chunk_stripe_length,
				      &low);

	      high = grub_divmod64 (middle, nstripes,
				    &stripen);
	      stripe_offset =
		low + chunk_stripe_length * high;
	      csize = chunk_stripe_length - low;
	      break;
	    }
	  case GRUB_BTRFS_CHUNK_TYPE_RAID10:
	    {
	      grub_uint64_t middle, high;
	      grub_uint64_t low;
	      grub_uint16_t nsubstripes;
	      nsubstripes = grub_le_to_cpu16 (chunk->nsubstripes) ? : 1;
	      middle = grub_divmod64 (off,
				      chunk_stripe_length,
				      &low);

	      high = grub_divmod64 (middle,
				    nstripes / nsubstripes ? : 1,
				    &stripen);
	      stripen *= nsubstripes;
	      redundancy = nsubstripes;
	      stripe_offset = low + chunk_stripe_length
		* high;
	      csize = chunk_stripe_length - low;

	      /*
	       * Substripes only apply to RAID10, and there
	       * should be exactly 2 sub-stripes.
	       */
	      if (grub_le_to_cpu16 (chunk->nsubstripes) != 2)
		{
		  grub_dprintf ("btrfs", "invalid RAID10: nsubstripes != 2 (%u)",
				grub_le_to_cpu16 (chunk->nsubstripes));
		  return grub_error (GRUB_ERR_BAD_FS,
				     "invalid RAID10: nsubstripes != 2 (%u)",
				     grub_le_to_cpu16 (chunk->nsubstripes));
		}

	      break;
	    }
	  case GRUB_BTRFS_CHUNK_TYPE_RAID5:
	  case GRUB_BTRFS_CHUNK_TYPE_RAID6:
	    {
	      grub_uint64_t nparities, stripe_nr, high, low;

	      redundancy = 1;	/* no redundancy for now */

	      if (grub_le_to_cpu64 (chunk->type) & GRUB_BTRFS_CHUNK_TYPE_RAID5)
		{
		  grub_dprintf ("btrfs", "RAID5\n");
		  nparities = 1;
		}
	      else
		{
		  grub_dprintf ("btrfs", "RAID6\n");
		  nparities = 2;
		}

	      /*
	       * RAID 6 layout consists of several stripes spread over
	       * the disks, e.g.:
	       *
	       *   Disk_0  Disk_1  Disk_2  Disk_3
	       *     A0      B0      P0      Q0
	       *     Q1      A1      B1      P1
	       *     P2      Q2      A2      B2
	       *
	       * Note: placement of the parities depend on row number.
	       *
	       * Pay attention that the btrfs terminology may differ from
	       * terminology used in other RAID implementations, e.g. LVM,
	       * dm or md. The main difference is that btrfs calls contiguous
	       * block of data on a given disk, e.g. A0, stripe instead of chunk.
	       *
	       * The variables listed below have following meaning:
	       *   - stripe_nr is the stripe number excluding the parities
	       *     (A0 = 0, B0 = 1, A1 = 2, B1 = 3, etc.),
	       *   - high is the row number (0 for A0...Q0, 1 for Q1...P1, etc.),
	       *   - stripen is the disk number in a row (0 for A0, Q1, P2,
	       *     1 for B0, A1, Q2, etc.),
	       *   - off is the logical address to read,
	       *   - chunk_stripe_length is the size of a stripe (typically 64 KiB),
	       *   - nstripes is the number of disks in a row,
	       *   - low is the offset of the data inside a stripe,
	       *   - stripe_offset is the data offset in an array,
	       *   - csize is the "potential" data to read; it will be reduced
	       *     to size if the latter is smaller,
	       *   - nparities is the number of parities (1 for RAID 5, 2 for
	       *     RAID 6); used only in RAID 5/6 code.
	       */
	      stripe_nr = grub_divmod64 (off, chunk_stripe_length, &low);

	      /*
	       * stripen is computed without the parities
	       * (0 for A0, A1, A2, 1 for B0, B1, B2, etc.).
	       */
	      if (nparities >= nstripes)
		return grub_error (GRUB_ERR_BAD_FS,
				   "invalid RAID5/6: nparities >= nstripes");
	      high = grub_divmod64 (stripe_nr, nstripes - nparities, &stripen);

	      /*
	       * The stripes are spread over the disks. Every each row their
	       * positions are shifted by 1 place. So, the real disks number
	       * change. Hence, we have to take into account current row number
	       * modulo nstripes (0 for A0, 1 for A1, 2 for A2, etc.).
	       */
	      grub_divmod64 (high + stripen, nstripes, &stripen);

	      /*
	       * parities_pos is equal to ((high - nparities) % nstripes)
	       * (see the diagram above). However, (high - nparities) can
	       * be negative, e.g. when high == 0, leading to an incorrect
	       * results. (high + nstripes - nparities) is always positive and
	       * modulo nstripes is equal to ((high - nparities) % nstripes).
	       */
	      grub_divmod64 (high + nstripes - nparities, nstripes, &parities_pos);

	      stripe_offset = chunk_stripe_length * high + low;
	      csize = chunk_stripe_length - low;

	      break;
	    }
	  default:
	    grub_dprintf ("btrfs", "unsupported RAID\n");
	    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			       "unsupported RAID flags %" PRIxGRUB_UINT64_T,
			       grub_le_to_cpu64 (chunk->type));
	  }
	if (csize == 0)
	  return grub_error (GRUB_ERR_BUG,
			     "couldn't find the chunk descriptor");
	if (csize > (grub_uint64_t) size)
	  csize = size;

	/*
	 * The space for a chunk stripe is limited to the space provide in the super-block's
	 * bootstrap mapping with an initial btrfs key at the start of each chunk.
	 */
	grub_size_t avail_stripes = sizeof (data->sblock.bootstrap_mapping) /
	  (sizeof (struct grub_btrfs_key) + sizeof (struct grub_btrfs_chunk_stripe));

	for (j = 0; j < 2; j++)
	  {
	    grub_size_t est_chunk_alloc = 0;

	    grub_dprintf ("btrfs", "chunk 0x%" PRIxGRUB_UINT64_T
			  "+0x%" PRIxGRUB_UINT64_T
			  " (%d stripes (%d substripes) of %"
			  PRIxGRUB_UINT64_T ")\n",
			  grub_le_to_cpu64 (key->offset),
			  grub_le_to_cpu64 (chunk->size),
			  grub_le_to_cpu16 (chunk->nstripes),
			  grub_le_to_cpu16 (chunk->nsubstripes),
			  grub_le_to_cpu64 (chunk->stripe_length));
	    grub_dprintf ("btrfs", "reading laddr 0x%" PRIxGRUB_UINT64_T "\n",
			  addr);

	    if (grub_mul (sizeof (struct grub_btrfs_chunk_stripe),
			  grub_le_to_cpu16 (chunk->nstripes), &est_chunk_alloc) ||
		grub_add (est_chunk_alloc,
			  sizeof (struct grub_btrfs_chunk_item), &est_chunk_alloc) ||
		est_chunk_alloc > chunk->size)
	      {
		err = GRUB_ERR_BAD_FS;
		break;
	      }

	   if (grub_le_to_cpu16 (chunk->nstripes) > avail_stripes)
             {
               err = GRUB_ERR_BAD_FS;
               break;
             }

	    if (is_raid56)
	      {
		err = btrfs_read_from_chunk (data, chunk, stripen,
					     stripe_offset,
					     0,     /* no mirror */
					     csize, buf);
		grub_errno = GRUB_ERR_NONE;
		if (err)
		  err = raid56_read_retry (data, chunk, stripe_offset,
					   stripen, csize, buf, parities_pos);
	      }
	    else
	      for (i = 0; i < redundancy; i++)
		{
		  err = btrfs_read_from_chunk (data, chunk, stripen,
					       stripe_offset,
					       i,     /* redundancy */
					       csize, buf);
		  if (!err)
		    break;
		  grub_errno = GRUB_ERR_NONE;
		}
	    if (!err)
	      break;
	  }
	if (err)
	  return grub_errno = err;
      }
      size -= csize;
      buf = (grub_uint8_t *) buf + csize;
      addr += csize;
      if (challoc)
	grub_free (chunk);
    }
  return GRUB_ERR_NONE;
}

static struct grub_btrfs_data *
grub_btrfs_mount (grub_device_t dev)
{
  struct grub_btrfs_data *data;
  grub_err_t err;

  if (!dev->disk)
    {
      grub_error (GRUB_ERR_BAD_FS, "not BtrFS");
      return NULL;
    }

  data = grub_zalloc (sizeof (*data));
  if (!data)
    return NULL;

  err = read_sblock (dev->disk, &data->sblock);
  if (err)
    {
      grub_free (data);
      return NULL;
    }

  data->n_devices_allocated = 16;
  data->devices_attached = grub_calloc (data->n_devices_allocated,
					sizeof (data->devices_attached[0]));
  if (!data->devices_attached)
    {
      grub_free (data);
      return NULL;
    }
  data->n_devices_attached = 1;
  data->devices_attached[0].dev = dev;
  data->devices_attached[0].id = data->sblock.this_device.device_id;

  return data;
}

static void
grub_btrfs_unmount (struct grub_btrfs_data *data)
{
  unsigned i;
  /* The device 0 is closed one layer upper.  */
  for (i = 1; i < data->n_devices_attached; i++)
    if (data->devices_attached[i].dev)
        grub_device_close (data->devices_attached[i].dev);
  grub_free (data->devices_attached);
  grub_free (data->extent);
  grub_free (data);
}

static grub_err_t
grub_btrfs_read_inode (struct grub_btrfs_data *data,
		       struct grub_btrfs_inode *inode, grub_uint64_t num,
		       grub_uint64_t tree)
{
  struct grub_btrfs_key key_in, key_out;
  grub_disk_addr_t elemaddr;
  grub_size_t elemsize;
  grub_err_t err;

  key_in.object_id = num;
  key_in.type = GRUB_BTRFS_ITEM_TYPE_INODE_ITEM;
  key_in.offset = 0;

  err = lower_bound (data, &key_in, &key_out, tree, &elemaddr, &elemsize, NULL,
		     0);
  if (err)
    return err;
  if (num != key_out.object_id
      || key_out.type != GRUB_BTRFS_ITEM_TYPE_INODE_ITEM)
    return grub_error (GRUB_ERR_BAD_FS, "inode not found");

  return grub_btrfs_read_logical (data, elemaddr, inode, sizeof (*inode), 0);
}

static void *grub_zstd_malloc (void *state __attribute__((unused)), size_t size)
{
  return grub_malloc (size);
}

static void grub_zstd_free (void *state __attribute__((unused)), void *address)
{
  return grub_free (address);
}

static ZSTD_customMem grub_zstd_allocator (void)
{
  ZSTD_customMem allocator;

  allocator.customAlloc = &grub_zstd_malloc;
  allocator.customFree = &grub_zstd_free;
  allocator.opaque = NULL;

  return allocator;
}

static grub_ssize_t
grub_btrfs_zstd_decompress (char *ibuf, grub_size_t isize, grub_off_t off,
			    char *obuf, grub_size_t osize)
{
  void *allocated = NULL;
  char *otmpbuf = obuf;
  grub_size_t otmpsize = osize;
  ZSTD_DCtx *dctx = NULL;
  grub_size_t zstd_ret;
  grub_ssize_t ret = -1;

  /*
   * Zstd will fail if it can't fit the entire output in the destination
   * buffer, so if osize isn't large enough, allocate a temporary buffer.
   */
  if (otmpsize < ZSTD_BTRFS_MAX_INPUT)
    {
      allocated = grub_malloc (ZSTD_BTRFS_MAX_INPUT);
      if (!allocated)
	{
	  grub_error (GRUB_ERR_OUT_OF_MEMORY, "failed allocate a zstd buffer");
	  goto err;
	}
      otmpbuf = (char *) allocated;
      otmpsize = ZSTD_BTRFS_MAX_INPUT;
    }

  /* Create the ZSTD_DCtx. */
  dctx = ZSTD_createDCtx_advanced (grub_zstd_allocator ());
  if (!dctx)
    {
      /* ZSTD_createDCtx_advanced() only fails if it is out of memory. */
      grub_error (GRUB_ERR_OUT_OF_MEMORY, "failed to create a zstd context");
      goto err;
    }

  /*
   * Get the real input size, there may be junk at the
   * end of the frame.
   */
  isize = ZSTD_findFrameCompressedSize (ibuf, isize);
  if (ZSTD_isError (isize))
    {
      grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "zstd data corrupted");
      goto err;
    }

  /* Decompress and check for errors. */
  zstd_ret = ZSTD_decompressDCtx (dctx, otmpbuf, otmpsize, ibuf, isize);
  if (ZSTD_isError (zstd_ret))
    {
      grub_error (GRUB_ERR_BAD_COMPRESSED_DATA, "zstd data corrupted");
      goto err;
    }

  /*
   * Move the requested data into the obuf. obuf may be equal
   * to otmpbuf, which is why grub_memmove() is required.
   */
  grub_memmove (obuf, otmpbuf + off, osize);
  ret = osize;

err:
  grub_free (allocated);
  ZSTD_freeDCtx (dctx);

  return ret;
}

static grub_ssize_t
grub_btrfs_lzo_decompress(char *ibuf, grub_size_t isize, grub_off_t off,
			  char *obuf, grub_size_t osize)
{
  grub_uint32_t total_size, cblock_size;
  grub_size_t ret = 0;
  char *ibuf0 = ibuf;

  total_size = grub_le_to_cpu32 (grub_get_unaligned32 (ibuf));
  ibuf += sizeof (total_size);

  if (isize < total_size)
    return -1;

  /* Jump forward to first block with requested data.  */
  while (off >= GRUB_BTRFS_LZO_BLOCK_SIZE)
    {
      /* Don't let following uint32_t cross the page boundary.  */
      if (((ibuf - ibuf0) & 0xffc) == 0xffc)
	ibuf = ((ibuf - ibuf0 + 3) & ~3) + ibuf0;

      cblock_size = grub_le_to_cpu32 (grub_get_unaligned32 (ibuf));
      ibuf += sizeof (cblock_size);

      if (cblock_size > GRUB_BTRFS_LZO_BLOCK_MAX_CSIZE)
	return -1;

      off -= GRUB_BTRFS_LZO_BLOCK_SIZE;
      ibuf += cblock_size;
    }

  while (osize > 0)
    {
      lzo_uint usize = GRUB_BTRFS_LZO_BLOCK_SIZE;

      /* Don't let following uint32_t cross the page boundary.  */
      if (((ibuf - ibuf0) & 0xffc) == 0xffc)
	ibuf = ((ibuf - ibuf0 + 3) & ~3) + ibuf0;

      cblock_size = grub_le_to_cpu32 (grub_get_unaligned32 (ibuf));
      ibuf += sizeof (cblock_size);

      if (cblock_size > GRUB_BTRFS_LZO_BLOCK_MAX_CSIZE)
	return -1;

      /* Block partially filled with requested data.  */
      if (off > 0 || osize < GRUB_BTRFS_LZO_BLOCK_SIZE)
	{
	  grub_size_t to_copy = GRUB_BTRFS_LZO_BLOCK_SIZE - off;
	  grub_uint8_t *buf;

	  if (to_copy > osize)
	    to_copy = osize;

	  buf = grub_malloc (GRUB_BTRFS_LZO_BLOCK_SIZE);
	  if (!buf)
	    return -1;

	  if (lzo1x_decompress_safe ((lzo_bytep)ibuf, cblock_size, buf, &usize,
	      NULL) != LZO_E_OK)
	    {
	      grub_free (buf);
	      return -1;
	    }

	  if (to_copy > usize)
	    to_copy = usize;
	  grub_memcpy(obuf, buf + off, to_copy);

	  osize -= to_copy;
	  ret += to_copy;
	  obuf += to_copy;
	  ibuf += cblock_size;
	  off = 0;

	  grub_free (buf);
	  continue;
	}

      /* Decompress whole block directly to output buffer.  */
      if (lzo1x_decompress_safe ((lzo_bytep)ibuf, cblock_size, (lzo_bytep)obuf,
	  &usize, NULL) != LZO_E_OK)
	return -1;

      osize -= usize;
      ret += usize;
      obuf += usize;
      ibuf += cblock_size;
    }

  return ret;
}

static grub_ssize_t
grub_btrfs_extent_read (struct grub_btrfs_data *data,
			grub_uint64_t ino, grub_uint64_t tree,
			grub_off_t pos0, char *buf, grub_size_t len)
{
  grub_off_t pos = pos0;
  while (len)
    {
      grub_size_t csize;
      grub_err_t err;
      grub_off_t extoff;
      struct grub_btrfs_leaf_descriptor desc;

      if (!data->extent || data->extstart > pos || data->extino != ino
	  || data->exttree != tree || data->extend <= pos)
	{
	  struct grub_btrfs_key key_in, key_out;
	  grub_disk_addr_t elemaddr;
	  grub_size_t elemsize;

	  grub_free (data->extent);
	  key_in.object_id = ino;
	  key_in.type = GRUB_BTRFS_ITEM_TYPE_EXTENT_ITEM;
	  key_in.offset = grub_cpu_to_le64 (pos);
	  err = lower_bound (data, &key_in, &key_out, tree,
			     &elemaddr, &elemsize, &desc, 0);
	  if (err)
	    {
	      grub_free (desc.data);
	      return -1;
	    }
	  if (key_out.object_id != ino
	      || key_out.type != GRUB_BTRFS_ITEM_TYPE_EXTENT_ITEM)
	    {
	      grub_error (GRUB_ERR_BAD_FS, "extent not found");
	      return -1;
	    }
	  if ((grub_ssize_t) elemsize < ((char *) &data->extent->inl
					 - (char *) data->extent))
	    {
	      grub_error (GRUB_ERR_BAD_FS, "extent descriptor is too short");
	      return -1;
	    }
	  data->extstart = grub_le_to_cpu64 (key_out.offset);
	  data->extsize = elemsize;
	  data->extent = grub_malloc (elemsize);
	  data->extino = ino;
	  data->exttree = tree;
	  if (!data->extent)
	    return grub_errno;

	  err = grub_btrfs_read_logical (data, elemaddr, data->extent,
					 elemsize, 0);
	  if (err)
	    return err;

	  data->extend = data->extstart + grub_le_to_cpu64 (data->extent->size);
	  if (data->extent->type == GRUB_BTRFS_EXTENT_REGULAR
	      && (char *) data->extent + elemsize
	      >= (char *) &data->extent->filled + sizeof (data->extent->filled))
	    data->extend =
	      data->extstart + grub_le_to_cpu64 (data->extent->filled);

	  grub_dprintf ("btrfs", "regular extent 0x%" PRIxGRUB_UINT64_T "+0x%"
			PRIxGRUB_UINT64_T "\n",
			grub_le_to_cpu64 (key_out.offset),
			grub_le_to_cpu64 (data->extent->size));
	  /*
	   * The way of extent item iteration is pretty bad, it completely
	   * requires all extents are contiguous, which is not ensured.
	   *
	   * Features like NO_HOLE and mixed inline/regular extents can cause
	   * gaps between file extent items.
	   *
	   * The correct way is to follow Linux kernel/U-boot to iterate item
	   * by item, without any assumption on the file offset continuity.
	   *
	   * Here we just manually skip to next item and re-do the verification.
	   *
	   * TODO: Rework the whole extent item iteration code, if not the
	   * whole btrfs implementation.
	   */
	  if (data->extend <= pos)
	    {
	      err = next (data, &desc, &elemaddr, &elemsize, &key_out);
	      if (err < 0)
		return -1;
	      /* No next item for the inode, we hit the end. */
	      if (err == 0 || key_out.object_id != ino ||
		  key_out.type != GRUB_BTRFS_ITEM_TYPE_EXTENT_ITEM)
		      return pos - pos0;

	      csize = grub_le_to_cpu64 (key_out.offset) - pos;
	      if (csize > len)
		      csize = len;

	      grub_memset (buf, 0, csize);
	      buf += csize;
	      pos += csize;
	      len -= csize;
	      continue;
	    }
	}
      csize = data->extend - pos;
      extoff = pos - data->extstart;
      if (csize > len)
	csize = len;

      if (data->extent->encryption)
	{
	  grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		      "encryption not supported");
	  return -1;
	}

      if (data->extent->compression != GRUB_BTRFS_COMPRESSION_NONE
	  && data->extent->compression != GRUB_BTRFS_COMPRESSION_ZLIB
	  && data->extent->compression != GRUB_BTRFS_COMPRESSION_LZO
	  && data->extent->compression != GRUB_BTRFS_COMPRESSION_ZSTD)
	{
	  grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		      "compression type 0x%x not supported",
		      data->extent->compression);
	  return -1;
	}

      if (data->extent->encoding)
	{
	  grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "encoding not supported");
	  return -1;
	}

      switch (data->extent->type)
	{
	case GRUB_BTRFS_EXTENT_INLINE:
	  if (data->extent->compression == GRUB_BTRFS_COMPRESSION_ZLIB)
	    {
	      if (grub_zlib_decompress (data->extent->inl, data->extsize -
					((grub_uint8_t *) data->extent->inl
					 - (grub_uint8_t *) data->extent),
					extoff, buf, csize)
		  != (grub_ssize_t) csize)
		{
		  if (!grub_errno)
		    grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				"premature end of compressed");
		  return -1;
		}
	    }
	  else if (data->extent->compression == GRUB_BTRFS_COMPRESSION_LZO)
	    {
	      if (grub_btrfs_lzo_decompress(data->extent->inl, data->extsize -
					   ((grub_uint8_t *) data->extent->inl
					    - (grub_uint8_t *) data->extent),
					   extoff, buf, csize)
		  != (grub_ssize_t) csize)
		return -1;
	    }
	  else if (data->extent->compression == GRUB_BTRFS_COMPRESSION_ZSTD)
	    {
	      if (grub_btrfs_zstd_decompress (data->extent->inl, data->extsize -
					      ((grub_uint8_t *) data->extent->inl
					       - (grub_uint8_t *) data->extent),
					      extoff, buf, csize)
		  != (grub_ssize_t) csize)
		return -1;
	    }
	  else
	    grub_memcpy (buf, data->extent->inl + extoff, csize);
	  break;
	case GRUB_BTRFS_EXTENT_REGULAR:
	  if (!data->extent->laddr)
	    {
	      grub_memset (buf, 0, csize);
	      break;
	    }

	  if (data->extent->compression != GRUB_BTRFS_COMPRESSION_NONE)
	    {
	      char *tmp;
	      grub_uint64_t zsize;
	      grub_ssize_t ret;

	      zsize = grub_le_to_cpu64 (data->extent->compressed_size);
	      tmp = grub_malloc (zsize);
	      if (!tmp)
		return -1;
	      err = grub_btrfs_read_logical (data,
					     grub_le_to_cpu64 (data->extent->laddr),
					     tmp, zsize, 0);
	      if (err)
		{
		  grub_free (tmp);
		  return -1;
		}

	      if (data->extent->compression == GRUB_BTRFS_COMPRESSION_ZLIB)
		ret = grub_zlib_decompress (tmp, zsize, extoff
				    + grub_le_to_cpu64 (data->extent->offset),
				    buf, csize);
	      else if (data->extent->compression == GRUB_BTRFS_COMPRESSION_LZO)
		ret = grub_btrfs_lzo_decompress (tmp, zsize, extoff
				    + grub_le_to_cpu64 (data->extent->offset),
				    buf, csize);
	      else if (data->extent->compression == GRUB_BTRFS_COMPRESSION_ZSTD)
		ret = grub_btrfs_zstd_decompress (tmp, zsize, extoff
				    + grub_le_to_cpu64 (data->extent->offset),
				    buf, csize);
	      else
		ret = -1;

	      grub_free (tmp);

	      if (ret != (grub_ssize_t) csize)
		{
		  if (!grub_errno)
		    grub_error (GRUB_ERR_BAD_COMPRESSED_DATA,
				"premature end of compressed");
		  return -1;
		}

	      break;
	    }
	  err = grub_btrfs_read_logical (data,
					 grub_le_to_cpu64 (data->extent->laddr)
					 + grub_le_to_cpu64 (data->extent->offset)
					 + extoff, buf, csize, 0);
	  if (err)
	    return -1;
	  break;
	default:
	  grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		      "unsupported extent type 0x%x", data->extent->type);
	  return -1;
	}
      buf += csize;
      pos += csize;
      len -= csize;
    }
  return pos - pos0;
}

static grub_err_t
get_root (struct grub_btrfs_data *data, struct grub_btrfs_key *key,
	  grub_uint64_t *tree, grub_uint8_t *type)
{
  grub_err_t err;
  grub_disk_addr_t elemaddr;
  grub_size_t elemsize;
  struct grub_btrfs_key key_out, key_in;
  struct grub_btrfs_root_item ri;

  key_in.object_id = grub_cpu_to_le64_compile_time (GRUB_BTRFS_ROOT_VOL_OBJECTID);
  key_in.offset = 0;
  key_in.type = GRUB_BTRFS_ITEM_TYPE_ROOT_ITEM;
  err = lower_bound (data, &key_in, &key_out,
		     data->sblock.root_tree,
		     &elemaddr, &elemsize, NULL, 0);
  if (err)
    return err;
  if (key_in.object_id != key_out.object_id
      || key_in.type != key_out.type
      || key_in.offset != key_out.offset)
    return grub_error (GRUB_ERR_BAD_FS, "no root");
  err = grub_btrfs_read_logical (data, elemaddr, &ri,
				 sizeof (ri), 0);
  if (err)
    return err;
  key->type = GRUB_BTRFS_ITEM_TYPE_DIR_ITEM;
  key->offset = 0;
  key->object_id = grub_cpu_to_le64_compile_time (GRUB_BTRFS_OBJECT_ID_CHUNK);
  *tree = ri.tree;
  *type = GRUB_BTRFS_DIR_ITEM_TYPE_DIRECTORY;
  return GRUB_ERR_NONE;
}

static grub_err_t
find_path (struct grub_btrfs_data *data,
	   const char *path, struct grub_btrfs_key *key,
	   grub_uint64_t *tree, grub_uint8_t *type)
{
  const char *slash = path;
  grub_err_t err;
  grub_disk_addr_t elemaddr;
  grub_size_t elemsize;
  grub_size_t allocated = 0;
  struct grub_btrfs_dir_item *direl = NULL;
  struct grub_btrfs_key key_out;
  const char *ctoken;
  grub_size_t ctokenlen;
  char *path_alloc = NULL;
  char *origpath = NULL;
  unsigned symlinks_max = 32;
  grub_size_t sz;

  err = get_root (data, key, tree, type);
  if (err)
    return err;

  origpath = grub_strdup (path);
  if (!origpath)
    return grub_errno;

  while (1)
    {
      while (path[0] == '/')
	path++;
      if (!path[0])
	break;
      slash = grub_strchr (path, '/');
      if (!slash)
	slash = path + grub_strlen (path);
      ctoken = path;
      ctokenlen = slash - path;

      if (*type != GRUB_BTRFS_DIR_ITEM_TYPE_DIRECTORY)
	{
	  grub_free (path_alloc);
	  grub_free (origpath);
	  return grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("not a directory"));
	}

      if (ctokenlen == 1 && ctoken[0] == '.')
	{
	  path = slash;
	  continue;
	}
      if (ctokenlen == 2 && ctoken[0] == '.' && ctoken[1] == '.')
	{
	  key->type = GRUB_BTRFS_ITEM_TYPE_INODE_REF;
	  key->offset = -1;

	  err = lower_bound (data, key, &key_out, *tree, &elemaddr, &elemsize,
			     NULL, 0);
	  if (err)
	    {
	      grub_free (direl);
	      grub_free (path_alloc);
	      grub_free (origpath);
	      return err;
	    }

	  if (key_out.type != key->type
	      || key->object_id != key_out.object_id)
	    {
	      grub_free (direl);
	      grub_free (path_alloc);
	      err = grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("file `%s' not found"), origpath);
	      grub_free (origpath);
	      return err;
	    }

	  *type = GRUB_BTRFS_DIR_ITEM_TYPE_DIRECTORY;
	  key->object_id = key_out.offset;

	  path = slash;

	  continue;
	}

      key->type = GRUB_BTRFS_ITEM_TYPE_DIR_ITEM;
      key->offset = grub_cpu_to_le64 (~grub_getcrc32c (1, ctoken, ctokenlen));

      err = lower_bound (data, key, &key_out, *tree, &elemaddr, &elemsize,
			 NULL, 0);
      if (err)
	{
	  grub_free (direl);
	  grub_free (path_alloc);
	  grub_free (origpath);
	  return err;
	}
      if (key_cmp (key, &key_out) != 0)
	{
	  grub_free (direl);
	  grub_free (path_alloc);
	  err = grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("file `%s' not found"), origpath);
	  grub_free (origpath);
	  return err;
	}

      struct grub_btrfs_dir_item *cdirel;
      if (elemsize > allocated)
	{
	  if (grub_mul (2, elemsize, &allocated) ||
	      grub_add (allocated, 1, &sz))
	    {
	      grub_free (path_alloc);
	      grub_free (origpath);
	      return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("directory item size overflow"));
	    }
	  grub_free (direl);
	  direl = grub_malloc (sz);
	  if (!direl)
	    {
	      grub_free (path_alloc);
	      grub_free (origpath);
	      return grub_errno;
	    }
	}

      err = grub_btrfs_read_logical (data, elemaddr, direl, elemsize, 0);
      if (err)
	{
	  grub_free (direl);
	  grub_free (path_alloc);
	  grub_free (origpath);
	  return err;
	}

      for (cdirel = direl;
	   (grub_uint8_t *) cdirel - (grub_uint8_t *) direl
	   < (grub_ssize_t) elemsize;
	   cdirel = (void *) ((grub_uint8_t *) (direl + 1)
			      + grub_le_to_cpu16 (cdirel->n)
			      + grub_le_to_cpu16 (cdirel->m)))
	{
	  if (ctokenlen == grub_le_to_cpu16 (cdirel->n)
	      && grub_memcmp (cdirel->name, ctoken, ctokenlen) == 0)
	    break;
	}
      if ((grub_uint8_t *) cdirel - (grub_uint8_t *) direl
	  >= (grub_ssize_t) elemsize)
	{
	  grub_free (direl);
	  grub_free (path_alloc);
	  err = grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("file `%s' not found"), origpath);
	  grub_free (origpath);
	  return err;
	}

      path = slash;
      if (cdirel->type == GRUB_BTRFS_DIR_ITEM_TYPE_SYMLINK)
	{
	  struct grub_btrfs_inode inode;
	  char *tmp;
	  if (--symlinks_max == 0)
	    {
	      grub_free (direl);
	      grub_free (path_alloc);
	      grub_free (origpath);
	      return grub_error (GRUB_ERR_SYMLINK_LOOP,
				 N_("too deep nesting of symlinks"));
	    }

	  err = grub_btrfs_read_inode (data, &inode,
				       cdirel->key.object_id, *tree);
	  if (err)
	    {
	      grub_free (direl);
	      grub_free (path_alloc);
	      grub_free (origpath);
	      return err;
	    }

	  if (grub_add (grub_le_to_cpu64 (inode.size), grub_strlen (path), &sz) ||
	      grub_add (sz, 1, &sz))
	    {
	      grub_free (direl);
	      grub_free (path_alloc);
	      grub_free (origpath);
	      return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("buffer size overflow"));
	    }
	  tmp = grub_malloc (sz);
	  if (!tmp)
	    {
	      grub_free (direl);
	      grub_free (path_alloc);
	      grub_free (origpath);
	      return grub_errno;
	    }

	  if (grub_btrfs_extent_read (data, cdirel->key.object_id,
				      *tree, 0, tmp,
				      grub_le_to_cpu64 (inode.size))
	      != (grub_ssize_t) grub_le_to_cpu64 (inode.size))
	    {
	      grub_free (direl);
	      grub_free (path_alloc);
	      grub_free (origpath);
	      grub_free (tmp);
	      return grub_errno;
	    }
	  grub_memcpy (tmp + grub_le_to_cpu64 (inode.size), path,
		       grub_strlen (path) + 1);
	  grub_free (path_alloc);
	  path = path_alloc = tmp;
	  if (path[0] == '/')
	    {
	      err = get_root (data, key, tree, type);
	      if (err)
		{
		  grub_free (direl);
		  grub_free (path_alloc);
		  grub_free (origpath);
		  return err;
		}
	    }
	  continue;
	}
      *type = cdirel->type;

      switch (cdirel->key.type)
	{
	case GRUB_BTRFS_ITEM_TYPE_ROOT_ITEM:
	  {
	    struct grub_btrfs_root_item ri;
	    err = lower_bound (data, &cdirel->key, &key_out,
			       data->sblock.root_tree,
			       &elemaddr, &elemsize, NULL, 0);
	    if (err)
	      {
		grub_free (direl);
		grub_free (path_alloc);
		grub_free (origpath);
		return err;
	      }
	    if (cdirel->key.object_id != key_out.object_id
		|| cdirel->key.type != key_out.type)
	      {
		grub_free (direl);
		grub_free (path_alloc);
		err = grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("file `%s' not found"), origpath);
		grub_free (origpath);
		return err;
	      }
	    err = grub_btrfs_read_logical (data, elemaddr, &ri,
					   sizeof (ri), 0);
	    if (err)
	      {
		grub_free (direl);
		grub_free (path_alloc);
		grub_free (origpath);
		return err;
	      }
	    key->type = GRUB_BTRFS_ITEM_TYPE_DIR_ITEM;
	    key->offset = 0;
	    key->object_id = grub_cpu_to_le64_compile_time (GRUB_BTRFS_OBJECT_ID_CHUNK);
	    *tree = ri.tree;
	    break;
	  }
	case GRUB_BTRFS_ITEM_TYPE_INODE_ITEM:
	  if (*slash && *type == GRUB_BTRFS_DIR_ITEM_TYPE_REGULAR)
	    {
	      grub_free (direl);
	      grub_free (path_alloc);
	      err = grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("file `%s' not found"), origpath);
	      grub_free (origpath);
	      return err;
	    }
	  *key = cdirel->key;
	  if (*type == GRUB_BTRFS_DIR_ITEM_TYPE_DIRECTORY)
	    key->type = GRUB_BTRFS_ITEM_TYPE_DIR_ITEM;
	  break;
	default:
	  grub_free (path_alloc);
	  grub_free (origpath);
	  grub_free (direl);
	  return grub_error (GRUB_ERR_BAD_FS, "unrecognised object type 0x%x",
			     cdirel->key.type);
	}
    }

  grub_free (direl);
  grub_free (origpath);
  grub_free (path_alloc);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_btrfs_dir (grub_device_t device, const char *path,
		grub_fs_dir_hook_t hook, void *hook_data)
{
  struct grub_btrfs_data *data = grub_btrfs_mount (device);
  struct grub_btrfs_key key_in, key_out;
  grub_err_t err;
  grub_disk_addr_t elemaddr;
  grub_size_t elemsize;
  grub_size_t allocated = 0;
  struct grub_btrfs_dir_item *direl = NULL;
  struct grub_btrfs_leaf_descriptor desc;
  int r = 0;
  grub_uint64_t tree;
  grub_uint8_t type;
  grub_size_t est_size = 0;
  grub_size_t sz;

  if (!data)
    return grub_errno;

  err = find_path (data, path, &key_in, &tree, &type);
  if (err)
    {
      grub_btrfs_unmount (data);
      return err;
    }
  if (type != GRUB_BTRFS_DIR_ITEM_TYPE_DIRECTORY)
    {
      grub_btrfs_unmount (data);
      return grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("not a directory"));
    }

  err = lower_bound (data, &key_in, &key_out, tree,
		     &elemaddr, &elemsize, &desc, 0);
  if (err)
    {
      grub_btrfs_unmount (data);
      grub_free (desc.data);
      return err;
    }
  if (key_out.type != GRUB_BTRFS_ITEM_TYPE_DIR_ITEM
      || key_out.object_id != key_in.object_id)
    {
      r = next (data, &desc, &elemaddr, &elemsize, &key_out);
      if (r <= 0)
	goto out;
    }
  do
    {
      struct grub_btrfs_dir_item *cdirel;
      if (key_out.type != GRUB_BTRFS_ITEM_TYPE_DIR_ITEM
	  || key_out.object_id != key_in.object_id)
	{
	  r = 0;
	  break;
	}
      if (elemsize > allocated)
	{
	  if (grub_mul (2, elemsize, &allocated) ||
	      grub_add (allocated, 1, &sz))
	    {
	      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("directory element size overflow"));
	      r = -grub_errno;
	      break;
	    }
	  grub_free (direl);
	  direl = grub_malloc (sz);
	  if (!direl)
	    {
	      r = -grub_errno;
	      break;
	    }
	}

      err = grub_btrfs_read_logical (data, elemaddr, direl, elemsize, 0);
      if (err)
	{
	  r = -err;
	  break;
	}

      if (direl == NULL ||
	  grub_add (grub_le_to_cpu16 (direl->n),
		    grub_le_to_cpu16 (direl->m), &est_size) ||
	  grub_add (est_size, sizeof (*direl), &est_size) ||
	  grub_sub (est_size, sizeof (direl->name), &est_size) ||
	  est_size > allocated)
       {
         grub_errno = GRUB_ERR_OUT_OF_RANGE;
         r = -grub_errno;
         goto out;
       }

      for (cdirel = direl;
	   (grub_uint8_t *) cdirel - (grub_uint8_t *) direl
	   < (grub_ssize_t) elemsize;
	   cdirel = (void *) ((grub_uint8_t *) (direl + 1)
			      + grub_le_to_cpu16 (cdirel->n)
			      + grub_le_to_cpu16 (cdirel->m)))
	{
	  char c;
	  struct grub_btrfs_inode inode;
	  struct grub_dirhook_info info;

	  if (cdirel == NULL ||
	      grub_add (grub_le_to_cpu16 (cdirel->n),
			grub_le_to_cpu16 (cdirel->m), &est_size) ||
	      grub_add (est_size, sizeof (*cdirel), &est_size) ||
	      grub_sub (est_size, sizeof (cdirel->name), &est_size) ||
	      est_size > allocated)
	   {
	     grub_errno = GRUB_ERR_OUT_OF_RANGE;
	     r = -grub_errno;
	     goto out;
	   }

	  err = grub_btrfs_read_inode (data, &inode, cdirel->key.object_id,
				       tree);
	  grub_memset (&info, 0, sizeof (info));
	  if (err)
	    grub_errno = GRUB_ERR_NONE;
	  else
	    {
	      info.mtime = grub_le_to_cpu64 (inode.mtime.sec);
	      info.mtimeset = 1;
	    }
	  c = cdirel->name[grub_le_to_cpu16 (cdirel->n)];
	  cdirel->name[grub_le_to_cpu16 (cdirel->n)] = 0;
	  info.dir = (cdirel->type == GRUB_BTRFS_DIR_ITEM_TYPE_DIRECTORY);
	  if (hook (cdirel->name, &info, hook_data))
	    goto out;
	  cdirel->name[grub_le_to_cpu16 (cdirel->n)] = c;
	}
      r = next (data, &desc, &elemaddr, &elemsize, &key_out);
    }
  while (r > 0);

out:
  grub_free (direl);

  free_iterator (&desc);
  grub_btrfs_unmount (data);

  return -r;
}

static grub_err_t
grub_btrfs_open (struct grub_file *file, const char *name)
{
  struct grub_btrfs_data *data = grub_btrfs_mount (file->device);
  grub_err_t err;
  struct grub_btrfs_inode inode;
  grub_uint8_t type;
  struct grub_btrfs_key key_in;

  if (!data)
    return grub_errno;

  err = find_path (data, name, &key_in, &data->tree, &type);
  if (err)
    {
      grub_btrfs_unmount (data);
      return err;
    }
  if (type != GRUB_BTRFS_DIR_ITEM_TYPE_REGULAR)
    {
      grub_btrfs_unmount (data);
      return grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("not a regular file"));
    }

  data->inode = key_in.object_id;
  err = grub_btrfs_read_inode (data, &inode, data->inode, data->tree);
  if (err)
    {
      grub_btrfs_unmount (data);
      return err;
    }

  file->data = data;
  file->size = grub_le_to_cpu64 (inode.size);

  return err;
}

static grub_err_t
grub_btrfs_close (grub_file_t file)
{
  grub_btrfs_unmount (file->data);

  return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_btrfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_btrfs_data *data = file->data;

  return grub_btrfs_extent_read (data, data->inode,
				 data->tree, file->offset, buf, len);
}

static grub_err_t
grub_btrfs_uuid (grub_device_t device, char **uuid)
{
  struct grub_btrfs_data *data;

  *uuid = NULL;

  data = grub_btrfs_mount (device);
  if (!data)
    return grub_errno;

  *uuid = grub_xasprintf ("%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
			  grub_be_to_cpu16 (data->sblock.uuid[0]),
			  grub_be_to_cpu16 (data->sblock.uuid[1]),
			  grub_be_to_cpu16 (data->sblock.uuid[2]),
			  grub_be_to_cpu16 (data->sblock.uuid[3]),
			  grub_be_to_cpu16 (data->sblock.uuid[4]),
			  grub_be_to_cpu16 (data->sblock.uuid[5]),
			  grub_be_to_cpu16 (data->sblock.uuid[6]),
			  grub_be_to_cpu16 (data->sblock.uuid[7]));

  grub_btrfs_unmount (data);

  return grub_errno;
}

static grub_err_t
grub_btrfs_label (grub_device_t device, char **label)
{
  struct grub_btrfs_data *data;

  *label = NULL;

  data = grub_btrfs_mount (device);
  if (!data)
    return grub_errno;

  *label = grub_strndup (data->sblock.label, sizeof (data->sblock.label));

  grub_btrfs_unmount (data);

  return grub_errno;
}

#ifdef GRUB_UTIL

struct embed_region {
  unsigned int start;
  unsigned int secs;
};

/*
 * https://btrfs.wiki.kernel.org/index.php/Manpage/btrfs(5)#BOOTLOADER_SUPPORT
 * The first 1 MiB on each device is unused with the exception of primary
 * superblock that is on the offset 64 KiB and spans 4 KiB.
 */

static const struct {
  struct embed_region available;
  struct embed_region used[6];
} btrfs_head = {
  .available = {0, GRUB_DISK_KiB_TO_SECTORS (1024)}, /* The first 1 MiB. */
  .used = {
    {0, 1},                                                        /* boot.S. */
    {GRUB_DISK_KiB_TO_SECTORS (64) - 1, 1},                        /* Overflow guard. */
    {GRUB_DISK_KiB_TO_SECTORS (64), GRUB_DISK_KiB_TO_SECTORS (4)}, /* 4 KiB superblock. */
    {GRUB_DISK_KiB_TO_SECTORS (68), 1},                            /* Overflow guard. */
    {GRUB_DISK_KiB_TO_SECTORS (1024) - 1, 1},                      /* Overflow guard. */
    {0, 0}                                                         /* Array terminator. */
  }
};

static grub_err_t
grub_btrfs_embed (grub_device_t device __attribute__ ((unused)),
		  unsigned int *nsectors,
		  unsigned int max_nsectors,
		  grub_embed_type_t embed_type,
		  grub_disk_addr_t **sectors)
{
  unsigned int i, j, n = 0;
  const struct embed_region *u;
  grub_disk_addr_t *map;

  if (embed_type != GRUB_EMBED_PCBIOS)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       "BtrFS currently supports only PC-BIOS embedding");

  map = grub_calloc (btrfs_head.available.secs, sizeof (*map));
  if (map == NULL)
    return grub_errno;

  /*
   * Populating the map array so that it can be used to index if a disk
   * address is available to embed:
   *   - 0: available,
   *   - 1: unavailable.
   */
  for (u = btrfs_head.used; u->secs; ++u)
    {
      unsigned int end = u->start + u->secs;

      if (end > btrfs_head.available.secs)
        end = btrfs_head.available.secs;
      for (i = u->start; i < end; ++i)
        map[i] = 1;
    }

  /* Adding up n until it matches total size of available embedding area. */
  for (i = 0; i < btrfs_head.available.secs; ++i)
    if (map[i] == 0)
      n++;

  if (n < *nsectors)
    {
      grub_free (map);
      return grub_error (GRUB_ERR_OUT_OF_RANGE,
		         N_("your core.img is unusually large.  "
			    "It won't fit in the embedding area"));
    }

  if (n > max_nsectors)
    n = max_nsectors;

  /*
   * Populating the array so that it can used to index disk block address for
   * an image file's offset to be embedded on disk (the unit is in sectors):
   *   - i: The disk block address relative to btrfs_head.available.start,
   *   - j: The offset in image file.
   */
  for (i = 0, j = 0; i < btrfs_head.available.secs && j < n; ++i)
    if (map[i] == 0)
      map[j++] = btrfs_head.available.start + i;

  *nsectors = n;
  *sectors = map;

  return GRUB_ERR_NONE;
}
#endif

static struct grub_fs grub_btrfs_fs = {
  .name = "btrfs",
  .fs_dir = grub_btrfs_dir,
  .fs_open = grub_btrfs_open,
  .fs_read = grub_btrfs_read,
  .fs_close = grub_btrfs_close,
  .fs_uuid = grub_btrfs_uuid,
  .fs_label = grub_btrfs_label,
#ifdef GRUB_UTIL
  .fs_embed = grub_btrfs_embed,
  .reserved_first_sector = 1,
  .blocklist_install = 0,
#endif
};

GRUB_MOD_INIT (btrfs)
{
  grub_btrfs_fs.mod = mod;
  grub_fs_register (&grub_btrfs_fs);
}

GRUB_MOD_FINI (btrfs)
{
  grub_fs_unregister (&grub_btrfs_fs);
}
