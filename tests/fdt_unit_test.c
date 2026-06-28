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
 * Unit test for the flattened device tree (FDT) manipulation library in
 * grub-core/lib/fdt.c.  It builds a small device tree in memory and exercises
 * tree creation, header validation, node insertion and lookup, property
 * set/get round-trips (including in-place overwrite and
 * grow-into-a-new-entry), node iteration and the error paths.  Being a native
 * unit test it links the library directly, so it also gives ASan/UBSan
 * coverage of this code.
 */

#include <grub/fdt.h>
#include <grub/misc.h>
#include <grub/test.h>
#include <grub/types.h>

/*
 * The buffer must be at least 8-byte aligned for the FDT memory reservation
 * block; a grub_uint64_t array guarantees that.
 */
#define FDT_BUF_SIZE 4096
static grub_uint64_t fdt_storage[FDT_BUF_SIZE / sizeof (grub_uint64_t)];

/*
 * A separate, all-zero buffer used to check header validation rejects a
 * non-FDT blob.
 */
static grub_uint64_t bad_storage[16];

static void
fdt_test (void)
{
  void *fdt = fdt_storage;
  int cpus, cpu0, chosen;
  int node, ret;
  const void *prop;
  const char *name;
  grub_uint32_t len;

  /*
   * A size below GRUB_FDT_EMPTY_TREE_SZ must be rejected before anything is
   * written.
   */
  grub_test_assert (grub_fdt_create_empty_tree (fdt, 16) == -1,
                    "create_empty_tree accepted an undersized buffer");

  /* Create a valid empty tree. */
  ret = grub_fdt_create_empty_tree (fdt, FDT_BUF_SIZE);
  grub_test_assert (ret == 0, "create_empty_tree failed: %d", ret);

  /* Header sanity. */
  grub_test_assert (grub_fdt_get_magic (fdt) == FDT_MAGIC, "bad magic: 0x%x",
                    grub_fdt_get_magic (fdt));
  grub_test_assert (grub_fdt_get_totalsize (fdt) == FDT_BUF_SIZE,
                    "bad totalsize: %u", grub_fdt_get_totalsize (fdt));
  grub_test_assert (grub_fdt_check_header (fdt, FDT_BUF_SIZE) == 0,
                    "check_header rejected a valid empty tree");
  grub_test_assert (grub_fdt_check_header_nosize (fdt) == 0,
                    "check_header_nosize rejected a valid empty tree");

  /* The root node has an empty name. */
  name = grub_fdt_get_nodename (fdt, 0);
  grub_test_assert (name != NULL && name[0] == '\0',
                    "root node name is not empty");

  /*
   * A property on the root node, set before any children are added so its
   * offset is unaffected by later insertions.
   */
  ret = grub_fdt_set_prop (fdt, 0, "compatible", "test,board", 11);
  grub_test_assert (ret == 0, "set root compatible failed: %d", ret);

  /* Add /cpus under the root node. */
  cpus = grub_fdt_add_subnode (fdt, 0, "cpus");
  grub_test_assert (cpus > 0, "add_subnode cpus failed: %d", cpus);
  grub_test_assert (grub_fdt_find_subnode (fdt, 0, "cpus") == cpus,
                    "find_subnode cpus mismatch");
  grub_test_assert (grub_strcmp (grub_fdt_get_nodename (fdt, cpus),
                                 "cpus") == 0,
                    "cpus nodename wrong: %s",
                    grub_fdt_get_nodename (fdt, cpus));

  /* A lookup for a node that does not exist must fail. */
  grub_test_assert (grub_fdt_find_subnode (fdt, 0, "nonexistent") == -1,
                    "find_subnode found a nonexistent node");

  /* Add /cpus/cpu@0 (nested node). */
  cpu0 = grub_fdt_add_subnode (fdt, cpus, "cpu@0");
  grub_test_assert (cpu0 > 0, "add_subnode cpu@0 failed: %d", cpu0);
  grub_test_assert (grub_fdt_find_subnode (fdt, cpus, "cpu@0") == cpu0,
                    "find_subnode cpu@0 mismatch");

  /* Set a string property and read it back. */
  ret = grub_fdt_set_prop (fdt, cpu0, "device_type", "cpu", 4);
  grub_test_assert (ret == 0, "set device_type failed: %d", ret);
  prop = grub_fdt_get_prop (fdt, cpu0, "device_type", &len);
  grub_test_assert (prop != NULL, "get device_type returned NULL");
  grub_test_assert (len == 4, "device_type length wrong: %u", len);
  grub_test_assert (grub_strcmp ((const char *)prop, "cpu") == 0,
                    "device_type value wrong: %s", (const char *)prop);

  /* Set a 32-bit cell property and read it back. */
  ret = grub_fdt_set_prop32 (fdt, cpu0, "reg", 0);
  grub_test_assert (ret == 0, "set reg failed: %d", ret);
  prop = grub_fdt_get_prop (fdt, cpu0, "reg", &len);
  grub_test_assert (prop != NULL && len == 4, "get reg wrong: len %u", len);
  grub_test_assert (grub_be_to_cpu32 (*(const grub_uint32_t *)prop) == 0,
                    "reg value wrong: %u",
                    grub_be_to_cpu32 (*(const grub_uint32_t *)prop));

  /* A property that does not exist must not be found. */
  grub_test_assert (grub_fdt_get_prop (fdt, cpu0, "missing", &len) == NULL,
                    "get_prop found a missing property");

  /*
   * Overwrite a property in place (same size) and confirm the neighbouring
   * property is untouched.
   */
  ret = grub_fdt_set_prop32 (fdt, cpu0, "reg", 0x12345678);
  grub_test_assert (ret == 0, "overwrite reg failed: %d", ret);
  prop = grub_fdt_get_prop (fdt, cpu0, "reg", &len);
  grub_test_assert (prop != NULL && len == 4
                        && grub_be_to_cpu32 (*(const grub_uint32_t *)prop)
                               == 0x12345678,
                    "reg overwrite value wrong");
  prop = grub_fdt_get_prop (fdt, cpu0, "device_type", &len);
  grub_test_assert (prop != NULL
                        && grub_strcmp ((const char *)prop, "cpu") == 0,
                    "device_type clobbered by reg overwrite");

  /*
   * Grow a property so a new entry has to be allocated (new value is larger
   * than the space the old one occupied).
   */
  ret = grub_fdt_set_prop (fdt, cpu0, "device_type", "cpu-extended", 13);
  grub_test_assert (ret == 0, "grow device_type failed: %d", ret);
  prop = grub_fdt_get_prop (fdt, cpu0, "device_type", &len);
  grub_test_assert (prop != NULL && len == 13
                        && grub_strcmp ((const char *)prop,
                                        "cpu-extended") == 0,
                    "grown device_type wrong: %s len %u",
                    (const char *)prop, len);

  /* Iterate the children of the root.  At this point /cpus is the only one. */
  node = grub_fdt_first_node (fdt, 0);
  grub_test_assert (node == grub_fdt_find_subnode (fdt, 0, "cpus"),
                    "first_node did not return cpus");
  grub_test_assert (grub_fdt_next_node (fdt, node) == -1,
                    "next_node found a sibling that should not exist");

  /*
   * Add a second child of the root and walk both with first_node/next_node.
   * add_subnode inserts a new node right after the parent's properties, i.e.
   * ahead of the existing children, so the new /chosen comes first.  Offsets
   * shift after this insertion, so everything below is re-derived by name.
   */
  chosen = grub_fdt_add_subnode (fdt, 0, "chosen");
  grub_test_assert (chosen > 0, "add_subnode chosen failed: %d", chosen);

  node = grub_fdt_first_node (fdt, 0);
  grub_test_assert (node == grub_fdt_find_subnode (fdt, 0, "chosen"),
                    "first_node did not return chosen");
  node = grub_fdt_next_node (fdt, node);
  grub_test_assert (node == grub_fdt_find_subnode (fdt, 0, "cpus"),
                    "next_node did not return cpus");
  grub_test_assert (grub_fdt_next_node (fdt, node) == -1,
                    "next_node did not terminate after the last child");

  /* The root property survives all of the structure-block mutations above. */
  prop = grub_fdt_get_prop (fdt, 0, "compatible", &len);
  grub_test_assert (prop != NULL && len == 11
                        && grub_strcmp ((const char *)prop, "test,board") == 0,
                    "root compatible property was lost or corrupted");

  /* Error paths. */
  grub_test_assert (grub_fdt_check_header (fdt, 8) == -1,
                    "check_header accepted a size smaller than the header");
  grub_test_assert (grub_fdt_check_header (bad_storage, sizeof (bad_storage))
                        == -1,
                    "check_header accepted a non-FDT blob");
  grub_test_assert (grub_fdt_find_subnode (fdt, 2, "x") == -1,
                    "find_subnode accepted a misaligned parent offset");
  grub_test_assert (grub_fdt_add_subnode (fdt, 2, "x") == -1,
                    "add_subnode accepted a misaligned parent offset");
}

/* Register fdt_test as a unit test. */
GRUB_UNIT_TEST ("fdt_unit_test", fdt_test);
