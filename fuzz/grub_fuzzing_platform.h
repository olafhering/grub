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
 *
 *  GRUB Fuzzing Platform - shared header for all libFuzzer fuzz targets
 */

#ifndef GRUB_FUZZING_PLATFORM_H
#define GRUB_FUZZING_PLATFORM_H 1

#include <stddef.h>
#include <stdint.h>

/*
 * Point the in-memory disk device at [data, data+size).
 * Call at the top of every LLVMFuzzerTestOneInput invocation before
 * opening any disk.  The buffer is owned by the caller (the fuzzer
 * runtime) and stays valid for the duration of the call.
 */
void fuzz_disk_set_image (const uint8_t *data, size_t size);

/*
 * Set a minimum logical disk capacity (in bytes) for the "fuzzdev" device.
 * When larger than the current input, the disk is presented at this capacity
 * and reads beyond the input are zero-filled.  Use it for filesystems whose
 * on-disk geometry requires a large device even though the metadata GRUB
 * reads is small.  Call once from LLVMFuzzerInitialize; pass 0 (the default)
 * to tie the logical size to the input size.
 */
void fuzz_disk_set_min_size (size_t bytes);

/*
 * One-time GRUB subsystem initialisation.
 * Call from LLVMFuzzerInitialize; argc/argv are forwarded to
 * grub_util_host_init for program-name / locale setup.
 */
void fuzz_grub_init (int *argc, char ***argv);

/*
 * Per-iteration cleanup.
 * Clears grub_errno and invalidates the disk sector cache so that
 * leftover state from one iteration cannot affect the next.
 */
void fuzz_grub_reset (void);

#endif /* GRUB_FUZZING_PLATFORM_H */
