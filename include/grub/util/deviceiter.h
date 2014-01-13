#ifndef GRUB_DEVICEITER_MACHINE_UTIL_HEADER
#define GRUB_DEVICEITER_MACHINE_UTIL_HEADER	1

#include <config.h>

typedef int (*grub_util_iterate_devices_hook_t) (const char *name,
						 int is_floppy, void *data);

void grub_util_iterate_devices (grub_util_iterate_devices_hook_t hook,
				void *hook_data, int floppy_disks);
void grub_util_emit_devicemap_entry (FILE *fp, char *name, int is_floppy,
				     int *num_fd, int *num_hd);

#endif /* ! GRUB_DEVICEITER_MACHINE_UTIL_HEADER */
