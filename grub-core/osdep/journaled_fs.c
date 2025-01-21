#ifdef __linux__
#include "linux/journaled_fs.c"
#else
#include "basic/journaled_fs.c"
#endif
