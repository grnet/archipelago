#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define MAGIC_POSIX_SD 6

struct posix_signal_desc {
	volatile uint64_t waitcue;
};
