#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define MAGIC_SEGDEV_SD 8
struct segdev_signal_desc {
	volatile uint64_t waitcue;
};
