#include <xtypes/xpool.h>

#define MAX_WAITERS 64
#define MAGIC_PTHREAD_SD 7

struct pthread_signal_desc{
	struct xpool waiters;
	struct xpool_node bufs[MAX_WAITERS];
};  
