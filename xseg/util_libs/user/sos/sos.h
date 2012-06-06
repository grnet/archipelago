#ifndef _SOS_H
#define _SOS_H

#include <stdlib.h>
#include <stdint.h>

struct sos_request {
	unsigned long id;		/* request id 			*/
	char *target;			/* target object name 		*/
	uint32_t targetlen;		/* target object name length	*/
	uint64_t offset;		/* target object offset 	*/
	uint64_t size;			/* requested size of data 	*/
	char *data;			/* data pointer 		*/
	uint32_t flags;			/* request flags		*/	
	volatile unsigned long state;	/* state of request 		*/
	int retval;			/* return value of the operation*/
	uint32_t op;			/* operation to be performed	*/
	void *priv;			/* private data 		*/
};

/* OPS */
#define S_NONE	0
#define S_READ	1
#define S_WRITE	2

typedef int (*sos_cb_t)(struct sos_request *req, unsigned long event_flags);

struct sos_handle;
typedef struct sos_handle *sos_handle_t;

sos_handle_t sos_init(sos_cb_t cb);
void sos_shut(sos_handle_t sos);
int sos_submit(sos_handle_t sos, struct sos_request *req);

void sos_set_debug_level(unsigned int level);
/* sos notify flags */
#define S_NOTIFY_FAIL	(1 << 0)
#define S_NOTIFY_ACK 	(1 << 1)
#define S_NOTIFY_COMMIT	(1 << 2)

#define SOS_POOL "sos"

/* sos request states */
#define S_PENDING 	(1 << 0)
#define S_ACKED 	(1 << 1)
#define S_COMMITED	(1 << 2)
#define S_FAILED 	(1 << 3)

/* sos request flags */
#define SF_SYNC		(1 << 1)
#define SF_FLUSH	(1 << 2)
#define SF_FUA		(1 << 3)


#endif	/* _SOS_H */
