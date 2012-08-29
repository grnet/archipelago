#ifndef _XSEG_H
#define _XSEG_H

#ifndef XSEG_VERSION
#define XSEG_VERSION 2012022601
#endif

#ifndef XSEG_PAGE_SHIFT
#define XSEG_PAGE_SHIFT 12
#endif

#define XSEG_BASE (0x37fd0UL << XSEG_PAGE_SHIFT)
#define XSEG_BASE_AS_PTR ((void *)XSEG_BASE)
#define XSEG_BASE_AS_BUF ((char *)XSEG_BASE)
#define XSEG_OFFSET(base, ptr) ((unsigned long)(ptr) - (unsigned long)(base))
#define XSEG_PTR_CONVERT(ptr, src, dst) ((void *)((unsigned long)(dst) + XSEG_OFFSET(src, ptr)))
#define XSEG_TAKE_PTR(ptr, base) XSEG_PTR_CONVERT(ptr, XSEG_BASE, base)
#define XSEG_MAKE_PTR(ptr, base) XSEG_PTR_CONVERT(ptr, base, XSEG_BASE)

#include <sys/util.h>
#include <xtypes/xq.h>

typedef uint64_t xserial;

#define NoSerial ((xserial)-1)

/* Peers and Segments
 *
 *  Segments are memory segments shared among peers.
 *  Peers are local execution contexes that share a segment.
 *
 *  xseg_type and xseg_peer
 *
 *  A peer needs an xseg_type in order to
 *  create or access a certain segment type,
 *  and it needs an xseg_peer in order to
 *  communicate with a certain type of peer.
 *  Both segment and peer types are identified by name strings.
 *
 *  Note that each peer (that is, context) type will need
 *  different code to access the same type of segment or peer.
 *  Therefore each peer must have its own "customized" version
 *  of the xseg library.
 *
 *  This is accomplished by mechanisms for registering both
 *  xseg_type's and xseg_peer's. This can be done at both at build time
 *  and at runtime, through a plugin-loading mechanism (where applicable).
 *  The plugin namespace serves both segment and peer type namespace,
 *  so if a segment type has the same name with a peer type,
 *  they must be provided by the same plugin.
 *
 *  Note also that peers of different types may share the same segment.
 *  Therefore each peer must know the type of each peer it needs to
 *  communicate with, and have a driver for it.
 *
*/

struct xseg;
struct xseg_port;

#define MAGIC_OBJH 	1
#define MAGIC_REQ 	2
#define MAGIC_PORT 	3
#define MAGIC_BUF4K 	4
#define MAGIC_BUF256K 	5
#define MAGIC_BUF4M 	6

struct xseg_operations {
	void  (*mfree)(void *mem);
	long  (*allocate)(const char *name, uint64_t size);
	long  (*deallocate)(const char *name);
	void *(*map)(const char *name, uint64_t size, struct xseg *seg);
	void  (*unmap)(void *xseg, uint64_t size);
};

#define XSEG_NAMESIZE 256
#define XSEG_TNAMESIZE 32

struct xseg_type {
	struct xseg_operations ops;
	char name[XSEG_TNAMESIZE];
};

struct xseg_peer_operations {
	int   (*signal_init)(void);
	void  (*signal_quit)(void);
	int   (*signal_join)(struct xseg *xseg);
	int   (*signal_leave)(struct xseg *xseg);
	int   (*prepare_wait)(struct xseg *xseg, uint32_t portno);
	int   (*cancel_wait)(struct xseg *xseg, uint32_t portno);
	int   (*wait_signal)(struct xseg *xseg, uint32_t usec_timeout);
	int   (*signal)(struct xseg *xseg, uint32_t portno);
	void *(*malloc)(uint64_t size);
	void *(*realloc)(void *mem, uint64_t size);
	void  (*mfree)(void *mem);
};

struct xseg_peer {
	struct xseg_peer_operations peer_ops;
	char name[XSEG_TNAMESIZE];
};

struct xseg_config {
	uint64_t heap_size;
	uint32_t page_shift;	/* the alignment unit */
	char type[XSEG_TNAMESIZE]; /* zero-terminated identifier */
	char name[XSEG_NAMESIZE];  /* zero-terminated identifier */
};

struct xseg_port {
	xptr free_queue;
	xptr request_queue;
	xptr reply_queue;
	uint64_t owner;
	volatile uint64_t waitcue;
	uint64_t peer_type;
};

struct xseg_request;

struct xseg_task {
	uint64_t epoch;
	struct xseg_request *req;
	xqindex *deps;
	xqindex nr_deps;
	xqindex __alloced_deps;
};

/* OPS */
#define X_PING      0
#define X_READ      1
#define X_WRITE     2
#define X_SYNC      3
#define X_TRUNCATE  4
#define X_DELETE    5
#define X_ACQUIRE   6
#define X_RELEASE   7
#define X_COPY      8
#define X_CLONE     9
#define X_COMMIT   10
#define X_INFO     11
#define X_MAPR     12
#define X_MAPW     13

/* FLAGS */
#define XF_NOSYNC (1 << 0)
#define XF_FLUSH  (1 << 1)
#define XF_FUA    (1 << 2)

/* STATES */
#define XS_SERVED	(1 << 0)
#define XS_FAILED	(1 << 1)

#define XS_ACCEPTED	(1 << 2)
#define XS_PENDING	(2 << 2)
#define XS_SERVING	(3 << 2)
#define XS_CONCLUDED	(3 << 2)

struct xseg_request {
	xserial serial;
	uint64_t offset;
	uint64_t size; /* FIXME: why are there both size and datalen fields? */
		/* FIXME: why does filed use ->datalen instead of ->size? */
	uint64_t serviced;
	xptr data;
	uint64_t datalen;
	xptr target;
	uint32_t targetlen;
	uint32_t op;
	uint32_t state;
	uint32_t flags;
	uint32_t portno;
	/* pad */
	xptr buffer;
	uint64_t bufferlen;
	xqindex task;
	uint64_t priv;
	struct timeval timestamp;
	uint64_t elapsed;
};

struct xseg_shared {
	uint64_t flags;
	char (*peer_types)[XSEG_TNAMESIZE]; /* alignment? */
	uint32_t nr_peer_types;
};

struct xseg_private {
	struct xseg_type segment_type;
	struct xseg_peer peer_type;
	struct xseg_peer **peer_types;
	uint32_t max_peer_types;
	void (*wakeup)(struct xseg *xseg, uint32_t portno);
};

struct xseg_counters {
	uint64_t avg_req_lat;
	uint64_t req_cnt;
};

struct xseg {
	uint64_t version;
	uint64_t segment_size;
	struct xseg *segment;
	struct xseg_heap *heap;
	struct xseg_object_handler *object_handlers;

	struct xseg_object_handler *requests;
	struct xseg_object_handler *ports;
	struct xseg_object_handler *buffers4K;
	struct xseg_object_handler *buffers256K;
	struct xseg_object_handler *buffers4M;

	struct xseg_shared *shared;
	struct xseg_private *priv;
	uint32_t max_peer_types;
	struct xseg_config config;
	struct xseg_counters counters;
};

#define XSEG_F_LOCK 0x1

/* ================= XSEG REQUEST INTERFACE ================================= */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_initialize      ( void                            );

                int    xseg_finalize        ( void                            );

                int    xseg_parse_spec      ( char                * spec,
                                              struct xseg_config  * config    );

   struct xseg_port *  xseg_bind_port       ( struct xseg         * xseg,
                                              uint32_t              portno    );

    static uint32_t    xseg_portno          ( struct xseg         * xseg,
                                              struct xseg_port    * port      );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_register_type   ( struct xseg_type    * type      );
                int    xseg_unregister_type ( const char          * name      );

                int    xseg_register_peer   ( struct xseg_peer    * peer      );
                int    xseg_unregister_peer ( const char          * name      );

               void    xseg_report_peer_types( void );

            int64_t    xseg_enable_driver   ( struct xseg         * xseg,
                                              const char          * name      );
                int    xseg_disable_driver  ( struct xseg         * xseg,
                                              const char          * name      );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_create          ( struct xseg_config  * cfg       );

               void    xseg_destroy         ( struct xseg         * xseg      );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
        struct xseg *  xseg_join            ( char                * segtype,
                                              char                * segname,
                                              char                * peertype,
                                              void               (* wakeup    )
                                             (struct xseg         * xseg,
                                              uint32_t              portno   ));

               void    xseg_leave           ( struct xseg         * xseg      );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_alloc_requests  ( struct xseg         * xseg,
                                              uint32_t              portno,
                                              uint32_t              nr        );

                int    xseg_free_requests   ( struct xseg         * xseg,
                                              uint32_t              portno,
                                              int                   nr        );

struct xseg_request *  xseg_get_request     ( struct xseg         * xseg,
                                              uint32_t              portno    );

                int    xseg_put_request     ( struct xseg         * xseg,
                                              uint32_t              portno,
                                              struct xseg_request * xreq      );

                int    xseg_prep_request    ( struct xseg_request * xreq,
                                              uint32_t              targetlen,
                                              uint64_t              datalen  );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
            xserial    xseg_submit          ( struct xseg         * xseg,
                                              uint32_t              portno,
                                              struct xseg_request * xreq      );

struct xseg_request *  xseg_receive         ( struct xseg         * xseg,
                                              uint32_t              portno    );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */

struct xseg_request *  xseg_accept          ( struct xseg         * xseg,
                                              uint32_t              portno    );

            xserial    xseg_respond         ( struct xseg         * xseg,
                                              uint32_t              portno,
                                              struct xseg_request * xreq      );
/*                    \___________________/                       \_________/ */
/*                     ___________________                         _________  */
/*                    /                   \                       /         \ */
                int    xseg_prepare_wait    ( struct xseg         * xseg,
                                              uint32_t              portno    );

                int    xseg_cancel_wait     ( struct xseg         * xseg,
                                              uint32_t              portno    );

                int    xseg_wait_signal     ( struct xseg         * xseg,
                                              uint32_t              utimeout  );

                int    xseg_signal          ( struct xseg         * xseg,
                                              uint32_t              portno    );
/*                    \___________________/                       \_________/ */



xptr xseg_get_obj(struct xseg_object_handler * obj_h, uint32_t flags);
void xseg_put_obj(struct xseg_object_handler * obj_h, struct xseg_object *obj);
int xseg_alloc_obj(struct xseg_object_handler *obj_h, uint64_t nr);
xptr xseg_allocate(struct xseg_heap *heap, uint64_t bytes);
void xseg_free(struct xseg_heap *heap, xptr ptr);
int xseg_init_object_handler(struct xseg *xseg, struct xseg_object_handler *obj_h, 
		uint32_t magic,	uint64_t size, xptr heap);

/*                                                                            */
/* ================= XSEG REQUEST INTERFACE ================================= */


static inline uint32_t xseg_portno(struct xseg *xseg, struct xseg_port *port)
{
	return port - xseg->ports;
}

#endif
