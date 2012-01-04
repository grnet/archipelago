#include <xseg/xseg.h>
#include <sys/util.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

#define XSEG_NR_TYPES 16
#define XSEG_NR_PEER_TYPES 64
#define XSEG_MIN_PAGE_SIZE 4096

#define __align(x, shift) (((((x) -1) >> (shift)) +1) << (shift))

static struct xseg_type *__types[XSEG_NR_TYPES];
static unsigned int __nr_types;
static struct xseg_peer *__peer_types[XSEG_NR_PEER_TYPES];
static unsigned int __nr_peer_types;
static struct xseg_peer __peer_type;

/* assuming size_t is long */
/*
void *memcpy(void *dest, const void *src, unsigned long n);
int strncmp(const char *s1, const char *s2, unsigned long n);
char *strncpy(char *dest, const char *src, unsigned long n);
void *memset(void *s, int c, unsigned long n);
*/

void __load_plugin(const char *name);
void __xseg_preinit(void);
uint32_t __get_id(void);

static void __lock_segment(struct xseg *xseg)
{
	volatile uint64_t *flags;
	flags = &xseg->shared->flags;
	while (__sync_fetch_and_or(flags, XSEG_F_LOCK));
}

static void __unlock_segment(struct xseg *xseg)
{
	volatile uint64_t *flags;
	flags = &xseg->shared->flags;
	__sync_fetch_and_and(flags, ~XSEG_F_LOCK);
}

static struct xseg_type *__find_type(const char *name, long *index)
{
	long i;
	for (i = 0; (*index = i) < __nr_types; i++)
		if (!strncmp(__types[i]->name, name, XSEG_TNAMESIZE))
			return __types[i];
	return NULL;
}

static struct xseg_peer *__find_peer_type(const char *name, long *index)
{
	long i;
	for (i = 0; (*index = i) < __nr_peer_types; i++) {
		if (!strncmp(__peer_types[i]->name, name, XSEG_TNAMESIZE))
			return __peer_types[i];
	}
	return NULL;
}

void xseg_report_peer_types(void)
{
	long i;
	LOGMSG("total %u peer types:\n", __nr_peer_types);
	for (i = 0; i < __nr_peer_types; i++)
		LOGMSG("%ld: '%s'\n", i, __peer_types[i]->name);
}

static struct xseg_type *__find_or_load_type(const char *name)
{
	long i;
	struct xseg_type *type = __find_type(name, &i);
	if (type)
		return type;

	__load_plugin(name);
	return __find_type(name, &i);
}

static struct xseg_peer *__find_or_load_peer_type(const char *name)
{
	long i;
	struct xseg_peer *peer_type = __find_peer_type(name, &i);
	if (peer_type)
		return peer_type;

	__load_plugin(name);
	return __find_peer_type(name, &i);
}

static struct xseg_peer *__get_peer_type(struct xseg *xseg, uint32_t serial)
{
	char *name;
	struct xseg_peer *type;
	char (*shared_peer_types)[XSEG_TNAMESIZE];

	if (serial >= xseg->max_peer_types) 
		return NULL;

	type = xseg->peer_types[serial];
	if (type)
		return type;

	if (serial >= (1 << xseg->config.page_shift) / XSEG_TNAMESIZE)
		return NULL;

	/* xseg->shared->peer_types is an append-only array,
	 * therefore this should be safe
	 * without either locking or string copying. */
	shared_peer_types = XSEG_TAKE_PTR(xseg->shared->peer_types, xseg->segment);
	name = shared_peer_types[serial];
	if (!*name)
		return NULL;

	type = __find_or_load_peer_type(name);
	xseg->peer_types[serial] = type;
	return type;
}

static inline int __validate_port(struct xseg *xseg, uint32_t portno)
{
	return portno < xseg->config.nr_ports;
}

/* type:name:nr_ports:nr_requests:request_size:extra_size:page_shift */

#define TOK(s, sp, def) \
	(s) = (sp); \
	for (;;) { \
		switch (*(sp)) { \
		case 0: \
			s = (def); \
			break; \
		case ':': \
			*(sp)++ = 0; \
			break; \
		default: \
			(sp) ++; \
			continue; \
		} \
		break; \
	} \

static unsigned long strul(char *s)
{
	unsigned long n = 0;
	for (;;) {
		unsigned char c = *s - '0';
		if (c >= 10)
			break;
		n = n * 10 + c;
		s ++;
	}
	return n;
}

/*
static char *strncopy(char *dest, const char *src, uint32_t n)
{
	uint32_t i;
	char c;
	for (i = 0; i < n; i++) {
		c = src[i];
		dest[i] = c;
		if (!c)
			break;
	}
	dest[n-1] = 0;
	return dest;
}
*/

int xseg_parse_spec(char *segspec, struct xseg_config *config)
{
	/* default: "posix:globalxseg:4:512:64:1024:12" */
	char *s = segspec, *sp = segspec;

	/* type */
	TOK(s, sp, "posix");
	strncpy(config->type, s, XSEG_TNAMESIZE);
	config->type[XSEG_TNAMESIZE-1] = 0;

	/* name */
	TOK(s, sp, "globalxseg");
	strncpy(config->name, s, XSEG_NAMESIZE);
	config->name[XSEG_NAMESIZE-1] = 0;

	/* nr_ports */
	TOK(s, sp, "4");
	config->nr_ports = strul(s);

	/* nr_requests */
	TOK(s, sp, "512");
	config->nr_requests = strul(s);

	/* request_size */
	TOK(s, sp, "64");
	config->request_size = strul(s);

	/* extra_size */
	TOK(s, sp, "128");
	config->extra_size = strul(s);

	/* page_shift */
	TOK(s, sp, "12");
	config->page_shift = strul(s);
	return 0;
}

int xseg_register_type(struct xseg_type *type)
{
	long i;
	struct xseg_type *__type = __find_type(type->name, &i);
	if (__type) {
		LOGMSG("type %s already exists\n", type->name);
		return -1;
	}

	if (__nr_types >= XSEG_NR_TYPES) {
		LOGMSG("maximum type registrations reached: %u\n", __nr_types);
		return -2;
	}

	type->name[XSEG_TNAMESIZE-1] = 0;
	__types[__nr_types] = type;
	__nr_types += 1;

	return 0;
}

int xseg_unregister_type(const char *name)
{
	long i;
	struct xseg_type *__type = __find_type(name, &i);
	if (!__type) {
		LOGMSG("segment type '%s' does not exist\n", name);
		return -1;
	}

	__nr_types -= 1;
	__types[i] = __types[__nr_types];
	__types[__nr_types] = NULL;
	return 0;
}

int xseg_register_peer(struct xseg_peer *peer_type)
{
	long i;
	struct xseg_peer *type = __find_peer_type(peer_type->name, &i);
	if (type) {
		LOGMSG("peer type '%s' already exists\n", type->name);
		return -1;
	}

	if (__nr_peer_types >= XSEG_NR_PEER_TYPES) {
		LOGMSG("maximum peer type registrations reached: %u",
			__nr_peer_types);
		return -2;
	}

	if (peer_type->peer_ops.signal_init()) {
		LOGMSG("peer type '%s': signal initialization failed\n",
			peer_type->name);
		return -3;
	}
	peer_type->name[XSEG_TNAMESIZE-1] = 0;
	__peer_types[__nr_peer_types] = peer_type;
	__nr_peer_types += 1;
	return 0;
}

int xseg_unregister_peer(const char *name)
{
	long i;
	struct xseg_peer *__type = __find_peer_type(name, &i);
	if (!__type) {
		LOGMSG("peer type '%s' does not exist\n", name);
		return -1;
	}

	__nr_peer_types -= 1;
	__peer_types[i] = __peer_types[__nr_peer_types];
	__peer_types[__nr_peer_types] = NULL;
	__type->peer_ops.signal_quit();

	return 0;
}

long __enable_driver(struct xseg *xseg, struct xseg_peer *driver)
{
	long r;
	char (*drivers)[XSEG_TNAMESIZE];
	uint32_t max_drivers = xseg->max_peer_types;

	if (xseg->shared->nr_peer_types >= max_drivers) {
		LOGMSG("cannot register '%s': driver namespace full\n",
			driver->name);
		return -1;
	}

	drivers = XSEG_TAKE_PTR(xseg->shared->peer_types, xseg->segment);
	for (r = 0; r < max_drivers; r++) {
		if (!*drivers[r])
			goto bind;
		if (!strncmp(drivers[r], driver->name, XSEG_TNAMESIZE))
			goto success;
	}

	/* Unreachable */
	return -666;

bind:
	/* assert(xseg->shared->nr_peer_types == r); */
	xseg->shared->nr_peer_types = r + 1;
	strncpy(drivers[r], driver->name, XSEG_TNAMESIZE);
	drivers[r][XSEG_TNAMESIZE-1] = 0;

success:
	xseg->peer_types[r] = driver;
	return r;
}

long xseg_enable_driver(struct xseg *xseg, const char *name)
{
	long r;
	struct xseg_peer *driver = __find_peer_type(name, &r);

	if (!driver) {
		LOGMSG("driver '%s' not found\n", name);
		return -1;
	}

	__lock_segment(xseg);
	r = __enable_driver(xseg, driver);
	__unlock_segment(xseg);
	return r;
}

int xseg_disable_driver(struct xseg *xseg, const char *name)
{
	long i;
	struct xseg_peer *driver =  __find_peer_type(name, &i);
	if (!driver) {
		LOGMSG("driver '%s' not found\n", name);
		return -1;
	}

	for (i = 0; i < xseg->max_peer_types; i++)
		if (xseg->peer_types[i] == driver)
			xseg->peer_types[i] = NULL;
	return 0;
}

/* NOTE: calculate_segment_size() and initialize_segment()
 * must always be exactly in sync!
*/

static uint64_t calculate_segment_size(struct xseg_config *config)
{
	uint64_t size = 0;
	uint32_t page_size, page_shift = config->page_shift;

	/* assert(sizeof(struct xseg) <= (1 << 9)); */

	if (page_shift < 9) {
		LOGMSG("page_shift must be >= %d\n", 9);
		return 0;
	}

	page_size = 1 << page_shift;

	/* struct xseg itself */
	size += page_size;
	/* free requests queue struct */
	size += page_size;

	size += config->nr_requests * sizeof(struct xseg_request);
	size = __align(size, page_shift);

	size += config->nr_requests * config->request_size * page_size;

	size += config->nr_ports * sizeof(struct xseg_port);
	size = __align(size, page_shift);

	/* queue entries for 3 xqueues per port... */
	size += config->nr_ports * 3 * config->nr_requests * sizeof(xqindex);
	size = __align(size, page_shift);

	/* ...and one global free queue */
	size += config->nr_requests * sizeof(xqindex);
	size = __align(size, page_shift);

	size += config->extra_size;
	size = __align(size, page_shift);

	size += sizeof(struct xseg_shared);
	size = __align(size, page_shift);

	/* page for type names */
	size += page_size;

	return size;
}

static long initialize_segment(struct xseg *xseg, struct xseg_config *cfg)
{
	uint32_t page_shift = cfg->page_shift, page_size = 1 << page_shift;
	struct xseg_shared *shared;
	char *segment = (char *)xseg;
	struct xq *q;
	void *qmem;
	uint64_t bodysize, size = page_size, i, nr_requests = cfg->nr_requests;

	if (page_size < XSEG_MIN_PAGE_SIZE)
		return -1;

	xseg->free_requests = XSEG_MAKE_PTR(segment + size, segment);
	size += page_size;

	xseg->requests = XSEG_MAKE_PTR(segment + size, segment);
	size += nr_requests * sizeof(struct xseg_request);
	size = __align(size, page_shift);

	xseg->buffers = XSEG_MAKE_PTR(segment + size, segment);
	size += nr_requests * cfg->request_size * page_size;

	for (i = 0; i < nr_requests; i++) {
		struct xseg_request *req = XSEG_TAKE_PTR(&xseg->requests[i], segment);
		/* xseg_allocate() zeroes the segment out */
		req->buffer = xseg->buffers + i * cfg->request_size * page_size;
		req->buffersize = cfg->request_size * page_size;
		req->data = req->buffer;
		req->datasize = req->buffersize;
	}

	xseg->ports = XSEG_MAKE_PTR(segment + size, segment);
	size += cfg->nr_ports * sizeof(struct xseg_port);
	bodysize = nr_requests * sizeof(xqindex);
	for (i = 0; i < cfg->nr_ports; i++) {
		struct xseg_port *port = XSEG_TAKE_PTR(&xseg->ports[i], segment);

		q = &port->free_queue;
		qmem = segment + size;
		xq_init_empty(q, nr_requests, qmem);
		size += bodysize;

		q = &port->request_queue;
		qmem = segment + size;
		xq_init_empty(q, nr_requests, qmem);
		size += bodysize;

		q = &port->reply_queue;
		qmem = segment + size;
		xq_init_empty(q, nr_requests, qmem);
		size += bodysize;
	}
	size = __align(size, page_shift);

	q = XSEG_TAKE_PTR(xseg->free_requests, segment);
	qmem = segment + size;
	xq_init_seq(q, nr_requests, nr_requests, qmem);
	size += bodysize;
	size = __align(size, page_shift);

	xseg->extra = XSEG_MAKE_PTR(segment + size, segment);
	size += cfg->extra_size;
	size = __align(size, page_shift);

	shared = (struct xseg_shared *)(segment + size);
	xseg->shared = XSEG_MAKE_PTR(shared, segment);
	shared->flags = 0;
	shared->nr_peer_types = 0;
	size += sizeof(struct xseg_shared);
	size = __align(size, page_shift);

	shared->peer_types = XSEG_MAKE_PTR(segment + size, segment);
	size += page_size;

	xseg->segment_size = size;
	memcpy(&xseg->config, cfg, sizeof(struct xseg_config));
	return 0;
}

int xseg_create(struct xseg_config *cfg)
{
	struct xseg *xseg = NULL;
	struct xseg_type *type;
	struct xseg_operations *xops;
	uint64_t size;
	long r;

	type = __find_or_load_type(cfg->type);
	if (!type) {
		cfg->type[XSEG_TNAMESIZE-1] = 0;
		LOGMSG("type '%s' does not exist\n", cfg->type);
		goto out_err;
	}

	size = calculate_segment_size(cfg);
	if (!size) {
		LOGMSG("invalid config!\n");
		goto out_err;
	}

	xops = &type->ops;
	cfg->name[XSEG_NAMESIZE-1] = 0;
	r = xops->allocate(cfg->name, size);
	if (r) {
		LOGMSG("cannot allocate segment!\n");
		goto out_err;
	}

	xseg = xops->map(cfg->name, size);
	if (!xseg) {
		LOGMSG("cannot map segment!\n");
		goto out_deallocate;
	}

	r = initialize_segment(xseg, cfg);
	xops->unmap(xseg, size);
	if (r) {
		LOGMSG("cannot initilize segment!\n");
		goto out_deallocate;
	}

	return 0;

out_deallocate:
	xops->deallocate(cfg->name);
out_err:
	return -1;
}

void xseg_destroy(struct xseg *xseg)
{
	struct xseg_type *type = __find_or_load_type(xseg->config.type);
	if (!type) {
		LOGMSG("no segment type '%s'\n", xseg->config.type);
		return;
	}

	/* should destroy() leave() first? */
	type->ops.deallocate(xseg->config.name);
}

static int pointer_ok(	unsigned long ptr,
			unsigned long base,
			uint64_t size,
			char *name)
{
	int ret = !(ptr >= base && ptr < base + size);
	if (ret)
		LOGMSG("invalid pointer '->%s' [%llx on %llx]!\n",
			(unsigned long long)ptr,
			(unsigned long long)base,
			name);
	return ret;
}

#define POINTER_OK(xseg, field, base) \
	 pointer_ok(	(unsigned long)((xseg)->field), \
			(unsigned long)(base), \
			(xseg)->segment_size, \
			#field)

static int xseg_validate_pointers(struct xseg *xseg)
{
	int r = 0;
	r += POINTER_OK(xseg, requests, xseg->segment);
	r += POINTER_OK(xseg, free_requests, xseg->segment);
	r += POINTER_OK(xseg, ports, xseg->segment);
	r += POINTER_OK(xseg, buffers, xseg->segment);
	r += POINTER_OK(xseg, extra, xseg->segment);
	r += POINTER_OK(xseg, shared, xseg->segment);
	return r;
}

struct xseg *xseg_join(char *typename, char *name)
{
	struct xseg *xseg, *__xseg;
	uint64_t size;
	struct xseg_type *type;
	struct xseg_operations *xops;
	int r;

	type = __find_or_load_type(typename);
	if (!type) {
		LOGMSG("no segment type '%s'\n", typename);
		goto err;
	}

	xops = &type->ops;

	xseg = xops->malloc(sizeof(struct xseg));
	if (!xseg) {
		LOGMSG("cannot allocate memory\n");
		goto err;
	}

	__xseg = xops->map(name, XSEG_MIN_PAGE_SIZE);
	if (!__xseg)
		goto err_seg;

	size = __xseg->segment_size;
	LOGMSG("size: %lu\n", (unsigned long)size);
	xops->unmap(__xseg, XSEG_MIN_PAGE_SIZE);

	__xseg = xops->map(name, size);
	if (!__xseg)
		goto err_seg;

	xseg->version = __xseg->version;
	xseg->requests = XSEG_TAKE_PTR(__xseg->requests, __xseg);
	xseg->free_requests = XSEG_TAKE_PTR(__xseg->free_requests, __xseg);
	xseg->ports = XSEG_TAKE_PTR(__xseg->ports, __xseg);
	xseg->buffers = XSEG_TAKE_PTR(__xseg->buffers, __xseg);
	xseg->extra = XSEG_TAKE_PTR(__xseg->extra, __xseg);
	xseg->shared = XSEG_TAKE_PTR(__xseg->shared, __xseg);
	xseg->segment_size = size;
	xseg->segment = __xseg;
	xseg->type = *type;
	xseg->config = __xseg->config;
	xseg->max_peer_types = (1 << xseg->config.page_shift) / XSEG_TNAMESIZE;
	xseg->peer_types = xops->malloc(sizeof(void *) * xseg->max_peer_types);
	if (!xseg->peer_types)
		goto err_unmap;
	memset(xseg->peer_types, 0, sizeof(void *) * xseg->max_peer_types);

	r =xseg_validate_pointers(xseg);
	if (r) {
		LOGMSG("found %d invalid xseg pointers!\n", r);
		goto err_unmap;
	}
	return xseg;

err_unmap:
	xops->unmap(__xseg, size);
err_seg:
	xops->mfree(xseg);
err:
	return NULL;
}

/* void xseg_leave(struct xseg *xseg) { at least free malloced memory } */

int xseg_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		return -1;

	port = &xseg->ports[portno];
	return __peer_type.peer_ops.prepare_wait(port);
}


int xseg_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		return -1;

	port = &xseg->ports[portno];
	return __peer_type.peer_ops.cancel_wait(port);
}

int xseg_wait_signal(struct xseg *xseg, uint32_t portno, uint32_t usec_timeout)
{
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		return -1;

	port = &xseg->ports[portno];
	return __peer_type.peer_ops.wait_signal(port, usec_timeout);
}

int xseg_signal(struct xseg *xseg, uint32_t portno)
{
	struct xseg_peer *type;
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		return -1;

	port = &xseg->ports[portno];
	type = __get_peer_type(xseg, port->peer_type);
	if (!type)
		return -1;

	return type->peer_ops.signal(port);
}

int xseg_alloc_requests(struct xseg *xseg, uint32_t portno, uint32_t nr)
{
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		return -1;

	port = &xseg->ports[portno];
	return xq_head_to_tail(xseg->free_requests, &port->free_queue, nr);
}

int xseg_free_requests(struct xseg *xseg, uint32_t portno, int nr)
{
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		return -1;

	port = &xseg->ports[portno];
	return xq_head_to_tail(&port->free_queue, xseg->free_requests, nr);
}

struct xseg_request *xseg_get_request(struct xseg *xseg, uint32_t portno)
{
	struct xseg_request *req;
	struct xseg_port *port;
	xqindex xqi;
	if (!__validate_port(xseg, portno))
		return NULL;

	port = &xseg->ports[portno];
	xqi = xq_pop_head(&port->free_queue);
	if (xqi == None)
		return NULL;

	req = &xseg->requests[xqi];
	req->portno = portno;
	return req;
}

int xseg_put_request (  struct xseg *xseg,
			uint32_t portno,
			struct xseg_request *xreq )
{
	xqindex xqi = xreq - xseg->requests;
	xreq->data = xreq->buffer;
	xreq->datasize = xreq->buffersize;
	xreq->name = NULL;
	xreq->namesize = 0;
	return xq_append_head(&xseg->ports[portno].free_queue, xqi) == None;
}

int xseg_prep_request ( struct xseg_request *req,
			uint32_t namesize, uint64_t datasize )
{
	if (namesize + datasize > req->buffersize)
		return -1;

	req->data = req->buffer;
	req->name = req->buffer + req->buffersize - namesize;
	req->datasize = datasize;
	req->namesize = namesize;
	return 0;
}

xserial xseg_submit (	struct xseg *xseg, uint32_t portno,
			struct xseg_request *xreq	)
{
	xserial serial = NoSerial;
	xqindex xqi;
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		goto out;

	port = &xseg->ports[portno];
	xqi = xreq - xseg->requests;
	serial = xq_append_tail(&port->request_queue, xqi);
	/* who signals? we do or caller does? */

out:
	return serial;
}

struct xseg_request *xseg_receive(struct xseg *xseg, uint32_t portno)
{
	xqindex xqi;
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		return NULL;

	port = &xseg->ports[portno];
	xqi = xq_pop_head(&port->reply_queue);
	if (xqi == None)
		return NULL;

	return xseg->requests + xqi;
}

struct xseg_request *xseg_accept(struct xseg *xseg, uint32_t portno)
{
	xqindex xqi;
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		return NULL;

	port = &xseg->ports[portno];
	xqi = xq_pop_head(&port->request_queue);
	if (xqi == None)
		return NULL;

	return xseg->requests + xqi;
}

xserial xseg_respond (  struct xseg *xseg, uint32_t portno,
			struct xseg_request *xreq  )
{
	xserial serial = NoSerial;
	xqindex xqi;
	struct xseg_port *port;
	if (!__validate_port(xseg, portno))
		goto out;

	port = &xseg->ports[portno];
	xqi = xreq - xseg->requests;
	serial = xq_append_tail(&port->reply_queue, xqi);
	/* who signals? we do? caller does? */

out:
	return serial;
}


struct xseg_port *xseg_bind_port(struct xseg *xseg, uint32_t req)
{
	uint32_t portno, maxno, id = __get_id(), force;
	struct xseg_port *port;

	if (req > xseg->config.nr_ports) {
		portno = 0;
		maxno = xseg->config.nr_ports;
		force = 0;
	} else {
		portno = req;
		maxno = req;
		force = 1;
	}

	__lock_segment(xseg);
	for (; portno <= maxno; portno++) {
		long driver;
		port = &xseg->ports[portno];
		if (port->owner && !force)
			continue;
		driver = __enable_driver(xseg, &__peer_type);
		if (driver < 0)
			break;
		port->peer_type = (uint32_t)driver;
		port->owner = id;
		goto out;
	}
	port = NULL;
out:
	__unlock_segment(xseg);
	return port;
}


int xseg_initialize(const char *_peer_type_name)
{
	struct xseg_peer *type;

	__xseg_preinit();
	type = __find_or_load_peer_type(_peer_type_name);
	if (!type) {
		LOGMSG("Cannot initialize '%s': no driver\n", _peer_type_name);
		return -1;
	}
	__peer_type = *type;
	return 0;
}

#ifdef __KERNEL__
#include <linux/module.h>
#include <xseg/xseg_exports.h>
#endif

