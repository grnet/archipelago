#include <xseg/xseg.h>
#include <xseg/domain.h>
#include <sys/util.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

#define XSEG_NR_TYPES 16
#define XSEG_NR_PEER_TYPES 64
#define XSEG_MIN_PAGE_SIZE 4096

static struct xseg_type *__types[XSEG_NR_TYPES];
static unsigned int __nr_types;
static struct xseg_peer *__peer_types[XSEG_NR_PEER_TYPES];
static unsigned int __nr_peer_types;

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

static struct xseg_peer *__find_peer_type(const char *name, int64_t *index)
{
	int64_t i;
	for (i = 0; (*index = i) < __nr_peer_types; i++) {
		if (!strncmp(__peer_types[i]->name, name, XSEG_TNAMESIZE))
			return __peer_types[i];
	}
	return NULL;
}

void xseg_report_peer_types(void)
{
	long i;
	XSEGLOG("total %u peer types:\n", __nr_peer_types);
	for (i = 0; i < __nr_peer_types; i++)
		XSEGLOG("%ld: '%s'\n", i, __peer_types[i]->name);
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
	int64_t i;
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
	struct xseg_private *priv = xseg->priv;
	char (*shared_peer_types)[XSEG_TNAMESIZE];

	if (serial >= xseg->max_peer_types) {
		XSEGLOG("invalid peer type serial %d >= %d\n",
			 serial, xseg->max_peer_types);
		return NULL;
	}

	type = priv->peer_types[serial];
	if (type)
		return type;

	/* xseg->shared->peer_types is an append-only array,
	 * therefore this should be safe
	 * without either locking or string copying. */
	shared_peer_types = XPTR_TAKE(xseg->shared->peer_types, xseg->segment);
	name = shared_peer_types[serial];
	if (!*name) {
		XSEGLOG("nonexistent peer type serial %d\n", serial);
		return NULL;
	}

	type = __find_or_load_peer_type(name);
	if (!type)
		XSEGLOG("could not find driver for peer type %d [%s]\n",
			 serial, name);

	priv->peer_types[serial] = type;
	return type;
}

static inline int __validate_port(struct xseg *xseg, uint32_t portno)
{
	return portno < xseg->config.nr_ports;
}

static inline int __validate_ptr(struct xseg *xseg, xptr ptr)
{
	return ptr < xseg->segment_size;
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
	/* default: "posix:globalxseg:4:256:12" */
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

	/* heap_size */
	TOK(s, sp, "256");
	config->heap_size = (uint64_t) (strul(s) * 1024UL * 1024UL);

	/* page_shift */
	TOK(s, sp, "12");
	config->page_shift = strul(s);
	return 0;
}

int xseg_register_type(struct xseg_type *type)
{
	long i;
	int r = -1;
	struct xseg_type *__type;
	__lock_domain();
	__type = __find_type(type->name, &i);
	if (__type) {
		XSEGLOG("type %s already exists\n", type->name);
		goto out;
	}

	if (__nr_types >= XSEG_NR_TYPES) {
		XSEGLOG("maximum type registrations reached: %u\n", __nr_types);
		r -= 1;
		goto out;
	}

	type->name[XSEG_TNAMESIZE-1] = 0;
	__types[__nr_types] = type;
	__nr_types += 1;
	r = 0;
out:
	__unlock_domain();
	return r;
}

int xseg_unregister_type(const char *name)
{
	long i;
	int r = -1;
	struct xseg_type *__type;
	__lock_domain();
	__type = __find_type(name, &i);
	if (!__type) {
		XSEGLOG("segment type '%s' does not exist\n", name);
		goto out;
	}

	__nr_types -= 1;
	__types[i] = __types[__nr_types];
	__types[__nr_types] = NULL;
	r = 0;
out:
	__unlock_domain();
	return r;
}

int xseg_register_peer(struct xseg_peer *peer_type)
{
	int64_t i;
	int r = -1;
	struct xseg_peer *type;
	__lock_domain();
	type = __find_peer_type(peer_type->name, &i);
	if (type) {
		XSEGLOG("peer type '%s' already exists\n", type->name);
		goto out;
	}

	if (__nr_peer_types >= XSEG_NR_PEER_TYPES) {
		XSEGLOG("maximum peer type registrations reached: %u",
			__nr_peer_types);
		r -= 1;
		goto out;
	}

	if (peer_type->peer_ops.signal_init()) {
		XSEGLOG("peer type '%s': signal initialization failed\n",
			peer_type->name);
		r -= 1;
		goto out;
	}

	peer_type->name[XSEG_TNAMESIZE-1] = 0;
	__peer_types[__nr_peer_types] = peer_type;
	__nr_peer_types += 1;
	r = 0;

out:
	__unlock_domain();
	return r;
}

int xseg_unregister_peer(const char *name)
{
	int64_t i;
	struct xseg_peer *driver;
	int r = -1;
	__lock_domain();
	driver = __find_peer_type(name, &i);
	if (!driver) {
		XSEGLOG("peer type '%s' does not exist\n", name);
		goto out;
	}

	__nr_peer_types -= 1;
	__peer_types[i] = __peer_types[__nr_peer_types];
	__peer_types[__nr_peer_types] = NULL;
	driver->peer_ops.signal_quit();
	r = 0;
out:
	__unlock_domain();
	return r;
}

int64_t __enable_driver(struct xseg *xseg, struct xseg_peer *driver)
{
	int64_t r;
	char (*drivers)[XSEG_TNAMESIZE];
	uint32_t max_drivers = xseg->max_peer_types;

	if (xseg->shared->nr_peer_types >= max_drivers) {
		XSEGLOG("cannot register '%s': driver namespace full\n",
			driver->name);
		return -1;
	}

	drivers = XPTR_TAKE(xseg->shared->peer_types, xseg->segment);
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
	xseg->priv->peer_types[r] = driver;
	return r;
}

int64_t xseg_enable_driver(struct xseg *xseg, const char *name)
{
	int64_t r = -1;
	struct xseg_peer *driver;

	__lock_domain();
	driver = __find_peer_type(name, &r);
	if (!driver) {
		XSEGLOG("driver '%s' not found\n", name);
		goto out;
	}

	__lock_segment(xseg);
	r = __enable_driver(xseg, driver);
	__unlock_segment(xseg);
out:
	__unlock_domain();
	return r;
}

int xseg_disable_driver(struct xseg *xseg, const char *name)
{
	int64_t i;
	int r = -1;
	struct xseg_private *priv = xseg->priv;
	struct xseg_peer *driver;
	__lock_domain();
	driver =  __find_peer_type(name, &i);
	if (!driver) {
		XSEGLOG("driver '%s' not found\n", name);
		goto out;
	}

	for (i = 0; i < xseg->max_peer_types; i++)
		if (priv->peer_types[i] == driver)
			priv->peer_types[i] = NULL;
	r = 0;
out:
	__unlock_domain();
	return r;
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
		XSEGLOG("page_shift must be >= %d\n", 9);
		return 0;
	}

	page_size = 1 << page_shift;

	/* struct xseg itself + struct xheap */
	size += 2*page_size + config->heap_size;
	size = __align(size, page_shift);
	
	return size;
}

static long initialize_segment(struct xseg *xseg, struct xseg_config *cfg)
{
	uint32_t page_shift = cfg->page_shift, page_size = 1 << page_shift;
	struct xseg_shared *shared;
	char *segment = (char *)xseg;
	uint64_t size = page_size, i;
	void *mem;
	struct xheap *heap;
	struct xobject_h *obj_h;
	int r;


	if (page_size < XSEG_MIN_PAGE_SIZE)
		return -1;

	xseg->segment_size = 2 * page_size + cfg->heap_size;
	xseg->segment = segment;

	/* build heap */
	xseg->heap = XPTR_MAKE(segment + size, segment);
	size += sizeof(struct xheap);
	size = __align(size, page_shift);

	heap = XPTR_TAKE(xseg->heap, segment);
	r = xheap_init(heap, cfg->heap_size, page_shift, segment+size);
	if (r < 0)
		return -1;

	/* build object_handler handler */
	mem = xheap_allocate(heap, sizeof(struct xobject_h));
	if (!mem)
		return -1;
	xseg->object_handlers = XPTR_MAKE(mem, segment);
	obj_h = mem;
	r = xobj_handler_init(obj_h, segment, MAGIC_OBJH, 
			sizeof(struct xobject_h), heap);
	if (r < 0)
		return -1;

	//now that we have object handlers handler, use that to allocate
	//new object handlers
	
	//allocate requests handler
	mem = xobj_get_obj(obj_h, X_ALLOC);
	if (!mem)
		return -1;
	obj_h = mem;
	r = xobj_handler_init(obj_h, segment, MAGIC_REQ, 
			sizeof(struct xseg_request), heap);
	if (r < 0)
		return -1;
	xseg->request_h = XPTR_MAKE(obj_h, segment);
	
	//allocate ports handler
	obj_h = XPTR_TAKE(xseg->object_handlers, segment);
	mem = xobj_get_obj(obj_h, X_ALLOC);
	if (!mem)
		return -1;
	obj_h = mem;
	r = xobj_handler_init(obj_h, segment, MAGIC_PORT, 
			sizeof(struct xseg_port), heap);
	if (r < 0)
		return -1;
	xseg->port_h = XPTR_MAKE(mem, segment);

	//allocate xptr port array to be used as a map
	//portno <--> xptr port
	mem = xheap_allocate(heap, sizeof(xptr)*cfg->nr_ports);
	if (!mem)
		return -1;
	xptr *ports = mem;
	for (i = 0; i < cfg->nr_ports; i++) {
		ports[i]=0;
	}
	xseg->ports = XPTR_MAKE(mem, segment);
	
	//allocate xseg_shared memory
	mem = xheap_allocate(heap, sizeof(struct xseg_shared));
	if (!mem)
		return -1;
	shared = (struct xseg_shared *) mem;
	shared->flags = 0;
	shared->nr_peer_types = 0;
	xseg->shared = XPTR_MAKE(mem, segment);
	
	mem = xheap_allocate(heap, page_size);
	if (!mem)
		return -1;
	shared->peer_types = XPTR_MAKE(mem, segment);
	xseg->max_peer_types = xheap_get_chunk_size(mem) / XSEG_TNAMESIZE;

	memcpy(&xseg->config, cfg, sizeof(struct xseg_config));

	xseg->counters.req_cnt = 0;
	xseg->counters.avg_req_lat = 0;

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
		XSEGLOG("type '%s' does not exist\n", cfg->type);
		goto out_err;
	}

	size = calculate_segment_size(cfg);
	if (!size) {
		XSEGLOG("invalid config!\n");
		goto out_err;
	}

	xops = &type->ops;
	cfg->name[XSEG_NAMESIZE-1] = 0;
	r = xops->allocate(cfg->name, size);
	if (r) {
		XSEGLOG("cannot allocate segment!\n");
		goto out_err;
	}

	xseg = xops->map(cfg->name, size, NULL);
	if (!xseg) {
		XSEGLOG("cannot map segment!\n");
		goto out_deallocate;
	}

	r = initialize_segment(xseg, cfg);
	xops->unmap(xseg, size);
	if (r) {
		XSEGLOG("cannot initilize segment!\n");
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
	struct xseg_type *type;

	__lock_domain();
	type = __find_or_load_type(xseg->config.type);
	if (!type) {
		XSEGLOG("no segment type '%s'\n", xseg->config.type);
		goto out;
	}

	/* should destroy() leave() first? */
	type->ops.deallocate(xseg->config.name);
out:
	__unlock_domain();
}

//FIXME
static int pointer_ok(	unsigned long ptr,
			unsigned long base,
			uint64_t size,
			char *name)
{
	int ret = !(ptr >= base && ptr < base + size);
	if (ret)
		XSEGLOG("invalid pointer '->%s' [%llx on %llx]!\n",
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
	r += POINTER_OK(xseg, object_handlers, xseg->segment);
	r += POINTER_OK(xseg, request_h, xseg->segment);
	r += POINTER_OK(xseg, port_h, xseg->segment);
	r += POINTER_OK(xseg, ports, xseg->segment);
	r += POINTER_OK(xseg, heap, xseg->segment);
	r += POINTER_OK(xseg, shared, xseg->segment);
	return r;
}

struct xseg *xseg_join(	char *segtypename,
			char *segname,
			char *peertypename,
			void (*wakeup)
			(	struct xseg *xseg,
				uint32_t portno		))
{
	struct xseg *xseg, *__xseg;
	uint64_t size;
	struct xseg_peer *peertype;
	struct xseg_type *segtype;
	struct xseg_private *priv;
	struct xseg_operations *xops;
	struct xseg_peer_operations *pops;
	int r;

	__lock_domain();

	peertype = __find_or_load_peer_type(peertypename);
	if (!peertype) {
		XSEGLOG("Peer type '%s' not found\n", peertypename);
		__unlock_domain();
		goto err;
	}

	segtype = __find_or_load_type(segtypename);
	if (!segtype) {
		XSEGLOG("Segment type '%s' not found\n", segtypename);
		__unlock_domain();
		goto err;
	}

	__unlock_domain();

	xops = &segtype->ops;
	pops = &peertype->peer_ops;

	xseg = pops->malloc(sizeof(struct xseg));
	if (!xseg) {
		XSEGLOG("Cannot allocate memory");
		goto err;
	}

	priv = pops->malloc(sizeof(struct xseg_private));
	if (!priv) {
		XSEGLOG("Cannot allocate memory");
		goto err_seg;
	}

	__xseg = xops->map(segname, XSEG_MIN_PAGE_SIZE, NULL);
	if (!__xseg) {
		XSEGLOG("Cannot map segment");
		goto err_priv;
	}

	size = __xseg->segment_size;
	/* XSEGLOG("joined segment of size: %lu\n", (unsigned long)size); */
	xops->unmap(__xseg, XSEG_MIN_PAGE_SIZE);

	__xseg = xops->map(segname, size, xseg);
	if (!__xseg) {
		XSEGLOG("Cannot map segment");
		goto err_priv;
	}

	priv->segment_type = *segtype;
	priv->peer_type = *peertype;
	priv->wakeup = wakeup;
	xseg->max_peer_types = __xseg->max_peer_types;

	priv->peer_types = pops->malloc(sizeof(void *) * xseg->max_peer_types);
	if (!priv->peer_types) {
		XSEGLOG("Cannot allocate memory");
		goto err_unmap;
	}
	memset(priv->peer_types, 0, sizeof(void *) * xseg->max_peer_types);

	xseg->priv = priv;
	xseg->config = __xseg->config;
	xseg->version = __xseg->version;
	xseg->request_h = XPTR_TAKE(__xseg->request_h, __xseg);
	xseg->port_h = XPTR_TAKE(__xseg->port_h, __xseg);
	xseg->ports = XPTR_TAKE(__xseg->ports, __xseg);
	xseg->heap = XPTR_TAKE(__xseg->heap, __xseg);
	xseg->object_handlers = XPTR_TAKE(__xseg->object_handlers, __xseg);
	xseg->shared = XPTR_TAKE(__xseg->shared, __xseg);
	xseg->segment_size = size;
	xseg->segment = __xseg;

	r = xseg_validate_pointers(xseg);
	if (r) {
		XSEGLOG("found %d invalid xseg pointers!\n", r);
		goto err_free_types;
	}

	/* Do we need this?
	r = xops->signal_join(xseg);
	if (r) {
		XSEGLOG("Cannot attach signaling to segment! (error: %d)\n", r);
		goto err_free_types;
	}
	*/

	return xseg;

err_free_types:
	pops->mfree(priv->peer_types);
err_unmap:
	xops->unmap(__xseg, size);
err_priv:
	pops->mfree(priv);
err_seg:
	pops->mfree(xseg);
err:
	return NULL;
}

void xseg_leave(struct xseg *xseg)
{
	struct xseg_type *type;

	__lock_domain();
	type = __find_or_load_type(xseg->config.type);
	if (!type) {
		XSEGLOG("no segment type '%s'\n", xseg->config.type);
		__unlock_domain();
		return;
	}
	__unlock_domain();

	type->ops.unmap(xseg->segment, xseg->segment_size);
}

struct xseg_port* xseg_get_port(struct xseg *xseg, uint32_t portno)
{
	xptr p;
	if (!__validate_port(xseg, portno))
		return NULL;
	p = xseg->ports[portno];
	if (p)
		return XPTR_TAKE(p, xseg->segment);
	else 
		return NULL;
}

struct xseg_port *xseg_alloc_port(struct xseg *xseg, uint32_t flags, uint64_t nr_reqs)
{
	struct xobject_h *obj_h = xseg->port_h;
	struct xseg_port *port = xobj_get_obj(obj_h, flags);
	if (!port)
		return NULL;

	void *mem;
	struct xheap *heap = xseg->heap;
	struct xq *q;
	char *buf;
	uint64_t bytes;
	
	//TODO since max number of requests is not fixed
	//	maybe we should make xqs expand when necessary

	//how many bytes to allocate for a queue
	bytes = sizeof(struct xq) + nr_reqs*sizeof(xqindex);
	mem = xheap_allocate(heap, bytes);
	if (!mem)
		goto err_free;

	//how many did we got, and calculate what's left of buffer
	bytes = xheap_get_chunk_size(mem) - sizeof(struct xq);
	port->free_queue = XPTR_MAKE(mem, xseg->segment);
	//initialize queue with max nr it can hold
	q = (struct xq *)XPTR_TAKE(port->free_queue, xseg->segment);
	buf = mem + sizeof(struct xq);
	xq_init_empty(q, bytes/sizeof(xqindex), buf); 

	//and for request queue
	bytes = sizeof(struct xq) + nr_reqs*sizeof(xqindex);
	mem = xheap_allocate(heap, bytes);
	if (!mem)
		goto err_req;

	bytes = xheap_get_chunk_size(mem) - sizeof(struct xq);
	port->request_queue = XPTR_MAKE(mem, xseg->segment);
	//initialize queue with max nr it can hold
	q = (struct xq *)XPTR_TAKE(port->request_queue, xseg->segment);
	buf = mem + sizeof(struct xq);
	xq_init_empty(q, bytes/sizeof(xqindex), buf); 
	
	//and for reply_queue
	bytes = sizeof(struct xq) + nr_reqs*sizeof(xqindex);
	mem = xheap_allocate(heap, bytes);
	if (!mem)
		goto err_reply;

	bytes = xheap_get_chunk_size(mem) - sizeof(struct xq);
	port->reply_queue = XPTR_MAKE(mem, xseg->segment);
	//initialize queue with max nr it can hold
	q = (struct xq *)XPTR_TAKE(port->reply_queue, xseg->segment);
	buf = mem + sizeof(struct xq);
	xq_init_empty(q, bytes/sizeof(xqindex), buf); 

	return port;

err_reply:
	xheap_free(XPTR_TAKE(port->request_queue, xseg->segment));
	port->request_queue = 0;
err_req:
	xheap_free(XPTR_TAKE(port->free_queue, xseg->segment));
	port->free_queue = 0;
err_free:
	xobj_put_obj(obj_h, port);

	return NULL;
	
}

void xseg_free_port(struct xseg *xseg, struct xseg_port *port)
{
	struct xobject_h *obj_h = xseg->port_h;

	if (port->request_queue) {
		xheap_free(XPTR_TAKE(port->request_queue, xseg->segment));
		port->request_queue = 0;
	}
	if (port->free_queue) {
		xheap_free(XPTR_TAKE(port->free_queue, xseg->segment));
		port->free_queue = 0;
	}
	if (port->reply_queue) {
		xheap_free(XPTR_TAKE(port->reply_queue, xseg->segment));
		port->reply_queue = 0;
	}
	xobj_put_obj(obj_h, port);
}

void* xseg_alloc_buffer(struct xseg *xseg, uint64_t size)
{
	struct xheap *heap = xseg->heap;
	return xheap_allocate(heap, size);
}

void xseg_free_buffer(struct xseg *xseg, void *ptr)
{
	xheap_free(ptr);
}

struct xseg_request* xseg_alloc_request(struct xseg *xseg, uint32_t flags)
{
	struct xobject_h *obj_h = xseg->request_h;
	return xobj_get_obj(obj_h, flags);
}

void xseg_free_request(struct xseg *xseg, void *ptr)
{
	struct xobject_h *obj_h = xseg->request_h;
	xobj_put_obj(obj_h, ptr);
}

int xseg_prepare_wait(struct xseg *xseg, uint32_t portno)
{
	if (!__validate_port(xseg, portno))
		return -1;

	return xseg->priv->peer_type.peer_ops.prepare_wait(xseg, portno);
}

int xseg_cancel_wait(struct xseg *xseg, uint32_t portno)
{
	if (!__validate_port(xseg, portno))
		return -1;
	return xseg->priv->peer_type.peer_ops.cancel_wait(xseg, portno);
}

int xseg_wait_signal(struct xseg *xseg, uint32_t usec_timeout)
{
	return xseg->priv->peer_type.peer_ops.wait_signal(xseg, usec_timeout);
}

int xseg_signal(struct xseg *xseg, uint32_t portno)
{
	struct xseg_peer *type;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;
	
	type = __get_peer_type(xseg, port->peer_type);
	if (!type)
		return -1;

	return type->peer_ops.signal(xseg, portno);
}

int xseg_alloc_requests(struct xseg *xseg, uint32_t portno, uint32_t nr)
{
	unsigned long i = 0;
	xqindex xqi;
	struct xq *q;
	struct xseg_request *req;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;

	q = XPTR_TAKE(port->free_queue, xseg->segment);
	while ((req = xseg_alloc_request(xseg, X_ALLOC)) != NULL && i < nr) {
		xqi = XPTR_MAKE(req, xseg->segment);
		xqi = xq_append_tail(q, xqi, portno);
		if (xqi == Noneidx)
			break;
		i++;
	}

	if (i == 0)
		i = -1;
	return i;
}

int xseg_free_requests(struct xseg *xseg, uint32_t portno, int nr)
{
	unsigned long i = 0;
	xqindex xqi;
	struct xq *q;
	struct xseg_request *req;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return -1;

	q = XPTR_TAKE(port->free_queue, xseg->segment);
	while ((xqi = xq_pop_head(q, portno)) != Noneidx && i < nr) {
		req = XPTR_TAKE(xqi, xseg->segment);
		xseg_free_request(xseg, req);
		i++;
	}
	if (i == 0)
		i = -1;
	return i;
}

struct xseg_request *xseg_get_request(struct xseg *xseg, uint32_t portno)
{
	//TODO add flags option 
	//X_ALLOC
	//X_LOCAL_ONLY (Maybe we want this as default, to give a hint to a peer
	//		how many requests it can have flying)
	struct xseg_request *req;
	struct xseg_port *port;
	struct xq *q;
	xqindex xqi;
	xptr ptr;

	port = xseg_get_port(xseg, portno);
	if (!port)
		return NULL;
	//try to allocate from free_queue
	q = XPTR_TAKE(port->free_queue, xseg->segment);
	xqi = xq_pop_head(q, portno);
	if (xqi != Noneidx){
		ptr = xqi;
		req = XPTR_TAKE(ptr, xseg->segment);
		goto done;
	}

	//else try to allocate from global heap
	req = xseg_alloc_request(xseg, X_ALLOC);
	if (!req)
		return NULL;
done:
	req->portno = portno;

	req->target = 0;
	req->data = 0;
	req->datalen = 0;
	req->targetlen = 0;
	
	req->elapsed = 0;
	req->timestamp.tv_sec = 0;
	req->timestamp.tv_usec = 0;

	return req;
}

int xseg_put_request (  struct xseg *xseg,
			uint32_t portno,
			struct xseg_request *xreq )
{
	xqindex xqi = XPTR_MAKE(xreq, xseg->segment);
	struct xq *q;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port) 
		return -1;
	q = XPTR_TAKE(port->free_queue, xseg->segment);

	if (xreq->buffer){
		void *ptr = XPTR_TAKE(xreq->buffer, xseg->segment);
		xseg_free_buffer(xseg, ptr);
	}
	xreq->target = 0;
	xreq->data = 0;
	xreq->datalen = 0;
	xreq->targetlen = 0;
	
	if (xreq->elapsed != 0) {
		__lock_segment(xseg);
		++(xseg->counters.req_cnt);
		xseg->counters.avg_req_lat += xreq->elapsed;
		__unlock_segment(xseg);
	}

	//try to put it in free_queue of the port
	xqi = xq_append_head(q, xqi, portno);
	if (xqi != Noneidx)
		return 0;

	//else return it to segment
	xseg_free_request(xseg, xreq);
	return 0;
}

int xseg_prep_request ( struct xseg* xseg, struct xseg_request *req,
			uint32_t targetlen, uint64_t datalen )
{
	uint64_t bufferlen = targetlen + datalen;
	void *buf = xseg_alloc_buffer(xseg, bufferlen);
	if (!buf)
		return -1;
	req->bufferlen = xheap_get_chunk_size(buf);
	req->buffer = XPTR_MAKE(buf, xseg->segment);
	
	req->data = req->buffer;
	req->target = req->buffer + req->bufferlen - targetlen;
	req->datalen = datalen;
	req->targetlen = targetlen;
	return 0;
}

static void __update_timestamp(struct xseg_request *xreq)
{
	struct timeval tv;

	__get_current_time(&tv);
	if (xreq->timestamp.tv_sec != 0)
		/*
		 * FIXME: Make xreq->elapsed timeval/timespec again to avoid the
		 * 		  multiplication?
		 */
		xreq->elapsed += (tv.tv_sec - xreq->timestamp.tv_sec) * 1000000 
						+ (tv.tv_usec - xreq->timestamp.tv_usec);

	xreq->timestamp.tv_sec = tv.tv_sec;
	xreq->timestamp.tv_usec = tv.tv_usec;
}

xserial xseg_submit (	struct xseg *xseg, uint32_t portno,
			struct xseg_request *xreq	)
{
	xserial serial = NoSerial;
	xqindex xqi;
	struct xq *q;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		goto out;

	__update_timestamp(xreq);
	
	q = XPTR_TAKE(port->request_queue, xseg->segment);
	xqi = XPTR_MAKE(xreq, xseg->segment);
	serial = xq_append_tail(q, xqi, portno);
out:
	return serial;
	
}

struct xseg_request *xseg_receive(struct xseg *xseg, uint32_t portno)
{
	xqindex xqi;
	struct xq *q;
	struct xseg_request *req;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return NULL;

	q = XPTR_TAKE(port->reply_queue, xseg->segment);
	xqi = xq_pop_head(q, portno);
	if (xqi == Noneidx)
		return NULL;

	req = XPTR_TAKE(xqi, xseg->segment);
	__update_timestamp(req);

	return req;
}

struct xseg_request *xseg_accept(struct xseg *xseg, uint32_t portno)
{
	xqindex xqi;
	struct xq *q;
	struct xseg_request *req;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		return NULL;
	q = XPTR_TAKE(port->request_queue, xseg->segment);
	xqi = xq_pop_head(q, portno);
	if (xqi == Noneidx)
		return NULL;

	req = XPTR_TAKE(xqi, xseg->segment);
	return req;

}

xserial xseg_respond (  struct xseg *xseg, uint32_t portno,
			struct xseg_request *xreq  )
{
	xserial serial = NoSerial;
	xqindex xqi;
	struct xq *q;
	struct xseg_port *port = xseg_get_port(xseg, portno);
	if (!port)
		goto out;

	
	q = XPTR_TAKE(port->reply_queue, xseg->segment);
	xqi = XPTR_MAKE(xreq, xseg->segment);
	serial = xq_append_tail(q, xqi, portno);
out:
	return serial;
	
}


struct xseg_port *xseg_bind_port(struct xseg *xseg, uint32_t req)
{
	uint32_t portno, maxno, id = __get_id(), force;
	struct xseg_port *port;

	if (req >= xseg->config.nr_ports) {
		portno = 0;
		maxno = xseg->config.nr_ports;
		force = 0;
	} else {
		portno = req;
		maxno = req + 1;
		force = 1;
	}

	port = xseg_alloc_port(xseg, X_ALLOC, 512);
	if (!port)
		return NULL;

	__lock_segment(xseg);
	for (; portno < maxno; portno++) {
		int64_t driver;
		if (xseg->ports[portno] && !force)
			continue;
		driver = __enable_driver(xseg, &xseg->priv->peer_type);
		if (driver < 0)
			break;
		port->peer_type = (uint64_t)driver;
		port->owner = id;
		port->portno = portno;
		xseg->ports[portno] = XPTR_MAKE(port, xseg->segment);
		goto out;
	}
	xseg_free_port(xseg, port);
	port = NULL;
out:
	__unlock_segment(xseg);
	return port;
}


int xseg_initialize(void)
{
	return __xseg_preinit();	/* with or without lock ? */
}

int xseg_finalize(void)
{
	/* finalize not supported yet */
	return -1;
}


#ifdef __KERNEL__
#include <linux/module.h>
#include <xseg/xseg_exports.h>
#endif

