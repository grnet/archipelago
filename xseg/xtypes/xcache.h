/*
 * Copyright 2013 GRNET S.A. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 *   1. Redistributions of source code must retain the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and
 * documentation are those of the authors and should not be
 * interpreted as representing official policies, either expressed
 * or implied, of GRNET S.A.
 */

#ifndef __XCACHE_H
#define __XCACHE_H

#include <xtypes/domain.h>
#include <xtypes/xlock.h>
#include <xtypes/xq.h>
#include <xtypes/xhash.h>
#include <xtypes/xbinheap.h>
#include <xseg/xseg.h>
#include <xseg/protocol.h>
#include <sys/util.h>

#define XCACHE_LRU_ARRAY      (1<<0)
#define XCACHE_LRU_HEAP       (1<<1)
#define XCACHE_USE_RMTABLE    (1<<2)

#define XCACHE_LRU_MAX   (uint64_t)(-1)

typedef xqindex xcache_handler;
#define NoEntry (xcache_handler)Noneidx

#define NODE_ACTIVE 0
#define NODE_EVICTED 1

/*
 * Called with out cache lock held:
 *
 * on_init:	called on cache entry initialization.
 *		Should return negative on error to abort cache entry
 *		initialization.
 *
 * on_put:	called when the last reference to the cache entry is put
 *
 * on_evict:	called when a cache entry is evicted. It is called with the old
 *		cache entry that gets evicted and the new cache entry that
 *		trigger the eviction as arguments.
 *		Return value interpretation:
 *			< 0 : Failure.
 *			= 0 : Success. Finished with the old cache entry.
 *			> 0 : Success. Pending actions on the old cache entry.
 *
 * on_node_init:
 *		called on initial node preparation.
 *		Must return NULL on error, to abort cache initialization.
 *
 * on_free:	called when a cache entry is freed.
 *
 * on_finalize:	FILLME
 *		Must return 0 if there are no pending actions to the entry.
 *		On non-zero value, user should get the entry which will be put
 *		to the evicted table.
 */
struct xcache_ops {
	int (*on_init)(void *cache_data, void *user_data);
	int (*on_evict)(void *cache_data, void *evicted_user_data);
	int (*on_finalize)(void *cache_data, void *evicted_user_data);
	void (*on_reinsert)(void *cache_data, void *user_data);
	void (*on_put)(void *cache_data, void *user_data);
	void (*on_free)(void *cache_data, void *user_data);
	void *(*on_node_init)(void *cache_data, void *data_handler);
};

/* FIXME: Does xcache_entry need lock? */
struct xcache_entry {
	struct xlock lock;
	volatile uint32_t ref;
	uint32_t state;
	char name[XSEG_MAX_TARGETLEN + 1];
	xbinheap_handler h;
	void *priv;
};

struct xcache {
	struct xlock lock;
	uint32_t size;
	uint32_t nr_nodes;
	struct xq free_nodes;
	xhash_t *entries;
	xhash_t *rm_entries;
	struct xlock rm_lock;
	struct xcache_entry *nodes;
	uint64_t time;
	uint64_t *times;
	struct xbinheap binheap;
	struct xcache_ops ops;
	uint32_t flags;
	void *priv;
};

static int __validate_idx(struct xcache *cache, xqindex idx)
{
	return (idx < cache->nr_nodes);
}

/*
 * Return a pointer to the associated cache entry.
 */
static void *xcache_get_entry(struct xcache *cache, xcache_handler h)
{
	xqindex idx = (xqindex)h;

	if (!__validate_idx(cache, idx))
		return NULL;

	return cache->nodes[idx].priv;
}

/*
 * Return a pointer to a NULL terminated string holding the name of the
 * associated cache entry.
 */
static char *xcache_get_name(struct xcache *cache, xcache_handler h)
{
	xqindex idx = (xqindex)h;

	if (!__validate_idx(cache, idx))
		return NULL;

	return cache->nodes[idx].name;
}

int xcache_init(struct xcache *cache, uint32_t xcache_size,
		struct xcache_ops *ops, uint32_t flags, void *priv);
void xcache_close(struct xcache *cache);
void xcache_free(struct xcache *cache);
xcache_handler xcache_lookup(struct xcache *cache, char *name);
xcache_handler xcache_alloc_init(struct xcache *cache, char *name);
xcache_handler xcache_insert(struct xcache *cache, xcache_handler h);
int xcache_remove(struct xcache *cache, xcache_handler h);
int xcache_invalidate(struct xcache *cache, char *name);
void xcache_put(struct xcache *cache, xcache_handler h);
void xcache_get(struct xcache *cache, xcache_handler h);
uint64_t xcache_free_nodes(struct xcache *cache);
void xcache_free_new(struct xcache *cache, xcache_handler h);

#endif /* __XCACHE_H */
