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

#include <xtypes/xcache.h>
//TODO container aware and xptrs

#if 0
static struct xcache_entry * get_cache_entry(struct xcache *cache, xqindex idx)
{
   return &cache->entries[idx];
}

static xqindex __get_cache_idx(struct xcache *cache, struct xcache_entry *ce)
{
	return (xqindex)(ce - cache->nodes);
}

static xqindex __alloc_cache_entry(struct xcache *cache)
{
	return __xq_pop_head(&cache->free_nodes);
}

static void __free_cache_entry(struct xcache *cache, xqindex idx)
{
	if (__xq_append_head(&cache->free_nodes, idx) == Noneidx)
		XSEGLOG("BUG: Could not free cache entry node. Queue is full");
}
#endif

/* table helper functions */
static xcache_handler __table_lookup(xhash_t *table, char *name)
{
	xqindex xqi = Noneidx;
	if (xhash_lookup(table, (xhashidx)name, &xqi) < 0)
		return NoEntry;
	return (xcache_handler)xqi;
}

static int __table_insert(xhash_t **table, struct xcache * cache, xcache_handler h)
{
	xhash_t *new;
	xqindex idx = (xqindex)h;
	struct xcache_entry *ce = &cache->nodes[idx];
	int r = 0;

	r = xhash_insert(*table, (xhashidx)ce->name, idx);
	if (r == -XHASH_ERESIZE){
		XSEGLOG("Rebuilding internal hash table");
		new = xhash_resize(*table,
				cache->rm_entries->size_shift,
				cache->rm_entries->limit, NULL);
		if (!new) {
			XSEGLOG("Error resizing hash table");
			return -1;
		}
		*table = new;

		/* We give insertion a second shot */
		r = xhash_insert(*table, (xhashidx)ce->name, idx);
		if (r == -XHASH_ERESIZE) {
			XSEGLOG("BUG: failed to insert entry after resize");
			return -1;
		}
	}

	return r;
}

static int __table_remove(xhash_t *table, char *name)
{
	int r;

	r = xhash_delete(table, (xhashidx)name);
	if (UNLIKELY(r<0)){
		if (r == -XHASH_ERESIZE)
			XSEGLOG("BUG: hash table must be resized");
		else if (r == -XHASH_EEXIST)
			XSEGLOG("BUG: Entry %s not found in hash table", name);
	}
	return r;
}

static xqindex alloc_cache_entry(struct xcache *cache)
{
	return xq_pop_head(&cache->free_nodes, 1);
}

static void __free_cache_entry(struct xcache *cache, xqindex idx)
{
	if (UNLIKELY(xq_append_head(&cache->free_nodes, idx, 1) == Noneidx))
		XSEGLOG("BUG: Could not free cache entry node. Queue is full");
}

static void free_cache_entry(struct xcache *cache, xqindex idx)
{
	struct xcache_entry *ce = &cache->nodes[idx];

	if (ce->ref != 0)
		XSEGLOG("BUG: Free entry has ref %lu (priv: %p, h: %p)", ce->priv, idx);

	__free_cache_entry(cache, idx);
	if (cache->ops.on_free)
		cache->ops.on_free(cache->priv, ce->priv);
}

static xqindex __count_free_nodes(struct xcache *cache)
{
	return xq_count(&cache->free_nodes);
}

static void __reset_times(struct xcache *cache)
{
	uint32_t i;
	struct xcache_entry *ce;
	xbinheapidx time;

	/* assert thatn cache->time does not get MAX value. If this happens, add
	 * one more, to overflow time and return to zero.
	 */
	if (cache->flags & XCACHE_LRU_ARRAY){
		for (i = 0; i < cache->size; i++) {
			if (cache->times[i] != XCACHE_LRU_MAX)
				cache->times[i] = cache->time++;
		}
	} else if (cache->flags & XCACHE_LRU_HEAP) {
		for (i = 0; i < cache->size; i++) {
			ce = &cache->nodes[i];
			if (ce->h == NoNode)
				continue;
			time = xbinheap_getkey(&cache->binheap, ce->h);
			if (time < cache->time)
				xbinheap_increasekey(&cache->binheap, ce->h, cache->time);
			else
				xbinheap_decreasekey(&cache->binheap, ce->h, cache->time);
		}
	}
}

/*
 * xbinheap should be protected by cache lock.
 */
static void __update_access_time(struct xcache *cache, xqindex idx)
{
	struct xcache_entry *ce = &cache->nodes[idx];

	/* assert thatn cache->time does not get MAX value. If this happen,
	 * reset it to zero, and also reset all access times.
	 */
	cache->time++;
	if (cache->time == XCACHE_LRU_MAX) {
		cache->time = 0;
		__reset_times(cache);
		return;
	}

	if (cache->flags & XCACHE_LRU_ARRAY){
		cache->times[idx] = cache->time;
	} else if (cache->flags & XCACHE_LRU_HEAP) {
		if (ce->h != NoNode){
			xbinheap_increasekey(&cache->binheap, ce->h, cache->time);
		} else {
			ce->h = xbinheap_insert(&cache->binheap, cache->time, idx);
			if (ce->h == NoNode){
				XSEGLOG("BUG: Cannot insert to lru binary heap");
			}
		}
	}
}

/* __xcache_entry_get needs no lock. */
static void __xcache_entry_get(struct xcache *cache, xqindex idx)
{
	struct xcache_entry *ce = &cache->nodes[idx];
	__sync_add_and_fetch(&ce->ref, 1);
}

/*
 * __xcache_entry_get_and_update must be called with cache->lock held, due to
 * the race for __update_access_time.
 */
static void __xcache_entry_get_and_update(struct xcache *cache, xqindex idx)
{
	__xcache_entry_get(cache, idx);
	__update_access_time(cache, idx);
}

/* after a succesfull call, the handler must be put */
static int __xcache_remove_entries(struct xcache *cache, xcache_handler h)
{
	int r;
	xqindex idx = (xqindex)h;
	struct xcache_entry *ce = &cache->nodes[idx];

	r = __table_remove(cache->entries, ce->name);
	if (UNLIKELY(r < 0)){
		XSEGLOG("Couldn't delete cache entry from hash table:\n"
				"h: %llu, name: %s, cache->nodes[h].priv: %p, ref: %llu",
				h, ce->name, cache->nodes[idx].priv, cache->nodes[idx].ref);
		return r;
	}

	if (cache->flags & XCACHE_LRU_ARRAY)
		cache->times[idx] = XCACHE_LRU_MAX;
	else if (cache->flags & XCACHE_LRU_HEAP) {
		if (ce->h != NoNode) {
			if (xbinheap_increasekey(&cache->binheap, ce->h, XCACHE_LRU_MAX) < 0){
				XSEGLOG("BUG: cannot increase key to XCACHE_LRU_MAX");
			}
			if (xbinheap_extract(&cache->binheap) == NoNode){
				XSEGLOG("BUG: cannot remove cache entry from lru");
			}
			ce->h = NoNode;
		}
	}
	//XSEGLOG("cache->times[%llu] = %llu", idx, cache->times[idx]);
	return 0;
}

/*
 * __xcache_remove_rm must always be called with cache->rm_lock held.
 * It finalizes the removal of an entry from the cache.
 */
static int __xcache_remove_rm(struct xcache *cache, xcache_handler h)
{
	int r;
	xqindex idx = (xqindex)h;
	struct xcache_entry *ce = &cache->nodes[idx];

	r = __table_remove(cache->rm_entries, ce->name);
	if (UNLIKELY(r < 0)) {
		XSEGLOG("Couldn't delete cache entry from hash table:\n"
				"h: %llu, name: %s, cache->nodes[h].priv: %p, ref: %llu",
				h, ce->name, cache->nodes[idx].priv, cache->nodes[idx].ref);
	}

	return r;
}

/*
 * __xcache_lookup_rm must always be called with cache->rm_lock held.
 * It checks if name exists in "rm_entries"
 */
static xcache_handler __xcache_lookup_rm(struct xcache *cache, char *name)
{
	return __table_lookup(cache->rm_entries, name);
}

static xcache_handler __xcache_lookup_and_get_rm(struct xcache *cache, char *name)
{
	xcache_handler h;

	h = __xcache_lookup_rm(cache, name);
	if (h != NoEntry){
		__xcache_entry_get_and_update(cache, h);
	}

	return h;
}

static xcache_handler __xcache_lookup_entries(struct xcache *cache, char *name)
{
	return __table_lookup(cache->entries, name);
}

static xcache_handler __xcache_lookup_and_get_entries(struct xcache *cache, char *name)
{
	xcache_handler h;

	h = __xcache_lookup_entries(cache, name);
	if (h != NoEntry){
		__xcache_entry_get_and_update(cache, h);
	}

	return h;
}

static xcache_handler __xcache_insert_rm(struct xcache *cache, xcache_handler h)
{
	return __table_insert(&cache->rm_entries, cache, h);
}

static xcache_handler __xcache_insert_entries(struct xcache *cache, xcache_handler h)
{
	return __table_insert(&cache->entries, cache, h);
}

/*
 * xcache_entry_put is thread-safe even without cache->lock (cache->rm_lock is
 * crucial though). This is why:
 *
 * a. We put the entry's refcount. If it doesn't drop to zero, we can move on.
 * b. If it drops to zero, then we inform the peer that the cache entry is about
 *    to leave with the "on_evict" hook.
 * c. If peer returns a negative value, we do not free the entry yet and leave.
 * d. If everything is ok, we get the rm_lock.
 * e. Since rm_lock is needed for a re-insertion or a simple 'get' for this
 *    entry, we can safely check again the entry's ref here. If it's > 0, then
 *    someone beat us to it and has a job to do. If it's 0 though, then by
 *    removing the entry from "rm_entries" we are safe to free that entry
 *    without rm_lock.
 */
static void xcache_entry_put(struct xcache *cache, xqindex idx)
{
	struct xcache_entry *ce = &cache->nodes[idx];
	unsigned long ref;

	xlock_acquire(&cache->rm_lock, 1);

	ref = __sync_sub_and_fetch(&ce->ref, 1);
	if (ref > 0)
		goto out;

	if (cache->ops.on_finalize)
		cache->ops.on_finalize(cache->priv, ce->priv);

	/*
	 * FIXME: BUG! Why? Say that on finalize has deemed that ce is clear.
	 * If we get descheduled before getting rm_lock and in the meantime, the
	 * cache entry is reinserted, dirtied and evicted? The ce->ref will be
	 * zero but we shouldn't leave since there are still dirty buckets.
	 */
	if (ce->ref != 0)
		goto out;
	if (__xcache_remove_rm(cache, idx) < 0)
		goto out;

	xlock_release(&cache->rm_lock);

	if (cache->ops.on_put)
		cache->ops.on_put(cache->priv, ce->priv);

	free_cache_entry(cache, idx);

	return;

out:
	xlock_release(&cache->rm_lock);
}

static int xcache_entry_init(struct xcache *cache, xqindex idx, char *name)
{
	int r = 0;
	struct xcache_entry *ce = &cache->nodes[idx];

	xlock_release(&ce->lock);
	if (UNLIKELY(ce->ref != 0))
		XSEGLOG("BUG: New entry has ref != 0 (h: %lu, ref: %lu, priv: %p)",
				idx, ce->ref, ce->priv);
	ce->ref = 1;
	strncpy(ce->name, name, XSEG_MAX_TARGETLEN);
	ce->name[XSEG_MAX_TARGETLEN] = 0;
	ce->h = NoNode;
	ce->state = NODE_ACTIVE;

	if (cache->ops.on_init)
		r = cache->ops.on_init(cache->priv, ce->priv);

	return r;
}


static xqindex __xcache_lru(struct xcache *cache)
{
	uint64_t min = -2;
	xqindex i, lru = Noneidx;
	struct xcache_entry *ce;

	if (cache->flags & XCACHE_LRU_ARRAY){
		for (i = 0; i < cache->nr_nodes; i++) {
			//XSEGLOG("cache->times[%llu] = %llu", i, cache->times[i]);
			if (min > cache->times[i]){
				min = cache->times[i];
				lru = i;
			}
		}
		//FIXME if cache->times[lru] == XCACHE_LRU_MAX
		//	lru = NoEntry;
		//XSEGLOG("Found lru cache->times[%llu] = %llu", lru, cache->times[lru]);
	} else if (cache->flags & XCACHE_LRU_HEAP) {
		lru = xbinheap_extract(&cache->binheap);
		if (lru == NoNode)
			return Noneidx;
		ce = &cache->nodes[lru];
		ce->h = NoNode;
	}
	return lru;
}

static int __xcache_evict(struct xcache *cache, xcache_handler h)
{
	//pre_evict
	//remove from entries
	//post_evict
	//insert to rm_entries

	struct xcache_entry *ce;
	int r;

	r = __xcache_remove_entries(cache, h);
	if (r < 0) {
		XSEGLOG("Failed to evict %llu from entries", h);
		return -1;
	}

	/*
	if (NoPendingActions)
		return 0;
	*/
	ce = &cache->nodes[h];

	if (UNLIKELY(ce->state == NODE_EVICTED))
		XSEGLOG("BUG: Evicting an already evicted entry (h: %lu, priv: %p)",
			 h, ce->priv);
	if (!cache->ops.post_evict ||
			!cache->ops.post_evict(cache->priv, ce->priv))
		return 0;

	ce->state = NODE_EVICTED;
	xlock_acquire(&cache->rm_lock, 1);
	r = __xcache_insert_rm(cache, h);
	xlock_release(&cache->rm_lock);

	if (r < 0) {
		ce->state = NODE_ACTIVE;
		XSEGLOG("BUG: Failed insert %llu to rm_entries", h);
		return -1;
	}

	return 0;
}

static xcache_handler __xcache_evict_lru(struct xcache *cache)
{
	int r;
	xcache_handler lru;

	lru = __xcache_lru(cache);
	if (lru == NoEntry){
		XSEGLOG("BUG: No lru found");
		return NoEntry;
	}

	r = __xcache_evict(cache, lru);
	if (r < 0)
		return NoEntry;
	return lru;
}

static int __xcache_remove(struct xcache *cache, xcache_handler h)
{
	return __xcache_remove_entries(cache, h);
}

/*
 * __xcache_insert is called with cache->lock held and has to hold
 * cache->rm_lock too when looking/inserting an entry in rm_entries. The
 * process is the following:
 *
 * 1. First, we search in "entries" to check if there was a race. If so, we
 *    return the appropriate handler.
 * 2. Then, we search in "rm_entries", to check if the target has been removed.
 *    If so we update its ref and try to insert it in cache.
 *
 * <if any of these steps fail, we return NoEntry.>
 *
 * 3. We now have a valid handler, either the one we started with or the one we
 *    re-insert. We check if there is space for it in "entries". If no space
 *    exists, we remove the oldest entry (LRU) and insert the new entry,
 *
 * When a valid handler is returned, the associated entry's refcount as well as
 * access time will always be increased. A re-inserted entry is 'got' two times,
 * the one to equalize the put that occured after its removal.
 * FIXME: Not the sanest decision to delete entries *first* from one table
 * *and then* copy them to other tables. Handle fails properly.
 */
static xcache_handler __xcache_insert(struct xcache *cache, xcache_handler h,
					xcache_handler *lru_handler,
					xcache_handler *reinsert_handler)
{
	int r;
	struct xcache_entry *ce;
	xcache_handler tmp_h, lru;

	lru = NoEntry;
	ce = &cache->nodes[h];

	/* lookup first to ensure we don't overwrite entries */
	tmp_h = __xcache_lookup_and_get_entries(cache, ce->name);
	if (tmp_h != NoEntry)
		return tmp_h;

	/* check if our "older self" exists in the rm_entries */
	xlock_acquire(&cache->rm_lock, 1);
	tmp_h = __xcache_lookup_rm(cache, ce->name);
	if (tmp_h != NoEntry) {
		/* if so then remove it from rm table */
		r = __xcache_remove_rm(cache, tmp_h);
		if (UNLIKELY(r < 0)) {
			XSEGLOG("Could not remove found entry (%llu) for %s"
				"from rm_entries", tmp_h, ce->name);
			xlock_release(&cache->rm_lock);
			return NoEntry;
		}

		/* and prepare it for reinsertion */
		ce = &cache->nodes[tmp_h];
		if (UNLIKELY(ce->state != NODE_EVICTED))
			XSEGLOG("BUG: Entry (%llu) in rm table not in evicted state", tmp_h);
		ce->state = NODE_ACTIVE;

		__xcache_entry_get(cache, tmp_h);
		h = tmp_h;
		*reinsert_handler = tmp_h;
	}
	xlock_release(&cache->rm_lock);

	/* insert new entry to cache */
	r = __xcache_insert_entries(cache, h);
	if (r == -XHASH_ENOSPC){
		lru = __xcache_evict_lru(cache);
		if (UNLIKELY(lru == NoEntry)) {
			XSEGLOG("BUG: Failed to evict lru entry");
			return NoEntry;
		}
		*lru_handler = lru;

		/*
		 * Cache entry is put when this function returns, without the
		 * cache lock held.
		 */
		r = __xcache_insert_entries(cache, h);
		if (r < 0) {
			XSEGLOG("BUG: failed to insert enries after eviction");
			return NoEntry;
		}
	}

	if (UNLIKELY(r >= 0 && ce->ref == 0))
		XSEGLOG("BUG: (Re)inserted entry has ref 0 (priv: %p, h: %lu)",
				ce->priv, h);

	if (r >= 0)
		__xcache_entry_get_and_update(cache, h);

	return (r < 0 ? NoEntry : h);
}

/*
 * xcache_insert tries to insert an xcache handler in cache.
 * On success, it returns either the same xcache handler or another one that is
 * associated with a cache entry with the same key (name).
 * If the cache node is marked as deleted, we return DelEntry.
 * If the insertion fails for any other reason, we return NoEntry.
 *
 * Finally, if a successful insertion results to an LRU eviction, we put the
 * LRU entry.
 */
xcache_handler xcache_insert(struct xcache *cache, xcache_handler h)
{
	struct xcache_entry *ce;
	xcache_handler ret = NoEntry;
	xcache_handler lru = NoEntry;
	xcache_handler reinsert_handler = NoEntry;

	xlock_acquire(&cache->lock, 1);
	ret = __xcache_insert(cache, h, &lru, &reinsert_handler);
	xlock_release(&cache->lock);

	if (lru != NoEntry) {
		if (UNLIKELY(ret == NoEntry))
			XSEGLOG("BUG: Unsuccessful insertion lead to LRU eviction.");
		ce = &cache->nodes[lru];
		if (cache->ops.on_evict)
			cache->ops.on_evict(cache->priv, ce->priv);
		xcache_entry_put(cache, lru);
	}

	if (reinsert_handler != NoEntry) {
		if (UNLIKELY(ret != reinsert_handler))
			XSEGLOG("BUG: Re-insert handler is different from returned handler"
					"(rei_h = %llu, ret_h = %llu)", reinsert_handler, ret);
		ce = &cache->nodes[reinsert_handler];
		if (cache->ops.on_reinsert)
			cache->ops.on_reinsert(cache->priv, ce->priv);
	}

	return ret;
}

/*
 * xcache_lookup looks only in "entries". There are several arguments behind
 * this choice:
 *
 * a. Speed: xcache_lookup won't bother with geting rm->lock or re-inserting
 *    entries in other hash tables this way.
 * b. Common case: Rarely will we ever need to lookup in "rm_entries"
 * c. Simplicity: <self-explanatory>
 */
xcache_handler xcache_lookup(struct xcache *cache, char *name)
{
	xcache_handler h = NoEntry;

	xlock_acquire(&cache->lock, 1);
	h = __xcache_lookup_and_get_entries(cache, name);
	xlock_release(&cache->lock);

	return h;
}

xcache_handler xcache_alloc_init(struct xcache *cache, char *name)
{
	int r;
	xcache_handler h;
	xqindex idx = alloc_cache_entry(cache);

	if (idx == Noneidx)
		return NoEntry;

	r = xcache_entry_init(cache, idx, name);
	if (r < 0){
		free_cache_entry(cache, idx);
		return NoEntry;
	}
	h = idx;

	return h;
}

/*
 * xcache_init initializes the following:
 * a. Two xhash tables:
 *    i. "entries", which indexes the active cache entries.
 *    ii. "rm_entries", which indexes the removed cache entries that are on the
 *        process of flushing their dirty data and/or finishing their pending
 *        requests.
 * b. The cache nodes. They are typically 2 x cache_size, since we need room for
 *    the removed cache entries too.
 * c. The LRU, which is chosen on compile time.
 */
int xcache_init(struct xcache *cache, uint32_t xcache_size,
		struct xcache_ops *ops, uint32_t flags, void *priv)
{
	struct xcache_entry *ce;
	unsigned long i;
	xhashidx shift;
	uint32_t tmp_size, floor_size, ceil_size;

	if (!xcache_size)
		return -1;

	/* xcache size must be a power of 2.
	 * Enforce it, by choosing the power of two that is closer to the xcache
	 * size requested.
	 */
	floor_size = 1 << (sizeof(xcache_size) * 8 - __builtin_clz(xcache_size) -1);
	ceil_size = 1 << (sizeof(xcache_size) * 8 - __builtin_clz(xcache_size));

	if (xcache_size - floor_size < ceil_size - xcache_size)
		cache->size = floor_size;
	else
		cache->size = ceil_size;

	if (cache->size != xcache_size)
		XSEGLOG("Cache has been resized from %lu entries to %lu entries",
				xcache_size, cache->size);

	/*
	 * Here we choose a proper size for the hash table.
	 * It must be able to contain at least xcache_size elements, before
	 * returns an -EXHASH_RESIZE.
	 * Thus it must be at least 3/2 * xcache_size (OK, the minimum power of
	 * two that meets this requirement to be exact).
	 *
	 * By choosing a xhash size 8 times the minimum required, we drastically
	 * decrease the number or xhash rebuilts required by xhash for
	 * perfomance reasons, sacrificing a logical amount of memory.
	 *
	 */

	tmp_size = 3 * cache->size  / 2;
	shift = sizeof(tmp_size) * 8 - __builtin_clz(tmp_size);
	shift += 3;

	xlock_release(&cache->lock);
	xlock_release(&cache->rm_lock);
	cache->nr_nodes = cache->size * 2;
	cache->time = 0;
	cache->ops = *ops;
	cache->priv = priv;
	cache->flags = flags;

	/* FIXME: If cache->size is UINT64_MAX then cache->nodes has overflowed */
	if (cache->size == (uint64_t)(-1))
		return -1;

	if (!xq_alloc_seq(&cache->free_nodes, cache->nr_nodes,
				cache->nr_nodes)){
		return -1;
	}

	cache->entries = xhash_new(shift, cache->size, STRING);
	if (!cache->entries){
		goto out_free_q;
	}

	/*
	 * "rm_entries" must have the same size as "entries" since each one indexes
	 * at most (cache->nodes / 2) entries
	 */
	cache->rm_entries = xhash_new(shift, cache->size, STRING);
	if (!cache->rm_entries){
		goto out_free_entries;
	}

	cache->nodes = xtypes_malloc(cache->nr_nodes * sizeof(struct xcache_entry));
	if (!cache->nodes){
		goto out_free_rm_entries;
	}

	if (flags & XCACHE_LRU_ARRAY){
		cache->times = xtypes_malloc(cache->nr_nodes * sizeof(uint64_t));
		if (!cache->times){
			goto out_free_nodes;
		}
		for (i = 0; i < cache->nr_nodes; i++) {
			cache->times[i] = XCACHE_LRU_MAX; //so lru will never return a this value;
		}
	}

	if (cache->ops.on_node_init){
		for (i = 0; i < cache->nr_nodes; i++) {
			ce = &cache->nodes[i];
			ce->ref = 0;
			/* FIXME: Is (void *) typecast necessary? */
			ce->priv = cache->ops.on_node_init(cache->priv, (void *)&i);
			if (!ce->priv)
				goto out_free_times;
		}
	}
	if (flags & XCACHE_LRU_HEAP){
		if (xbinheap_init(&cache->binheap, cache->size, XBINHEAP_MIN,
					NULL) < 0){
			goto out_free_times;
		}
	}

	return 0;

out_free_times:
	if (flags & XCACHE_LRU_ARRAY)
		xtypes_free(cache->times);
out_free_nodes:
	xtypes_free(cache->nodes);
out_free_rm_entries:
	xhash_free(cache->rm_entries);
out_free_entries:
	xhash_free(cache->entries);
out_free_q:
	xq_free(&cache->free_nodes);
	return -1;

}

int xcache_remove(struct xcache *cache, xcache_handler h)
{
	int r;
	xlock_acquire(&cache->lock, 1);
	r = __xcache_remove(cache, h);
	xlock_release(&cache->lock);
	return r;
}

//This is just an atomic
//	lookup
//	remove if Found
int xcache_invalidate(struct xcache *cache, char *name)
{
	int r = 0;
	xcache_handler h;

	xlock_acquire(&cache->lock, 1);
	xlock_acquire(&cache->rm_lock, 1);

	h = __xcache_lookup_entries(cache, name);
	if (h != NoEntry){
		r = __xcache_remove_entries(cache, h);
		goto out_put;
	}

	h = __xcache_lookup_rm(cache, name);
	if (h != NoEntry){
		r = __xcache_remove_rm(cache, h);
	}

	xlock_release(&cache->rm_lock);
	xlock_release(&cache->lock);

	return r;

out_put:
	xlock_release(&cache->rm_lock);
	xlock_release(&cache->lock);

	if (r >= 0)
		xcache_put(cache, h);
	return r;

}

/*
 * xcache_get is called with no locking.
 * It simply increases the refcount by one. The entry can either be in "entries"
 * or "rm_entries".
 */
void xcache_get(struct xcache *cache, xcache_handler h)
{
	xqindex idx = (xqindex)h;
	__xcache_entry_get(cache, idx);
}

/*
 * xcache_put is called with no locking, but when the refcount of the entry
 * drops to 0, it takes rm_lock.
 * The entry can either be in "entries" or "rm_entries".
 */
void xcache_put(struct xcache *cache, xcache_handler h)
{
	xqindex idx = (xqindex)h;
	xcache_entry_put(cache, idx);
}

/*
 * xcache_free_new is called with no locking and will not hold any lock too.
 * It must be called when an entry has not been inserted in cache (e.g. due to
 * re-insertion) and we want to free it. In this case, the refcount can safely
 * drop to zero
 */
void xcache_free_new(struct xcache *cache, xcache_handler h)
{
	xqindex idx = (xqindex)h;
	struct xcache_entry *ce = &cache->nodes[idx];

	ce->ref = 0;
	free_cache_entry(cache, idx);
}
/*
 * Put all cache entries.
 * Does not free cache resources.
 * xcache_free should be called by the client when all entries are put.
 */
void xcache_close(struct xcache *cache)
{
	uint32_t i;
	struct xcache_entry *ce;
	for (i = 0; i < cache->nr_nodes; i++) {
		ce = &cache->nodes[i];
		if (!ce->ref)
			continue;
		xcache_invalidate(cache, ce->name);
		xcache_entry_put(cache, i);
	}
}

void xcache_free(struct xcache *cache)
{
	if (cache->flags & XCACHE_LRU_HEAP){
		xbinheap_free(&cache->binheap);
	} else if (cache->flags & XCACHE_LRU_ARRAY){
		xtypes_free(cache->times);
	}
	xtypes_free(cache->nodes);
	xhash_free(cache->entries);
}

/*
 * Return how many free nodes exist.
 * Hint only, since its racy.
 */
uint64_t xcache_free_nodes(struct xcache *cache)
{
	return (uint64_t)__count_free_nodes(cache);
}

#ifdef __KERNEL__
#include <linux/module.h>
#include <xtypes/xcache_exports.h>
#endif
