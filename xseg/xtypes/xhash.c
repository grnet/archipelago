/*
 * Copyright 2012 GRNET S.A. All rights reserved.
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

/* python hash for C
 *  originally by gtsouk@cslab.ece.ntua.gr
 *  -- kkourt@cslab.ece.ntua.gr
 */

#include <xtypes/xhash.h>

#define UNUSED (~(xhashidx)0)      /* this entry was never used */
#define DUMMY  ((~(xhashidx)0)-1)  /* this entry was used, but now its empty */

//#define VAL_OVERLOAD
//#define KEY_OVERLOAD
//#define NO_OVERLOAD /* use separate bitarray -- not implemented */

#define PERTURB_SHIFT 5

static inline xhashidx hash_int(xhashidx key)
{
	return key;
}

static inline int cmp_int(xhashidx key1, xhashidx key2)
{
	return (key1 == key2);
}

static inline xhashidx hash_string(xhashidx key) 
{
	//assume a valid NULL terminated string
	
	//function to access key if in container
	char *string = (char *) key;
	unsigned int i, len = strlen(string);
	xhashidx hv = string[0] << 7;
	for (i = 1; i <= len; i++) {
		hv = (hv * 1000003) ^ string[i];
	}
	if (hv == Noxhashidx)
		hv = Noxhashidx -1;

//	XSEGLOG("String %s (%lx). Hash value: %llu",
//			string, string, hv);
	return hv; 
}

static inline int cmp_string(xhashidx key1, xhashidx key2)
{
	char *string1 = (char *) key1;
	char *string2 = (char *) key2;
	int value = !strcmp(string1, string2);
//	XSEGLOG("String1 %s (%lx), string2: %s(%lx), r: %d",
//			string1, (unsigned long) string1,
//			string2, (unsigned long) string2,
//			value);

	return (value);
}

typedef int (*xhash_cmp_fun_t)(xhashidx key1, xhashidx key2);
typedef xhashidx (*xhash_hash_fun_t)(xhashidx key);

struct types_functions {
//	int (*cmp_fun)(xhashidx key1, xhashidx key2);
//	xhashidx (*hash_fun)(xhashidx key);
	xhash_cmp_fun_t cmp_fun;
	xhash_hash_fun_t hash_fun;
};

static struct types_functions types_fun[] = {
	{ .cmp_fun = cmp_int, .hash_fun = hash_int },
	{ .cmp_fun = cmp_string, .hash_fun = hash_string }
};


static inline void
set_dummy_key(xhash_t *xhash, xhashidx idx)
{
    xhashidx *kvs = xhash_kvs(xhash);
    kvs[idx] = DUMMY;
}

static inline void
set_dummy_val(xhash_t *xhash, xhashidx idx)
{
    xhashidx *vals = xhash_vals(xhash);
    vals[idx] = DUMMY;
}

static bool
item_dummy(xhash_t *xhash, xhashidx idx, bool vals)
{
    bool ret;
    xhashidx *pvals;
    xhashidx *kvs = xhash_kvs(xhash);

    if (!vals) {
        ret = (kvs[idx] == DUMMY);
    } else {
        #if defined(VAL_OVERLOAD)
        pvals = xhash_vals(xhash);
        ret = (pvals[idx] == DUMMY);
        #elif defined(KEY_OVERLOAD)
        ret = (kvs[idx] == DUMMY);
        #endif
    }
    return ret;

}

static void set_dummy_item(xhash_t *xhash, xhashidx idx, bool vals)
{
    if (!vals) {
        set_dummy_key(xhash, idx);
        return;
    }

    #ifdef VAL_OVERLOAD
    set_dummy_val(xhash, idx);
    return;
    #elif defined(KEY_OVERLOAD)
    set_dummy_key(xhash, idx);
    return;
    #endif
}
static inline void
set_unused_key(xhash_t *xhash, xhashidx idx)
{
    xhashidx *kvs = xhash_kvs(xhash);
    kvs[idx] = UNUSED;
}

static inline void
set_unused_val(xhash_t *xhash, xhashidx idx)
{
    xhashidx *vals = xhash_vals(xhash);
    vals[idx] = UNUSED;
}

static inline bool
val_unused(xhash_t *xhash, xhashidx idx)
{
    xhashidx *vals = xhash_vals(xhash);
    return vals[idx] == UNUSED;
}

static bool
item_unused(xhash_t *xhash, xhashidx idx, bool vals)
{
    xhashidx *kvs = xhash_kvs(xhash);
    if (!vals) {
        return kvs[idx] == UNUSED;
    }

    #if defined(VAL_OVERLOAD)
    return val_unused(xhash, idx);
    #elif defined(KEY_OVERLOAD)
    return kvs[idx] == UNUSED;
    #endif

}

static inline unsigned item_valid(xhash_t *xhash, xhashidx idx, bool vals)
{
    return !(item_dummy(xhash, idx, vals) || item_unused(xhash, idx, vals));
}
/*
static void __attribute__((unused))
assert_key(xhashidx key)
{
    assert((key != UNUSED) && (key != DUMMY));
}

static void
assert_val(xhashidx val)
{
    assert((val != UNUSED) && (val != DUMMY));
}

static inline void
assert_kv(xhashidx k, xhashidx v)
{
    #if defined(KEY_OVERLOAD)
    assert_key(k);
    #elif defined(VAL_OVERLOAD)
    assert_val(v);
    #endif
}
*/

void
xhash_init__(xhash_t *xhash, xhashidx size_shift, xhashidx minsize_shift,
		xhashidx limit, enum xhash_type type, bool vals)
{
    xhashidx nr_items = 1UL << size_shift;
    xhashidx *kvs = (xhashidx *) ((char *) xhash + sizeof(struct xhash));
    xhashidx i;

    XPTRSET(&xhash->kvs, kvs);


    if (!vals) {
        for (i=0; i < nr_items; i++)
            kvs[i] = UNUSED;
        goto out;
    }

    for (i=0; i < nr_items; i++){
        #if defined(VAL_OVERLOAD)
        kvs[nr_items + i] = UNUSED;
        #elif  defined(KEY_OVERLOAD)
        kvs[i] = UNUSED;
        #endif
    }

out:
    xhash->dummies = xhash->used = 0;
    xhash->size_shift = size_shift;
    xhash->minsize_shift = minsize_shift;
    xhash->limit = limit;
    xhash->type = type;

    ZEROSTAT(xhash->inserts);
    ZEROSTAT(xhash->deletes);
    ZEROSTAT(xhash->lookups);
    ZEROSTAT(xhash->bounces);
}

static ssize_t
get_alloc_size(xhashidx size_shift, bool vals)
{
    xhashidx nr_items = 1UL << size_shift;
    size_t keys_size = nr_items*sizeof(xhashidx);
    size_t alloc_size = vals ? keys_size<<1 : keys_size;
    return sizeof(struct xhash) + alloc_size;
}


xhash_t *
xhash_new__(xhashidx size_shift, xhashidx minsize_shift, xhashidx limit, 
		enum xhash_type type, bool vals) 
{
    struct xhash *xhash;
    xhash = xtypes_malloc(get_alloc_size(size_shift, vals));
    if (!xhash) {
	XSEGLOG("couldn't malloc\n");
	return NULL;
    }

    xhash_init__(xhash, size_shift, minsize_shift, limit, type, vals);
    
    return xhash;
}


xhash_t *
xhash_resize__(struct xhash *xhash, xhashidx new_size_shift, xhashidx new_limit,
		bool vals)
{
    return xhash_new__(new_size_shift, xhash->minsize_shift, new_limit, 
		    	xhash->type, vals);
}

int
xhash_delete__(xhash_t *xhash, xhashidx key, bool vals)
{
//    XSEGLOG("Deleting %lx", key);
    xhash_cmp_fun_t cmp_fun = types_fun[xhash->type].cmp_fun;
    xhash_hash_fun_t hash_fun = types_fun[xhash->type].hash_fun; 
    xhashidx perturb = hash_fun(key);
    xhashidx mask = xhash_size(xhash)-1;
    xhashidx idx = hash_fun(key) & mask;
    xhashidx *kvs = xhash_kvs(xhash);

    for (;;) {
        if ( item_unused(xhash, idx, vals) ){
            return -2;
        }

        if ( !item_dummy(xhash, idx, vals) && cmp_fun(kvs[idx],key)){
            INCSTAT(xhash->deletes);
            set_dummy_item(xhash, idx, vals);
            xhash->dummies++;
            //fprintf(stderr, "rm: used: %lu\n", xhash->used);
            xhash->used--;
            return 0;
        }

        INCSTAT(xhash->bounces);
        idx = ((idx<<2) + idx + 1 + perturb) & mask;
        perturb >>= PERTURB_SHIFT;
    }
}

xhashidx
xhash_grow_size_shift(xhash_t *xhash)
{
    xhashidx old_size_shift = xhash->size_shift;
    xhashidx new_size_shift;
    xhashidx u;

    u = xhash->used;
    //printf("used: %lu\n", u);
    if (u/2 + u >= ((xhashidx)1 << old_size_shift)) {
        new_size_shift = old_size_shift + 1;
    } else {
        new_size_shift = old_size_shift;
    }

    return new_size_shift;
}

xhashidx
xhash_shrink_size_shift(xhash_t *xhash)
{
    xhashidx old_size_shift = xhash->size_shift;
    xhashidx new_size_shift;
    new_size_shift = old_size_shift - 1;
    if (new_size_shift < xhash->minsize_shift) {
        new_size_shift = xhash->minsize_shift;
    }
    return new_size_shift;
}

static bool
grow_check(xhash_t *xhash)
{
    xhashidx size_shift = xhash->size_shift;
    xhashidx u = xhash->used + xhash->dummies;
    xhashidx size = (xhashidx)1UL<<size_shift;
    return ((u/2 + u) >= size) ? true : false;
}

static bool
shrink_check(xhash_t *xhash)
{
    xhashidx size_shift = xhash->size_shift;
    xhashidx size = (xhashidx)1<<size_shift;
    xhashidx u = xhash->used;
    return (4*u < size && size_shift > xhash->minsize_shift) ? true : false;
}


/**
 * Phash functions
 */

ssize_t 
xhash_get_alloc_size(xhashidx size_shift)
{
	return get_alloc_size(size_shift, true);
}

xhash_t *
xhash_new(xhashidx minsize_shift, xhashidx limit, enum xhash_type type)
{
    return xhash_new__(minsize_shift, minsize_shift, limit,  type, true);
}

void xhash_free(struct xhash *xhash)
{
    xtypes_free(xhash);
}

void xhash_init(struct xhash *xhash, xhashidx minsize_shift, xhashidx limit,
		enum xhash_type type)
{
	xhash_init__(xhash, minsize_shift, minsize_shift, limit, type, true);
}

/*
xhash_t *
xhash_grow(struct xhash *xhash)
{
    xhashidx new_size_shift = xhash_grow_size_shift(xhash);
    return xhash_resize(xhash, new_size_shift);
}

xhash_t *
xhash_shrink(struct xhash *xhash)
{
    xhashidx new_size_shift = xhash_shrink_size_shift(xhash);
    return xhash_resize(xhash, new_size_shift);
}

static inline xhash_t*
xhash_grow_check(xhash_t *xhash)
{
    if (grow_check(xhash))
        return xhash_grow(xhash);
    else 
	return NULL;
}
*/

#define PHASH_UPDATE(xhash, key, val, vals_flag)      \
{                                                     \
    xhash_cmp_fun_t cmp_fun = types_fun[xhash->type].cmp_fun;         \
    xhash_hash_fun_t hash_fun = types_fun[xhash->type].hash_fun;       \
    xhashidx size = 1UL<<(xhash->size_shift);         \
    xhashidx perturb = hash_fun(key);                           \
    xhashidx mask = size-1;                           \
    xhashidx idx = hash_fun(key) & mask;              \
    xhashidx *kvs = xhash_kvs(xhash);                 \
                                                      \
    INCSTAT(xhash->inserts);                          \
    for (;;) {                                        \
        if ( !item_valid(xhash, idx, vals_flag) ){    \
             PHUPD_SET__(xhash, idx, key, val);       \
             break;                                   \
        }                                             \
        if (cmp_fun(kvs[idx], key)){                  \
            PHUPD_UPDATE__(xhash, idx, key, val);     \
            break;                                    \
        }                                             \
                                                      \
        again: __attribute__((unused))                \
        INCSTAT(xhash->bounces);                      \
        idx = ((idx<<2) + idx + 1 + perturb) & mask;  \
        perturb >>= PERTURB_SHIFT;                    \
    }                                                 \
}

static inline void
set_val(xhash_t *p, xhashidx idx, xhashidx key, xhashidx val)
{
    xhashidx *kvs = xhash_kvs(p);
    xhashidx *vals = xhash_vals(p);
    kvs[idx] = key;
    vals[idx] = val;
    //XSEGLOG("Seting idx %llu to key: %lx, val: %lx", idx, key, val);
}

void static inline xhash_upd_set(xhash_t *p, xhashidx idx, xhashidx key, xhashidx val)
{
    xhashidx *kvs = xhash_kvs(p);
    xhashidx *vals = xhash_vals(p);
    if (item_dummy(p, idx, true))
        p->dummies--;
    p->used++;
    kvs[idx] = key;
    vals[idx] = val;
    //XSEGLOG("Seting idx %llu to key: %lx, val: %lx", idx, key, val);
}

static inline void
inc_val(xhash_t *p, xhashidx idx, xhashidx val)
{
    xhashidx *vals = xhash_vals(p);
    vals[idx] += val;
}

void xhash_insert__(struct xhash *xhash, xhashidx key, xhashidx val)
{
    //XSEGLOG("inserting %lx", key);
    //fprintf(stderr, "insert: (%lu,%lu)\n", key, val);
    #define PHUPD_UPDATE__(_p, _i, _k, _v) set_val(_p, _i, _k, _v)
    #define PHUPD_SET__(_p, _i, _k, _v)    xhash_upd_set(_p, _i, _k, _v)
    PHASH_UPDATE(xhash, key, val, true)
    #undef PHUPD_UPDATE__
    #undef PHUPD_SET__
}

int xhash_insert(struct xhash *xhash, xhashidx key, xhashidx val)
{
    if (xhash->limit && xhash->used >= xhash->limit)
	return -XHASH_ENOSPC;
    if (grow_check(xhash))
        return -XHASH_ERESIZE;
    xhash_insert__(xhash, key, val);
    return 0;
}


void xhash_freql_update__(struct xhash *xhash, xhashidx key, xhashidx val)
{
    #define PHUPD_UPDATE__(_p, _i, _k, _v) inc_val(_p, _i, _v)
    #define PHUPD_SET__(_p, _i, _k, _v)    xhash_upd_set(_p, _i, _k, _v)
    PHASH_UPDATE(xhash, key, val, true)
    #undef PHUPD_UPDATE__
    #undef PHUPD_SET__
}

int xhash_freql_update(struct xhash *xhash, xhashidx key, xhashidx val)
{
    if (grow_check(xhash))
        return -XHASH_ERESIZE;
    xhash_freql_update__(xhash, key, val);
    return 0;
}

xhash_t *
xhash_resize(xhash_t *xhash, xhashidx new_size_shift, xhashidx new_limit,
		xhash_t *new)
{
    //XSEGLOG("Resizing xhash from %llu to %llu", xhash->size_shift, new_size_shift);
    xhashidx i;
    int f = !!new;
    if (!f)
        new = xhash_new__(new_size_shift, xhash->minsize_shift, new_limit,
				xhash->type, true);
    else
        xhash_init__(new, new_size_shift, xhash->minsize_shift, new_limit,
				xhash->type, true);

    if (!new)
	    return NULL;
        
    //fprintf(stderr, "resizing: (%lu,%lu,%lu)\n", xhash->size_shift, xhash->used, xhash->dummies);
    for (i = 0; i < xhash_size(xhash); i++) {
        if (item_valid(xhash, i, true)){
            //fprintf(stderr, "rs: inserting (%lu,%lu)\n", item->k, item->v);
            xhash_insert__(new, *(xhash_kvs(xhash) + i), *(xhash_vals(xhash) + i));
        }
    }

    if (!f)
        xtypes_free(xhash);
    return new;
}

/*
 * note that his function does not modify the internal structure of the hash
 * and thus its safe to use it for updating values during a xhash_iterate()
 */
int xhash_update(struct xhash *xhash, xhashidx key, xhashidx val) {

    //fprintf(stderr, "update: (%lu,%lu)\n", key, val);
    #define PHUPD_UPDATE__(_p, _i, _k, _v) set_val(_p, _i, _k, _v)
    #define PHUPD_SET__(_p, _i, _k, _v)    goto again
    PHASH_UPDATE(xhash, key, val, true)
    #undef PHUPD_UPDATE__
    #undef PHUPD_SET__

    return 1;
}


int xhash_delete(struct xhash *xhash, xhashidx key)
{
    if (shrink_check(xhash))
	    return -XHASH_ERESIZE;
    return xhash_delete__(xhash, key, true);
}

int xhash_lookup__(xhash_t *xhash, xhashidx key, xhashidx *idx_ret, bool vals)
{
    //XSEGLOG("looking up %lx", key);
    xhash_cmp_fun_t cmp_fun = types_fun[xhash->type].cmp_fun;
    xhash_hash_fun_t hash_fun = types_fun[xhash->type].hash_fun; 
    xhashidx size_shift = xhash->size_shift;
    xhashidx size = (1UL)<<size_shift;
    xhashidx perturb = hash_fun(key);
    xhashidx mask = size-1;
    xhashidx idx = hash_fun(key) & mask;
    xhashidx *kvs = xhash_kvs(xhash);

    INCSTAT(xhash->lookups);
    for (;;) {
	//XSEGLOG("size %llu, perturb %llu idx %llu mask %llu",
	//	    size, perturb, idx, mask);		
        if ( item_unused(xhash, idx, vals) )
            return -XHASH_EEXIST;

        if ( !item_dummy(xhash, idx, vals) && cmp_fun(kvs[idx],key)){
            *idx_ret = idx;
            return 0;
        }

        INCSTAT(xhash->bounces);
        idx = ((idx<<2) + idx + 1 + perturb) & mask;
        perturb >>= PERTURB_SHIFT;
    }
}

int xhash_lookup(struct xhash *xhash, xhashidx key, xhashidx *val)
{
    xhashidx idx;
    int ret = xhash_lookup__(xhash, key, &idx, true);
    if (ret == 0) {
        xhashidx *values = xhash_vals(xhash);
        *val = values[idx];
    }
    return ret;
}

//FIXME iteration broken
void
xhash_iter_init(xhash_t *xhash, xhash_iter_t *pi)
{
    pi->cnt = pi->loc = 0;
}

int
xhash_iterate__(xhash_t *xhash, bool vals,
                xhash_iter_t *pi, xhashidx *key_ret,  xhashidx *idx_ret)
{
    xhashidx idx = pi->loc;
    xhashidx size = (xhashidx)1<<xhash->size_shift;
    xhashidx *kvs = xhash_kvs(xhash);
    INCSTAT(xhash->lookups);
    for (;;){
        if (xhash->used == pi->cnt || idx >= size)
            return 0;

        if (item_valid(xhash, idx, vals)){
            *key_ret = kvs[idx];
            *idx_ret = idx++;
            pi->loc = idx;
            pi->cnt++;
            return 1;
        }

        idx++;
    }
}

int xhash_iterate(xhash_t *xhash, xhash_iter_t *pi, xhashidx *key, xhashidx *val)
{
    xhashidx idx;
    int ret = xhash_iterate__(xhash, true, pi, key, &idx);
    if (ret) {
        xhashidx *vals = xhash_vals(xhash);
        *val = vals[idx];
    }
    return ret;
}

void xhash_print(xhash_t *xhash)
{
    xhashidx key, val;
    xhash_iter_t pi;
    int ret;

    xhash_iter_init(xhash, &pi);
    XSEGLOG("PHASH(%p):\n", xhash);
    for (;;){
        ret = xhash_iterate(xhash, &pi, &key, &val);
        if (!ret){
            break;
        }
        XSEGLOG(" 0x%017lx : 0x%017lx\n", key, val);
    }
    XSEGLOG("\n");
}

#ifdef PHASH_MAIN
#define BUFLEN 1024
void help()
{
    printf("Help:\n"
           "  insert : I <key> <val> \n"
           "  update : U <key> <val> (->v += val if exists) \n"
           "  get    : G <key>       \n"
           "  delete : D <key>       \n"
           "  size   : S             \n"
           "  print  : P             \n");
}

int main(int argc, char **argv)
{
    struct xhash *ph;
    char *s, buf[BUFLEN];
    xhashidx key, val;
    int ret;

    ph = xhash_new(2, INTEGER);

    for (;;){
        s = fgets(buf, BUFLEN-1, stdin);
        if (s == NULL){
            break;
        }

        switch (*s) {
            case 'I':
            ret = sscanf(s+1, "%lu %lu", &key, &val);
            if (ret == 2){
                xhash_insert(ph, key, val);
            }
            break;

            case 'U':
            ret = sscanf(s+1, "%lu %lu", &key, &val);
            if (ret == 2){
                xhash_freql_update(ph, key, val);
            }
            break;

            case 'G':
            ret = sscanf(s+1, "%lu", &key);
            if (ret == 1){
                ret = xhash_lookup(ph, key, &val);
                if (ret){
                    printf("%lu\n", val);
                } else {
                    printf("<None>\n");
                }
            }
            break;

            case 'D':
            ret = sscanf(s+1, "%lu", &key);
            if (ret == 1){
                xhash_delete(ph, key);
            }
            break;

            case 'S':
            printf("%lu\n", xhash_elements(ph));
            break;

            case 'P':
            xhash_print(ph);
            break;

            case '#':
            break;

            default:
            help();
            break;

        }
        fflush(stdout);
    }

    xhash_free(ph);
    return 0;
}
#endif

#if 0
/**
 * Pset functions
 */
pset_t *
pset_new(xhashidx minsize_shift)
{
    pset_t *pset;
    pset = malloc(sizeof(pset_t));
    if (!pset) {
        perror("malloc");
        exit(1);
    }
    xhash_init__(&pset->ph_, minsize_shift, false);
    return pset;
}

void
pset_init(pset_t *pset, xhashidx minsize_shift)
{
    xhash_init__(&pset->ph_, minsize_shift, false);
}

void
pset_free(pset_t *pset)
{
    xhash_tfree(&pset->ph_);
    free(pset);
}

void
pset_tfree(pset_t *pset)
{
    xhash_tfree(&pset->ph_);
}

void
pset_resize(pset_t *pset, xhashidx new_size_shift)
{
    pset_t  old;
    xhash_cp(&(old.ph_), &pset->ph_);

    xhash_resize__(&pset->ph_, new_size_shift, false);
    for (xhashidx i = 0; i < pset_size(&old); i++) {
        if (item_valid(&(old.ph_), i, false)){
            //fprintf(stderr, "rs: inserting (%lu,%lu)\n", item->k, item->v);
            pset_insert(pset, old.ph_.kvs[i]);
        }
    }
    free(old.ph_.kvs);
}

void
pset_grow(pset_t *pset)
{
    xhashidx new_size_shift = grow_size_shift(&pset->ph_);
    pset_resize(pset, new_size_shift);
}

static inline void
pset_grow_check(pset_t *pset)
{
    if (grow_check(&pset->ph_))
        pset_grow(pset);
}

void static inline pset_upd_set(xhash_t *p, xhashidx idx, xhashidx key)
{
    if (item_dummy(p, idx, false))
        p->dummies--;
    p->used++;
    p->kvs[idx] = key;
}

void pset_insert(pset_t *pset, xhashidx key)
{
    xhash_t *ph = &pset->ph_;
    assert_key(key);
    pset_grow_check(pset);
    #define PHUPD_UPDATE__(_p, _i, _k, _v) do { } while (0)
    #define PHUPD_SET__(_p, _i, _k, _v) pset_upd_set(_p, _i, _k)
    PHASH_UPDATE(ph, key, 0xdeadbabe, false)
    #undef PHUPD_UPDATE__
    #undef PHUPD_SET__
}

void
pset_shrink(pset_t *pset)
{
    xhashidx new_size_shift = shrink_size_shift(&pset->ph_);
    pset_resize(pset, new_size_shift);
}

int pset_delete(pset_t *pset, xhashidx key)
{
    if (pset->ph_.used == 0)
        return false;

    assert_key(key);
    xhashidx size_shift = pset->ph_.size_shift;
    xhashidx size = (xhashidx)1<<size_shift;
    xhashidx u = pset->ph_.used;
    if (4*u < size)
        pset_shrink(pset);
    return xhash_delete__(&pset->ph_, key, false);
}

bool pset_lookup(pset_t *pset, xhashidx key)
{
    xhashidx idx;
    return !!xhash_lookup__(&pset->ph_, key, &idx, false);
}

int pset_iterate(pset_t *pset, xhash_iter_t *pi, xhashidx *key)
{
    xhashidx idx;
    int ret = xhash_iterate__(&pset->ph_, false, pi, key, &idx);
    return ret;
}

void pset_print(pset_t *pset)
{
    xhashidx key;
    int ret;
    pset_iter_t pi;

    pset_iter_init(pset, &pi);
    printf("PSET(%p):\n", pset);
    for (;;){
        ret = pset_iterate(pset, &pi, &key);
        if (!ret){
            break;
        }
        printf(" 0x%017lx\n", key);
    }
    printf("\n");
}

#if defined(PSET_MAIN)
#define BUFLEN 1024
void help()
{
    printf("Help:\n"
           "  insert : I <key> <val> \n"
           "  get    : G <key>       \n"
           "  delete : D <key>       \n"
           "  size   : S             \n"
           "  print  : P             \n");
}

int main(int argc, char **argv)
{
    pset_t *ps;
    char *s, buf[BUFLEN];
    xhashidx key;
    int ret;

    ps = pset_new(2);

    for (;;){
        s = fgets(buf, BUFLEN-1, stdin);
        if (s == NULL){
            break;
        }

        switch (*s) {
            case 'I':
            ret = sscanf(s+1, "%lu", &key);
            if (ret == 1){
                pset_insert(ps, key);
            }
            break;

            case 'G':
            ret = sscanf(s+1, "%lu", &key);
            if (ret == 1){
                ret = pset_lookup(ps, key);
                printf("%lu -> %s\n", key, ret ? "true" : "false");
            }
            break;

            case 'D':
            ret = sscanf(s+1, "%lu", &key);
            if (ret == 1){
                pset_delete(ps, key);
            }
            break;

            case 'S':
            printf("%lu\n", pset_elements(ps));
            break;

            case 'P':
            pset_print(ps);
            break;

            case '#':
            break;

            default:
            help();
            break;

        }
        fflush(stdout);
    }

    pset_free(ps);
    return 0;
}
#endif

#endif //if 0

#ifdef __KERNEL__
#include <linux/module.h>
#include <xtypes/xhash_exports.h>
#endif

// vim:expandtab:tabstop=8:shiftwidth=4:softtabstop=4
