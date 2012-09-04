//#include <stdio.h>
//#include <stdlib.h>
//#include <assert.h>
//#include <unistd.h>
//#include <stdbool.h>

#define assert(...) 

/* python hash for C
 *  originally by gtsouk@cslab.ece.ntua.gr
 *  -- kkourt@cslab.ece.ntua.gr
 */

#include <xtypes/xhash.h>

#define UNUSED (~(ul_t)0)      /* this entry was never used */
#define DUMMY  ((~(ul_t)0)-1)  /* this entry was used, but now its empty */

//#define VAL_OVERLOAD
//#define KEY_OVERLOAD
//#define NO_OVERLOAD /* use separate bitarray -- not implemented */

#define PERTURB_SHIFT 5

static inline void
set_dummy_key(xhash_t *xhash, ul_t idx)
{
    ul_t *kvs = xhash_kvs(xhash);
    kvs[idx] = DUMMY;
}

static inline void
set_dummy_val(xhash_t *xhash, ul_t idx)
{
    ul_t *vals = xhash_vals(xhash);
    vals[idx] = DUMMY;
}

static bool
item_dummy(xhash_t *xhash, ul_t idx, bool vals)
{
    bool ret;
    ul_t *pvals;
    ul_t *kvs = xhash_kvs(xhash);

    if (!vals) {
        ret = (kvs[idx] == DUMMY);
    } else {
        #if defined(VAL_OVERLOAD)
        assert(vals);
        pvals = xhash_vals(xhash);
        ret = (pvals[idx] == DUMMY);
        #elif defined(KEY_OVERLOAD)
        ret = (kvs[idx] == DUMMY);
        #endif
    }
    return ret;

}

static void set_dummy_item(xhash_t *xhash, ul_t idx, bool vals)
{
    if (!vals) {
        set_dummy_key(xhash, idx);
        return;
    }

    #ifdef VAL_OVERLOAD
    assert(vals);
    set_dummy_val(xhash, idx);
    return;
    #elif defined(KEY_OVERLOAD)
    set_dummy_key(xhash, idx);
    return;
    #endif
}
static inline void
set_unused_key(xhash_t *xhash, ul_t idx)
{
    ul_t *kvs = xhash_kvs(xhash);
    kvs[idx] = UNUSED;
}

static inline void
set_unused_val(xhash_t *xhash, ul_t idx)
{
    ul_t *vals = xhash_vals(xhash);
    vals[idx] = UNUSED;
}

static inline bool
val_unused(xhash_t *xhash, ul_t idx)
{
    ul_t *vals = xhash_vals(xhash);
    return vals[idx] == UNUSED;
}

static bool
item_unused(xhash_t *xhash, ul_t idx, bool vals)
{
    ul_t *kvs = xhash_kvs(xhash);
    if (!vals) {
        return kvs[idx] == UNUSED;
    }

    #if defined(VAL_OVERLOAD)
    assert(vals);
    return val_unused(xhash, idx);
    #elif defined(KEY_OVERLOAD)
    return kvs[idx] == UNUSED;
    #endif

}

static inline unsigned item_valid(xhash_t *xhash, ul_t idx, bool vals)
{
    return !(item_dummy(xhash, idx, vals) || item_unused(xhash, idx, vals));
}

static void __attribute__((unused))
assert_key(ul_t key)
{
    assert((key != UNUSED) && (key != DUMMY));
}

static void
assert_val(ul_t val)
{
    assert((val != UNUSED) && (val != DUMMY));
}

static inline void
assert_kv(ul_t k, ul_t v)
{
    #if defined(KEY_OVERLOAD)
    assert_key(k);
    #elif defined(VAL_OVERLOAD)
    assert_val(v);
    #endif
}

void
xhash_init__(xhash_t *xhash, ul_t size_shift, ul_t minsize_shift, bool vals)
{
    ul_t nr_items = 1UL << size_shift;
    ul_t *kvs = (ul_t *) ((char *) xhash + sizeof(struct xhash));
    ul_t i;

    XPTRSET(&xhash->kvs, kvs);

    
    if (!vals) {
        for (i=0; i < nr_items; i++)
            kvs[i] = UNUSED;
        goto out;
    }

    for (i=0; i < nr_items; i++){
        #if defined(VAL_OVERLOAD)
        assert(vals);
        kvs[nr_items + i] = UNUSED;
        #elif  defined(KEY_OVERLOAD)
        kvs[i] = UNUSED;
        #endif
    }

out:
    xhash->dummies = xhash->used = 0;
    xhash->size_shift = size_shift;
    xhash->minsize_shift = minsize_shift;

    ZEROSTAT(xhash->inserts);
    ZEROSTAT(xhash->deletes);
    ZEROSTAT(xhash->lookups);
    ZEROSTAT(xhash->bounces);
}

static ssize_t
get_alloc_size(ul_t size_shift, bool vals)
{
    ul_t nr_items = 1UL << size_shift;
    size_t keys_size = nr_items*sizeof(ul_t);
    size_t alloc_size = vals ? keys_size<<1 : keys_size;
    return sizeof(struct xhash) + alloc_size;
}


xhash_t *
xhash_new__(ul_t size_shift, ul_t minsize_shift, bool vals) {
    struct xhash *xhash;
    xhash = xtypes_malloc(get_alloc_size(size_shift, vals));
    if (!xhash) {
	XSEGLOG("couldn't malloc\n");
	return NULL;
    }

    xhash_init__(xhash, size_shift, minsize_shift, vals);
    
    return xhash;
}


xhash_t *
xhash_resize__(struct xhash *xhash, ul_t new_size_shift, bool vals)
{
    return xhash_new__(new_size_shift, xhash->minsize_shift, vals);
}

int
xhash_delete__(xhash_t *xhash, ul_t key, bool vals)
{
    ul_t perturb = key;
    ul_t mask = xhash_size(xhash)-1;
    ul_t idx = key & mask;
    ul_t *kvs = xhash_kvs(xhash);

    for (;;) {
        if ( item_unused(xhash, idx, vals) ){
            assert(0);
            return -2;
        }

        if ( !item_dummy(xhash, idx, vals) && kvs[idx] == key){
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

ul_t
grow_size_shift(xhash_t *xhash)
{
    ul_t old_size_shift = xhash->size_shift;
    ul_t new_size_shift;
    ul_t u;

    u = xhash->used;
    //printf("used: %lu\n", u);
    if (u/2 + u >= ((ul_t)1 << old_size_shift)) {
        new_size_shift = old_size_shift + 1;
    } else {
        new_size_shift = old_size_shift;
    }

    return new_size_shift;
}

ul_t
shrink_size_shift(xhash_t *xhash)
{
    ul_t old_size_shift = xhash->size_shift;
    ul_t new_size_shift;
    new_size_shift = old_size_shift - 1;
    if (new_size_shift < xhash->minsize_shift) {
        new_size_shift = xhash->minsize_shift;
    }
    return new_size_shift;
}

static bool
grow_check(xhash_t *xhash)
{
    ul_t size_shift = xhash->size_shift;
    ul_t u = xhash->used + xhash->dummies;
    ul_t size = (ul_t)1UL<<size_shift;
    return ((u/2 + u) >= size) ? true : false;
}

static bool
shrink_check(xhash_t *xhash)
{
    ul_t size_shift = xhash->size_shift;
    ul_t size = (ul_t)1<<size_shift;
    ul_t u = xhash->used;
    return (4*u < size && size_shift >= xhash->minsize_shift) ? true : false;
}


/**
 * Phash functions
 */

ssize_t 
xhash_get_alloc_size(ul_t size_shift)
{
	return get_alloc_size(size_shift, true);
}

xhash_t *
xhash_new(ul_t minsize_shift)
{
    return xhash_new__(minsize_shift, minsize_shift, true);
}

void xhash_free(struct xhash *xhash)
{
    xtypes_free(xhash);
}

void xhash_init(struct xhash *xhash, ul_t minsize_shift)
{
	xhash_init__(xhash, minsize_shift, minsize_shift, true);
}

/*
xhash_t *
xhash_grow(struct xhash *xhash)
{
    ul_t new_size_shift = grow_size_shift(xhash);
    return xhash_resize(xhash, new_size_shift);
}

xhash_t *
xhash_shrink(struct xhash *xhash)
{
    ul_t new_size_shift = shrink_size_shift(xhash);
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
    ul_t size = 1UL<<(xhash->size_shift);             \
    ul_t perturb = key;                               \
    ul_t mask = size-1;                               \
    ul_t idx = key & mask;                            \
    ul_t *kvs = xhash_kvs(xhash);                      \
                                                      \
    INCSTAT(xhash->inserts);                          \
    for (;;) {                                        \
        if ( !item_valid(xhash, idx, vals_flag) ){    \
             PHUPD_SET__(xhash, idx, key, val);       \
             break;                                   \
        }                                             \
        if (kvs[idx] == key){                  \
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
set_val(xhash_t *p, ul_t idx, ul_t key, ul_t val)
{
    ul_t *kvs = xhash_kvs(p);
    ul_t *vals = xhash_vals(p);
    kvs[idx] = key;
    vals[idx] = val;
}

void static inline xhash_upd_set(xhash_t *p, ul_t idx, ul_t key, ul_t val)
{
    ul_t *kvs = xhash_kvs(p);
    ul_t *vals = xhash_vals(p);
    if (item_dummy(p, idx, true))
        p->dummies--;
    p->used++;
    kvs[idx] = key;
    vals[idx] = val;
}

static inline void
inc_val(xhash_t *p, ul_t idx, ul_t val)
{
    ul_t *vals = xhash_vals(p);
    vals[idx] += val;
}

void xhash_insert__(struct xhash *xhash, ul_t key, ul_t val)
{
    //fprintf(stderr, "insert: (%lu,%lu)\n", key, val);
    assert_kv(key, val);
    #define PHUPD_UPDATE__(_p, _i, _k, _v) set_val(_p, _i, _k, _v)
    #define PHUPD_SET__(_p, _i, _k, _v)    xhash_upd_set(_p, _i, _k, _v)
    PHASH_UPDATE(xhash, key, val, true)
    #undef PHUPD_UPDATE__
    #undef PHUPD_SET__
}

int xhash_insert(struct xhash *xhash, ul_t key, ul_t val)
{
    if (grow_check(xhash))
        return -XHASH_ERESIZE;
    xhash_insert__(xhash, key, val);
    return 0;
}


void xhash_freql_update__(struct xhash *xhash, ul_t key, ul_t val)
{
    assert_kv(key, val);
    assert_val(val);
    #define PHUPD_UPDATE__(_p, _i, _k, _v) inc_val(_p, _i, _v)
    #define PHUPD_SET__(_p, _i, _k, _v)    xhash_upd_set(_p, _i, _k, _v)
    PHASH_UPDATE(xhash, key, val, true)
    #undef PHUPD_UPDATE__
    #undef PHUPD_SET__
}

int xhash_freql_update(struct xhash *xhash, ul_t key, ul_t val)
{
    assert_kv(key, val);
    assert_val(val);
    if (grow_check(xhash))
        return -XHASH_ERESIZE;
    xhash_freql_update__(xhash, key, val);
    return 0;
}

xhash_t *
xhash_resize(xhash_t *xhash, ul_t new_size_shift, xhash_t *new)
{
    ul_t i;
    int f = !!new;
    if (!f)
        new = xhash_new__(new_size_shift, xhash->minsize_shift, true);
    else
        xhash_init__(new, new_size_shift, xhash->minsize_shift, true);

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
int xhash_update(struct xhash *xhash, ul_t key, ul_t val) {

    //fprintf(stderr, "update: (%lu,%lu)\n", key, val);
    assert_kv(key, val);
    #define PHUPD_UPDATE__(_p, _i, _k, _v) set_val(_p, _i, _k, _v)
    #define PHUPD_SET__(_p, _i, _k, _v)    goto again
    PHASH_UPDATE(xhash, key, val, true)
    #undef PHUPD_UPDATE__
    #undef PHUPD_SET__

    return 1;
}


int xhash_delete(struct xhash *xhash, ul_t key)
{
    #if defined(KEY_OVERLOAD)
    assert_key(key);
    #endif
    if (shrink_check(xhash))
	    return -XHASH_ERESIZE;
    return xhash_delete__(xhash, key, true);
}

int xhash_lookup__(xhash_t *xhash, ul_t key, ul_t *idx_ret, bool vals)
{
    #if defined(KEY_OVERLOAD)
    assert_key(key);
    #endif

    ul_t size_shift = xhash->size_shift;
    ul_t size = (ul_t)1<<size_shift;
    ul_t perturb = key;
    ul_t mask = size-1;
    ul_t idx = key & mask;
    ul_t *kvs = xhash_kvs(xhash);

    INCSTAT(xhash->lookups);
    for (;;) {
        if ( item_unused(xhash, idx, vals) )
            return -XHASH_EEXIST;

        if ( !item_dummy(xhash, idx, vals) && kvs[idx] == key){
            *idx_ret = idx;
            return 0;
        }

        INCSTAT(xhash->bounces);
        idx = ((idx<<2) + idx + 1 + perturb) & mask;
        perturb >>= PERTURB_SHIFT;
    }
}

int xhash_lookup(struct xhash *xhash, ul_t key, ul_t *val)
{
    ul_t idx;
    int ret = xhash_lookup__(xhash, key, &idx, true);
    if (ret == 0) {
        ul_t *values = xhash_vals(xhash);
        *val = values[idx];
    }
    return ret;
}

void
xhash_iter_init(xhash_t *xhash, xhash_iter_t *pi)
{
    pi->cnt = pi->loc = 0;
}

int
xhash_iterate__(xhash_t *xhash, bool vals,
                xhash_iter_t *pi, ul_t *key_ret,  ul_t *idx_ret)
{
    ul_t idx = pi->loc;
    ul_t size = (ul_t)1<<xhash->size_shift;
    ul_t *kvs = xhash_kvs(xhash);
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

int xhash_iterate(xhash_t *xhash, xhash_iter_t *pi, ul_t *key, ul_t *val)
{
    ul_t idx;
    int ret = xhash_iterate__(xhash, true, pi, key, &idx);
    if (ret) {
        ul_t *vals = xhash_vals(xhash);
        *val = vals[idx];
    }
    return ret;
}

void xhash_print(xhash_t *xhash)
{
    ul_t key, val;
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
    ul_t key, val;
    int ret;

    ph = xhash_new(2);

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
pset_new(ul_t minsize_shift)
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
pset_init(pset_t *pset, ul_t minsize_shift)
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
pset_resize(pset_t *pset, ul_t new_size_shift)
{
    pset_t  old;
    xhash_cp(&(old.ph_), &pset->ph_);

    xhash_resize__(&pset->ph_, new_size_shift, false);
    for (ul_t i = 0; i < pset_size(&old); i++) {
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
    ul_t new_size_shift = grow_size_shift(&pset->ph_);
    pset_resize(pset, new_size_shift);
}

static inline void
pset_grow_check(pset_t *pset)
{
    if (grow_check(&pset->ph_))
        pset_grow(pset);
}

void static inline pset_upd_set(xhash_t *p, ul_t idx, ul_t key)
{
    if (item_dummy(p, idx, false))
        p->dummies--;
    p->used++;
    p->kvs[idx] = key;
}

void pset_insert(pset_t *pset, ul_t key)
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
    ul_t new_size_shift = shrink_size_shift(&pset->ph_);
    pset_resize(pset, new_size_shift);
}

int pset_delete(pset_t *pset, ul_t key)
{
    if (pset->ph_.used == 0)
        return false;

    assert_key(key);
    ul_t size_shift = pset->ph_.size_shift;
    ul_t size = (ul_t)1<<size_shift;
    ul_t u = pset->ph_.used;
    if (4*u < size)
        pset_shrink(pset);
    return xhash_delete__(&pset->ph_, key, false);
}

bool pset_lookup(pset_t *pset, ul_t key)
{
    ul_t idx;
    return !!xhash_lookup__(&pset->ph_, key, &idx, false);
}

int pset_iterate(pset_t *pset, xhash_iter_t *pi, ul_t *key)
{
    ul_t idx;
    int ret = xhash_iterate__(&pset->ph_, false, pi, key, &idx);
    return ret;
}

void pset_print(pset_t *pset)
{
    ul_t key;
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
    ul_t key;
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
// vim:expandtab:tabstop=8:shiftwidth=4:softtabstop=4
