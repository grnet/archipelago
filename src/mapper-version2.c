/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <mapper.h>
#include <mapper-version2.h>
#include <xseg/xseg.h>
#include <stdlib.h>
#include <asm/byteorder.h>


/* Must be a power of 2, as the blocksize */
#define v2_chunksize (512*1024)

/* v2 functions */

static uint32_t get_map_block_name(char *target, struct map *map,
                                   uint64_t block_id)
{
    uint32_t targetlen;
    uint64_t be_block_id = __cpu_to_be64(block_id);
    char buf[sizeof(be_block_id) * 2 + 1];

    hexlify((unsigned char *) &be_block_id, sizeof(be_block_id), buf);
    buf[2 * sizeof(block_id)] = 0;
    sprintf(target, "%s_%s", map->volume, buf);
    targetlen = map->volumelen + 1 + (sizeof(be_block_id) * 2);

    return targetlen;
}

static uint32_t get_chunk_size(struct map *map)
{
    return (map->blocksize < v2_chunksize) ? map->blocksize : v2_chunksize;
}

static int get_block_id(struct map *map, uint64_t idx)
{
    return (idx * v2_objectsize_in_map) / map->blocksize;
}

static uint64_t get_offset_in_block(struct map *map, uint64_t idx)
{
    uint64_t objects_in_block = map->blocksize / v2_objectsize_in_map;
    return ((idx % objects_in_block) * v2_objectsize_in_map) % map->blocksize;
}

static uint32_t get_offset_in_chunk(struct map *map, uint64_t offset)
{
    uint32_t chunksize = get_chunk_size(map);
    /* since blocksize and chunksize are both power of two, the following is
     * equivalent to:
     * offset_in_block = offset % map->blocksize;
     * offset_in_chunk = offset % chunksize;
     */
    return offset % chunksize;
}

struct chunk {
    char target[XSEG_MAX_TARGETLEN + 1];
    uint32_t targetlen;
    uint64_t start;
    uint64_t nr;
};


static int split_to_chunks(struct map *map, uint64_t start, uint64_t nr,
                           struct chunk **chunks)
{
    uint32_t i;
    int nr_chunks;
    uint64_t processed;
    struct chunk *chunk;
    int blockid;
    uint64_t offset_in_block, objects_in_block, objects_in_chunk, obj;
    uint32_t chunksize = get_chunk_size(map);

    if (!nr) {
        *chunks = 0;
        return 0;
    }


    objects_in_block = map->blocksize / v2_objectsize_in_map;
    objects_in_chunk = chunksize / v2_objectsize_in_map;

    nr_chunks = 0;
    obj = start;
    do {
        nr_chunks++;
        offset_in_block = obj % objects_in_block;
        if (offset_in_block + objects_in_chunk < objects_in_block) {
            obj += objects_in_chunk;
        } else {
            obj += objects_in_block - offset_in_block;
        }
    } while (obj < nr);

    chunk = calloc(nr_chunks, sizeof(struct chunk));
    *chunks = chunk;
    if (!chunk) {
        return -ENOMEM;
    }


    i = 0;
    obj = start;
    do {
        blockid = get_block_id(map, obj);
        chunk[i].targetlen = get_map_block_name(chunk[i].target, map, blockid);
        chunk[i].start = obj;
        offset_in_block = obj % objects_in_block;
        if (nr > objects_in_chunk) {
            if (offset_in_block + objects_in_chunk > objects_in_block) {
                chunk[i].nr = objects_in_block - offset_in_block;
            } else {
                chunk[i].nr = objects_in_chunk;
            }
        } else {
            if (offset_in_block + nr > objects_in_block) {
                chunk[i].nr = objects_in_block - offset_in_block;
            } else {
                chunk[i].nr = nr;
            }
        }
        obj += chunk[i].nr;
        nr -= chunk[i].nr;
        i++;
    } while (nr > 0);


    return nr_chunks;
}


static int read_object_v2(struct map_node *mn, unsigned char *buf)
{
    char c = buf[0];
    int len = 0;
    uint32_t objectlen;

    mn->flags = 0;
    mn->flags |= MF_OBJECT_WRITABLE & c;
    mn->flags |= MF_OBJECT_ARCHIP & c;
    mn->flags |= MF_OBJECT_ZERO & c;
    mn->flags |= MF_OBJECT_DELETED & c;
    objectlen = *(typeof(objectlen) *) (buf + 1);
    mn->objectlen = objectlen;
    if (mn->objectlen > v2_max_objectlen) {
        XSEGLOG2(&lc, D, "mn: %p, buf: %p, objectlen: %u", mn, buf,
                 mn->objectlen);
        XSEGLOG2(&lc, E, "Invalid object len %u", mn->objectlen);
        return -1;
    }
//      if (mn->flags & MF_OBJECT_ARCHIP){
//              strcpy(mn->object, MAPPER_PREFIX);
//              len += MAPPER_PREFIX_LEN;
//      }
    memcpy(mn->object + len, buf + sizeof(objectlen) + 1, mn->objectlen);
    mn->object[mn->objectlen] = 0;

    return 0;
}

/* Fill a buffer representing an object on disk from a given map node */
static void object_to_map_v2(unsigned char *buf, struct map_node *mn)
{
    struct v2_object_on_disk *object;

    //_Static_assert(typeof(mn->objectlen), typeof(object->objectlen));
    if (mn->objectlen > v2_max_objectlen) {
        XSEGLOG2(&lc, E, "Invalid object len %u", mn->objectlen);
        mn->objectlen = v2_max_objectlen;
    }

    memset(buf, 0, v2_objectsize_in_map);
    object = (struct v2_object_on_disk *) buf;

    object->flags = 0;
    object->flags |= mn->flags & MF_OBJECT_WRITABLE;
    object->flags |= mn->flags & MF_OBJECT_ARCHIP;
    object->flags |= mn->flags & MF_OBJECT_ZERO;
    object->flags |= mn->flags & MF_OBJECT_DELETED;


    object->objectlen = mn->objectlen;
    memcpy(object->object, mn->object, object->objectlen);
}

static struct xseg_request *prepare_write_chunk(struct peer_req *pr,
                                                struct map *map,
                                                struct chunk *chunk)
{
    struct xseg_request *req;
    uint64_t limit, obj, pos, datalen;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    char *data;
    struct map_node *mn;

    datalen = v2_chunksize;

    XSEGLOG2(&lc, D, "Starting for map %s, start: %llu, nr: %llu "
             "offset:%llu, size: %llu",
             map->volume, chunk->start, chunk->nr,
             get_offset_in_block(map, chunk->start),
             v2_objectsize_in_map * chunk->nr);

    req = get_request(pr, mapper->mbportno, chunk->target, chunk->targetlen,
                      datalen);
    if (!req) {
        XSEGLOG2(&lc, E, "Cannot get request");
        return NULL;
    }

    req->op = X_WRITE;
    req->offset = get_offset_in_block(map, chunk->start);
    req->size = v2_objectsize_in_map * chunk->nr;

    data = xseg_get_data(peer->xseg, req);
    //assert chunk->size > v2_objectsize_in_map

    XSEGLOG2(&lc, D, "Start: %llu, nr: %llu", chunk->start, chunk->nr);
    pos = 0;
    for (obj = chunk->start; obj < chunk->start + chunk->nr; obj++) {
        mn = &map->objects[obj];
        object_to_map_v2((unsigned char *) (data + pos), mn);
        pos += v2_objectsize_in_map;
    }

    return req;

}

static struct xseg_request *prepare_load_chunk(struct peer_req *pr,
                                               struct map *map,
                                               struct chunk *chunk)
{
    struct xseg_request *req;
    uint64_t limit, obj, pos, datalen;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    char *data;
    struct map_node *mn;
    uint64_t size, offset;
    uint64_t offset_in_first_object;

    size = v2_objectsize_in_map * chunk->nr;
    offset = get_offset_in_block(map, chunk->start);
    //chunksize will be at most v2_chunksize
    datalen = v2_chunksize;

    XSEGLOG2(&lc, D, "Starting for map %s, start: %llu, nr: %llu, "
             "offset:%llu, size: %llu",
             map->volume, chunk->start, chunk->nr, offset, size);

    req = get_request(pr, mapper->mbportno, chunk->target, chunk->targetlen,
                      datalen);
    if (!req) {
        XSEGLOG2(&lc, E, "Cannot get request");
        return NULL;
    }

    req->op = X_READ;
    req->offset = offset;
    req->size = size;

    return req;

}

struct xseg_request *prepare_write_objects_v2(struct peer_req *pr,
                                              struct map *map, uint64_t start,
                                              uint64_t nr)
{
    struct chunk *chunks;
    int nr_chunks;

    nr_chunks = split_to_chunks(map, start, nr, &chunks);
    if (nr_chunks != 1) {
        XSEGLOG2(&lc, E, "Map %s, start: %llu, nr: %llu return %d chunks",
                 map->volume, start, nr, nr_chunks);
        return NULL;
    }

    return prepare_write_chunk(pr, map, chunks);
}

static struct xseg_request *prepare_write_object_v2(struct peer_req *pr,
                                                    struct map *map,
                                                    struct map_node *mn)
{
    struct peerd *peer = pr->peer;
    char *data;
    struct xseg_request *req;

    req = prepare_write_objects_v2(pr, map, mn->objectidx, 1);
    if (!req) {
        return NULL;
    }
    data = xseg_get_data(peer->xseg, req);
    object_to_map_v2((unsigned char *) data, mn);
    return req;
}


int read_map_objects_v2(struct map *map, unsigned char *data, uint64_t start,
                        uint64_t nr)
{
    int r;
    struct map_node *map_node;
    uint64_t i;
    uint64_t pos = 0;

    if (start + nr > map->nr_objs) {
        return -1;
    }

    if (!map->objects) {
        XSEGLOG2(&lc, D, "Allocating %llu nr_objs for size %llu",
                 map->nr_objs, map->size);
        map_node = calloc(map->nr_objs, sizeof(struct map_node));
        if (!map_node) {
            XSEGLOG2(&lc, E, "Cannot allocate mem for %llu objects",
                     map->nr_objs);
            return -1;
        }
        map->objects = map_node;
        r = initialize_map_objects(map);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot initialize map objects for map %s",
                     map->volume);
            goto out_free;
        }
    }

    map_node = map->objects;

    for (i = start; i < nr; i++) {
        r = read_object_v2(&map_node[i], data + pos);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Map %s: Could not read object %llu",
                     map->volume, i);
            goto out_free;
        }
        pos += v2_objectsize_in_map;
    }
    return 0;

  out_free:
    free(map->objects);
    map->objects = NULL;
    return -1;
}

static int read_map_v2(struct map *m, unsigned char *data)
{
    /* totally unsafe */
    return read_map_objects_v2(m, data, 0, m->nr_objs);
}

static void delete_map_data_v2_cb(struct peer_req *pr,
                                  struct xseg_request *req)
{
    struct mapper_io *mio = __get_mapper_io(pr);

    if (req->state & XS_FAILED) {
        mio->err = 1;
        XSEGLOG2(&lc, E, "Request failed");
    }

    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;
}


static int __delete_map_data_v2(struct peer_req *pr, struct map *map)
{
    int r, i;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;
    char target[v2_max_objectlen];
    uint32_t targetlen, blockid;
    uint64_t objects_in_block, obj;

    objects_in_block = map->blocksize / v2_objectsize_in_map;
    for (obj = 0; obj < map->nr_objs; obj += objects_in_block) {
        blockid = get_block_id(map, obj);
        targetlen = get_map_block_name(target, map, blockid);
        req = get_request(pr, mapper->mbportno, target, targetlen, 0);
        if (!req) {
            XSEGLOG2(&lc, E, "Cannot get request");
            goto out_err;
        }
        req->op = X_DELETE;
        req->offset = 0;
        req->size = 0;
        XSEGLOG2(&lc, D, "Deleting %s(%u)", target, targetlen);
        r = send_request(pr, req);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot send request");
            goto out_put;
        }
        mio->pending_reqs++;
    }
    return 0;

  out_put:
    put_request(pr, req);
  out_err:
    mio->err = 1;
    return -1;
}

static int delete_map_data_v2(struct peer_req *pr, struct map *map)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    mio->cb = delete_map_data_v2_cb;

    r = __delete_map_data_v2(pr, map);
    if (r < 0) {
        mio->err = 1;
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    mio->priv = NULL;
    mio->cb = NULL;
    return (mio->err ? -1 : 0);
}

static void write_objects_v2_cb(struct peer_req *pr, struct xseg_request *req)
{
    struct mapper_io *mio = __get_mapper_io(pr);

    if (req->state & XS_FAILED) {
        mio->err = 1;
        XSEGLOG2(&lc, E, "Request failed");
        goto out;
    }

    if (req->serviced != req->size) {
        mio->err = 1;
        XSEGLOG2(&lc, E, "Serviced != size");
        goto out;
    }

  out:
    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;
}

static int __write_objects_v2(struct peer_req *pr, struct map *map,
                              uint64_t start, uint64_t nr)
{
    int r;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;
    struct chunk *chunks;
    int nr_chunks, i;

    XSEGLOG2(&lc, D, "Writing objects for %s: start: %llu, nr: %llu",
             map->volume, start, nr);
    if (start + nr > map->nr_objs) {
        XSEGLOG2(&lc, E, "Attempting to write beyond nr_objs");
        return -1;
    }

    nr_chunks = split_to_chunks(map, start, nr, &chunks);

    if (nr_chunks < 0) {
        goto out_err;
    }

    for (i = 0; i < nr_chunks; i++) {
        req = prepare_write_chunk(pr, map, &chunks[i]);
        if (!req) {
            goto out_free;

        }
        XSEGLOG2(&lc, D, "Writing chunk %s(%u) , start: %llu, nr :%llu",
                 chunks[i].target, chunks[i].targetlen, chunks[i].start,
                 chunks[i].nr);
        r = send_request(pr, req);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot send request");
            goto out_put;
        }
        mio->pending_reqs++;
    }

    free(chunks);
    return 0;

  out_put:
    put_request(pr, req);
  out_free:
    free(chunks);
  out_err:
    mio->err = 1;
    return -1;
}

static int write_objects_v2(struct peer_req *pr, struct map *map,
                            uint64_t start, uint64_t nr)
{
    int r;
    //unsigned char *buf;
    struct mapper_io *mio = __get_mapper_io(pr);
    mio->cb = write_objects_v2_cb;

    r = __write_objects_v2(pr, map, start, nr);
    if (r < 0) {
        mio->err = 1;
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    mio->priv = NULL;
    mio->cb = NULL;
    return (mio->err ? -1 : 0);
}

static int write_map_data_v2(struct peer_req *pr, struct map *map)
{
    return write_objects_v2(pr, map, 0, map->nr_objs);
}

static void load_map_data_v2_cb(struct peer_req *pr, struct xseg_request *req)
{
    char *data;
    unsigned char *buf;
    struct mapper_io *mio = __get_mapper_io(pr);
    struct peerd *peer = pr->peer;
    buf = (unsigned char *) __get_node(mio, req);

    XSEGLOG2(&lc, I, "Callback of req %p, buf: %p", req, buf);

    //buf = (unsigned char *)mio->priv;
    if (!buf) {
        XSEGLOG2(&lc, E, "Cannot get load buffer");
        mio->err = 1;
        goto out;
    }

    if (req->state & XS_FAILED) {
        mio->err = 1;
        XSEGLOG2(&lc, E, "Request failed");
        goto out;
    }

    if (req->serviced != req->size) {
        mio->err = 1;
        XSEGLOG2(&lc, E, "Serviced != size");
        goto out;
    }

    data = xseg_get_data(peer->xseg, req);
    XSEGLOG2(&lc, D, "Memcpy %llu to %p from (%p)", req->serviced, buf, data);
    memcpy(buf, data, req->serviced);

  out:
    __set_node(mio, req, NULL);
    put_request(pr, req);
    mio->pending_reqs--;
    signal_pr(pr);
    return;
}

static int __load_map_objects_v2(struct peer_req *pr, struct map *map,
                                 uint64_t start, uint64_t nr,
                                 unsigned char *buf)
{
    int r;
    struct peerd *peer = pr->peer;
    struct mapperd *mapper = __get_mapperd(peer);
    struct mapper_io *mio = __get_mapper_io(pr);
    struct xseg_request *req;
    struct chunk *chunk;
    int nr_chunks, i;

    unsigned char *obuf = buf;

    if (start + nr > map->nr_objs) {
        XSEGLOG2(&lc, E, "Attempting to load beyond nr_objs");
        goto out_err;
    }

    nr_chunks = split_to_chunks(map, start, nr, &chunk);
    if (nr_chunks < 0) {
        return -1;
    }

    for (i = 0; i < nr_chunks; i++) {
        req = prepare_load_chunk(pr, map, &chunk[i]);
        if (!req) {
            XSEGLOG2(&lc, E, "Cannot get request");
            goto out_free;
        }
        XSEGLOG2(&lc, D, "Reading chunk %s(%u) , start %llu, nr :%llu",
                 chunk[i].target, chunk[i].targetlen,
                 chunk[i].start, chunk[i].nr);
        r = __set_node(mio, req, (struct map_node *) (buf));
        XSEGLOG2(&lc, D, "Send buf: %p, offset from start: %d, "
                 "nr_objs: %d", buf, buf - obuf,
                 (buf - obuf) / v2_objectsize_in_map);
        buf += chunk[i].nr * v2_objectsize_in_map;
        XSEGLOG2(&lc, D, "Next buf: %p, offset from start: %d, "
                 "nr_objs: %d", buf, buf - obuf,
                 (buf - obuf) / v2_objectsize_in_map);
        r = send_request(pr, req);
        if (r < 0) {
            XSEGLOG2(&lc, E, "Cannot send request");
            goto out_put;
        }
        mio->pending_reqs++;
    }

    free(chunk);
    return 0;

  out_put:
    put_request(pr, req);
  out_free:
    free(chunk);
  out_err:
    mio->err = 1;
    return -1;
}

static int load_map_objects_v2(struct peer_req *pr, struct map *map,
                               uint64_t start, uint64_t nr)
{
    int r;
    unsigned char *buf;
    struct mapper_io *mio = __get_mapper_io(pr);
    uint32_t rem;

    if (map->flags & MF_MAP_DELETED) {
        XSEGLOG2(&lc, I, "Map deleted. Ignoring loading objects");
        return 0;
    }

    buf = calloc(nr, sizeof(unsigned char) * v2_objectsize_in_map);
    if (!buf) {
        XSEGLOG2(&lc, E, "Cannot allocate memory");
        return -1;
    }

    mio->priv = buf;
    mio->cb = load_map_data_v2_cb;
    XSEGLOG2(&lc, D, "Allocated buf: %p for %llu objs", buf, nr);

    r = __load_map_objects_v2(pr, map, start, nr, buf);
    if (r < 0) {
        mio->err = 1;
    }

    if (mio->pending_reqs > 0) {
        wait_on_pr(pr, mio->pending_reqs > 0);
    }

    if (mio->err) {
        XSEGLOG2(&lc, E, "Error issuing load request");
        goto out;
    }
    XSEGLOG2(&lc, D, "Loaded mapdata. Proceed to reading");
    r = read_map_objects_v2(map, buf, start, nr);
    if (r < 0) {
        mio->err = 1;
    }
  out:
    free(buf);
    mio->priv = NULL;
    mio->cb = NULL;
    return (mio->err ? -1 : 0);
}

static int load_map_data_v2(struct peer_req *pr, struct map *map)
{
    return load_map_objects_v2(pr, map, 0, map->nr_objs);
}

struct map_ops v2_ops = {
    .object_to_map = object_to_map_v2,
    .read_object = read_object_v2,
    .prepare_write_object = prepare_write_object_v2,
    .load_map_data = load_map_data_v2,
    .write_map_data = write_map_data_v2,
    .delete_map_data = delete_map_data_v2
};

void write_map_header_v2(struct map *map, struct v2_header_struct *v2_hdr)
{
    v2_hdr->signature = __cpu_to_be32(MAP_SIGNATURE);
    v2_hdr->version = __cpu_to_be32(MAP_V2);
    v2_hdr->size = __cpu_to_be64(map->size);
    v2_hdr->blocksize = __cpu_to_be32(map->blocksize);
    v2_hdr->flags = __cpu_to_be32(map->flags);
    v2_hdr->epoch = __cpu_to_be64(map->epoch);
}

int read_map_header_v2(struct map *map, struct v2_header_struct *v2_hdr)
{
    int r;
    uint32_t version = __be32_to_cpu(v2_hdr->version);
    if (version != MAP_V2) {
        return -1;
    }
    map->version = version;
    map->signature = __be32_to_cpu(v2_hdr->signature);
    map->size = __be64_to_cpu(v2_hdr->size);
    map->blocksize = __be32_to_cpu(v2_hdr->blocksize);
    //FIXME check each flag seperately
    map->flags = __be32_to_cpu(v2_hdr->flags);
    map->epoch = __be64_to_cpu(v2_hdr->epoch);
    /* sanitize flags */
    //map->flags &= MF_MAP_SANITIZE;
    map->nr_objs = calc_map_obj(map);
    map->mops = &v2_ops;

    return 0;
}
