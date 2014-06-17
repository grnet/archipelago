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

#include <mapper.h>
#include <mapper-version2.h>
#include <xseg/xseg.h>
#include <stdlib.h>
#include <asm/byteorder.h>

/* v2 functions */

static uint32_t get_map_block_name(char *target, struct map *map, uint64_t block_id)
{
	uint32_t targetlen;
	char buf[sizeof(block_id)*2 + 1];
	hexlify((unsigned char *)&block_id, sizeof(block_id), buf);
	buf[2*sizeof(block_id)] = 0;
	sprintf(target, "%s_%s", map->volume, buf);
	targetlen = map->volumelen + 1 + (sizeof(block_id) * 2);

	return targetlen;
}

struct obj2chunk {
	uint64_t start_obj;
	uint64_t nr_objs;
	char target[XSEG_MAX_TARGETLEN + 1];
	uint32_t targetlen;
	uint32_t offset;
	uint32_t len;
};

static struct obj2chunk get_chunk(struct map *map, uint64_t start, uint64_t nr)
{
	struct obj2chunk ret;
	uint64_t nr_objs_per_block, nr_objs_per_chunk, nr_chunks_per_block;
	uint64_t start_map_block, start_chunk_in_map_block, start_obj_in_chunk;

	nr_objs_per_chunk = v2_read_chunk_size/v2_objectsize_in_map;
	nr_chunks_per_block = map->blocksize/v2_read_chunk_size;
	nr_objs_per_block = nr_chunks_per_block * nr_objs_per_chunk;

	start_map_block = start / nr_objs_per_block;
	start_chunk_in_map_block = (start % nr_objs_per_block)/nr_objs_per_chunk;
	start_obj_in_chunk = (start - start_map_block * nr_objs_per_block - start_chunk_in_map_block * nr_objs_per_chunk);

	ret.targetlen = get_map_block_name(ret.target, map, start_map_block);

	ret.start_obj = start;
	if (start_obj_in_chunk + nr > nr_objs_per_chunk)
		ret.nr_objs = nr_objs_per_chunk - start_obj_in_chunk;
	else
		ret.nr_objs = nr;

	ret.offset = start_chunk_in_map_block * v2_read_chunk_size;
	ret.offset += start_obj_in_chunk * v2_objectsize_in_map;
	ret.len = ret.nr_objs * v2_objectsize_in_map;

	XSEGLOG2(&lc, D, "For map %s, start: %llu, nr: %llu calculated: "
			"target: %s (%u), start_obj: %llu, nr_objs: %llu, "
			"offset: %u, len: %u", map->volume, start, nr,
			ret.target, ret.targetlen, ret.start_obj, ret.nr_objs,
			ret.offset, ret.len);

	return ret;
}

int read_object_v2(struct map_node *mn, unsigned char *buf)
{
	char c = buf[0];
	int len = 0;
	uint32_t objectlen;

	mn->flags = 0;
	mn->flags |= MF_OBJECT_WRITABLE & c;
	mn->flags |= MF_OBJECT_ARCHIP & c;
	mn->flags |= MF_OBJECT_ZERO & c;
	mn->flags |= MF_OBJECT_DELETED & c;
	objectlen = *(typeof(objectlen) *)(buf + 1);
	mn->objectlen = objectlen;
	if (mn->objectlen > v2_max_objectlen) {
		XSEGLOG2(&lc, D, "mn: %p, buf: %p, objectlen: %u", mn, buf, mn->objectlen);
		XSEGLOG2(&lc, E, "Invalid object len %u", mn->objectlen);
		return -1;
	}

//	if (mn->flags & MF_OBJECT_ARCHIP){
//		strcpy(mn->object, MAPPER_PREFIX);
//		len += MAPPER_PREFIX_LEN;
//	}
	memcpy(mn->object + len, buf + sizeof(objectlen) + 1, mn->objectlen);
	mn->object[mn->objectlen] = 0;

	return 0;
}

void object_to_map_v2(unsigned char* buf, struct map_node *mn)
{
	uint32_t *objectlen;
	uint32_t len;
	buf[0] = 0;
	buf[0] |= mn->flags & MF_OBJECT_WRITABLE;
	buf[0] |= mn->flags & MF_OBJECT_ARCHIP;
	buf[0] |= mn->flags & MF_OBJECT_ZERO;
	buf[0] |= mn->flags & MF_OBJECT_DELETED;

	if (!__builtin_types_compatible_p(typeof(mn->objectlen), typeof(*objectlen))) {
		XSEGLOG2(&lc, W, "Mapnode objectlen incompatible with map "
				 "objectlen buffer");
	}

	objectlen = (typeof(objectlen))(buf + 1);
	*objectlen = mn->objectlen & 0xFFFFFFFF;
	if (*objectlen > v2_max_objectlen) {
		XSEGLOG2(&lc, E, "Invalid object len %u", mn->objectlen);
	}

	len = 0;
//	if (mn->flags & MF_OBJECT_ARCHIP){
//		/* strip common prefix */
//		len += MAPPER_PREFIX_LEN;
//	}
	memcpy((buf + 1 + sizeof(uint32_t)), mn->object + len, mn->objectlen);
}

struct xseg_request * prepare_write_objects_o2c_v2(struct peer_req *pr, struct map *map,
				struct obj2chunk o2c)
{
	struct xseg_request *req;
	uint64_t limit, k, pos, datalen;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	char *data;
	struct map_node *mn;

	datalen = v2_read_chunk_size;

	XSEGLOG2(&lc, D, "Starting for map %s, start_obj: %llu, nr_objs: %llu",
			map->volume, o2c.start_obj, o2c.nr_objs);

	req = get_request(pr, mapper->mbportno, o2c.target,
			o2c.targetlen, datalen);
	if (!req) {
		XSEGLOG2(&lc, E, "Cannot get request");
		return NULL;
	}

	req->op = X_WRITE;
	req->offset = o2c.offset;
	req->size = o2c.len;

	data = xseg_get_data(peer->xseg, req);
	limit = o2c.start_obj + o2c.nr_objs;
	pos = 0;
	for (k = o2c.start_obj; k < limit; k++) {
		mn = &map->objects[k];
		object_to_map_v2((unsigned char *)(data+pos), mn);
		pos += v2_objectsize_in_map;
	}

	return req;

}

struct xseg_request * prepare_write_objects_v2(struct peer_req *pr, struct map *map,
				uint64_t start, uint64_t nr)
{
	struct obj2chunk o2c;
	o2c = get_chunk(map, start, nr);
	if (o2c.nr_objs != nr) {
		return NULL;
	}
	return prepare_write_objects_o2c_v2(pr, map, o2c);
}

struct xseg_request * prepare_write_object_v2(struct peer_req *pr, struct map *map,
				struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	char *data;
	struct xseg_request *req;

	req = prepare_write_objects_v2(pr, map, mn->objectidx, 1);
	if (!req)
		return NULL;

	data = xseg_get_data(peer->xseg, req);
	object_to_map_v2((unsigned char *)(data), mn);
	return req;
}


int read_map_objects_v2(struct map *map, unsigned char *data, uint64_t start, uint64_t nr)
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
		r = read_object_v2(&map_node[i], data+pos);
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

int read_map_v2(struct map *m, unsigned char *data)
{
	/* totally unsafe */
	return read_map_objects_v2(m, data, 0, m->nr_objs);
}

void delete_map_data_v2_cb(struct peer_req *pr, struct xseg_request *req)
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


int __delete_map_data_v2(struct peer_req *pr, struct map *map)
{
	int r;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	struct xseg_request *req;
	char target[XSEG_MAX_TARGETLEN];
	uint32_t targetlen;
	uint64_t nr_objs_per_block, nr_objs_per_chunk, nr_chunks_per_block;
	uint64_t nr_map_blocks, i;
	char buf[sizeof(i)*2 + 1];

	nr_objs_per_chunk = v2_read_chunk_size/v2_objectsize_in_map;
	nr_chunks_per_block = map->blocksize/v2_read_chunk_size;
	nr_objs_per_block = nr_chunks_per_block * nr_objs_per_chunk;
	nr_map_blocks = map->nr_objs / nr_objs_per_block;
	if (map->nr_objs % nr_objs_per_block) {
		nr_map_blocks++;
	}

	XSEGLOG2(&lc, D, "nr_objs_per_chunk: %llu, nr_chunks_per_block: %llu, "
			"nr_objs_per_block: %llu, nr_map_blocks: %llu",
			nr_objs_per_chunk, nr_chunks_per_block, nr_objs_per_block,
			nr_map_blocks);
	for (i = 0; i < nr_map_blocks; i++) {
		hexlify((unsigned char *)&i, sizeof(i), buf);
		buf[2*sizeof(i)] = 0;
		sprintf(target, "%s_%s", map->volume, buf);
		targetlen = map->volumelen + 1 + (sizeof(i) << 1);

		req = get_request(pr, mapper->mbportno, target, targetlen, 0);
		if (!req) {
			XSEGLOG2(&lc, E, "Cannot get request");
			goto out_err;
		}
		req->op = X_DELETE;
		req->offset = 0;
		req->size = 0;
		XSEGLOG2(&lc, D, "Deleting chunk %s(%u)", target,  targetlen);
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

int delete_map_data_v2(struct peer_req *pr, struct map *map)
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

void write_map_data_v2_cb(struct peer_req *pr, struct xseg_request *req)
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

int __write_map_data_v2(struct peer_req *pr, struct map *map)
{
	int r;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	uint64_t datalen;
	struct xseg_request *req;
	char target[XSEG_MAX_TARGETLEN];
	uint32_t targetlen;
	uint64_t nr_objs_per_block, nr_objs_per_chunk, nr_chunks_per_block;
	uint64_t nr_map_blocks, i, j;
	uint64_t k, start, limit, pos, count;
	char buf[sizeof(i)*2 + 1];
	char *data;
	struct map_node *mn;

	datalen = v2_read_chunk_size;

	count = 0;
	nr_objs_per_chunk = v2_read_chunk_size/v2_objectsize_in_map;
	nr_chunks_per_block = map->blocksize/v2_read_chunk_size;
//	nr_objs_per_block = map->blocksize / v2_objectsize_in_map;
	nr_objs_per_block = nr_chunks_per_block * nr_objs_per_chunk;
	nr_map_blocks = map->nr_objs / nr_objs_per_block;
	if (map->nr_objs % nr_objs_per_block) {
		nr_map_blocks++;
	}

	XSEGLOG2(&lc, D, "nr_objs_per_chunk: %llu, nr_chunks_per_block: %llu, "
			"nr_objs_per_block: %llu, nr_map_blocks: %llu",
			nr_objs_per_chunk, nr_chunks_per_block, nr_objs_per_block,
			nr_map_blocks);
	for (i = 0; i < nr_map_blocks && count < map->nr_objs; i++) {
		for (j = 0; j < nr_chunks_per_block && count < map->nr_objs; j++) {
			hexlify((unsigned char *)&i, sizeof(i), buf);
			buf[2*sizeof(i)] = 0;
			sprintf(target, "%s_%s", map->volume, buf);
			targetlen = map->volumelen + 1 + (sizeof(i) << 1);

			req = get_request(pr, mapper->mbportno, target,
					targetlen, datalen);
			if (!req) {
				XSEGLOG2(&lc, E, "Cannot get request");
				goto out_err;
			}
			req->op = X_WRITE;
			req->offset = j * v2_read_chunk_size;
			req->size = v2_read_chunk_size;
			data = xseg_get_data(peer->xseg, req);
			start = i * nr_objs_per_block + j * nr_objs_per_chunk;
			limit = start + nr_objs_per_chunk;
			pos = 0;
			for (k = start; k < map->nr_objs && k < limit; k++) {
				mn = &map->objects[k];
				object_to_map_v2((unsigned char *)(data+pos), mn);
				pos += v2_objectsize_in_map;
			}

			XSEGLOG2(&lc, D, "Writing chunk %s(%u) , offset :%llu",
					target, targetlen, req->offset);

			r = send_request(pr, req);
			if (r < 0) {
				XSEGLOG2(&lc, E, "Cannot send request");
				goto out_put;
			}
			mio->pending_reqs++;
			count += nr_objs_per_chunk;
		}
	}
	return 0;

out_put:
	put_request(pr, req);
out_err:
	mio->err = 1;
	return -1;
}

int __write_objects_v2(struct peer_req *pr, struct map *map, uint64_t start, uint64_t nr)
{
	int r;
	struct mapper_io *mio = __get_mapper_io(pr);
	struct xseg_request *req;
	struct obj2chunk o2c;

	XSEGLOG2(&lc, D, "Writing objects for %s: start: %llu, nr: %llu",
			map->volume, start, nr);
	if (start + nr > map->nr_objs) {
		XSEGLOG2(&lc, E, "Attempting to write beyond nr_objs");
		return -1;
	}

	while (nr > 0) {
		o2c = get_chunk(map, start, nr);

		req = prepare_write_objects_o2c_v2(pr, map, o2c);

		XSEGLOG2(&lc, D, "Writing chunk %s(%u) , offset :%llu",
				o2c.target, o2c.targetlen, req->offset);


		r = send_request(pr, req);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Cannot send request");
			put_request(pr, req);
			mio->err = 1;
			return -1;
		}
		mio->pending_reqs++;
		nr -= o2c.nr_objs;
		start += o2c.nr_objs;
	}
	return 0;
}

int write_objects_v2(struct peer_req *pr, struct map *map, uint64_t start, uint64_t nr)
{
	int r;
	//unsigned char *buf;
	struct mapper_io *mio = __get_mapper_io(pr);
	mio->cb = write_map_data_v2_cb;

	r = __write_objects_v2(pr, map, start, nr);
	if (r < 0)
		mio->err = 1;

	if (mio->pending_reqs > 0)
		wait_on_pr(pr, mio->pending_reqs > 0);

	mio->priv = NULL;
	mio->cb = NULL;
	return (mio->err ? -1 : 0);
}

int write_map_data_v2(struct peer_req *pr, struct map *map)
{
	return write_objects_v2(pr, map, 0, map->nr_objs);
}

void load_map_data_v2_cb(struct peer_req *pr, struct xseg_request *req)
{
	char *data;
	unsigned char *buf;
	struct mapper_io *mio = __get_mapper_io(pr);
	struct peerd *peer = pr->peer;
	buf = (unsigned char *)__get_node(mio, req);

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
	XSEGLOG2(&lc, D, "Memcpy %llu to %p (%u)", req->serviced, buf, *(uint32_t *)(data+1));
	memcpy(buf, data, req->serviced);

out:
	__set_node(mio, req, NULL);
	put_request(pr, req);
	mio->pending_reqs--;
	signal_pr(pr);
	return;
}

int __load_map_objects_v2(struct peer_req *pr, struct map *map, uint64_t start, uint64_t nr, unsigned char *buf)
{
	int r;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct mapper_io *mio = __get_mapper_io(pr);
	uint64_t datalen;
	struct xseg_request *req;
	struct obj2chunk o2c;

	datalen = v2_read_chunk_size;

	if (start + nr > map->nr_objs) {
		XSEGLOG2(&lc, E, "Attempting to load beyond nr_objs");
		return -1;
	}

	while (nr > 0) {
		o2c = get_chunk(map, start, nr);

		req = get_request(pr, mapper->mbportno, o2c.target,
				o2c.targetlen, datalen);
		if (!req) {
			XSEGLOG2(&lc, E, "Cannot get request");
			goto out_err;
		}
		req->op = X_READ;
		req->offset = o2c.offset;
		req->size = o2c.len;

		XSEGLOG2(&lc, D, "Reading chunk %s(%u) , offset :%llu",
				o2c.target, o2c.targetlen, req->offset);

		r = __set_node(mio, req, (struct map_node *)(buf + o2c.start_obj * v2_objectsize_in_map));

		r = send_request(pr, req);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Cannot send request");
			goto out_put;
		}
		mio->pending_reqs++;
		nr -= o2c.nr_objs;
		start += o2c.nr_objs;
	}
	return 0;

out_put:
	put_request(pr, req);
out_err:
	mio->err = 1;
	return -1;
}

int load_map_objects_v2(struct peer_req *pr, struct map *map, uint64_t start, uint64_t nr)
{
	int r;
	unsigned char *buf;
	struct mapper_io *mio = __get_mapper_io(pr);
	uint32_t buf_size = sizeof(unsigned char) * nr * v2_objectsize_in_map;
	uint32_t rem;

	if (map->flags & MF_MAP_DELETED) {
		XSEGLOG2(&lc, I, "Map deleted. Ignoring loading objects");
		return 0;
	}

	if (buf_size < v2_read_chunk_size) {
		buf_size = v2_read_chunk_size;
	}
	/* buf size must be a multiple of v2_read_chunk_size */
	rem = buf_size % v2_read_chunk_size;
	XSEGLOG2(&lc, D, "Buf size %u, rem: %u", buf_size, rem);
	if (rem)
		buf_size += (v2_read_chunk_size - rem);
	XSEGLOG2(&lc, D, "Allocating %u bytes buffer", buf_size);
	buf = malloc(buf_size);
	if (!buf) {
		XSEGLOG2(&lc, E, "Cannot allocate memory");
		return -1;
	}

	mio->priv = buf;
	mio->cb = load_map_data_v2_cb;

	r = __load_map_objects_v2(pr, map, start, nr, buf);
	if (r < 0)
		mio->err = 1;

	if (mio->pending_reqs > 0)
		wait_on_pr(pr, mio->pending_reqs > 0);

	if (mio->err) {
		XSEGLOG2(&lc, E, "Error issuing load request");
		goto out;
	}
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

int load_map_data_v2(struct peer_req *pr, struct map *map)
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
	if(version != MAP_V2) {
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
