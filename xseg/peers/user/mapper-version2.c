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

/* v2 functions */

int read_object_v2(struct map_node *mn, unsigned char *buf)
{
	char c = buf[0];
	int len = 0;
	uint32_t objectlen;

	mn->flags = 0;
	mn->flags |= MF_OBJECT_WRITABLE & c;
	mn->flags |= MF_OBJECT_ARCHIP & c;
	mn->flags |= MF_OBJECT_ZERO & c;
	objectlen = *(typeof(objectlen) *)(buf + 1);
	mn->objectlen = objectlen;
	if (mn->objectlen > v2_max_objectlen) {
		XSEGLOG2(&lc, D, "mn: %p, buf: %p, objectlen: %u", mn, buf, mn->objectlen);
		XSEGLOG2(&lc, E, "Invalid object len %u", mn->objectlen);
		return -1;
	}

	if (mn->flags & MF_OBJECT_ARCHIP){
		strcpy(mn->object, MAPPER_PREFIX);
		len += MAPPER_PREFIX_LEN;
	}
	memcpy(mn->object + len, buf + sizeof(objectlen) + 1, mn->objectlen);
	mn->object[mn->objectlen] = 0;
	return 0;
}

void v2_object_to_map(unsigned char* buf, struct map_node *mn)
{
	uint32_t *objectlen;
	uint32_t len;
	buf[0] = 0;
	buf[0] |= mn->flags & MF_OBJECT_WRITABLE;
	buf[0] |= mn->flags & MF_OBJECT_ARCHIP;
	buf[0] |= mn->flags & MF_OBJECT_ZERO;

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
	if (mn->flags & MF_OBJECT_ARCHIP){
		/* strip common prefix */
		len += MAPPER_PREFIX_LEN;
	}
	memcpy((buf + 1 + sizeof(uint32_t)), mn->object + len, mn->objectlen);
}

struct xseg_request * prepare_write_object_v2(struct peer_req *pr, struct map *map,
				struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request *req;
	char *data;
	char target[XSEG_MAX_TARGETLEN];
	uint32_t targetlen;
	char buf[sizeof(uint64_t)*2 + 1];
	uint64_t nr_objs_per_block, my_block;
	uint64_t nr_objs_per_chunk, nr_chunks_per_block;

	nr_objs_per_chunk = v2_read_chunk_size/v2_objectsize_in_map;
	nr_chunks_per_block = map->blocksize/v2_read_chunk_size;
//	nr_objs_per_block = map->blocksize / v2_objectsize_in_map;
	nr_objs_per_block = nr_chunks_per_block * nr_objs_per_chunk;
	my_block = mn->objectidx / nr_objs_per_block;


	XSEGLOG2(&lc, D, "nr_objs_per_block: %llu, mapnode idx: %llu, mapnode block: %llu",
			nr_objs_per_block, mn->objectidx, my_block);
	hexlify((unsigned char *)&my_block, sizeof(my_block), buf);
	buf[2*sizeof(my_block)] = 0;
	sprintf(target, "%s_%s", map->volume, buf);
	targetlen = map->volumelen + (sizeof(my_block) *2) + 1;
	req = get_request(pr, mapper->mbportno, target, targetlen,
			v2_objectsize_in_map);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		return NULL;
	}

	req->op = X_WRITE;
	req->size = v2_objectsize_in_map;
	req->offset = mn->objectidx * v2_objectsize_in_map;

	data = xseg_get_data(pr->peer->xseg, req);
	v2_object_to_map((unsigned char *)data, mn);
	return req;
}

int read_map_v2(struct map *m, unsigned char *data)
{
	int r;
	struct map_node *map_node;
	uint64_t i;
	uint64_t pos = 0;
	uint64_t nr_objs = m->nr_objs;
	char nulls[SHA256_DIGEST_SIZE];
	memset(nulls, 0, SHA256_DIGEST_SIZE);

	r = !memcmp(data, nulls, SHA256_DIGEST_SIZE);
	if (r) {
		XSEGLOG2(&lc, E, "Read zeros");
		return -1;
	}

	map_node = calloc(m->nr_objs, sizeof(struct map_node));
	if (!map_node)
		return -1;
	m->objects = map_node;

	for (i = 0; i < nr_objs; i++) {
		map_node[i].map = m;
		map_node[i].objectidx = i;
		map_node[i].waiters = 0;
		map_node[i].state = 0;
		map_node[i].ref = 1;
		map_node[i].cond = st_cond_new(); //FIXME err check;
		r = read_object_v2(&map_node[i], data+pos);
		if (r < 0) {
			XSEGLOG2(&lc, E, "Map %s: Could not read object %llu",
					m->volume, i);
			free(m->objects);
			m->objects = NULL;
			return -1;
		}
		pos += v2_objectsize_in_map;
	}
	return 0;
}

void write_map_v2_cb(struct peer_req *pr, struct xseg_request *req)
{
	struct peerd *peer = pr->peer;
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

int __write_map_v2(struct peer_req *pr, struct map *map)
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

	/* write metadata first */
	datalen = v2_mapheader_size;
	mio->pending_reqs = 0;

	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			datalen);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		goto out_err;
	}


	data = xseg_get_data(peer->xseg, req);
	pos = 0;
	memcpy(data + pos, &map->version, sizeof(map->version));
	pos += sizeof(map->version);
	memcpy(data + pos, &map->size, sizeof(map->size));
	pos += sizeof(map->size);
	memcpy(data + pos, &map->blocksize, sizeof(map->blocksize));
	pos += sizeof(map->blocksize);
	//FIXME check each flag seperately
	memcpy(data + pos, &map->flags, sizeof(map->flags));
	pos += sizeof(map->flags);
	memcpy(data + pos, &map->epoch, sizeof(map->epoch));
	pos += sizeof(map->epoch);

	req->op = X_WRITE;
	req->size = datalen;
	req->offset = 0;

	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_put;
	}
	mio->pending_reqs++;

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
				v2_object_to_map((unsigned char *)(data+pos), mn);
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

int write_map_v2(struct peer_req *pr, struct map *map)
{
	int r;
	//unsigned char *buf;
	struct mapper_io *mio = __get_mapper_io(pr);
//	buf = malloc(sizeof(char) * map->nr_objs * v2_objectsize_in_map);
//	if (!buf) {
//		XSEGLOG2(&lc, E, "Cannot allocate memory");
//		return -1;
//	}

//	mio->priv = buf;
	mio->cb = write_map_v2_cb;

	r = __write_map_v2(pr, map);
	if (r < 0)
		mio->err = 1;

	if (mio->pending_reqs > 0)
		wait_on_pr(pr, mio->pending_reqs > 0);

//	read_map_v2(map, buf);
//	free(buf);
	mio->priv = NULL;
	mio->cb = NULL;
	return (mio->err ? -1 : 0);
}

#if 0
struct xseg_request * __write_map_v2(struct peer_req *pr, struct map *map)
{
	int r;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request *req;
	char *data;
	uint64_t datalen;
	uint64_t pos, i;
	struct map_node *mn;

	datalen = v2_mapheader_size + map->nr_objs * v2_objectsize_in_map;

	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			datalen);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		goto out_err;
	}


	data = xseg_get_data(peer->xseg, req);
	pos = 0;
	memcpy(data + pos, &map->version, sizeof(map->version));
	pos += sizeof(map->version);
	memcpy(data + pos, &map->size, sizeof(map->size));
	pos += sizeof(map->size);
	memcpy(data + pos, &map->blocksize, sizeof(map->blocksize));
	pos += sizeof(map->blocksize);
	memcpy(data + pos, &map->flags, sizeof(map->flags));
	pos += sizeof(map->flags);
	memcpy(data + pos, &map->epoch, sizeof(map->epoch));
	pos += sizeof(map->epoch);

	req->op = X_WRITE;
	req->size = datalen;
	req->offset = 0;

	for (i = 0; i < map->nr_objs; i++) {
		mn = &map->objects[i];
		v2_object_to_map((unsigned char *)(data+pos), mn);
		pos += v2_objectsize_in_map;
	}

	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_put;
	}

	return req;

out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_err:
	XSEGLOG2(&lc, E, "Map write for map %s failed.", map->volume);
	return NULL;
}

int write_map_v2(struct peer_req *pr, struct map *map)
{
	int r = 0;
	struct peerd *peer = pr->peer;
	struct xseg_request *req = __write_map_v2(pr, map);
	if (!req)
		return -1;
	wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
	if (req->state & XS_FAILED)
		r = -1;
	xseg_put_request(peer->xseg, req, pr->portno);
	return r;
}
#endif

void load_map_v2_cb(struct peer_req *pr, struct xseg_request *req)
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

int __load_map_v2(struct peer_req *pr, struct map *map, unsigned char *mapbuf)
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
	uint64_t nr_map_blocks;
	uint64_t count, i, j;
	char buf[sizeof(i)*2 + 1];

	datalen = v2_read_chunk_size;
	mio->pending_reqs = 0;

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
				mio->err = 1;
				return -1;
			}
			req->op = X_READ;
			req->offset = j * v2_read_chunk_size;
			req->size = v2_read_chunk_size;

			XSEGLOG2(&lc, D, "Loading chunk %s(%u) , offset :%llu",
					target, targetlen, req->offset);

			//FIXME
			//r = __set_node(mio, req, (struct map_node *)(mapbuf + i*map->blocksize + j*v2_read_chunk_size));
			r = __set_node(mio, req, (struct map_node *)(mapbuf + i*(nr_objs_per_block * v2_objectsize_in_map) + j*v2_read_chunk_size));

			r = send_request(pr, req);
			if (r < 0) {
				put_request(pr, req);
				XSEGLOG2(&lc, E, "Cannot send request");
				mio->err = 1;
				return -1;
			}
			mio->pending_reqs++;
			count += nr_objs_per_chunk;
		}
	}
	return 0;
}

int load_map_v2(struct peer_req *pr, struct map *map)
{
	int r;
	unsigned char *buf;
	struct mapper_io *mio = __get_mapper_io(pr);
	uint32_t buf_size = sizeof(char) * map->nr_objs * v2_objectsize_in_map;
	uint32_t rem;

	if (map->flags & MF_MAP_DELETED) {
		XSEGLOG2(&lc, I, "Loaded deleted map. Ignoring loading objects");
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
	mio->cb = load_map_v2_cb;

	r = __load_map_v2(pr, map, buf);
	if (r < 0)
		mio->err = 1;

	if (mio->pending_reqs > 0)
		wait_on_pr(pr, mio->pending_reqs > 0);

	r = read_map_v2(map, buf);
	if (r < 0) {
		mio->err = 1;
	}
	free(buf);
	mio->priv = NULL;
	mio->cb = NULL;
	return (mio->err ? -1 : 0);
}

#if 0
struct xseg_request * __load_map_v2(struct peer_req *pr, struct map *map)
{
	int r;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	uint64_t datalen;


	//FIXME if this 
	datalen = map->nr_objs * v2_objectsize_in_map;
	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			datalen);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
		goto out_fail;
	}

	req->op = X_READ;
	req->size = datalen;
	req->offset = v2_mapheader_size;

	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_put;
	}
	return req;

out_put:
	xseg_put_request(peer->xseg, req, pr->portno);
out_fail:
	return NULL;
}

int load_map_v2(struct peer_req *pr, struct map *map)
{
	int r = 0;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	char *data;

	req = __load_map_v2(pr, map);
	if (!req)
		return -1;
	wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));

	if (req->state & XS_FAILED){
		XSEGLOG2(&lc, E, "Map load failed for map %s", map->volume);
		xseg_put_request(peer->xseg, req, pr->portno);
		return -1;
	}
	//assert req->service == req->size
	data = xseg_get_data(peer->xseg, req);
	r = read_map_v2(map, (unsigned char *)data);
	xseg_put_request(peer->xseg, req, pr->portno);
	return r;
}
#endif

int read_map_metadata_v2(struct map *map, unsigned char *metadata,
		uint32_t metadata_len)
{
	int r;
	char nulls[v2_mapheader_size];
	uint64_t pos;
	if (metadata_len < v2_mapheader_size) {
		XSEGLOG2(&lc, E, "Metadata len < v2_mapheader_size");
		return -1;
	}
	memset(nulls, 0, v2_mapheader_size);
	r = !memcmp(metadata, nulls, v2_mapheader_size);
	if (r) {
		XSEGLOG2(&lc, E, "Read zeros");
		return -1;
	}

	pos = 0;
	/* read header */
	map->version = *(uint32_t *)(metadata + pos);
	pos += sizeof(uint32_t);
	map->size = *(uint64_t *)(metadata + pos);
	pos += sizeof(uint64_t);
	map->blocksize = *(uint32_t *)(metadata + pos);
	pos += sizeof(uint32_t);
	//FIXME check each flag seperately
	map->flags = *(uint64_t *)(metadata + pos);
	pos += sizeof(uint32_t);
	map->epoch = *(uint64_t *)(metadata + pos);
	pos += sizeof(uint64_t);
	/* sanitize flags */
	//map->flags &= MF_MAP_SANITIZE;

	map->nr_objs = calc_map_obj(map);

	return 0;
}
