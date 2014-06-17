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

#include <xseg/xseg.h>
#include <mapper.h>
#include <mapper-version0.h>
#include <stdlib.h>

/* version 0 functions */
#define v0_chunked_read_size (512*1024)

int read_object_v0(struct map_node *mn, unsigned char *buf)
{
	hexlify(buf, SHA256_DIGEST_SIZE, mn->object);
	mn->object[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;
	mn->objectlen = HEXLIFIED_SHA256_DIGEST_SIZE;
	mn->flags = 0; //not MF_OBJECT_WRITABLE;
	//check if zero
	if (!strncmp(mn->object, zero_block, ZERO_BLOCK_LEN)) {
		mn->flags |= MF_OBJECT_ZERO;
	}

	return 0;
}

void object_to_map_v0(unsigned char *data, struct map_node *mn)
{
	unhexlify(mn->object, data);
	//if name == zero block, raize MF_OBJECT_ZERO
}

struct xseg_request * prepare_write_object_v0(struct peer_req *pr, struct map *map,
			struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request *req;
	char *data;
	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			v0_objectsize_in_map);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		return NULL;
	}

	req->op = X_WRITE;
	req->size = v0_objectsize_in_map;
	req->offset = v0_mapheader_size + mn->objectidx * v0_objectsize_in_map;

	data = xseg_get_data(pr->peer->xseg, req);
	object_to_map_v0((unsigned char *)data, mn);
	return req;
}

int read_map_v0(struct map *m, unsigned char * data)
{
	int r;
	struct map_node *map_node;
	uint64_t i;
	uint64_t pos = 0, limit;
	uint64_t max_read_obj = v0_chunked_read_size / v0_objectsize_in_map;
	char nulls[SHA256_DIGEST_SIZE];
	memset(nulls, 0, SHA256_DIGEST_SIZE);

	map_node = realloc(m->objects,
			(m->nr_objs + max_read_obj) * sizeof(struct map_node));
	if (!map_node)
		return -1;
	m->objects = map_node;
	limit = m->nr_objs + max_read_obj;
	for (i = m->nr_objs; i < limit; i++) {
		if (!memcmp(data+pos, nulls, v0_objectsize_in_map))
			break;
		map_node[i].objectidx = i;
		map_node[i].map = m;
		map_node[i].waiters = 0;
		map_node[i].state = 0;
		map_node[i].ref = 1;
		map_node[i].cond = st_cond_new(); //FIXME err check;
		read_object_v0(&map_node[i], data+pos);
		pos += v0_objectsize_in_map;
	}
	XSEGLOG2(&lc, D, "Found %llu objects", i);
	m->size = i * MAPPER_DEFAULT_BLOCKSIZE;
	m->nr_objs = i;
	return (limit - m->nr_objs);
}

int delete_map_data_v0(struct peer_req *pr, struct map *map)
{
	return -1;
	//perhaps use an X_DELETE ?
}

struct xseg_request * __write_map_data_v0(struct peer_req *pr, struct map *map)
{
	int r;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request *req;
	char *data;
	uint64_t datalen, pos, i;
	struct map_node *mn;

	datalen = v0_mapheader_size + map->nr_objs * v0_objectsize_in_map;
	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			datalen);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		goto out_err;
	}


	data = xseg_get_data(peer->xseg, req);

	req->op = X_WRITE;
	req->size = datalen;
	req->offset = 0;

	pos = 0;
	for (i = 0; i < map->nr_objs; i++) {
		mn = &map->objects[i];
		object_to_map_v0((unsigned char *)(data+pos), mn);
		pos += v0_objectsize_in_map;
	}

	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_put;
	}

	return req;

out_put:
	put_request(pr, req);
out_err:
	XSEGLOG2(&lc, E, "Map write for map %s failed.", map->volume);
	return NULL;
}

int write_map_data_v0(struct peer_req *pr, struct map *map)
{
	int r = 0;
	struct xseg_request *req = __write_map_data_v0(pr, map);
	if (!req)
		return -1;
	wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
	if (req->state & XS_FAILED)
		r = -1;
	put_request(pr, req);
	return r;
}


struct xseg_request * __load_map_data_v0(struct peer_req *pr, struct map *map)
{
	int r;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	uint64_t datalen;

	if (v0_chunked_read_size % v0_objectsize_in_map) {
		XSEGLOG2(&lc, E, "v0_chunked_read_size should be a multiple of",
				"v0_objectsize_in_map");
		return NULL;
	}

	datalen = v0_chunked_read_size;

	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			datalen);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
		goto out_fail;
	}

	req->op = X_READ;
	req->size = datalen;
	req->offset = v0_mapheader_size + map->nr_objs * v0_objectsize_in_map;

	r = send_request(pr, req);
	if (r < 0) {
		XSEGLOG2(&lc, E, "Cannot send request %p, pr: %p, map: %s",
				req, pr, map->volume);
		goto out_put;
	}
	return req;

out_put:
	put_request(pr, req);
out_fail:
	return NULL;
}

int load_map_data_v0(struct peer_req *pr, struct map *map)
{
	int r = 0;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	char *data;

retry:
	req = __load_map_data_v0(pr, map);
	if (!req)
		return -1;
	wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));

	if (req->state & XS_FAILED){
		XSEGLOG2(&lc, E, "Map load failed for map %s", map->volume);
		put_request(pr, req);
		return -1;
	}
	//assert req->service == req->size
	data = xseg_get_data(peer->xseg, req);
	r = read_map_v0(map, (unsigned char *)data);
	put_request(pr, req);
	if (!r)
		goto retry;
	return 0;
}

struct map_ops v0_ops = {
	.object_to_map = object_to_map_v0,
	.read_object = read_object_v0,
	.prepare_write_object = prepare_write_object_v0,
	.load_map_data = load_map_data_v0,
	.write_map_data = write_map_data_v0,
	.delete_map_data = delete_map_data_v0
};

int read_map_header_v0(struct map *map, struct v0_header_struct *v0_hdr)
{
	/* No header. Just set defaults */
	map->version = MAP_V0;
	map->size = 0;
	map->blocksize = MAPPER_DEFAULT_BLOCKSIZE;
	map->nr_objs = 0;
	map->flags = MF_MAP_READONLY;
	map->epoch = 0;
	map->objects = NULL;
	map->mops = &v0_ops;

	return 0;
}

void write_map_header_v0(struct map *map, struct v0_header_struct *v0_hdr)
{
	return;
}
