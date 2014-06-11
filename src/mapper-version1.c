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
#include <mapper-version1.h>
#include <asm/byteorder.h>
#include <stdlib.h>

/* v1 functions */

int read_object_v1(struct map_node *mn, unsigned char *buf)
{
	char c = buf[0];
	mn->flags = 0;
	if (c){
		mn->flags |= MF_OBJECT_WRITABLE;
		mn->flags |= MF_OBJECT_ARCHIP;
		strcpy(mn->object, MAPPER_PREFIX);
		hexlify(buf+1, SHA256_DIGEST_SIZE, mn->object + MAPPER_PREFIX_LEN);
		mn->object[MAX_OBJECT_LEN] = 0;
		mn->objectlen = strlen(mn->object);
	}
	else {
		mn->flags &= ~MF_OBJECT_WRITABLE;
		mn->flags &= ~MF_OBJECT_ARCHIP;
		hexlify(buf+1, SHA256_DIGEST_SIZE, mn->object);
		mn->object[HEXLIFIED_SHA256_DIGEST_SIZE] = 0;
		mn->objectlen = strlen(mn->object);
	}
	return 0;
}

void object_to_map_v1(unsigned char* buf, struct map_node *mn)
{
	buf[0] = (mn->flags & MF_OBJECT_WRITABLE)? 1 : 0;
	//assert !(mn->flags & MF_OBJECT_ARCHIP)
	if (buf[0]){
		/* strip common prefix */
		unhexlify(mn->object+MAPPER_PREFIX_LEN, (unsigned char *)(buf+1));
	}
	else {
		unhexlify(mn->object, (unsigned char *)(buf+1));
	}
	//if name == zero block, raize MF_OBJECT_ZERO
}

struct xseg_request * prepare_write_object_v1(struct peer_req *pr, struct map *map,
				struct map_node *mn)
{
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request *req;
	char *data;

	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			v1_objectsize_in_map);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		return NULL;
	}

	req->op = X_WRITE;
	req->size = v1_objectsize_in_map;
	req->offset = v1_mapheader_size + mn->objectidx * v1_objectsize_in_map;

	data = xseg_get_data(pr->peer->xseg, req);
	object_to_map_v1((unsigned char *)data, mn);
	return NULL;
}

int read_map_v1(struct map *m, unsigned char *data)
{
	int r;
	struct map_node *map_node;
	uint64_t i;
	uint64_t pos = 0;
	uint64_t nr_objs = m->nr_objs;

	map_node = calloc(nr_objs, sizeof(struct map_node));
	if (!map_node)
		return -1;
	m->objects = map_node;

	for (i = 0; i < nr_objs; i++) {
		map_node[i].map = m;
		map_node[i].objectidx = i;
		map_node[i].waiters = 0;
		map_node[i].ref = 1;
		map_node[i].state = 0;
		map_node[i].cond = st_cond_new(); //FIXME err check;
		read_object_v1(&map_node[i], data+pos);
		pos += v1_objectsize_in_map;
	}
	return 0;
}

int delete_map_data_v1(struct peer_req *pr, struct map *map)
{
	return -1;
	//Perhaps use X_TRUNCATE ?
}


struct xseg_request * __write_map_data_v1(struct peer_req *pr, struct map *map)
{
	int r;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	struct xseg_request *req;
	char *data;
	uint64_t i, pos;
	struct map_node *mn;

	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
				map->nr_objs * v1_objectsize_in_map);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s",
				map->volume);
		goto out_err;
	}


	data = xseg_get_data(peer->xseg, req);

	req->op = X_WRITE;
	req->size = req->datalen;
	req->offset = v1_mapheader_size;

	pos = 0;
	for (i = 0; i < map->nr_objs; i++) {
		mn = &map->objects[i];
		object_to_map_v1((unsigned char *)(data+pos), mn);
		pos += v1_objectsize_in_map;
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

int write_map_data_v1(struct peer_req *pr, struct map *map)
{
	int r = 0;
	struct xseg_request *req = __write_map_data_v1(pr, map);
	if (!req)
		return -1;
	wait_on_pr(pr, (!(req->state & XS_FAILED || req->state & XS_SERVED)));
	if (req->state & XS_FAILED)
		r = -1;
	put_request(pr, req);
	return r;
}


struct xseg_request * __load_map_data_v1(struct peer_req *pr, struct map *map)
{
	int r;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	struct mapperd *mapper = __get_mapperd(peer);
	uint64_t datalen;


	datalen = calc_map_obj(map) * v1_objectsize_in_map;
	req = get_request(pr, mapper->mbportno, map->volume, map->volumelen,
			datalen);
	if (!req){
		XSEGLOG2(&lc, E, "Cannot get request for map %s", map->volume);
		goto out_fail;
	}

	req->op = X_READ;
	req->size = datalen;
	req->offset = v1_mapheader_size;

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

int load_map_data_v1(struct peer_req *pr, struct map *map)
{
	int r = 0;
	struct xseg_request *req;
	struct peerd *peer = pr->peer;
	char *data;

	req = __load_map_data_v1(pr, map);
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
	r = read_map_v1(map, (unsigned char *)data);
	put_request(pr, req);
	return r;
}

struct map_ops v1_ops = {
	.object_to_map = object_to_map_v1,
	.read_object = read_object_v1,
	.prepare_write_object = prepare_write_object_v1,
	.load_map_data = load_map_data_v1,
	.write_map_data = write_map_data_v1,
	.delete_map_data = delete_map_data_v1
};


int read_map_header_v1(struct map *map, struct v1_header_struct *v1_hdr)
{
	//assert version 1
	/* read header */
	uint32_t version = __le32_to_cpu(v1_hdr->version);
	if (version != MAP_V1) {
		return -1;
	}
	map->version = version;
	map->size = __le64_to_cpu(v1_hdr->size);

	/* set defaults */
	map->flags = 0;
	map->epoch = 0;
	map->objects = NULL;
	map->blocksize = MAPPER_DEFAULT_BLOCKSIZE;
	map->nr_objs = calc_map_obj(map);;

	map->mops = &v1_ops;

	return 0;
}

void write_map_header_v1(struct map *map, struct v1_header_struct *v1_hdr)
{
	v1_hdr->version = __cpu_to_le32(MAP_V1);
	v1_hdr->size = __cpu_to_le64(map->size);
}

