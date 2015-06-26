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

#define _GNU_SOURCE
#include <xseg/xseg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>
#include <peer.h>
#include <time.h>
#include <xseg/util.h>
#include <signal.h>
#include <bench-xseg.h>
#include <bench-lfsr.h>
#include <limits.h>
#include <math.h>

/*
 * This macro checks two things:
 * a) If in-flight requests are less than given iodepth
 * b) If we have submitted all of the requests
 * c) If we are not in ping mode
 * d) If we have been asked to terminate
 */
#define CAN_SEND_REQUEST(__p)                                               \
	((__p->status->submitted - __p->status->received < __p->iodepth) && \
	(__p->status->submitted < __p->status->max) &&                      \
	(GET_FLAG(PING, __p->flags) == PING_MODE_OFF) &&                    \
	 !isTerminate())

#define CAN_VERIFY(__p)                                                     \
	((GET_FLAG(VERIFY, __p->flags) != VERIFY_NO) && __p->op == X_READ)

#define CAN_PRINT_PROGRESS(__p, __nr)                                       \
	((GET_FLAG(PROGRESS, __p->flags) != PROGRESS_NO) &&                 \
	(GET_FLAG(PING, __p->flags) == PING_MODE_OFF) &&                    \
	(__p->status->received == __nr))

void custom_peer_usage()
{
	fprintf(stderr, "Custom peer options: \n"
		"  --------------------------------------------\n"
		"\n"
		"a) Benchmark options: \n"
		"  --------------------------------------------\n"
		"    -op       | None    | XSEG operation:\n"
		"              |         |     [read|write|info|delete]\n"
		"    --pattern | None    | I/O pattern [seq|rand]\n"
		"    -rc       | None    | Request cap\n"
		"    -to       | None    | Total objects\n"
		"    -ts       | None    | Total I/O size\n"
		"    -os       | 4M      | Object size\n"
		"    -bs       | 4k      | Block size\n"
		"    -tp       | None    | Target port\n"
		"    --iodepth | 1       | Number of in-flight I/O requests\n"
		"    --seed    | None    | Initialize LFSR and target names\n"
		"\n"
		"b) Object naming options: \n"
		"  --------------------------------------------\n"
		"    --prefix  | bench   | Add a common prefix to all object names\n"
		"    --objname | None    | Use only one object with this name\n"
		"\n"
		"c) Data verification options: \n"
		"  --------------------------------------------\n"
		"    --verify  | no      | Verify written requests:\n"
		"              |         |     [no|meta|full]\n"
		"\n"
		"d) Progress report options: \n"
		"  --------------------------------------------\n"
		"    --progress  | yes     | Show progress of benchmark:\n"
		"                |         |     [yes|no]\n"
		"    --ptype     | both    | Progress report type:\n"
		"                |         |     [req|io|both]\n"
		"    --pinterval | 5%%      | Intervals at which progress is shown\n"
		"    --insanity  | sane    | Adjust insanity level of benchmark:\n"
		"                |         |     [sane|eccentric|manic|paranoid]\n"
		"\n"
		"e) Misc options: \n"
		"  --------------------------------------------\n"
		"    --ping    | no      | Ping target before starting:\n"
		"              |         |     [yes|no]\n"
		"\n"
		"Additional information:\n"
		"  --------------------------------------------\n"
		"  * The -to and -ts options are mutually exclusive\n"
		"\n"
		"  * The object name is always not null-terminated and\n"
		"    defaults to the following structure:\n"
		"           <prefix>-<seed>-<object number>\n"
		"\n"
		"    where:\n"
		"    a. <prefix> is given by user or defaults to 'bench'\n"
		"    b. <seed> is given by user or defaults to a random value.\n"
		"       Its length will be 9 digits, with trailing zeros where\n"
		"       necessary\n"
		"    c. <object number> is out of the user's control. It is\n"
		"       calculated during the benchmark and is a 15-digit\n"
		"       number, allowing a maximum of 1 quadrillion objects\n"
		"\n"
		"   So, if bench is called with the arguments:\n"
		"           --prefix obj --seed 999\n"
		"\n"
		"   and <object number> is 9,the resulting object name will\n"
		"   be:\n"
		"           obj-000000999-000000000000009\n"
		"\n"
		" * The above object name structure can be bypassed with the\n"
		"   --objname <object name> argument. This implies the\n"
		"   following:\n"
		"\n"
		"   a. -to option is strictly restricted to 1\n"
		"   b. -ts option defaults to (and can't be larger than)\n"
		"      the object size (-os argument)\n"
		"   c. --prefix is must be unused. If used, it produces an\n"
		"      error to alert the user\n"
		"\n"
		" * The progress report is printed by default at intervals of\n"
		"   5%%.\n"
		"   There are three progress types:\n"
		"\n"
		"   a. req: it prints the request status so far i.e. how many\n"
		"      requests have been subitted, received, failed etc.\n"
		"   b. io: it prints the bandwidth and IOPS status of the\n"
		"      elapsed 5%% of the benchmark\n"
		"   c. both: it combines the output of <req> and <io>.\n"
		"\n"
		" * Interval is commonly a percentage of max requests. This\n"
		"   means that when a user gives:\n"
		"           --pinterval 33%%\n"
		"\n"
		"   the progress report will be printed 3 times during the\n"
		"   benchmark. Else, if the user wants to, he/she can give:\n"
		"           --pinterval 1234\n"
		"\n"
		"  and the progress report will be printed every 1234\n"
		"  requests.\n"
		"\n");
}

int custom_peer_init(struct peerd *peer, int argc, char *argv[])
{
	struct bench *prefs;
	char request_cap[MAX_ARG_LEN + 1];
	char total_objects[MAX_ARG_LEN + 1];
	char total_size[MAX_ARG_LEN + 1];
	char object_size[MAX_ARG_LEN + 1];
	char block_size[MAX_ARG_LEN + 1];
	char op[MAX_ARG_LEN + 1];
	char pattern[MAX_ARG_LEN + 1];
	char insanity[MAX_ARG_LEN + 1];
	char verify[MAX_ARG_LEN + 1];
	char progress[MAX_ARG_LEN + 1];
	char ptype[MAX_ARG_LEN + 1];
	char pinterval[MAX_ARG_LEN + 1];
	char ping[MAX_ARG_LEN + 1];
	char prefix[XSEG_MAX_TARGETLEN + 1];
	char objname[XSEG_MAX_TARGETLEN + 1];
	struct xseg *xseg = peer->xseg;
	struct object_vars *obv;
	unsigned int xseg_page_size = 1 << xseg->config.page_shift;
	long iodepth = -1;
	long dst_port = -1;
	unsigned long seed = -1;
	unsigned long seed_max;
	uint64_t rc;
	struct timespec *ts;
	int set_by_hand = 1;
	int j, r;

	op[0] = 0;
	pattern[0] = 0;
	total_objects[0] = 0;
	total_size[0] = 0;
	block_size[0] = 0;
	object_size[0] = 0;
	insanity[0] = 0;
	verify[0] = 0;
	request_cap[0] = 0;
	progress[0] = 0;
	ptype[0] = 0;
	pinterval[0] = 0;
	ping[0] = 0;
	prefix[0] = 0;
	objname[0] = 0;

	/* allocate struct bench */
	prefs = malloc(sizeof(struct bench));
	if (!prefs) {
		perror("malloc");
		goto prefs_fail;
	}
	memset(prefs, 0, sizeof(struct bench));

	/* allocate struct req_status */
	prefs->status = malloc(sizeof(struct req_status));
	if (!prefs->status) {
		perror("malloc");
		goto status_fail;
	}
	memset(prefs->status, 0, sizeof(struct req_status));

	/* allocate struct object_name */
	prefs->objvars = malloc(sizeof(struct object_vars));
	if (!prefs->objvars) {
		perror("malloc");
		goto object_name_fail;
	}
	memset(prefs->objvars, 0, sizeof(struct object_vars));

	/* allocate struct object_name */
	prefs->rep = malloc(sizeof(struct progress_report));
	if (!prefs->rep) {
		perror("malloc");
		goto progress_report_fail;
	}
	memset(prefs->rep, 0, sizeof(struct progress_report));

	/* allocate a struct timespec for each peer request */
	for (j = 0; j < peer->nr_ops; j++) {
		ts = malloc(sizeof(struct timespec));
		if (!ts) {
			perror("malloc");
			goto priv_fail;
		}
		peer->peer_reqs[j].priv = ts;
	}

	//Begin reading the benchmark-specific arguments
	BEGIN_READ_ARGS(argc, argv);
	READ_ARG_STRING("-rc", request_cap, MAX_ARG_LEN);
	READ_ARG_STRING("-op", op, MAX_ARG_LEN);
	READ_ARG_STRING("--pattern", pattern, MAX_ARG_LEN);
	READ_ARG_STRING("-to", total_objects, MAX_ARG_LEN);
	READ_ARG_STRING("-ts", total_size, MAX_ARG_LEN);
	READ_ARG_STRING("-os", object_size, MAX_ARG_LEN);
	READ_ARG_STRING("-bs", block_size, MAX_ARG_LEN);
	READ_ARG_ULONG("--iodepth", iodepth);
	READ_ARG_ULONG("-tp", dst_port);
	READ_ARG_ULONG("--seed", seed);
	READ_ARG_STRING("--insanity", insanity, MAX_ARG_LEN);
	READ_ARG_STRING("--verify", verify, MAX_ARG_LEN);
	READ_ARG_STRING("--progress", progress, MAX_ARG_LEN);
	READ_ARG_STRING("--ptype", ptype, MAX_ARG_LEN);
	READ_ARG_STRING("--pinterval", pinterval, MAX_ARG_LEN);
	READ_ARG_STRING("--ping", ping, MAX_ARG_LEN);
	READ_ARG_STRING("--prefix", prefix, XSEG_MAX_TARGETLEN);
	READ_ARG_STRING("--objname", objname, XSEG_MAX_TARGETLEN);
	END_READ_ARGS();

	/********************************\
	 * Check object name parameters *
	\********************************/
	if (objname[0] && prefix[0]) {
		XSEGLOG2(E, "--objname and --prefix options cannot be"
				"used together.");
		goto arg_fail;
	}

	obv = prefs->objvars;
	obv->seedlen = SEEDLEN;
	obv->objnumlen = OBJNUMLEN;
	if (objname[0]) {
		strncpy(obv->name, objname, XSEG_MAX_TARGETLEN);
		obv->prefixlen = 0;
		obv->namelen = strlen(objname);
	} else {
		if (!prefix[0])	/* In this case we use a default value */
			strcpy(prefix, "bench");
		strncpy(obv->prefix, prefix, XSEG_MAX_TARGETLEN);
		obv->prefixlen = strlen(prefix);
		/* We add 2 for the extra dashes */
		obv->namelen = obv->prefixlen + obv->seedlen +
			obv->objnumlen + 2;
	}

	/* Only --prefix can exceed bounds since --objname is bounded */
	if (obv->namelen > XSEG_MAX_TARGETLEN) {
		XSEGLOG2(E, "--prefix %s: Prefix is too long.", prefix);
		goto arg_fail;
	}

	/*****************************\
	 * Check I/O type parameters *
	\*****************************/

	//We support 4 xseg operations: X_READ, X_WRITE, X_DELETE, X_INFO
	//The I/O pattern of these operations can be either sequential (seq) or
	//random (rand)
	if (!op[0]) {
		XSEGLOG2(E, "xseg operation needs to be supplied\n");
		goto arg_fail;
	}
	r = read_op(op);
	if (r < 0) {
		XSEGLOG2(E, "Invalid syntax: -op %s\n", op);
		goto arg_fail;
	}
	prefs->op = r;

	if (!pattern[0]) {
		XSEGLOG2(E, "I/O pattern needs to be supplied\n");
		goto arg_fail;
	}
	r = read_pattern(pattern);
	if (r < 0) {
		XSEGLOG2(E, "Invalid syntax: --pattern %s\n", pattern);
		goto arg_fail;
	}
	SET_FLAG(PATTERN, prefs->flags, r);

	if (!verify[0])
		strcpy(verify, "no");
	r = read_verify(verify);
	if (r < 0) {
		XSEGLOG2(E, "Invalid syntax: --verify %s\n", verify);
		goto arg_fail;
	}
	SET_FLAG(VERIFY, prefs->flags, r);

	//Default iodepth value is 1
	if (iodepth < 0)
		prefs->iodepth = 1;
	else
		prefs->iodepth = iodepth;

	/**************************\
	 * Check timer parameters *
	\**************************/

	//Most of the times, not all timers need to be used.
	//We can choose which timers will be used by adjusting the "insanity"
	//level of the benchmark i.e. the obscurity of code paths (get request,
	//submit request) that will be timed.
	if (!insanity[0])
		strcpy(insanity, "sane");

	r = read_insanity(insanity);
	if (r < 0) {
		XSEGLOG2(E, "Invalid syntax: --insanity %s\n", insanity);
		goto arg_fail;
	}
	SET_FLAG(INSANITY, prefs->flags, r);

	/*****************************\
	 * Check I/O size parameters *
	\*****************************/

	//Block size (bs): Defaults to 4K.
	//It must be a number followed by one of these characters:
	//						[k|K|m|M|g|G]
	//If not, it will be considered as size in bytes.
	//Must be integer multiple of segment's page size (typically 4k).
	if (!block_size[0])
		strcpy(block_size,"4k");

	prefs->bs = str2num(block_size);
	if (!prefs->bs) {
		XSEGLOG2(E, "Invalid syntax: -bs %s\n", block_size);
		goto arg_fail;
	} else if (prefs->bs % xseg_page_size) {
		XSEGLOG2(E, "Misaligned block size: %s\n", block_size);
		goto arg_fail;
	}

	//Object size (os): Defaults to 4M.
	//Must have the same format as "block size"
	//Must be integer multiple of "block size"
	if (!object_size[0])
		strcpy(object_size,"4M");

	prefs->os = str2num(object_size);
	if (!prefs->os) {
		XSEGLOG2(E, "Invalid syntax: -os %s\n", object_size);
		goto arg_fail;
	} else if (prefs->os % prefs->bs) {
		XSEGLOG2(E, "Misaligned object size: %s\n", object_size);
		goto arg_fail;
	}

	//Total objects (to) or total I/O size (ts).
	//Must have the same format as "block size"
	//They are mutually exclusive
	if (total_objects[0] && total_size[0]) {
		XSEGLOG2(E, "Total objects and total size are "
				"mutually exclusive\n");
		goto arg_fail;
	} else if (total_objects[0]) {
		prefs->to = str2num(total_objects);
		if (!prefs->to) {
			XSEGLOG2(E, "Invalid syntax: -to %s\n",
					total_objects);
			goto arg_fail;
		}
		//In this case, the maximum number of requests is the total
		//number of objects we will handle
		prefs->status->max = prefs->to;
	} else if (total_size[0]) {
		if (prefs->op != X_READ && prefs->op != X_WRITE) {
			XSEGLOG2(E, "Total objects must be supplied "
					"(required by -op %s)\n", op);
			goto arg_fail;
		}
		prefs->ts = str2num(total_size);
		if (!prefs->ts) {
			XSEGLOG2(E, "Invalid syntax: -ts %s\n", total_size);
			goto arg_fail;
		} else if (prefs->ts % prefs->bs) {
			XSEGLOG2(E, "Misaligned total I/O size: %s\n", total_size);
			goto arg_fail;
		}
		//In this case, the maximum number of requests is the number of
		//blocks we need to cover the total I/O size
		prefs->status->max = prefs->ts / prefs->bs;
	} else if (!objname[0]) {
		XSEGLOG2(E, "Total objects or total size must be supplied\n");
		goto arg_fail;
	}

	/*
	 * Enforce --objname restrictions here.
	 */
	if (obv->name[0]) {
		if (prefs->to > 1) {
			XSEGLOG2(E, "-to %s: Total objects are restricted "
					"to 1 due to --objname %s\n",
					total_objects, objname);
			goto arg_fail;
		} else if (prefs->ts > prefs->os) {
			XSEGLOG2(E, "-ts %s: Total size can't be larger "
					"than object size (%s) due to "
					"--objname %s\n",
					total_size, object_size, objname);
			goto arg_fail;
		} else if (prefs->op == X_READ || prefs->op == X_WRITE) {
			prefs->ts = prefs->os;
			prefs->status->max = prefs->ts / prefs->bs;
		} else {
			prefs->to = 1;
			prefs->status->max = 1;
		}
	}

	if (prefs->status->max == 1)
		SET_FLAG(PATTERN, prefs->flags, PATTERN_SEQ);

	/*************************\
	 * Check port parameters *
	\*************************/

	if (dst_port < 0){
		XSEGLOG2(E, "Target port must be supplied\n");
		goto arg_fail;
	}

	prefs->src_port = peer->portno_start; //TODO: allow user to change this
	prefs->dst_port = (xport) dst_port;

	/*********************************\
	 * Create timers for all metrics *
	\*********************************/

	if (init_timer(&prefs->total_tm, INSANITY_SANE))
		goto tm_fail;
	if (init_timer(&prefs->sub_tm, INSANITY_MANIC))
		goto tm_fail;
	if (init_timer(&prefs->get_tm, INSANITY_PARANOID))
		goto tm_fail;
	if (init_timer(&prefs->rec_tm, INSANITY_ECCENTRIC))
		goto tm_fail;

	/***********************\
	 * Initialize the LFSR *
	\***********************/

	seed_max = pow(10, obv->seedlen + 1) - 1;
	if (seed == -1) {
		srand(time(NULL));
		set_by_hand = 0;
	} else if (validate_seed(prefs, seed)) {
		XSEGLOG2(E, "--seed %lu: Seed larger than %lu. Only its "
				"first %d digits will be used",
				seed, seed_max, obv->seedlen);
		goto arg_fail;
	}

reseed:
	if (!set_by_hand)
		seed = rand() % seed_max + 1;

	if (GET_FLAG(PATTERN, prefs->flags) == PATTERN_RAND) {
		prefs->lfsr = malloc(sizeof(struct bench_lfsr));
		if (!prefs->lfsr) {
			perror("malloc");
			goto lfsr_fail;
		}

		r = lfsr_init(prefs->lfsr, prefs->status->max,
				seed, seed & 0xF);
		if (r) {
			if (!set_by_hand) {
				free(prefs->lfsr);
				goto reseed;
			}
			XSEGLOG2(E, "LFSR could not be initialized.\n");
			goto lfsr_fail;
		}
	}
	obv->seed = seed;

	/*********************************\
	 * Miscellaneous initializations *
	\*********************************/

	/* The request cap must be enforced only after the LFSR is initialized */
	if (request_cap[0]) {
		rc = str2num(request_cap);
		if (!rc) {
			XSEGLOG2(E, "Invalid syntax: -rc %s\n", request_cap);
			goto arg_fail;
		} else if (rc > prefs->status->max) {
			XSEGLOG2(E, "Request cap exceeds current request total.\n");
			goto arg_fail;
		}
		prefs->status->max = rc;
	}

	/**********************************\
	 * Progress report initialization *
	\**********************************/

	/* Progress report is on by default */
	if (!progress[0])
		strcpy(progress, "yes");
	r = read_progress(progress);
	if (r < 0) {
		XSEGLOG2(E, "Invalid syntax: --progress %s\n", progress);
		goto arg_fail;
	}
	SET_FLAG(PROGRESS, prefs->flags, r);

	/*
	 * Progress report interval definition or progress type definition makes
	 * no sense with disabled progress reports.
	 */
	if ((GET_FLAG(PROGRESS, prefs->flags) == PROGRESS_NO) &&
			(pinterval[0] || ptype[0])) {
		XSEGLOG2(E, "Cannot define progress interval or progress "
				"type without enabling progress report\n");
		goto arg_fail;
	}

	if (GET_FLAG(PROGRESS, prefs->flags) != PROGRESS_NO) {
		/* Progress type is 'both' by default */
		if (!ptype[0])
			strcpy(ptype, "both");
		prefs->rep->type = read_progress_type(ptype);
		if (prefs->rep->type < 0) {
			XSEGLOG2(E, "Invalid syntax: --ptype %s\n", ptype);
			goto arg_fail;
		}
		prefs->rep->lines = calculate_report_lines(prefs);
	}

	if (GET_FLAG(PROGRESS, prefs->flags) != PROGRESS_NO) {
		/* By default, we print every 5% */
		if (!pinterval[0])
			strcpy(pinterval, "5%");
		prefs->rep->interval = read_interval(prefs, pinterval);
		if (prefs->rep->interval == 0) {
			XSEGLOG2(E, "Invalid syntax: --pinterval %s\n",
					pinterval);
			goto arg_fail;
		}
	}

	/* Pinging the target peer is on by default */
	if (!ping[0])
		strcpy(ping, "no");
	r = read_ping(ping);
	if (r < 0) {
		XSEGLOG2(E, "Invalid syntax: --ping %s\n", ping);
		goto arg_fail;
	}
	SET_FLAG(PING, prefs->flags, r);

	prefs->peer = peer;
	peer->peerd_loop = bench_peerd_loop;
	peer->priv = (void *) prefs;

	if (obv->prefixlen)
		XSEGLOG2(I, "Seed is %u, prefix is %s",
				obv->seed, obv->prefix);
	else
		XSEGLOG2(I, "Seed is %u, object name is %s",
				obv->seed, obv->name);

	return 0;

arg_fail:
	custom_peer_usage();
lfsr_fail:
	free(prefs->lfsr);
tm_fail:
	free(prefs->total_tm);
	free(prefs->sub_tm);
	free(prefs->get_tm);
	free(prefs->rec_tm);
priv_fail:
	j--;
	for (; j >= 0; j--) {
		free(peer->peer_reqs[j].priv);
	}
progress_report_fail:
	free(prefs->rep);
object_name_fail:
	free(prefs->objvars);
status_fail:
	free(prefs->status);
prefs_fail:
	free(prefs);
	return -1;
}


static int send_request(struct peerd *peer, struct bench *prefs)
{
	struct xseg_request *req;
	struct xseg *xseg = peer->xseg;
	struct peer_req *pr;
	struct object_vars *obv = prefs->objvars;
	xport srcport = prefs->src_port;
	xport dstport = prefs->dst_port;
	xport p;

	int r;
	uint64_t new;
	uint64_t size = prefs->bs;
	struct timespec *ts;

	//srcport and dstport must already be provided by the user.
	//returns struct xseg_request with basic initializations
	XSEGLOG2(D, "Get new request\n");
	timer_start(prefs, prefs->get_tm);
	req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		XSEGLOG2(W, "Cannot get request\n");
		return -1;
	}
	timer_stop(prefs, prefs->get_tm, NULL);

	/*
	 * Allocate enough space for the data and the target's name.
	 * Also, allocate one extra byte to prevent buffer overflow due to the
	 * obligatory null termination of snprint(). This extra byte will not be
	 * counted as part of the target's name.
	 */
	XSEGLOG2(D, "Prepare new request\n");
	r = xseg_prep_request(xseg, req, obv->namelen + 1, size);
	if (r < 0) {
		XSEGLOG2(W, "Cannot prepare request! (%lu, %llu)\n",
				obv->namelen + 1, (unsigned long long)size);
		goto put_xseg_request;
	}
	req->targetlen--;

	//Determine what the next target/chunk will be, based on I/O pattern
	new = determine_next(prefs);
	req->op = prefs->op;
	XSEGLOG2(I, "Our new request is %lu\n", new);
	obv->objnum = __get_object(prefs, new);
	create_target(prefs, req);

	if (prefs->op == X_WRITE || prefs->op == X_READ) {
		req->size = size;
		//Calculate the chunk's offset inside the object
		req->offset = calculate_offset(prefs, new);
		XSEGLOG2(D, "Offset of request %lu is %lu\n", new, req->offset);

		if (prefs->op == X_WRITE)
			create_chunk(prefs, req, new);
	}

	XSEGLOG2(D, "Allocate peer request\n");
	pr = alloc_peer_req(peer);
	if (!pr) {
		XSEGLOG2(W, "Cannot allocate peer request (%ld remaining)\n",
				peer->nr_ops - xq_count(&peer->free_reqs));
		goto put_xseg_request;
	}
	pr->peer = peer;
	pr->portno = srcport;
	pr->req = req;

	//XSEGLOG2(D, "Set request data\n");
	r = xseg_set_req_data(xseg, req, pr);
	if (r < 0) {
		XSEGLOG2(W, "Cannot set request data\n");
		goto put_peer_request;
	}

	/*
	 * Start measuring receive time.
	 * When we receive a request, we need to have its submission time to
	 * measure elapsed time. Thus, we copy its submission time to pr->priv.
	 * QUESTION: Is this the fastest way?
	 */
	timer_start(prefs, prefs->rec_tm);
	if (prefs->rec_tm->insanity <= GET_FLAG(INSANITY, prefs->flags)) {
		ts = (struct timespec *)pr->priv;
		ts->tv_sec = prefs->rec_tm->start_time.tv_sec;
		ts->tv_nsec = prefs->rec_tm->start_time.tv_nsec;
	}

	//Submit the request from the source port to the target port
	XSEGLOG2(D, "Submit request %lu\n", new);
	timer_start(prefs, prefs->sub_tm);
	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort) {
		XSEGLOG2(W, "Cannot submit request\n");
		goto put_peer_request;
	}
	prefs->status->submitted++;
	timer_stop(prefs, prefs->sub_tm, NULL);

	//Send SIGIO to the process that has bound this port to inform that
	//IO is possible
	r = xseg_signal(xseg, p);
	//if (r < 0)
	//	XSEGLOG2(W, "Cannot signal destination peer (reason %d)\n", r);

	return 0;

put_peer_request:
	free_peer_req(peer, pr);
put_xseg_request:
	if (xseg_put_request(xseg, req, srcport))
		XSEGLOG2(W, "Cannot put request\n");
	return -1;
}

static int send_ping_request(struct peerd *peer, struct bench *prefs)
{
	struct xseg_request *req;
	struct xseg *xseg = peer->xseg;
	struct peer_req *pr;
	xport srcport = prefs->src_port;
	xport dstport = prefs->dst_port;
	xport p;
	int r;

	XSEGLOG2(I, "Sending ping request...");
	//srcport and dstport must already be provided by the user.
	//returns struct xseg_request with basic initializations
	XSEGLOG2(D, "Get new request\n");
	req = xseg_get_request(xseg, srcport, dstport, X_ALLOC);
	if (!req) {
		XSEGLOG2(W, "Cannot get request\n");
		return -1;
	}
	req->op = X_PING;

	XSEGLOG2(D, "Allocate peer request\n");
	pr = alloc_peer_req(peer);
	if (!pr) {
		XSEGLOG2(W, "Cannot allocate peer request (%ld remaining)\n",
				peer->nr_ops - xq_count(&peer->free_reqs));
		goto put_xseg_request;
	}
	pr->peer = peer;
	pr->portno = srcport;
	pr->req = req;

	r = xseg_set_req_data(xseg, req, pr);
	if (r < 0) {
		XSEGLOG2(W, "Cannot set request data\n");
		goto put_peer_request;
	}

	//Submit the request from the source port to the target port
	XSEGLOG2(D, "Submit ping request");
	p = xseg_submit(xseg, req, srcport, X_ALLOC);
	if (p == NoPort) {
		XSEGLOG2(W, "Cannot submit request\n");
		goto put_peer_request;
	}
	timer_stop(prefs, prefs->sub_tm, NULL);

	//Send SIGIO to the process that has bound this port to inform that
	//IO is possible
	r = xseg_signal(xseg, p);
	//if (r < 0)
	//	XSEGLOG2(W, "Cannot signal destination peer (reason %d)\n", r);

	return 0;

put_peer_request:
	free_peer_req(peer, pr);
put_xseg_request:
	if (xseg_put_request(xseg, req, srcport))
		XSEGLOG2(W, "Cannot put request\n");
	return -1;
}

/*
 * This function substitutes the default generic_peerd_loop of peer.c.
 * It's plugged to struct peerd at custom peer's initialisation
 */
int bench_peerd_loop(void *arg)
{
#ifdef MT
	struct thread *t = (struct thread *) arg;
	struct peerd *peer = t->peer;
	char *id = t->arg;
#else
	struct peerd *peer = (struct peerd *) arg;
	char id[4] = {'P','e','e','r'};
#endif
	struct xseg *xseg = peer->xseg;
	struct bench *prefs = peer->priv;
	xport portno_start = peer->portno_start;
	xport portno_end = peer->portno_end;
	pid_t pid = syscall(SYS_gettid);
	uint64_t threshold = peer->threshold;
        threshold /= (1 + portno_end - portno_start);
	threshold += 1;
	uint64_t next_report = prefs->rep->interval;
	uint64_t loops;
	int r;

	XSEGLOG2(I, "%s has tid %u.\n",id, pid);
	xseg_init_local_signal(xseg, peer->portno_start);

	if (GET_FLAG(PROGRESS, prefs->flags) != PROGRESS_NO)
		print_dummy_progress(prefs);

	/* If no ping is going to be sent, we can begin the benchmark now. */
	if (GET_FLAG(PING, prefs->flags) == PING_MODE_ON)
		send_ping_request(peer, prefs);
	else
		timer_start(prefs, prefs->total_tm);

send_request:
	while (!(isTerminate() && all_peer_reqs_free(peer))) {
		while (CAN_SEND_REQUEST(prefs)) {
			xseg_cancel_wait(xseg, peer->portno_start);
			XSEGLOG2(D, "...because %lu < %lu && %lu < %lu\n",
				prefs->status->submitted - prefs->status->received,
				prefs->iodepth, prefs->status->received,
				prefs->status->max);
			XSEGLOG2(D, "Start sending new request\n");
			r = send_request(peer, prefs);
			if (r < 0)
				break;
		}
		//Heart of peerd_loop. This loop is common for everyone.
		for (loops = threshold; loops > 0; loops--) {
			if (loops == 1)
				xseg_prepare_wait(xseg, peer->portno_start);

			if (CAN_PRINT_PROGRESS(prefs, next_report)) {
				print_progress(prefs);
				next_report += prefs->rep->interval;
			}

			if (check_ports(peer)) {
				//If an old request has just been acked, the
				//most sensible thing to do is to immediately
				//send a new one
				if (prefs->status->received < prefs->status->max)
					goto send_request;
				else
					return 0;
			}
		}
		XSEGLOG2(I, "%s goes to sleep\n", id);
		xseg_wait_signal(xseg, peer->sd, 10000000UL);
		xseg_cancel_wait(xseg, peer->portno_start);
		XSEGLOG2(I, "%s woke up\n", id);
	}

	XSEGLOG2(I, "peer->free_reqs = %d, peer->nr_ops = %d\n",
			xq_count(&peer->free_reqs), peer->nr_ops);
	return 0;
}

void custom_peer_finalize(struct peerd *peer)
{
	struct bench *prefs = peer->priv;
	//TODO: Measure mean time, standard variation

	timer_stop(prefs, prefs->total_tm, NULL);

	if (GET_FLAG(PROGRESS, prefs->flags) != PROGRESS_NO)
		clear_report_lines(prefs->rep->lines);

	print_req_stats(prefs);
	print_remaining(prefs);
	print_total_res(prefs);

	if (GET_FLAG(INSANITY, prefs->flags) >= prefs->rec_tm->insanity)
		print_rec_res(prefs);

	print_divider();
	/*
	 * This is kinda hacky but is reasonable.
	 * During the benchmark, we need to calculate the bandwidth within an
	 * interval.
	 * After the benchmark, we need to calculate the total bandwidth. To do
	 * so, we treat the benchmark as one single interval, and that's what
	 * the two lines below do. This way, the same code can aplly to both
	 * cases
	 */
	prefs->total_tm->elapsed_time = prefs->total_tm->sum;
	prefs->rep->interval = prefs->status->received;
	print_io_stats(prefs);
	fflush(stdout);
	return;
}

/*
 * handle_received: +1 to our received requests.
 * Do some sanity checks and then check if request is failed.
 * If not try to verify the request if asked.
 */
static void handle_received(struct peerd *peer, struct peer_req *pr)
{
	//FIXME: handle null pointer
	struct bench *prefs = peer->priv;
	struct timer *rec = prefs->rec_tm;
	int start_timer = 0;

	if (!pr->req) {
		//This is a serious error, so we must stop
		XSEGLOG2(E, "Received peer request with no xseg request");
		terminated++;
		return;
	}

	/*
	 * If we were in ping mode, we can now switch off and start the
	 * benchmark.
	 */
	if (GET_FLAG(PING, prefs->flags) == PING_MODE_ON) {
		XSEGLOG2(I, "Ping received. Benchmark can start now.");
		SET_FLAG(PING, prefs->flags, PING_MODE_OFF);
		start_timer = 1;
		goto out;
	}

	prefs->status->received++;

	if ((GET_FLAG(INSANITY, prefs->flags) < rec->insanity) && !pr->priv) {
		XSEGLOG2(W, "Cannot find submission time of request");
		return;
	}

	timer_stop(prefs, rec, (struct timespec *)pr->priv);

	if (!(pr->req->state & XS_SERVED))
		prefs->status->failed++;
	else if (CAN_VERIFY(prefs) && read_chunk(prefs, pr->req))
		prefs->status->corrupted++;

out:
	if (xseg_put_request(peer->xseg, pr->req, pr->portno))
		XSEGLOG2(W, "Cannot put xseg request\n");

	free_peer_req(peer, pr);

	if (start_timer)
		timer_start(prefs, prefs->total_tm);
}

int dispatch(struct peerd *peer, struct peer_req *pr, struct xseg_request *req,
		enum dispatch_reason reason)
{
	switch (reason) {
		case dispatch_accept:
			//This is wrong, benchmarking peer should not accept requests,
			//only receive them.
			XSEGLOG2(W, "Bench peer should not accept requests\n");
			complete(peer, pr);
			break;
		case dispatch_receive:
			handle_received(peer, pr);
			break;
		default:
			fail(peer, pr);
	}
	return 0;
}
