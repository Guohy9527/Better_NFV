/*-
 *   BSD LICENSE
 *
 *   Copyright 2018 Mellanox.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of 6WIND S.A. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <assert.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>

#include "rte_vswitch.h"
#include "rte_vswitch_private.h"

#define AGING_PAGE_SIZE (16*1024)
#define AGING_N_FLOWS (4*1024*1024)
#define AGING_N_PAGES (AGING_N_FLOWS / AGING_PAGE_SIZE)
#define AGING_INTERVAL_US 1e6
#define AGING_N_REQS 4
#define AGING_N_PORTS RTE_MAX_ETHPORTS

#define IDX2CNT(port, page, idx) \
	(page->page_id * AGING_PAGE_SIZE + idx + port->count_base)
#define CNT2IDX(port, cnt_id) ((cnt_id - port->count_base) % AGING_PAGE_SIZE)
#define CNT2PAGE(port, cnt_id) ((cnt_id - port->count_base) / AGING_PAGE_SIZE)


static uint64_t aging_tsc; /* Aging timer interval of rdtsc. */

enum {
	AGING_STATE_FREE,
	AGING_STATE_ATTACHED,
	AGING_STATE_PENDING,
};

/* Flow counter page. */
struct aging_counter_page {
	/*
	 * Lock to protect page data.
	 * Need to avoid nested lock with port lock,
	 * Acquire this page lock first if unavoidable.
	 */
	rte_spinlock_t lock;
	uint16_t page_id; /* Page id. */
	int min; /* Min index used, default to -1. */
	int max; /* Max index used, default to -1. */
	uint32_t n_counter; /* number of counters allocated. */
	uint32_t n_reusable; /* number of counters reusable. */
	uint64_t map_reuse[AGING_PAGE_SIZE / sizeof(uint64_t) / 8 > 0 ?
			   AGING_PAGE_SIZE / sizeof(uint64_t) / 8 : 1];
	/*
	 * To speedup reusable counter map loading, a high level cache line
	 * index is used to locate which cache line to search.
	 * AGING_PAGE_SIZE / 8 / 64: number of cache line
	 */
	uint64_t map_cl[AGING_PAGE_SIZE / 8 / 64 / 8 / sizeof(uint64_t) > 0 ?
			AGING_PAGE_SIZE / 8 / 64 / 8 / sizeof(uint64_t) : 1];
	struct {
		uint32_t state:2; /* 0: free, 1: attached, 2: pending. */
		uint32_t ttl:13; /* Time to live of attached flow */
		uint32_t version:1; /* Version at detached time. */
		uint32_t last:16; /* Last active time. */
		struct rte_flow_count_value counter; /* Last value pair. */
	} info[AGING_PAGE_SIZE];
	struct {
		uint8_t seg; /* Counter segment id. */
		void *flow; /* Flow attached to. */
		struct rte_flow_count_value base; /* Base value pair. */
	} flows[AGING_PAGE_SIZE];
	struct {
		void *handle; /* Counter range opaque handle. */
		uint32_t counter_id; /* Start coutner id of range. */
		/*
		 * TODO, remove. Hopefully we could support bigger and
		 * fixed number for each seg.
		 */
		uint32_t number; /* Number of counters in range. */
	} counter_segs[AGING_PAGE_SIZE / 128];
	uint32_t n_counter_segs;
};

struct aging_port_context {
	/* Counter pages indexed by counter id, dynamic increase. */
	struct aging_counter_page *pages[AGING_N_PAGES];
	uint16_t port_id; /* port device ID. */
	int version; /* Increase before flow sync and batch query. */
	struct rte_vswitch_ctx *port;
	uint32_t count_base; /* Base counter ID. */
	int n_counter; /* Number of allocated counter id. */
	int n_reusable; /* Number of reusable counter id. */
	/* Index of which page has reusable counter id. */
	uint64_t map_reuse[AGING_N_PAGES / 64];
};

/* Flow counter async batch query. */
struct aging_async_request {
	int min; /* Min index. -1 if request not used. */
	int max; /* Max index. */
	int ret; /* Return code of async response event. */
	struct aging_port_context *port;
	struct aging_counter_page *page;
	/* Counter value buffer has to be 8 aligned. */
	struct rte_flow_count_value *buf;
};

struct aging_context {
	struct aging_async_request requests[AGING_N_REQS];
	int state; /* 0: stop, 1: started. */
	int last_port;
	pthread_t thread;
	struct rte_ring *resp_ring; /* Responses of async batch query. */
	int n_async; /* Pending outgoing async batch query requests. */
	struct aging_port_context ports[AGING_N_PORTS]; /* Indexed by dev id. */
	int n_ports; /* Number of ports registered. */
	int next_page_id; /* Next page index of an aging scan. */
	/*
	 * Protect resources like async request from concurrent access,
	 * aging thread and interrupt thread.
	 */
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int pressure; /* 1: fake all 2: real counter/query 3: real flow */
	struct rte_qpool flow_pool;
	struct {
		uint64_t idle; /* Total idle time. */
		uint64_t active; /* Total busy time. */
		uint64_t query; /* Total counter query time. */
		uint64_t wait; /* Total time waiting query. */
		uint64_t scan; /* Total aging check time. */
		uint64_t destroy; /* Total time on remove. */
		uint64_t max_active; /* Max aging time. */
		uint64_t min_active; /* Min aging time. */
		uint16_t n_pages; /* Pages allocated. */
		uint16_t n_pages_active; /* Pages in use. */
		int n_flows; /* Flows registered. */
		int n_aged; /* Flows aged out. */
		int aging:1; /* Busy on aging. */
		uint64_t start; /* Recent aging start time. */
		uint16_t n_pages_last_active; /* Pages in use in latest scan. */
		uint16_t n_pages_last; /* Pages found in latest scan. */
		int n_checked; /* Flows checked in latest scan. */
		int n_last_aged; /* Flows aged out in latest scan. */
		uint16_t ratio; /* Aging time ratio on table full . */
	} stats;
	/* Aged out flows in page process. */
	int n_aged;
	struct rte_vswitch_offload_flow *aged[AGING_PAGE_SIZE];
};

struct aging_context *ctx;

/*
 * Get system time in unit of 0.1 sec.
 */
static inline uint16_t
vswitch_aging_time(void)
{
	uint64_t rdtsc;

	RTE_ASSERT(aging_tsc);
	rdtsc = rte_rdtsc() / aging_tsc;
	return rdtsc;
}

static int
aging_get_port_index(uint16_t dev_id)
{
	if (!ctx->ports[dev_id].port)
		rte_panic("Aging: use unregistered device id %hu\n", dev_id);
	/* Always use PF port as representor is using shared DevX. */
	return ctx->ports[dev_id].port->pf->data->port_id;

}

static void*
aging_counter2handle(struct aging_port_context *port,
		     struct aging_counter_page *page, uint32_t counter_id)
{
	uint32_t seg = page->flows[CNT2IDX(port, counter_id)].seg;
	RTE_ASSERT(page->counter_segs[seg].handle);
	RTE_ASSERT(page->counter_segs[seg].number);
	return page->counter_segs[seg].handle;
}

#define DEV2PORT(dev_id) (&ctx->ports[aging_get_port_index(dev_id)])

int
aging_register_port(uint32_t index, uint16_t dev_id,
		    struct rte_vswitch_ctx *dev)
{
	if (index >= RTE_DIM(ctx->ports) || dev_id >= RTE_DIM(ctx->ports))
		rte_panic("Aging: invalid port index %u\n", index);
	ctx->ports[dev_id].port_id = dev_id;
	ctx->ports[dev_id].port = dev;
	ctx->n_ports++;
	return 0;
}

static int
aging_counter_set_reusable(struct aging_counter_page *page, int offset)
{
	/* Set reusable bit. */
	page->map_reuse[offset / 64] |= (1LU << (offset % 64));
	page->map_cl[offset / 512 / 64] |=
			(1LU << ((offset / 512) % 64));
	return 0;
}

static int
aging_page_set_reusable(struct aging_port_context *port,
			struct aging_counter_page *page, int n)
{
	page->n_reusable += n;
	port->map_reuse[page->page_id / 64] |= (1LU << (page->page_id % 64));
	port->n_reusable += n;
	return 0;
}

void *
aging_counter_alloc(uint16_t port_id, uint32_t *counter_id,
		    struct rte_flow_count_value *bias)
{
	struct aging_port_context *port = DEV2PORT(port_id);
	uint32_t i, j, k, cl, page_id, idx;
	uint32_t batch;
	struct aging_counter_page *page;
	uint64_t *map;
	void *handle = NULL;
	int cl_set = 0;
	struct rte_flow_error error = { .type = RTE_FLOW_ERROR_TYPE_NONE };
	static int seq;

	if (!port->n_reusable) {
		if (port->n_counter >= AGING_N_FLOWS) {
			RTE_LOG(ERR, VSWITCH, "out of counters\n");
			return NULL;
		}
		if (ctx->pressure == 1) { /* Fake counter. */
			*counter_id = ++seq;
			*counter_id &= (AGING_N_FLOWS - 1);
			handle = (void *)(uintptr_t)seq;
		} else {
			handle = _rte_flow_counter_alloc(port->port_id,
							 counter_id,
							 &batch, &error);
			if (!handle) {
				RTE_LOG(ERR, VSWITCH, "%s\n", error.message);
				return NULL;
			}
			RTE_ASSERT(batch);
			if (!port->count_base)
				port->count_base = *counter_id;
		}
		RTE_ASSERT(handle);
		if (*counter_id - port->count_base >= AGING_N_FLOWS) {
			RTE_LOG(ERR, VSWITCH, "no more counters\n");
			if (ctx->pressure != 1)
				_rte_flow_counter_free(port->port_id, handle,
						       &error);
			return NULL;
		}
		page = port->pages[CNT2PAGE(port, *counter_id)];
		if (!page) {
			page = rte_zmalloc_socket(__func__, sizeof(*page), 0,
						  rte_socket_id());
			if (!page) {
				_rte_flow_counter_free(port->port_id, handle,
						       &error);
				RTE_LOG(ERR, VSWITCH, "unable to allocate counter page\n");
				return NULL;
			}
			page->page_id = CNT2PAGE(port, *counter_id);
			page->min = -1;
			page->max = -1;
			rte_spinlock_init(&page->lock);
			port->pages[page->page_id] = page;
			ctx->stats.n_pages++;
			RTE_LOG(INFO, VSWITCH, "new aging page %d created\n",
				page->page_id);
		}
		rte_spinlock_lock(&page->lock);
		page->counter_segs[page->n_counter_segs].handle = handle;
		page->counter_segs[page->n_counter_segs].counter_id =
				*counter_id;
		page->counter_segs[page->n_counter_segs].number = batch;
		idx = CNT2IDX(port, *counter_id);
		if (idx + batch > AGING_PAGE_SIZE)
			batch = AGING_PAGE_SIZE - idx;
		page->n_counter += batch;
		port->n_counter += batch;
		assert((batch % 64) == 0);
		for (i = idx; i < idx + batch; i++)
			page->flows[i].seg = page->n_counter_segs;
		page->n_counter_segs++;
		for (i = idx; i < idx + batch; i += 64)
			page->map_reuse[i / 64] = UINT64_MAX;
		for (i = idx; i < idx + batch; i += 512)
			page->map_cl[i / 512 / 64] |= (1LU << ((i / 512) % 64));
		aging_page_set_reusable(port, page, batch);
		rte_spinlock_unlock(&page->lock);
	}
	/* Locate a reusable page. */
	for (k = 0; k < RTE_DIM(port->map_reuse); ++k) {
		if (port->map_reuse[k])
			break;
	}
	RTE_ASSERT(k != RTE_DIM(port->map_reuse));
	page_id = __builtin_ctzll(port->map_reuse[k]);
	page = port->pages[k * 64 + page_id];
	RTE_ASSERT(page && page->n_reusable);
	rte_spinlock_lock(&page->lock);
	/* Locate cache line index of reusable bitmap. */
	for (j = 0; j < RTE_DIM(page->map_cl); j++) {
		if (page->map_cl[j])
			break;
	}
	RTE_ASSERT(j != RTE_DIM(page->map_cl));
	cl = __builtin_ctzll(page->map_cl[j]);
	map =  &page->map_reuse[(j * 64 + cl) * 8];
	/* Locate reusable counter id inside cache line via bitmap. */
	*counter_id = 0;
	for (i = 0; i < 8; i++) {
		if (!*counter_id && map[i]) {
			*counter_id = __builtin_ctzll(map[i]);
			/* Clear reusable bit. */
			map[i] &= ~(1LU << *counter_id);
			*counter_id += i * 64;
			*counter_id += (j * 64 + cl) * 8 * 64;
			RTE_ASSERT(page->info[*counter_id].state ==
				   AGING_STATE_FREE);
			RTE_ASSERT(page->flows[*counter_id].flow == NULL);
			*bias = page->flows[*counter_id].base;
			*counter_id = IDX2CNT(port, page, *counter_id);
			handle = aging_counter2handle(port, page, *counter_id);
			RTE_ASSERT(handle);
			page->n_reusable--;
			port->n_reusable--;
		}
		if (map[i]) {
			cl_set = 1;
			if (*counter_id)
				break;
		}
	}
	if (!cl_set)
		page->map_cl[j] &= ~(1LU << cl);
	rte_spinlock_unlock(&page->lock);
	if (!page->n_reusable)
		port->map_reuse[k] &= ~(1LU << page_id);
	return handle;
}

/* Release counter if flow creation failed. */
int
aging_counter_free(uint16_t port_id, int counter_id)
{
	struct aging_port_context *port = DEV2PORT(port_id);
	int idx = CNT2IDX(port, counter_id);
	struct aging_counter_page *page =
			port->pages[CNT2PAGE(port, counter_id)];

	if (counter_id == 0)
		return 0;
	RTE_ASSERT(port && page);
	if (!page)
		rte_panic("invalid page of counter_id %d", counter_id);
	if (page->flows[idx].flow ||
	    page->info[idx].state != AGING_STATE_FREE) {
		RTE_LOG(ERR, VSWITCH, "free invalid counter_id %d\n",
			counter_id);
		return -EINVAL;
	}
	rte_spinlock_lock(&page->lock);
	aging_counter_set_reusable(page, idx);
	aging_page_set_reusable(port, page, 1);
	rte_spinlock_unlock(&page->lock);
	RTE_LOG(DEBUG, VSWITCH, "counter id %d freed from aging\n",
		counter_id);
	return 0;
}

int
aging_on_flow_create(uint16_t port_id,
		     struct rte_vswitch_offload_flow *flow,
		     uint16_t ttl, int counter_id)
{
	int idx;
	struct aging_port_context *port = DEV2PORT(port_id);
	struct aging_counter_page *page;
	uint16_t create_time = vswitch_aging_time();

	RTE_ASSERT(flow);
	/* Insert into page according to counter ID. */
	idx = CNT2IDX(port, counter_id);
	page = port->pages[CNT2PAGE(port, counter_id)];
	RTE_ASSERT(page);
	rte_spinlock_lock(&page->lock);
	RTE_ASSERT(page->flows[idx].flow == NULL);
	page->flows[idx].flow = flow;
	page->info[idx].state = AGING_STATE_ATTACHED;
	page->info[idx].ttl = ttl * 1e6 / AGING_INTERVAL_US;
	page->info[idx].last = create_time;
	if (page->max == -1)
		ctx->stats.n_pages_active++;
	/* Update page min and max. */
	if (idx > page->max)
		page->max = idx;
	if (idx < page->min || page->min == -1)
		page->min = idx;
	/* Update aging ration. */
	ctx->stats.n_flows++;
	rte_spinlock_unlock(&page->lock);
	RTE_LOG(DEBUG, VSWITCH, "aging port %hu registered counter id %d timeout %hu, time: %hu(%lu)\n",
		port->port_id, counter_id, ttl, create_time, time(NULL));
	return 0;
}

int
aging_on_flow_destroy(uint16_t port_id,
		      struct rte_vswitch_offload_flow *flow __rte_unused,
		      int counter_id)
{
	struct aging_port_context *port = DEV2PORT(port_id);
	int idx = CNT2IDX(port, counter_id);
	struct aging_counter_page *page;

	if (counter_id == 0)
		return 0;
	page = port->pages[CNT2PAGE(port, counter_id)];
	RTE_ASSERT(port && flow && page);
	if (!page)
		rte_panic("invalid page of counter_id %d", counter_id);
	rte_spinlock_lock(&page->lock);
	if (idx < page->min || idx > page->max || !page->flows[idx].flow ||
	    page->info[idx].state != AGING_STATE_ATTACHED) {
		RTE_LOG(INFO, VSWITCH, "destroy invalid counter_id %d, aged out?\n",
			counter_id);
		rte_spinlock_unlock(&page->lock);
		return 0;
	}
	RTE_ASSERT(page->flows[idx].flow == flow);
	page->flows[idx].flow = NULL;
	/* Need another query to get latest counter value for reuse. */
	page->info[idx].version = port->version;
	page->info[idx].state = AGING_STATE_PENDING;
	ctx->stats.n_flows--;
	rte_spinlock_unlock(&page->lock);
	RTE_LOG(DEBUG, VSWITCH, "removed counter id %d from aging\n",
		counter_id);
	return 0;
}

int
aging_flow_modify(uint16_t port_id, struct rte_vswitch_offload_flow *flow,
		  uint16_t timeout)
{
	struct aging_port_context *port = DEV2PORT(port_id);
	int idx = CNT2IDX(port, flow->counter_id);
	struct aging_counter_page *page =
			port->pages[CNT2PAGE(port, flow->counter_id)];

	RTE_ASSERT(ctx && flow);
	if (!page) {
		RTE_LOG(WARNING, VSWITCH, "invalid aging page of flow %p counter_id %d\n",
			flow, flow->counter_id);
		return -EINVAL;
	}
	rte_spinlock_lock(&page->lock);
	if (idx < page->min || idx > page->max ||
	    page->flows[idx].flow != flow) {
		RTE_LOG(INFO, VSWITCH, "flow %p counter_id %d not found\n",
			flow, flow->counter_id);
		return -EEXIST;
	}
	page->info[idx].ttl = timeout * 1e6 / AGING_INTERVAL_US;
	rte_spinlock_unlock(&page->lock);
	RTE_LOG(DEBUG, VSWITCH, "flow %p counter_id %d timeout changed to %hu\n",
		flow, flow->counter_id, timeout);
	return 0;
}

int
aging_flow_query(uint16_t port_id, struct rte_vswitch_offload_flow *flow,
		 struct rte_flow_count_value *status)
{
	RTE_ASSERT(flow && status);
	struct aging_port_context *port = DEV2PORT(port_id);
	int idx = CNT2IDX(port, flow->counter_id);
	struct aging_counter_page *page =
			port->pages[CNT2PAGE(port, flow->counter_id)];

	if (!page) {
		RTE_LOG(WARNING, VSWITCH, "invalid aging page of flow %p counter_id %d\n",
			flow, flow->counter_id);
		return -EINVAL;
	}
	rte_spinlock_lock(&page->lock);
	if (idx < page->min || idx > page->max ||
	    page->flows[idx].flow != flow) {
		rte_spinlock_unlock(&page->lock);
		RTE_LOG(INFO, VSWITCH, "flow %p counter_id %d not found\n",
			flow, flow->counter_id);
		return -EEXIST;
	}
	status->hits = page->info[idx].counter.hits -
		       page->flows[idx].base.hits;
	status->bytes = page->info[idx].counter.bytes -
			page->flows[idx].base.bytes;
	rte_spinlock_unlock(&page->lock);
	return 0;
}

static int
aging_age_flows(struct aging_port_context *port)
{
	int i;

	PERF_START();
	if (ctx->pressure == 1 || ctx->pressure == 2) { /* Fake flow. */
		for (i = 0; i < ctx->n_aged; ++i)
			rte_qpool_free(&ctx->flow_pool, ctx->aged[i]);
		RTE_LOG(DEBUG, VSWITCH, "port: %hu %d flows aged out\n",
			port->port_id, i);
	} else {
		vswitch_on_flows_aged(port->port, ctx->aged, ctx->n_aged);
	}
	PERF_ADD(ctx->stats.destroy);
	return 0;
}

static int
aging_age_page(struct aging_async_request *req)
{
	int i;
	int new_min = -1;
	int new_max = -1;
	struct aging_counter_page *page = req->page;
	uint32_t start = page->counter_segs[page->flows[req->min].seg]
					    .counter_id;
	struct rte_flow_count_value *buf = req->buf;
	uint16_t curr = vswitch_aging_time();
	uint64_t last_hits;
	int n_freed = 0;

	PERF_START();
	RTE_ASSERT(page && page->min != -1 && page->max != -1);
	rte_spinlock_lock(&page->lock);
	ctx->n_aged = 0;
	start = (start - req->port->count_base) % AGING_PAGE_SIZE;
	buf -= start;
	for (i = req->min; i <= req->max; i++) {
		if (!ctx->state) {
			rte_spinlock_unlock(&page->lock);
			return -1;
		}
		if (page->info[i].state == AGING_STATE_FREE)
			continue;
		if (page->info[i].state == AGING_STATE_ATTACHED)
			ctx->stats.n_checked++;
		last_hits = page->info[i].counter.hits;
		page->info[i].counter.hits = rte_be_to_cpu_64(buf[i].hits);
		page->info[i].counter.bytes = rte_be_to_cpu_64(buf[i].bytes);
		if (page->info[i].state == AGING_STATE_PENDING) {
			/* Latest counter value updated for pending flow,
			 * ready for reuse.
			 */
			if (page->info[i].version ==
			    (req->port->version & 0x1)) {
				new_max = i;
				if (new_min == -1)
					new_min = i;
				/* Only free pending counter before sync. */
				continue;
			}
			page->info[i].state = AGING_STATE_FREE;
			page->flows[i].base = page->info[i].counter;
			RTE_ASSERT(page->flows[i].flow == NULL);
			aging_counter_set_reusable(page, i);
			n_freed++;
			RTE_LOG(DEBUG, VSWITCH, "port: %hu counter id %d aged -> free\n",
				req->port->port_id,
				page->page_id * AGING_PAGE_SIZE + i);
			continue;
		} else if (page->info[i].ttl &&
			   last_hits != page->info[i].counter.hits) {
			/* New packets since last check, reset timeout. */
			page->info[i].last = curr;
		} else if (page->info[i].ttl &&
			   curr - (uint16_t)page->info[i].last >=
			   (page->info[i].ttl >> ctx->stats.ratio)) {
			/* Timeout, quick remove from page. */
			page->info[i].version = req->port->version;
			page->info[i].state = AGING_STATE_PENDING;
			page->info[i].ttl = 0;
			page->info[i].last = 0;
			ctx->aged[ctx->n_aged++] = page->flows[i].flow;
			page->flows[i].flow = NULL;
			RTE_LOG(DEBUG, VSWITCH, "port: %hu counter id %d aged out. time %hu(%lu)\n",
				req->port->port_id,
				page->page_id * AGING_PAGE_SIZE + i,
				curr, time(NULL));
		}
		/* Update flow min/max index. */
		if (new_min == -1)
			new_min = i;
		new_max = i;
	}
	if (n_freed) {
		pthread_mutex_lock(&ctx->lock);
		aging_page_set_reusable(req->port, page, n_freed);
		pthread_mutex_unlock(&ctx->lock);
		if (req->port->n_reusable == req->port->n_counter)
			RTE_LOG(INFO, VSWITCH, "port %hu all counters freed: %d\n",
				req->port->port_id, req->port->n_counter);
	}
	/* Update page min/max counter. */
	if (page->min != -1 && page->min >= req->min)
		/* No new flows during batch query. */
		page->min = new_min;
	if (page->max <= req->max)
		/* No new flows during batch query. */
		page->max = new_max;
	if (page->min == -1)
		ctx->stats.n_pages_active--;
	rte_spinlock_unlock(&page->lock);
	PERF_ADD(ctx->stats.scan);
	ctx->stats.n_aged += ctx->n_aged;
	ctx->stats.n_last_aged += ctx->n_aged;
	ctx->stats.n_flows -= ctx->n_aged;
	/* Reset request. */
	req->min = -1;
	ctx->n_async--;
	return 0;
}

static void
aging_counter_query_callback(int ret, void *req)
{
	RTE_ASSERT(req);
	((struct aging_async_request *)req)->ret = ret;
	rte_ring_enqueue(ctx->resp_ring, req);
	pthread_mutex_lock(&ctx->lock);
	pthread_cond_signal(&ctx->cond);
	pthread_mutex_unlock(&ctx->lock);
}

static void
aging_thread_wait(void)
{
	struct timeval now;
	struct timespec outtime;

	PERF_START();
	/* Conditional signal(async response) wait. */
	pthread_mutex_lock(&ctx->lock);
	while (ctx->state) {
		gettimeofday(&now, NULL);
		outtime.tv_sec = now.tv_sec + 1;
		outtime.tv_nsec = now.tv_usec * 1000;
		if (pthread_cond_timedwait(&ctx->cond, &ctx->lock, &outtime) !=
		    ETIMEDOUT)
			break;
	}
	pthread_mutex_unlock(&ctx->lock);
	PERF_ADD(ctx->stats.wait);
}

static int
aging_counter_query(struct aging_async_request *req,
		    struct aging_counter_page *page)
{
	struct rte_flow_error error = { .type = 0 };
	int rc = 0;
	int start;
	int max = page->max;
	void *handle;

	PERF_START();
	/* Sync flows before each querying each port. */
	if (ctx->last_port != req->port->port_id) {
		req->port->version++;
		rc = _rte_flow_sync(req->port->port_id, &error);
		if (rc)
			goto err;
		ctx->last_port = req->port->port_id;
	}
	/* Must start with range first?! */
	start = page->counter_segs[page->flows[page->min].seg].counter_id;
	handle = page->counter_segs[page->flows[page->min].seg].handle;
	max = RTE_ALIGN_CEIL(max + 1, 4);
	rc = _rte_flow_counter_query(req->port->port_id,
				     start,
				     handle,
				     max - CNT2IDX(req->port, start),
				     req->buf, AGING_PAGE_SIZE,
				     aging_counter_query_callback,
				     req, &error);
err:
	if (rc)
		RTE_LOG(ERR, VSWITCH, "%s\n", error.message);
	PERF_ADD(ctx->stats.query);
	return rc;
}

static int
aging_req_next_page(struct aging_async_request *req)
{
	int page_id;
	int port;
	struct aging_counter_page *page;
	int rc = 0;

	/* Locate next counter page to query. */
	while (1) {
		if (!ctx->state)
			return -1;
		if (ctx->next_page_id >= AGING_N_PAGES * AGING_N_PORTS)
			return -ENOENT;
		port = ctx->next_page_id / AGING_N_PAGES;
		page_id = ctx->next_page_id % AGING_N_PAGES;
		ctx->next_page_id++;
		/* Skip representors which share PF's counter space. */
		if (!ctx->ports[port].port ||
		    ctx->ports[port].port->pf->data->port_id !=
		    ctx->ports[port].port_id)
			continue;
		page = ctx->ports[port].pages[page_id];
		if (!page)
			continue;
		ctx->stats.n_pages_last++;
		if (page->max != -1)
			break;
	}
	ctx->stats.n_pages_last_active++;
	RTE_ASSERT(page->min != -1);
	/* Lock page. */
	rte_spinlock_lock(&page->lock);
	/* Setup Async request. */
	req->min = page->min;
	req->max = page->max;
	req->page = page;
	req->port = &ctx->ports[port];
	/* Unlock page. */
	rte_spinlock_unlock(&page->lock);
	if (ctx->pressure == 1) { /* Fake counter, no query. */
		req->ret = 0;
		rte_ring_enqueue(ctx->resp_ring, req);
		ctx->n_async++;
	} else {
		rc = aging_counter_query(req, page);
		if (rc)
			req->min = -1;
		else
			ctx->n_async++;
	}
	return rc;
}

static struct aging_async_request *
aging_get_async_response(void)
{
	struct aging_async_request *req = NULL;

	if (!ctx->state)
		return NULL;
	rte_ring_dequeue(ctx->resp_ring, (void **)&req);
	if (req && req->ret) {
		RTE_LOG(ERR, VSWITCH, "counter query failed, page: %hu, min: %d max: %d\n",
			req->page->page_id, req->min, req->max);
		ctx->n_async--;
		req->min = -1;
		req = NULL;
	}
	return req;
}

static struct aging_async_request *
aging_get_async_request(void)
{
	uint32_t i;

	for (i = 0; i < RTE_DIM(ctx->requests); ++i) {
		if (!ctx->state)
			return NULL;
		if (ctx->requests[i].min == -1)
			return &ctx->requests[i];
	}
	return NULL;
}

static int
aging_age(void)
{
	struct aging_async_request *async;
	struct aging_port_context *port;
	uint64_t tsc = rte_rdtsc();

	ctx->next_page_id = 0;
	ctx->last_port = -1;
	while (1) {
		while (ctx->state) {
			async = aging_get_async_request();
			if (!async || aging_req_next_page(async))
				break;
		}
		while (ctx->state) {
			async = aging_get_async_response();
			if (!async)
				break;
			aging_age_page(async);
			port = async->port;
			if (ctx->n_aged)
				aging_age_flows(port);
			aging_req_next_page(async);
		}
		if (ctx->state && ctx->n_async)
			aging_thread_wait();
		else
			break;
	}
	tsc = rte_rdtsc() - tsc;
	ctx->stats.active += tsc;
	/* Update max aging time. */
	if (tsc > ctx->stats.max_active)
		ctx->stats.max_active = tsc;
	if (!ctx->stats.min_active || tsc < ctx->stats.max_active)
		ctx->stats.min_active = tsc;
	return 0;
}

static void
aging_task(void)
{
	uint64_t start_tsc;
	uint64_t tsc;
	uint64_t tsc_idle;
	uint64_t us;

	RTE_LOG(INFO, VSWITCH, "aging task starting\n");
	while (ctx->state == 1) {
		start_tsc = rte_rdtsc();
		if (!ctx->stats.ratio &&
		    ctx->stats.n_flows > AGING_N_FLOWS * 0.8) {
			ctx->stats.ratio = 1;
			RTE_LOG(INFO, VSWITCH, "flows capacity > 0.8, aging time / %u\n",
				1u << ctx->stats.ratio);
		}
		ctx->stats.n_pages_last = 0;
		ctx->stats.n_pages_last_active = 0;
		ctx->stats.n_last_aged = 0;
		ctx->stats.n_checked = 0;
		ctx->stats.aging = 1;
		tsc = rte_rdtsc();
		ctx->stats.start = tsc;
		aging_age();
		ctx->stats.aging = 0;
		if (ctx->stats.ratio &&
		    ctx->stats.n_flows < AGING_N_FLOWS * 0.8) {
			ctx->stats.ratio = 0;
			RTE_LOG(INFO, VSWITCH, "flows capacity restored, aging time / %u\n",
				1u << ctx->stats.ratio);
		}
		if (ctx->stats.n_last_aged && !ctx->stats.n_flows)
			RTE_LOG(INFO, VSWITCH, "all flows aged out\n");
		/* Sleep until 1 second. */
		tsc_idle = rte_rdtsc();
		while (ctx->state) {
			tsc = rte_rdtsc();
			if (tsc > start_tsc + aging_tsc)
				break;
			us = (start_tsc + aging_tsc - tsc) /
			     (rte_get_tsc_hz() / 1000000);
			if (!us)
				break;
			usleep(us);
		}
		ctx->stats.idle += (tsc - tsc_idle);
	}
	ctx->thread = 0;
	RTE_LOG(INFO, VSWITCH, "aging task stopped\n");
}

int
aging_init(void)
{
	int ret;
	char thread_name[RTE_MAX_THREAD_NAME_LEN];
	unsigned int lcore_id = rte_lcore_id();
	cpu_set_t *cpusetp = (void *)&lcore_config[lcore_id].cpuset;
	pthread_attr_t attr;
	uint32_t i;

	if (ctx)
		return 0;
	/* Init aging context. */
	ctx = rte_zmalloc_socket(__func__, sizeof(*ctx), 0, rte_socket_id());
	if (!ctx)
		rte_panic("Cannot allocate memory for aging context\n");
	for (i = 0; i < RTE_DIM(ctx->requests); ++i) {
		ctx->requests[i].min = -1;
		ctx->requests[i].buf = rte_malloc_socket(NULL,
			AGING_PAGE_SIZE * sizeof(*ctx->requests[i].buf),
			4096, rte_socket_id());
		if (!ctx->requests[i].buf)
			rte_panic("Cannot allocate memory for aging request %u\n",
				  i);
	}
	ctx->resp_ring = rte_ring_create("aging_response", AGING_N_REQS,
					 rte_socket_id(),
					 RING_F_SP_ENQ | RING_F_SC_DEQ |
					 RING_F_EXACT_SZ);
	if (!ctx->resp_ring) {
		RTE_LOG(ERR, VSWITCH, "Cannot init pthread cond\n");
		return -rte_errno;
	}
	ctx->state = 1;
	ret = pthread_cond_init(&ctx->cond, NULL);
	if (ret)
		RTE_LOG(ERR, VSWITCH, "Cannot init pthread cond\n");
	aging_tsc = rte_get_tsc_hz() / (1e6 / AGING_INTERVAL_US);
	/* Start aging thread. */
	pthread_attr_init(&attr);
	ret = pthread_attr_setaffinity_np(&attr, sizeof(*cpusetp), cpusetp);
	if (ret != 0)
		RTE_LOG(INFO, VSWITCH, "Cannot set thread affinity\n");
	ret = pthread_create(&ctx->thread, NULL, (void *)aging_task, NULL);
	if (ret)
		rte_panic("Cannot create aging thread for\n");
	snprintf(thread_name, RTE_MAX_THREAD_NAME_LEN, "flow-aging");
	ret = pthread_setname_np(ctx->thread, thread_name);
	if (ret != 0)
		RTE_LOG(INFO, VSWITCH, "Cannot set thread name\n");
	RTE_LOG(INFO, VSWITCH, "aging task %lu created\n", ctx->thread);
	return 0;
}

/*
 * Reset aging data inside port.
 * Used on port fw reset.
 */
void
aging_reset(int port)
{
	uint32_t j;
	struct aging_counter_page *page;

	if (!ctx->ports[port].port)
		return;
	for (j = 0; j < RTE_DIM(ctx->ports[0].pages); ++j) {
		page = ctx->ports[port].pages[j];
		if (!page)
			continue;
		rte_spinlock_lock(&page->lock);
		page->min = -1;
		page->max = -1;
		page->n_counter_segs = 0;
		memset(page->flows, 0, sizeof(page->flows));
		memset(page->map_cl, 0, sizeof(page->map_cl));
		memset(page->map_reuse, 0, sizeof(page->map_reuse));
		memset(page->counter_segs, 0, sizeof(page->counter_segs));
		rte_spinlock_unlock(&page->lock);
	}
	RTE_LOG(INFO, VSWITCH, "aging port %d reset\n", port);
	ctx->ports[port].n_counter = 0;
	ctx->ports[port].n_reusable = 0;
	memset(ctx->ports[port].map_reuse, 0,
	       sizeof(ctx->ports[port].map_reuse));
}

static uint32_t
aging_free_page(struct aging_port_context *port,
		struct aging_counter_page *page)
{
	uint32_t k;
	struct rte_flow_error error;
	int rc;

	rte_spinlock_lock(&page->lock);
	for (k = 0; ctx->pressure != 1 && k < page->n_counter_segs; k++) {
		if (!page->counter_segs[k].handle)
			continue;
		rc = rte_flow_counter_free(port->port_id,
					   page->counter_segs[k].handle,
					   &error);
		if (rc)
			RTE_LOG(ERR, VSWITCH, "Failed to free counter%s\n",
				error.message);
	}
	rte_free(page);
	return k;
}

void
aging_close(void)
{
	uint32_t i, j;
	struct aging_counter_page *page;

	if (!ctx)
		return;
	ctx->state = 0;
	while (ctx->thread)
		sleep(0); /* wait aging thread to close */
	for (i = 0; i < RTE_DIM(ctx->ports); ++i) {
		if (!ctx->ports[i].port)
			continue;
		for (j = 0; j < RTE_DIM(ctx->ports[0].pages); ++j) {
			page = ctx->ports[i].pages[j];
			if (!page)
				continue;
			aging_free_page(&ctx->ports[i], page);
		}
	}
	rte_ring_free(ctx->resp_ring);
	for (i = 0; i < RTE_DIM(ctx->requests); ++i)
		rte_free(ctx->requests[i].buf);
	rte_free(ctx);
	ctx = NULL;
	RTE_LOG(INFO, VSWITCH, "aging closed\n");
}

void
aging_dump(int clear)
{
	uint64_t active = ctx->stats.active;
	double ttl = ctx->stats.idle + ctx->stats.active;

	printf("Aging %d async requests, %u responses, scanning page %hu of %hu/%hu, aging %d/%d flow, total aged %d\n",
	       ctx->n_async, rte_ring_count(ctx->resp_ring),
	       ctx->stats.n_pages_last_active,
	       ctx->stats.n_pages_active, ctx->stats.n_pages,
	       ctx->stats.n_last_aged,
	       ctx->stats.n_flows, ctx->stats.n_aged);
	printf("Aging active: %.3lf%% (query: %.3lf%% wait: %.3lf%% scan: %.3lf%% destroy: %.3lf%%), %lums - %lums\n",
	       active * 100 / (double)ttl,
	       ctx->stats.query * 100 / (double)active,
	       ctx->stats.wait * 100 / (double)active,
	       ctx->stats.scan * 100 / (double)active,
	       ctx->stats.destroy * 100 / (double)active,
	       ctx->stats.min_active * 1000 / rte_get_tsc_hz(),
	       ctx->stats.max_active * 1000 / rte_get_tsc_hz());
	/* Clear average time between each dump. */
	ctx->stats.idle = 0;
	ctx->stats.active = 0;
	ctx->stats.scan = 0;
	ctx->stats.query = 0;
	ctx->stats.wait = 0;
	ctx->stats.destroy = 0;
	ctx->stats.max_active = 0;
	/* Clear stats. */
	if (clear)
		ctx->stats.n_aged = ctx->stats.n_flows;
	rte_qpool_dump(&ctx->flow_pool, "flow_pool", clear);
}

/*
 * Simulate new flows for pressure test.
 */
void
rte_vswitch_aging_pressure(struct rte_vswitch_ctx *port, uint16_t vport,
			   int mode, int count, uint16_t timeout)
{
	int i;
	struct rte_vswitch_offload_flow *flow;
	int counter_id;
	void *handle;
	struct rte_flow_count_value bias;
	uint64_t total_time = 0;
	struct rte_vswitch_flow_keys key = { .tunnel_type = RTE_VSWITCH_TUNNEL_TYPE_VXLAN };
	struct rte_vswitch_flow_actions action = {
		.count = 1, .timeout = timeout, .vport_id = 0
	};
	static uint32_t seq;

	ctx->pressure = mode;
	PERF_START();
	for (i = 0; ctx->pressure == 3 && i < count; ++i) {
		key.outer.dst_addr = seq++;
		if (!rte_vswitch_create_offload_flow(port, vport, &key,
						     &action))
			RTE_LOG(ERR, VSWITCH, "failed to create flow %d\n", i);
	}
	for (i = 0; ctx->pressure && ctx->pressure < 3 && i < count; ++i) {
		handle = aging_counter_alloc(port->pf->data->port_id,
					     (uint32_t *)&counter_id, &bias);
		if (!handle)
			return;
		flow = rte_qpool_malloc(&ctx->flow_pool, sizeof(*flow));
		if (!flow) {
			RTE_LOG(ERR, VSWITCH, "aging failed to malloc flow from pool %d\n",
				i);
			return;
		}
		aging_on_flow_create(port->pf->data->port_id, flow,
				     timeout, counter_id);
	}
	PERF_ADD(total_time);
	printf("Created %d flows in %.3f seconds\n", i,
	       ((double)total_time) / (double)rte_get_tsc_hz());
}
