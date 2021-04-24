#include "libnfv_lb.h"

#define MK_FLOW_ITEM(t, s) \
	[RTE_FLOW_ITEM_TYPE_ ## t] = { \
		.name = # t, \
		.size = s, \
	}

/** Information about known flow pattern items. */
static const struct {
	const char *name;
	size_t size;
} flow_item[] = {
	MK_FLOW_ITEM(END, 0),
	MK_FLOW_ITEM(VOID, 0),
	MK_FLOW_ITEM(INVERT, 0),
	MK_FLOW_ITEM(ANY, sizeof(struct rte_flow_item_any)),
	MK_FLOW_ITEM(PF, 0),
	MK_FLOW_ITEM(VF, sizeof(struct rte_flow_item_vf)),
	MK_FLOW_ITEM(PORT, sizeof(struct rte_flow_item_port)),
	MK_FLOW_ITEM(PORT_ID, sizeof(struct rte_flow_item_port_id)),
	MK_FLOW_ITEM(RAW, sizeof(struct rte_flow_item_raw)),
	MK_FLOW_ITEM(ETH, sizeof(struct rte_flow_item_eth)),
	MK_FLOW_ITEM(VLAN, sizeof(struct rte_flow_item_vlan)),
	MK_FLOW_ITEM(IPV4, sizeof(struct rte_flow_item_ipv4)),
	MK_FLOW_ITEM(IPV6, sizeof(struct rte_flow_item_ipv6)),
	MK_FLOW_ITEM(ICMP, sizeof(struct rte_flow_item_icmp)),
	MK_FLOW_ITEM(ICMPV6, sizeof(struct rte_flow_item_icmpv6)),
	MK_FLOW_ITEM(UDP, sizeof(struct rte_flow_item_udp)),
	MK_FLOW_ITEM(TCP, sizeof(struct rte_flow_item_tcp)),
	MK_FLOW_ITEM(SCTP, sizeof(struct rte_flow_item_sctp)),
	MK_FLOW_ITEM(VXLAN, sizeof(struct rte_flow_item_vxlan)),
	MK_FLOW_ITEM(VXLAN_GPE, sizeof(struct rte_flow_item_vxlan_gpe)),
	MK_FLOW_ITEM(E_TAG, sizeof(struct rte_flow_item_e_tag)),
	MK_FLOW_ITEM(NVGRE, sizeof(struct rte_flow_item_nvgre)),
	MK_FLOW_ITEM(MPLS, sizeof(struct rte_flow_item_mpls)),
	MK_FLOW_ITEM(GRE, sizeof(struct rte_flow_item_gre)),
	MK_FLOW_ITEM(GRE_OPT_KEY, sizeof(struct rte_flow_item_gre_opt_key)),
	MK_FLOW_ITEM(FUZZY, sizeof(struct rte_flow_item_fuzzy)),
	MK_FLOW_ITEM(GTP, sizeof(struct rte_flow_item_gtp)),
	MK_FLOW_ITEM(GTPC, sizeof(struct rte_flow_item_gtp)),
	MK_FLOW_ITEM(GTPU, sizeof(struct rte_flow_item_gtp)),
	MK_FLOW_ITEM(META, sizeof(struct rte_flow_item_meta)),
	MK_FLOW_ITEM(META_EXT, sizeof(struct rte_flow_item_meta_ext)),
};

/** Generate flow_action[] entry. */
#define MK_FLOW_ACTION(t, s) \
	[RTE_FLOW_ACTION_TYPE_ ## t] = { \
		.name = # t, \
		.size = s, \
	}

/** Information about known flow actions. */
static const struct {
	const char *name;
	size_t size;
} flow_action[] = {
	MK_FLOW_ACTION(END, 0),
	MK_FLOW_ACTION(VOID, 0),
	MK_FLOW_ACTION(PASSTHRU, 0),
	MK_FLOW_ACTION(MARK, sizeof(struct rte_flow_action_mark)),
	MK_FLOW_ACTION(FLAG, 0),
	MK_FLOW_ACTION(QUEUE, sizeof(struct rte_flow_action_queue)),
	MK_FLOW_ACTION(DROP, 0),
	MK_FLOW_ACTION(COUNT, 0),
	MK_FLOW_ACTION(DUP, sizeof(struct rte_flow_action_dup)),
	MK_FLOW_ACTION(RSS, sizeof(struct rte_flow_action_rss)), /* +queue[] */
	MK_FLOW_ACTION(PF, 0),
	MK_FLOW_ACTION(VF, sizeof(struct rte_flow_action_vf)),
	MK_FLOW_ACTION(TUNNEL_L3_ENCAP,
		       sizeof(struct rte_flow_action_tunnel_l3_encap)),
	MK_FLOW_ACTION(TUNNEL_L3_DECAP,
		       sizeof(struct rte_flow_action_tunnel_l3_decap)),
	MK_FLOW_ACTION(SET_IPV4_SRC,
		       sizeof(struct rte_flow_action_set_ipv4)),
	MK_FLOW_ACTION(SET_IPV4_DST,
		       sizeof(struct rte_flow_action_set_ipv4)),
	MK_FLOW_ACTION(SET_IPV6_SRC,
		       sizeof(struct rte_flow_action_set_ipv6)),
	MK_FLOW_ACTION(SET_IPV6_DST,
		       sizeof(struct rte_flow_action_set_ipv6)),
	MK_FLOW_ACTION(SET_TP_SRC,
		       sizeof(struct rte_flow_action_set_tp)),
	MK_FLOW_ACTION(SET_TP_DST,
		       sizeof(struct rte_flow_action_set_tp)),
	MK_FLOW_ACTION(DEC_TTL, 0),
	MK_FLOW_ACTION(SET_TTL,
		       sizeof(struct rte_flow_action_set_ttl)),
	MK_FLOW_ACTION(SET_MAC_SRC,
		       sizeof(struct rte_flow_action_set_mac)),
	MK_FLOW_ACTION(SET_MAC_DST,
		       sizeof(struct rte_flow_action_set_mac)),
	MK_FLOW_ACTION(JUMP,
		       sizeof(struct rte_flow_action_jump)),
	MK_FLOW_ACTION(VXLAN_ENCAP,
		       sizeof(struct rte_flow_action_vxlan_encap)),
	MK_FLOW_ACTION(VXLAN_DECAP, 0),
	MK_FLOW_ACTION(NVGRE_ENCAP,
		       sizeof(struct rte_flow_action_nvgre_encap)),
	MK_FLOW_ACTION(NVGRE_DECAP, 0),
	MK_FLOW_ACTION(RAW_ENCAP,
		       sizeof(struct rte_flow_action_raw_encap)),
	MK_FLOW_ACTION(RAW_DECAP,
		       sizeof(struct rte_flow_action_raw_decap)),
	MK_FLOW_ACTION(PORT_ID, sizeof(struct rte_flow_action_port_id)),
	MK_FLOW_ACTION(OF_POP_VLAN, 0),
	MK_FLOW_ACTION(OF_PUSH_VLAN,
		       sizeof(struct rte_flow_action_of_push_vlan)),
	MK_FLOW_ACTION(OF_SET_VLAN_VID,
		       sizeof(struct rte_flow_action_of_set_vlan_vid)),
	MK_FLOW_ACTION(OF_SET_VLAN_PCP,
		       sizeof(struct rte_flow_action_of_set_vlan_pcp)),
	MK_FLOW_ACTION(OF_POP_MPLS,
		       sizeof(struct rte_flow_action_of_pop_mpls)),
	MK_FLOW_ACTION(OF_PUSH_MPLS,
		       sizeof(struct rte_flow_action_of_push_mpls)),
	MK_FLOW_ACTION(INC_TCP_SEQ,
		       sizeof(struct rte_flow_action_modify_tcp_seq)),
	MK_FLOW_ACTION(DEC_TCP_SEQ,
		       sizeof(struct rte_flow_action_modify_tcp_seq)),
	MK_FLOW_ACTION(INC_TCP_ACK,
		       sizeof(struct rte_flow_action_modify_tcp_ack)),
	MK_FLOW_ACTION(DEC_TCP_ACK,
		       sizeof(struct rte_flow_action_modify_tcp_ack)),
	MK_FLOW_ACTION(METER,
		       sizeof(struct rte_flow_action_meter)),
	MK_FLOW_ACTION(SET_META,
	       sizeof(struct rte_flow_action_set_meta)),

};

/** Print a message out of a flow error. */
int
lcore_flow_complain(struct rte_flow_error *error)
{
	static const char *const errstrlist[] = {
		[RTE_FLOW_ERROR_TYPE_NONE] = "no error",
		[RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
		[RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
		[RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
		[RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
		[RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
		[RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
		[RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
		[RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
		[RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
		[RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
	};
	const char *errstr;
	char buf[32];
	int err = rte_errno;

	if ((unsigned int)error->type >= RTE_DIM(errstrlist) ||
	    !errstrlist[error->type])
		errstr = "unknown type";
	else
		errstr = errstrlist[error->type];
	printf("Caught error type %d (%s): %s%s\n",
	       error->type, errstr,
	       error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ",
					error->cause), buf) : "",
	       error->message ? error->message : "(no stated reason)");
	return -err;
}

/** Compute storage space needed by item specification. */
void
flow_item_spec_size(const struct rte_flow_item *item,
		    size_t *size, size_t *pad)
{
	if (!item->spec) {
		*size = 0;
		goto empty;
	}
	switch (item->type) {
		union {
			const struct rte_flow_item_raw *raw;
		} spec;

	case RTE_FLOW_ITEM_TYPE_RAW:
		spec.raw = item->spec;
		*size = offsetof(struct rte_flow_item_raw, pattern) +
			spec.raw->length * sizeof(*spec.raw->pattern);
		break;
	default:
		*size = flow_item[item->type].size;
		break;
	}
empty:
	*pad = RTE_ALIGN_CEIL(*size, sizeof(double)) - *size;
}

/** Compute storage space needed by action configuration. */
void
flow_action_conf_size(const struct rte_flow_action *action,
		      size_t *size, size_t *pad)
{
	if (!action->conf) {
		*size = 0;
		goto empty;
	}
	switch (action->type) {
		union {
			const struct rte_flow_action_rss *rss;
		} conf;

	case RTE_FLOW_ACTION_TYPE_RSS:
		conf.rss = action->conf;
		*size = offsetof(struct rte_flow_action_rss, queue) +
			conf.rss->num * sizeof(*conf.rss->queue);
		break;
	default:
		*size = flow_action[action->type].size;
		break;
	}
empty:
	*pad = RTE_ALIGN_CEIL(*size, sizeof(double)) - *size;
}

/** Generate a port_flow entry from attributes/pattern/actions. */
struct lcore_flow *
lcore_flow_new(const struct rte_flow_attr *attr,
	      const struct rte_flow_item *pattern,
	      const struct rte_flow_action *actions)
{
	const struct rte_flow_item *item;
	const struct rte_flow_action *action;
	struct lcore_flow *pf = NULL;
	size_t tmp;
	size_t pad;
	size_t off1 = 0;
	size_t off2 = 0;
	int err = ENOTSUP;

store:
	item = pattern;
	if (pf)
		pf->pattern = (void *)&pf->data[off1];
	do {
		struct rte_flow_item *dst = NULL;

		if ((unsigned int)item->type >= RTE_DIM(flow_item) ||
		    !flow_item[item->type].name)
			goto notsup;
		if (pf)
			dst = memcpy(pf->data + off1, item, sizeof(*item));
		off1 += sizeof(*item);
		flow_item_spec_size(item, &tmp, &pad);
		if (item->spec) {
			if (pf)
				dst->spec = memcpy(pf->data + off2,
						   item->spec, tmp);
			off2 += tmp + pad;
		}
		if (item->last) {
			if (pf)
				dst->last = memcpy(pf->data + off2,
						   item->last, tmp);
			off2 += tmp + pad;
		}
		if (item->mask) {
			if (pf)
				dst->mask = memcpy(pf->data + off2,
						   item->mask, tmp);
			off2 += tmp + pad;
		}
		off2 = RTE_ALIGN_CEIL(off2, sizeof(double));
	} while ((item++)->type != RTE_FLOW_ITEM_TYPE_END);
	off1 = RTE_ALIGN_CEIL(off1, sizeof(double));
	action = actions;
	if (pf)
		pf->actions = (void *)&pf->data[off1];
	do {
		struct rte_flow_action *dst = NULL;

		if ((unsigned int)action->type >= RTE_DIM(flow_action) ||
		    !flow_action[action->type].name)
			goto notsup;
		if (pf)
			dst = memcpy(pf->data + off1, action, sizeof(*action));
		off1 += sizeof(*action);
		flow_action_conf_size(action, &tmp, &pad);
		if (action->conf) {
			if (pf)
				dst->conf = memcpy(pf->data + off2,
						   action->conf, tmp);
			off2 += tmp + pad;
		}
		off2 = RTE_ALIGN_CEIL(off2, sizeof(double));
	} while ((action++)->type != RTE_FLOW_ACTION_TYPE_END);
	if (pf != NULL)
		return pf;
	off1 = RTE_ALIGN_CEIL(off1, sizeof(double));
	tmp = RTE_ALIGN_CEIL(offsetof(struct lcore_flow, data), sizeof(double));
	pf = calloc(1, tmp + off1 + off2);
	if (pf == NULL)
		err = errno;
	else {
		*pf = (const struct lcore_flow){
			.size = tmp + off1 + off2,
			.attr = *attr,
		};
		tmp -= offsetof(struct lcore_flow, data);
		off2 = tmp + off1;
		off1 = tmp;
		goto store;
	}
notsup:
	rte_errno = err;
	return NULL;
}

/** Create flow rule. */
int
lcore_flow_create(uint16_t port_id, uint16_t lcore_id,
		 const struct rte_flow_attr *attr,
		 const struct rte_flow_item *pattern,
		 const struct rte_flow_action *actions)
{
	struct rte_flow *flow;
//	struct rte_port *port;
	struct lcore_conf *qconf;
	struct lcore_flow *pf;
	uint32_t id;
	struct rte_flow_error error;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x22, sizeof(error));
	flow = rte_flow_create(port_id, attr, pattern, actions, &error);
	if (!flow)
		return lcore_flow_complain(&error);
	qconf = &lcore_conf[lcore_id];
	if (qconf->flow_list) {
		if (qconf->flow_list->id == UINT32_MAX) {
			printf("Highest rule ID is already assigned, delete"
			       " it first");
			rte_flow_destroy(port_id, flow, NULL);
			return -ENOMEM;
		}
		id = qconf->flow_list->id + 1;
	} else
		id = 0;
	pf = lcore_flow_new(attr, pattern, actions);
	if (!pf) {
		int err = rte_errno;

		printf("Cannot allocate flow: %s\n", rte_strerror(err));
		rte_flow_destroy(port_id, flow, NULL);
		return -err;
	}
	pf->next = qconf->flow_list;
	pf->id = id;
	pf->flow = flow;
	qconf->flow_list = pf;
	// if (!(verbose_level & 0x8000))
	// 	printf("Flow rule #%u created\n", pf->id);
	return 0;
}

/** Destroy a number of flow rules. */
int
lcore_flow_destroy(uint16_t port_id, uint16_t lcore_id, uint32_t n, const uint32_t *rule)
{
	//struct rte_port *port;
	struct lcore_conf *qconf;
	struct lcore_flow **tmp;
	uint32_t c = 0;
	int ret = 0;

	// if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	//     port_id == (portid_t)RTE_PORT_ALL)
	// 	return -EINVAL;
	qconf = &lcore_conf[lcore_id];
	tmp = &qconf->flow_list;
	while (*tmp) {
		uint32_t i;

		for (i = 0; i != n; ++i) {
			struct rte_flow_error error;
			struct lcore_flow *pf = *tmp;

			if (rule[i] != pf->id)
				continue;
			/*
			 * Poisoning to make sure PMDs update it in case
			 * of error.
			 */
			memset(&error, 0x33, sizeof(error));
			if (rte_flow_destroy(port_id, pf->flow, &error)) {
				ret = lcore_flow_complain(&error);
				continue;
			}
			printf("Flow rule #%u destroyed\n", pf->id);
			*tmp = pf->next;
			free(pf);
			break;
		}
		if (i == n)
			tmp = &(*tmp)->next;
		++c;
	}
	return ret;
}

/*
 * 函数的作用：下发指定规则的flow
 * 
 *
 */
#define MAX_PATTERN_NUM		3
#define MAX_ACTION_NUM		2
int
generate_ipv4_flow(uint16_t port_id, uint16_t lcore_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	//struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = rx_q };
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	int res;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (ETH).
	 * since in this example we just want to get the
	 * ipv4 we set this level to allow all.
	 */
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

	/*
	 * setting the second level of the pattern (IP).
	 * in this example this is the level we care about
	 * so we set it according to the parameters.
	 */
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ip_spec.hdr.dst_addr = htonl(dest_ip);
	ip_mask.hdr.dst_addr = dest_mask;
	ip_spec.hdr.src_addr = htonl(src_ip);
	ip_mask.hdr.src_addr = src_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;

	/* the final level must be always type end */
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	// res = rte_flow_validate(port_id, &attr, pattern, action, error);
	// if (!res)
	res = lcore_flow_create(port_id, lcore_id, &attr, pattern, action);

	//	printf("\nflow rule created!\n");

	return res;
}

/**
 * 函数的作用：清楚port上下发的所有fdir规则
 * 
 *
 */
int
port_flow_flush(uint16_t port_id)
{
	struct rte_flow_error error;
	struct lcore_conf *qconf;
	uint16_t lcore_id = 0;
	int ret = 0;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x44, sizeof(error));
	if (rte_flow_flush(port_id, &error)) {
		ret = lcore_flow_complain(&error);
		// if (port_id_is_invalid(port_id, DISABLED_WARN) ||
		//     port_id == (portid_t)RTE_PORT_ALL)
		// 	return ret;
	}
	for(lcore_id=0;lcore_id<RTE_MAX_LCORE;lcore_id++){
		qconf = &lcore_conf[lcore_id];
		while (qconf->flow_list) {
			struct lcore_flow *pf = qconf->flow_list->next;

			free(qconf->flow_list);
			qconf->flow_list = pf;
		}
	}
	return ret;
}


/**
 * 函数的作用：测试下发函数，在初始化的时候下发100条规则测试是否正常；
 * fdir最开始的几条规则下发时间远大于平均时间，为消除影响，在初始化的时候先下发一部分规则以减少影响
 * 
 *
 */
void 
nfv_lb_init_fdir(void)
{
	uint16_t num = 6;
	uint8_t selected_queue = 2;
	uint32_t src_ip = (2<<24) + (2<<16) + (2<<8) + 4;
	uint32_t dst_ip = (2<<24) + (2<<16) + (2<<8) + 6;
	uint32_t src_mask = 0x0;
	uint32_t dst_mask = 0xffffffff;
	uint16_t port_id = 0;
	int res, cout;

	for(cout=0;cout<100;cout++)
	{
		dst_ip += cout;
		res = generate_ipv4_flow(port_id, num, selected_queue, src_ip, src_mask,dst_ip, dst_mask);
		if(res)
		{
			rte_exit(EXIT_FAILURE, "error in creating flow");
		}
		else
			printf("flow rule %d created!\n",lcore_conf[num].flow_list->id);
	}
}

/**
 * 函数的作用：通过判断rq_ci左边第K个位置的CQE来判断当前网卡硬件队列是否发生拥塞
 * 
 *
 */
// int nfv_lb_burst_detection(struct data_from_driver * nic_rxq_data){
//     unsigned int k = 128;
// 	uint8_t op_code, op_owner, op_own;

//     if(nic_rxq_data == NULL)
//         return 0;

// 	unsigned int pos = (nic_rxq_data->nic_rq_ci - k) & (nic_rxq_data->nic_q_n -1);
// 	unsigned int ownership = !!((nic_rxq_data->nic_rq_ci - k) & nic_rxq_data->nic_q_n);
// 	op_own = (nic_rxq_data ->nic_cq + pos) ->op_own;
// 	op_owner = op_own & 0x1;
// 	op_code = op_own >> 4;
// 	if ((op_owner != ownership) || (op_code == 0xf))
// 		return 0; /* No CQE. */
// 	return 1;               
// }

// uint16_t nfv_lb_queue_size_check(struct data_from_driver * nic_rxq_data){
// 	uint8_t op_code, op_owner, op_own;
// 	uint16_t counter;
// 	uint16_t n;

// 	if(nic_rxq_data == NULL)
// 		return 0;

// 	for(n=0; n<nic_rxq_data->nic_q_n; n++){
// 		unsigned int pos = (nic_rxq_data->nic_rq_ci - n) & (nic_rxq_data->nic_q_n -1);
// 		unsigned int ownership = !!((nic_rxq_data->nic_rq_ci - n) & nic_rxq_data->nic_q_n);	
// 		op_own = (nic_rxq_data ->nic_cq + pos) ->op_own;
// 		op_owner = op_own & 0x1;
// 		op_code = op_own >> 4;
// 		if ((op_owner != ownership) || (op_code == 0xf))
// 			continue; /* No CQE. */
// 		else 
// 			break;
// 	}
// 	return nic_rxq_data->nic_q_n - n;
// }

void solver(void){
	unsigned int a,b;
	srand((unsigned)rte_rdtsc());
	a = rand()%100;
	if(a<=85){
		if(a<=10)
		{
			b=rand()%20;
			rte_delay_us(b);
		}
		else{
			b =rand()%15+20;
			rte_delay_us(b);
		}

	}
	else{
		b = rand()%35+35;
		rte_delay_us(b);
	}

}