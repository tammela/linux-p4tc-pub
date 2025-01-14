/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_P4TC_H
#define __NET_P4TC_H

#include <uapi/linux/p4tc.h>
#include <linux/workqueue.h>
#include <net/sch_generic.h>
#include <net/net_namespace.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/rhashtable-types.h>
#include <net/tc_act/p4tc.h>
#include <net/p4tc_types.h>
#include <linux/bpf.h>

#define P4TC_DEFAULT_NUM_TABLES P4TC_MINTABLES_COUNT
#define P4TC_DEFAULT_MAX_RULES 1
#define P4TC_PATH_MAX 3
#define P4TC_MAX_TENTRIES 0x2000000
#define P4TC_DEFAULT_TENTRIES 256
#define P4TC_MAX_TMASKS 1024
#define P4TC_DEFAULT_TMASKS 8
#define P4TC_MAX_T_AGING_MS 864000000
#define P4TC_DEFAULT_T_AGING_MS 30000
#define P4TC_DEFAULT_NUM_TIMER_PROFILES 4
#define P4TC_MAX_NUM_TIMER_PROFILES P4TC_MSGBATCH_SIZE

#define P4TC_TIMER_PROFILE_ZERO_AGING_MS 30000
#define P4TC_DEFAULT_TIMER_PROFILE_ID 0

#define P4TC_DEFAULT_NUM_EXT_INSTS 1
#define P4TC_MAX_NUM_EXT_INSTS 1024
#define P4TC_DEFAULT_NUM_EXT_INST_ELEMS 1
#define P4TC_MAX_NUM_EXT_INST_ELEMS P4TC_MAX_TENTRIES

#define P4TC_MAX_PERMISSION (GENMASK(P4TC_PERM_MAX_BIT, 0))

#define P4TC_KERNEL_PIPEID 0

#define P4TC_PID_IDX 0
#define P4TC_TBLID_IDX 1
#define P4TC_AID_IDX 1
#define P4TC_PARSEID_IDX 1
#define P4TC_TMPL_EXT_IDX 1
#define P4TC_TMPL_EXT_INST_IDX 2

struct p4tc_filter {
	struct p4tc_filter_oper *operation;
	union {
		struct {
			u32 tbl_id;
			u32 ext_id;
		};
	};
	u32 obj_id;
};

struct p4tc_filter_context {
	struct p4tc_pipeline *pipeline;
	union {
		struct p4tc_table *table;
		struct p4tc_extern_inst *inst;
	};
	int cmd;
	u32 obj_id;
};

struct p4tc_dump_ctx {
	u32 ids[P4TC_PATH_MAX];
	struct rhashtable_iter *iter;
	struct p4tc_filter *entry_filter;
};

struct p4tc_filter_data {
	union {
		struct {
			u32 id;
			struct p4tc_table_entry *entry;
		} table;
		struct p4tc_extern_common *common;
	};
	int cmd;
	u32 obj_id;
};

enum {
	P4TC_FILTER_OBJ_UNSPEC,
	P4TC_FILTER_OBJ_TMPL_PIPELINE,
	P4TC_FILTER_OBJ_TMPL_ACT,
	P4TC_FILTER_OBJ_TMPL_TABLE,
	P4TC_FILTER_OBJ_TMPL_EXT,
	P4TC_FILTER_OBJ_RUNTIME_TABLE,
	P4TC_FILTER_OBJ_RUNTIME_EXT,
	__P4TC_FILTER_OBJ_MAX,
};

#define P4TC_FILTER_OBJ_MAX (__P4TC_FILTER_OBJ_MAX - 1)

enum {
	P4TC_FILTER_OPND_KIND_UNSPEC,
	P4TC_FILTER_OPND_KIND_ENTRY,
	P4TC_FILTER_OPND_KIND_CMD,
	P4TC_FILTER_OPND_KIND_EXT,
	P4TC_FILTER_OPND_KIND_EXT_PARAM,
	__P4TC_FILTER_OPND_KIND_MAX,
};

#define P4TC_FILTER_OPND_KIND_MAX (__P4TC_FILTER_OPND_KIND_MAX - 1)

static inline int
p4tc_nlmsg_filtered_notify(struct net *net, struct sk_buff *skb,
			   u32 portid, gfp_t gfp_flags, unsigned int group,
			   bool echo, netlink_filter_fn filter,
			   void *filter_data)
{
	int exclude_portid = 0;
	int err;

	if (echo) {
		refcount_inc(&skb->users);
		exclude_portid = portid;
	}

	err = nlmsg_multicast_filtered(net->rtnl, skb, exclude_portid,
				       group, gfp_flags,
				       filter, filter_data);
	if (err == -ESRCH)
		err = 0;

	if (echo) {
		int err2;

		err2 = nlmsg_unicast(net->rtnl, skb, portid);
		if (!err)
			err = err2;
	}

	if (!err)
		return 0;

	return err;
}

static inline int p4tc_obj_to_filter_obj(const u32 p4tc_obj, bool runtime)
{
	if (runtime) {
		switch (p4tc_obj) {
		case P4TC_OBJ_RUNTIME_TABLE:
			return P4TC_FILTER_OBJ_RUNTIME_TABLE;
		case P4TC_OBJ_RUNTIME_EXTERN:
			return P4TC_FILTER_OBJ_RUNTIME_EXT;
		default:
			return -EINVAL;
		}
	} else {
		switch (p4tc_obj) {
		case P4TC_OBJ_PIPELINE:
			return P4TC_FILTER_OBJ_TMPL_PIPELINE;
		case P4TC_OBJ_ACT:
			return P4TC_FILTER_OBJ_TMPL_ACT;
		case P4TC_OBJ_TABLE:
			return P4TC_FILTER_OBJ_TMPL_TABLE;
		case P4TC_OBJ_EXT:
			return P4TC_FILTER_OBJ_TMPL_EXT;
		default:
			return -EINVAL;
		}
	}
}

struct p4tc_template_common;

struct p4tc_path_nlattrs {
	char                     *pname;
	u32                      *ids;
	bool                     pname_passed;
};

struct p4tc_pipeline;
struct p4tc_template_ops {
	struct p4tc_template_common *(*cu)(struct net *net, struct nlmsghdr *n,
					   struct nlattr *nla,
					   struct p4tc_path_nlattrs *nl_pname,
					   struct netlink_ext_ack *extack);
	int (*put)(struct p4tc_pipeline *pipeline,
		   struct p4tc_template_common *tmpl,
		   struct netlink_ext_ack *extack);
	int (*gd)(struct net *net, struct sk_buff *skb, struct nlmsghdr *n,
		  struct nlattr *nla, struct p4tc_path_nlattrs *nl_pname,
		  struct netlink_ext_ack *extack);
	int (*fill_nlmsg)(struct net *net, struct sk_buff *skb,
			  struct p4tc_template_common *tmpl,
			  struct netlink_ext_ack *extack);
	int (*dump)(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
		    struct nlattr *nla, char **p_name, u32 *ids,
		    struct netlink_ext_ack *extack);
	int (*dump_1)(struct sk_buff *skb, struct p4tc_template_common *common);
	u32 obj_id;
};

struct p4tc_template_common {
	char                     name[P4TC_TMPL_NAMSZ];
	struct p4tc_template_ops *ops;
	u32                      p_id;
	u32                      __pad0;
};

struct p4tc_pipeline {
	struct p4tc_template_common common;
	struct idr                  p_act_idr;
	struct idr                  p_tbl_idr;
	/* IDR where the externs are stored globally in the root pipeline */
	struct idr                  p_ext_idr;
	/* IDR where the per user pipeline data related to externs is stored */
	struct idr                  user_ext_idr;
	struct rcu_head             rcu;
	struct net                  *net;
	u32                         num_created_acts;
	/* Accounts for how many entities are referencing this pipeline.
	 * As for now only P4 filters can refer to pipelines.
	 */
	refcount_t                  p_ctrl_ref;
	u16                         num_tables;
	u16                         curr_tables;
	u8                          p_state;
};

#define P4TC_PIPELINE_MAX_ARRAY 32

struct p4tc_tbl_cache_key {
	u32 pipeid;
	u32 tblid;
};

extern const struct rhashtable_params tbl_cache_ht_params;

struct p4tc_table;

int p4tc_tbl_cache_insert(struct net *net, u32 pipeid,
			  struct p4tc_table *table);
void p4tc_tbl_cache_remove(struct net *net, struct p4tc_table *table);
struct p4tc_table *p4tc_tbl_cache_lookup(struct net *net, u32 pipeid,
					 u32 tblid);

#define P4TC_TBLS_CACHE_SIZE 32

struct p4tc_pipeline_net {
	struct list_head  tbls_cache[P4TC_TBLS_CACHE_SIZE];
	struct idr        pipeline_idr;
};

static inline bool p4tc_tmpl_msg_is_update(struct nlmsghdr *n)
{
	return n->nlmsg_type == RTM_UPDATEP4TEMPLATE;
}

int p4tc_tmpl_register_ops(const struct p4tc_template_ops *tmpl_ops);

int p4tc_tmpl_generic_dump(struct sk_buff *skb, struct p4tc_dump_ctx *ctx,
			   struct idr *idr, int idx,
			   struct netlink_ext_ack *extack);

struct p4tc_pipeline *p4tc_pipeline_find_byany(struct net *net,
					       const char *p_name,
					       const u32 pipeid,
					       struct netlink_ext_ack *extack);
struct p4tc_pipeline *p4tc_pipeline_find_byid(struct net *net,
					      const u32 pipeid);
struct p4tc_pipeline *
p4tc_pipeline_find_get(struct net *net, const char *p_name,
		       const u32 pipeid, struct netlink_ext_ack *extack);
struct p4tc_pipeline *
p4tc_pipeline_find_get_sealed(struct net *net, const char *p_name,
			      const u32 pipeid, struct netlink_ext_ack *extack);

static inline bool p4tc_pipeline_get(struct p4tc_pipeline *pipeline)
{
	return refcount_inc_not_zero(&pipeline->p_ctrl_ref);
}

static inline void p4tc_pipeline_put_ref(struct p4tc_pipeline *pipeline)
{
	refcount_dec(&pipeline->p_ctrl_ref);
}

void p4tc_pipeline_put(struct p4tc_pipeline *pipeline);
struct p4tc_pipeline *
p4tc_pipeline_find_byany_unsealed(struct net *net, const char *p_name,
				  const u32 pipeid,
				  struct netlink_ext_ack *extack);

struct p4tc_act *p4a_runt_find(struct net *net,
			       const struct tc_action_ops *a_o,
			       struct netlink_ext_ack *extack);
void
p4a_runt_prealloc_put(struct p4tc_act *act, struct tcf_p4act *p4_act);

static inline bool p4tc_pipeline_sealed(struct p4tc_pipeline *pipeline)
{
	return pipeline->p_state == P4TC_STATE_READY;
}

static inline int p4tc_action_destroy(struct tc_action *acts[])
{
	struct tc_action *acts_non_prealloc[TCA_ACT_MAX_PRIO] = {NULL};
	struct tc_action *a;
	int ret = 0;
	int j = 0;
	int i;

	tcf_act_for_each_action(i, a, acts) {
		if (acts[i]->tcfa_flags & TCA_ACT_FLAGS_PREALLOC) {
			struct tcf_p4act *p4act;
			struct p4tc_act *act;
			struct net *net;

			p4act = (struct tcf_p4act *)acts[i];
			net = maybe_get_net(acts[i]->idrinfo->net);

			if (net) {
				const struct tc_action_ops *ops;

				ops = acts[i]->ops;
				act = p4a_runt_find(net, ops, NULL);
				p4a_runt_prealloc_put(act, p4act);
				put_net(net);
			} else {
				/* If net is coming down, template
				 * action will be deleted, so no need to
				 * remove from prealloc list, just decr
				 * refcounts.
				 */
				acts_non_prealloc[j] = acts[i];
				j++;
			}
		} else {
			acts_non_prealloc[j] = acts[i];
			j++;
		}
	}

	ret = tcf_action_destroy(acts_non_prealloc, TCA_ACT_UNBIND);

	return ret;
}

#define P4TC_CONTROL_PERMISSIONS (GENMASK(13, 7))
#define P4TC_DATA_PERMISSIONS (GENMASK(6, 0))

#define P4TC_TABLE_DEFAULT_PERMISSIONS                                   \
	((GENMASK(P4TC_CTRL_PERM_C_BIT, P4TC_CTRL_PERM_D_BIT)) | \
	 P4TC_CTRL_PERM_P | P4TC_CTRL_PERM_S | P4TC_DATA_PERM_R | \
	 P4TC_DATA_PERM_X)

#define P4TC_EXTERN_DEFAULT_PERMISSIONS \
	(P4TC_CTRL_PERM_R | P4TC_CTRL_PERM_U | P4TC_CTRL_PERM_P | \
	 P4TC_CTRL_PERM_S | P4TC_DATA_PERM_R | P4TC_DATA_PERM_X)

#define P4TC_PERMISSIONS_UNINIT (1 << P4TC_PERM_MAX_BIT)

#define P4TC_MAX_PARAM_DATA_SIZE 124

#define P4TC_EXT_MAX_PARAM_DATA_SIZE 64

#define P4TC_EXT_FLAGS_UNSPEC 0x0
#define P4TC_EXT_FLAGS_CONTROL_READ 0x1
#define P4TC_EXT_FLAGS_CONTROL_WRITE 0x2

enum {
	P4TC_EXT_INST_FLAGS_UNSPEC,
	P4TC_EXT_INST_FLAGS_HAS_CUST_PARAM,
};

struct p4tc_ext_bpf_params {
	u32 pipe_id;
	u32 ext_id;
	u32 inst_id;
	u32 tbl_id;
	u32 index;
	u32 flags;
	u8  in_params[P4TC_EXT_MAX_PARAM_DATA_SIZE]; /* extern specific params if any */
};

struct p4tc_ext_bpf_val {
	u32 ext_id;
	u32 index;
	u32 verdict;
	u8 out_params[P4TC_EXT_MAX_PARAM_DATA_SIZE]; /* specific values if any */
};

#define P4TC_EXT_CNT_DIRECT BIT(0)
#define P4TC_EXT_CNT_INDIRECT BIT(1)
#define P4TC_EXT_METER_DIRECT BIT(2)
#define P4TC_EXT_METER_INDIRECT BIT(3)

struct p4tc_table_defact {
	struct tc_action *acts[2];
	/* Will have two 7 bits blocks containing CRUDXPS (Create, read, update,
	 * delete, execute, publish and subscribe) permissions for control plane
	 * and data plane. The first 5 bits are for control and the next five
	 * are for data plane. |crudxpscrudxps| if we were to denote it as UNIX
	 * permission flags.
	 */
	__u16 perm;
	struct rcu_head  rcu;
};

struct p4tc_table_perm {
	__u16           permissions;
	struct rcu_head rcu;
};

struct p4tc_table {
	struct p4tc_template_common         common;
	struct list_head                    tbl_cache_node;
	struct list_head                    tbl_acts_list;
	struct idr                          tbl_masks_idr;
	struct ida                          tbl_prio_ida;
	struct xarray                       tbl_profiles_xa;
	struct rhltable                     tbl_entries;
	/* Mutex that protects tbl_profiles_xa */
	struct mutex                        tbl_profiles_xa_lock;
	struct p4tc_table_entry             *tbl_entry;
	struct p4tc_table_defact __rcu      *tbl_dflt_hitact;
	struct p4tc_table_defact __rcu      *tbl_dflt_missact;
	struct p4tc_table_perm __rcu        *tbl_permissions;
	struct p4tc_table_entry_mask __rcu  **tbl_masks_array;
	unsigned long __rcu                 *tbl_free_masks_bitmap;
	struct p4tc_extern_inst             *tbl_counter;
	struct p4tc_extern_inst             *tbl_meter;
	/* Locks the available masks IDR which will be used when adding and
	 * deleting table entries.
	 */
	spinlock_t                          tbl_masks_idr_lock;
	u32                                 tbl_keysz;
	u32                                 tbl_id;
	u32                                 tbl_max_entries;
	u32                                 tbl_max_masks;
	u32                                 tbl_curr_num_masks;
	atomic_t                            tbl_num_timer_profiles;
	/* Accounts for how many entries this table has */
	atomic_t                            tbl_nelems;
	/* Accounts for how many entities refer to this table. Usually just the
	 * pipeline it belongs to.
	 */
	refcount_t                          tbl_ctrl_ref;
	u16                                 tbl_type;
	u16                                 __pad0;
};

struct p4tc_act_param {
	struct list_head head;
	struct rcu_head	rcu;
	void            *value;
	void            *mask;
	struct p4tc_type *type;
	u32             id;
	u32             index;
	u16             bitend;
	u8              flags;
	u8              __pad0;
	char            name[P4TC_ACT_PARAM_NAMSIZ];
};

struct p4tc_act_param_ops {
	int (*init_value)(struct net *net, struct p4tc_act_param_ops *op,
			  struct p4tc_act_param *nparam, struct nlattr **tb,
			  struct netlink_ext_ack *extack);
	int (*dump_value)(struct sk_buff *skb, struct p4tc_act_param_ops *op,
			  struct p4tc_act_param *param);
	void (*free)(struct p4tc_act_param *param);
	u32 len;
	u32 alloc_len;
};

struct p4tc_act {
	struct p4tc_template_common common;
	struct tc_action_ops        ops;
	struct tc_action_net        *tn;
	struct p4tc_pipeline        *pipeline;
	struct idr                  params_idr;
	struct tcf_exts             exts;
	struct list_head            head;
	struct list_head            prealloc_list;
	/* Locks the preallocated actions list.
	 * The list will be used whenever a table entry with an action or a
	 * table default action gets created, updated or deleted. Note that
	 * table entries may be added by both control and data path, so the
	 * list can be modified from both contexts.
	 */
	spinlock_t                  list_lock;
	u32                         a_id;
	u32                         num_params;
	u32                         num_prealloc_acts;
	/* Accounts for how many entities refer to this action. Usually just the
	 * pipeline it belongs to.
	 */
	refcount_t                  a_ref;
	atomic_t                    num_insts;
	bool                        active;
	char                        fullname[ACTNAMSIZ];
};

struct p4tc_table_act {
	struct list_head node;
	struct p4tc_act *act;
	u8     flags;
};

struct p4tc_table_timer_profile {
	struct rcu_head rcu;
	u64 aging_ms;
	u32 profile_id;
};

extern const struct rhashtable_params entry_hlt_params;

struct p4tc_table_entry_act_bpf_params {
	u32 pipeid;
	u32 tblid;
};

struct p4tc_table_entry_create_bpf_params {
	struct p4tc_table_entry_act_bpf act_bpf;
	u32 profile_id;
	u32 pipeid;
	u32 tblid;
	u32 handle;
	u32 chain;
	u32 classid;
	u16 proto;
	u16 prio;
};

enum {
	P4TC_ENTRY_CREATE_BPF_PARAMS_SZ = 160,
	P4TC_ENTRY_ACT_BPF_PARAMS_SZ = 8,
	P4TC_EXT_BPF_PARAMS_SZ = 88,
	P4TC_EXT_BPF_RES_SZ = 76,
};

#define P4TC_TASK_COMM_LEN 64

struct p4tc_table_entry;
struct p4tc_table_entry_work {
	struct work_struct   work;
	char who_deleted[P4TC_TASK_COMM_LEN];
	struct p4tc_pipeline *pipeline;
	struct p4tc_table_entry *entry;
	struct p4tc_table *table;
	u16 who_deleted_ent;
	pid_t who_deleted_pid;
	bool send_event;
};

struct p4tc_table_entry_key {
	u32 keysz;
	/* Key start */
	u32 maskid;
	unsigned char fa_key[] __aligned(8);
};

struct p4tc_table_entry_value_proc {
	char                             who_created[P4TC_TASK_COMM_LEN];
	char                             who_updated[P4TC_TASK_COMM_LEN];
	pid_t                            who_created_pid;
	pid_t                            who_updated_pid;
};

struct p4tc_table_entry_value {
	struct tc_action                         *acts[2];
	struct p4tc_extern_common                *counter;
	struct p4tc_extern_common                *meter;
	/* Accounts for how many entities are referencing it
	 * eg: Data path, one or more control path and timer.
	 */
	u32                                      prio;
	refcount_t                               entries_ref;
	u32                                      permissions;
	u32                                      __pad0;
	struct p4tc_table_entry_tm __rcu         *tm;
	struct p4tc_table_entry_work             *entry_work;
	u64                                      aging_ms;
	struct hrtimer                           entry_timer;
	struct p4tc_table_entry_value_proc __rcu *value_proc;
	bool                                     is_dyn;
	bool                                     tmpl_created;
};

struct p4tc_table_entry_mask {
	struct rcu_head	 rcu;
	u32              sz;
	u32              mask_index;
	/* Accounts for how many entries are using this mask */
	refcount_t       mask_ref;
	u32              mask_id;
	unsigned char fa_value[] __aligned(8);
};

struct p4tc_table_entry {
	struct rcu_head rcu;
	struct rhlist_head ht_node;
	struct p4tc_table_entry_key key;
	/* fallthrough: key data + value */
};

struct p4tc_entry_key_bpf {
	void *key;
	void *mask;
	u32 key_sz;
	u32 mask_sz;
};

#define P4TC_KEYSZ_BYTES(bits) (round_up(BITS_TO_BYTES(bits), 8))

#define P4TC_ENTRY_KEY_SZ_BYTES(bits) \
	(P4TC_ENTRY_KEY_OFFSET + P4TC_KEYSZ_BYTES(bits))

#define P4TC_ENTRY_KEY_OFFSET (offsetof(struct p4tc_table_entry_key, fa_key))

#define P4TC_ENTRY_VALUE_OFFSET(entry) \
	(offsetof(struct p4tc_table_entry, key) + P4TC_ENTRY_KEY_OFFSET \
	 + P4TC_KEYSZ_BYTES((entry)->key.keysz))

static inline void *p4tc_table_entry_value(struct p4tc_table_entry *entry)
{
	return entry->key.fa_key + P4TC_KEYSZ_BYTES(entry->key.keysz);
}

static inline struct p4tc_table_entry_work *
p4tc_table_entry_work(struct p4tc_table_entry *entry)
{
	struct p4tc_table_entry_value *value = p4tc_table_entry_value(entry);

	return value->entry_work;
}

extern const struct nla_policy p4tc_root_policy[P4TC_ROOT_MAX + 1];
extern const struct nla_policy p4tc_policy[P4TC_MAX + 1];

struct p4tc_table_entry *
p4tc_table_entry_lookup_direct(struct p4tc_table *table,
			       struct p4tc_table_entry_key *key);

struct p4tc_table_entry_act_bpf *
p4tc_table_entry_create_act_bpf(struct tc_action *action,
				struct netlink_ext_ack *extack);
int register_p4tc_tbl_bpf(void);
int
p4tc_table_entry_create_bpf(struct p4tc_pipeline *pipeline,
			    struct p4tc_table *table,
			    struct p4tc_table_entry_key *key,
			    struct p4tc_table_entry_act_bpf *act_bpf,
			    struct p4tc_table_entry_create_bpf_params *params);
int p4tc_table_entry_update_bpf(struct p4tc_pipeline *pipeline,
				struct p4tc_table *table,
				struct p4tc_table_entry_key *key,
				struct p4tc_table_entry_act_bpf *act_bpf,
				struct p4tc_table_entry_create_bpf_params *params);

int p4tc_table_entry_del_bpf(struct p4tc_pipeline *pipeline,
			     struct p4tc_table *table,
			     struct p4tc_table_entry_key *key,
			     struct p4tc_table_entry_create_bpf_params *params);

static inline int p4tc_action_init(struct net *net, struct nlattr *nla,
				   struct tc_action *acts[], u32 pipeid,
				   u32 flags, struct netlink_ext_ack *extack)
{
	struct nlattr *tb[TCA_ACT_MAX_PRIO + 1] = {};
	int init_res[TCA_ACT_MAX_PRIO];
	struct tc_action *a;
	size_t attrs_size;
	size_t nacts = 0;
	int ret;
	int i;

	ret = nla_parse_nested_deprecated(tb, TCA_ACT_MAX_PRIO, nla, NULL,
					  extack);
	if (ret < 0)
		return ret;

	for (i = 1; i < TCA_ACT_MAX_PRIO + 1; i++)
		nacts += !!tb[i];

	if (nacts > 1) {
		NL_SET_ERR_MSG(extack, "Only one action is allowed");
		return -E2BIG;
	}

	/* If action was already created, just bind to existing one */
	flags |= TCA_ACT_FLAGS_BIND;
	flags |= TCA_ACT_FLAGS_FROM_P4TC;
	ret = tcf_action_init(net, NULL, nla, NULL, acts, init_res, &attrs_size,
			      flags, 0, extack);

	/* Check if we are trying to bind to dynamic action from different
	 * pipeline.
	 */
	tcf_act_for_each_action(i, a, acts) {
		struct tcf_p4act *p;

		if (a->ops->id <= TCA_ID_MAX)
			continue;

		p = to_p4act(a);
		if (p->p_id != pipeid) {
			NL_SET_ERR_MSG(extack,
				       "Unable to bind to dynact from different pipeline");
			ret = -EPERM;
			goto destroy_acts;
		}
	}

	return ret;

destroy_acts:
	p4tc_action_destroy(acts);
	return ret;
}

struct p4tc_act *p4a_tmpl_get(struct p4tc_pipeline *pipeline,
			      const char *act_name, const u32 a_id,
			      struct netlink_ext_ack *extack);
struct p4tc_act *p4a_tmpl_find_byid(struct p4tc_pipeline *pipeline,
				    const u32 a_id);

static inline bool p4tc_action_put_ref(struct p4tc_act *act)
{
	return refcount_dec_not_one(&act->a_ref);
}

struct p4tc_act_param *p4a_parm_find_byid(struct idr *params_idr,
					  const u32 param_id);

struct p4tc_act_param *
p4a_parm_find_byany(struct p4tc_act *act, const char *param_name,
		    const u32 param_id, struct netlink_ext_ack *extack);

struct p4tc_table *p4tc_table_find_byany(struct p4tc_pipeline *pipeline,
					 const char *tblname, const u32 tbl_id,
					 struct netlink_ext_ack *extack);
struct p4tc_table *p4tc_table_find_byid(struct p4tc_pipeline *pipeline,
					const u32 tbl_id);
int p4tc_table_try_set_state_ready(struct p4tc_pipeline *pipeline,
				   struct netlink_ext_ack *extack);
void p4tc_table_put_mask_array(struct p4tc_pipeline *pipeline);

static inline int p4tc_table_get(struct p4tc_table *table)
{
	return refcount_inc_not_zero(&table->tbl_ctrl_ref);
}

struct p4tc_table *p4tc_table_find_get(struct p4tc_pipeline *pipeline,
				       const char *tblname, const u32 tbl_id,
				       struct netlink_ext_ack *extack);

static inline bool p4tc_table_put_ref(struct p4tc_table *table)
{
	return refcount_dec_not_one(&table->tbl_ctrl_ref);
}

struct p4tc_table_defact_params {
	struct p4tc_table_defact *hitact;
	struct p4tc_table_defact *missact;
	struct nlattr *nla_hit;
	struct nlattr *nla_miss;
};

int p4tc_table_init_default_acts(struct net *net,
				 struct p4tc_table_defact_params *dflt,
				 struct p4tc_table *table,
				 struct list_head *acts_list,
				 struct netlink_ext_ack *extack);

static inline bool p4tc_table_act_is_noaction(struct p4tc_table_act *table_act)
{
	return !table_act->act->common.p_id && !table_act->act->a_id;
}

static inline bool p4tc_table_defact_is_noaction(struct tcf_p4act *p4_defact)
{
	return !p4_defact->p_id && !p4_defact->act_id;
}

static inline void p4tc_table_defact_destroy(struct p4tc_table_defact *defact)
{
	if (defact) {
		if (defact->acts[0]) {
			struct tcf_p4act *dflt = to_p4act(defact->acts[0]);

			if (p4tc_table_defact_is_noaction(dflt)) {
				struct p4tc_table_entry_act_bpf_kern *act_bpf;

				act_bpf =
					rcu_dereference_protected(dflt->act_bpf,
								  1);
				kfree(act_bpf);
				kfree(dflt);
			} else {
				p4tc_action_destroy(defact->acts);
			}
		}
		kfree(defact);
	}
}

static inline void p4tc_table_defacts_acts_copy(struct p4tc_table_defact *dst,
						struct p4tc_table_defact *src)
{
	dst->acts[0] = src->acts[0];
	dst->acts[1] = NULL;
}

void p4tc_table_replace_default_acts(struct p4tc_table *table,
				     struct p4tc_table_defact_params *dflt,
				     bool lock_rtnl);

struct p4tc_table_perm *
p4tc_table_init_permissions(struct p4tc_table *table, u16 permissions,
			    struct netlink_ext_ack *extack);
void p4tc_table_replace_permissions(struct p4tc_table *table,
				    struct p4tc_table_perm *tbl_perm,
				    bool lock_rtnl);
int p4tc_table_timer_profile_update(struct p4tc_table *table,
				    struct nlattr *nla,
				    struct netlink_ext_ack *extack);
struct p4tc_table_timer_profile *
p4tc_table_timer_profile_find_byaging(struct p4tc_table *table,
				      u64 aging_ms);
bool p4tc_table_check_act(struct p4tc_table *table,
			  const u32 p_id, const u32 act_id,
			  const bool check_default_only);
struct p4tc_table_timer_profile *
p4tc_table_timer_profile_find(struct p4tc_table *table, u32 profile_id);

void p4tc_table_entry_destroy_hash(void *ptr, void *arg);

struct p4tc_table_entry *
p4tc_tmpl_table_entry_cu(struct net *net, struct nlattr *arg,
			 struct p4tc_pipeline *pipeline,
			 struct p4tc_table *table,
			 struct netlink_ext_ack *extack);
int p4tc_tbl_entry_root(struct net *net, struct sk_buff *skb,
			struct nlmsghdr *n, struct nlattr **tb,
			struct netlink_ext_ack *extack);
int p4tc_tbl_entry_filter_sub(struct sk_buff *skb,
			      struct p4tc_path_nlattrs *nl_path_attrs,
			      struct nlattr *nla, u32 cmd,
			      struct netlink_ext_ack *extack);
int p4tc_tbl_entry_dumpit(struct net *net, struct sk_buff *skb,
			  struct netlink_callback *cb,
			  struct nlattr *arg, char *p_name);
int p4tc_tbl_entry_fill(struct sk_buff *skb, struct p4tc_table *table,
			struct p4tc_table_entry *entry,
			const u16 who_deleted_ent, const char *who_deleted,
			const u32 who_deleted_pid);
void p4tc_tbl_entry_mask_key(u8 *masked_key, u8 *key, const u8 *mask,
			     u32 masksz);

struct p4tc_filter *
p4tc_filter_build(struct p4tc_filter_context *ctx,
		  struct nlattr *nla, struct netlink_ext_ack *extack);
bool p4tc_filter_exec(struct p4tc_filter *filter,
		      struct p4tc_filter_data *filter_data);
int p4tc_filter_broadcast_cb(struct sock *dsk, struct sk_buff *skb,
			     void *data);
void p4tc_filter_destroy(struct p4tc_filter *filter);
void p4tc_filter_sock_table_init(void);
int p4tc_filter_subscribe(struct sk_buff *skb,
			  struct p4tc_filter_context *ctx,
			  struct nlattr *nla,
			  struct netlink_ext_ack *extack);

struct tcf_p4act *
p4a_runt_prealloc_get_next(struct p4tc_act *act);
void p4a_runt_prealloc_reference(struct p4tc_act *act, struct tcf_p4act *p4act);
void p4a_runt_parm_destroy(struct p4tc_act_param *parm);
struct p4tc_act_param *
p4a_runt_parm_init(struct net *net, struct p4tc_act *act,
		   struct nlattr *nla, struct netlink_ext_ack *extack);

static inline bool p4tc_runtime_msg_is_update(struct nlmsghdr *n)
{
	return n->nlmsg_type == RTM_P4TC_UPDATE;
}

struct p4tc_tmpl_extern {
	struct p4tc_template_common  common;
	struct idr                   params_idr;
	const struct p4tc_extern_ops *ops;
	u32                          ext_id;
	u32                          num_params;
	u32                          max_num_insts;
	/* Accounts for how many pipelines refer to this extern. */
	refcount_t                   tmpl_ref;
	char                         mod_name[MODULE_NAME_LEN];
	u16                          ext_permissions;
	bool                         has_exec_method;
};

static inline struct p4tc_tmpl_extern *
p4tc_tmpl_ext_find_byid(struct p4tc_pipeline *pipeline, const u32 ext_id)
{
	return idr_find(&pipeline->p_ext_idr, ext_id);
}

/* struct p4tc_tmpl_extern is global, however the data of each instances is
 * associated to a pipeline. To do that association we create a per pipeline
 * analagous struct (p4tc_user_pipeline_extern) for p4tc_tmpl_extern that holds
 * the instances inside an IDR.
 */
struct p4tc_user_pipeline_extern {
	struct idr		e_inst_idr;
	struct p4tc_tmpl_extern	*tmpl_ext;
	void (*free)(struct p4tc_user_pipeline_extern *pipe_ext,
		     struct idr *tmpl_exts_idr);
	u32			ext_id;
	/* Accounts for how many instances refer to this extern. */
	refcount_t		ext_ref;
	/* Counts how many instances this extern has */
	atomic_t                curr_insts_num;
	u32                     __pad0;
	char			ext_name[P4TC_EXTERN_NAMSIZ];
};

struct p4tc_extern_inst {
	struct p4tc_template_common      common;
	struct p4tc_extern_params        *params;
	const struct p4tc_extern_ops     *ops;
	struct idr                       control_elems_idr;
	struct list_head                 unused_elems;
	/* Locks the available externs list.
	 * Which will be used by table entries that reference externs (refer to
	 * direct counters and meters in P4).
	 * Note that table entries can be created, update or deleted by both
	 * control and data path. So this list may be modified from both
	 * contexts.
	 */
	spinlock_t                       available_list_lock;
	/* Accounts for how many elements refer to this extern. */
	refcount_t                       inst_ref;
	struct p4tc_user_pipeline_extern *pipe_ext;
	char                             *ext_name;
	atomic_t                         curr_num_elems;
	u32                              max_num_elems;
	u32                              ext_id;
	u32                              ext_inst_id;
	u32                              num_control_params;
	struct p4tc_extern_params        *constr_params;
	u32				 flags;
	bool                             tbl_bindable;
	bool				 is_scalar;
};

struct p4tc_table_counters {
	u64 bytes;
	u32 pkts;
};

struct p4tc_extern_inst *
p4tc_ext_inst_find_bynames(struct net *net, struct p4tc_pipeline *pipeline,
			   const char *extname, const char *instname,
			   struct netlink_ext_ack *extack);
struct p4tc_user_pipeline_extern *
p4tc_pipe_ext_find_bynames(struct net *net, struct p4tc_pipeline *pipeline,
			   const char *extname, struct netlink_ext_ack *extack);
struct p4tc_extern_inst *
p4tc_ext_inst_table_bind(struct p4tc_pipeline *pipeline,
			 struct p4tc_user_pipeline_extern **pipe_ext,
			 const char *ext_inst_path,
			 struct netlink_ext_ack *extack);
void
p4tc_ext_inst_table_unbind(struct p4tc_table *table,
			   struct p4tc_user_pipeline_extern *pipe_ext,
			   struct p4tc_extern_inst *inst);

static inline struct p4tc_extern_inst *
p4tc_ext_inst_get_ref(struct p4tc_extern_inst *inst)
{
	/* Extern instance template was deleted in parallel */
	if (!refcount_inc_not_zero(&inst->inst_ref))
		return ERR_PTR(-EBUSY);

	return inst;
}

static inline void p4tc_ext_inst_put_ref(struct p4tc_extern_inst *inst)
{
	refcount_dec(&inst->inst_ref);
}

struct p4tc_extern_inst *
p4tc_ext_inst_get_byids(struct net *net, struct p4tc_pipeline **pipeline,
			struct p4tc_ext_bpf_params *params);
struct p4tc_extern_inst *
p4tc_ext_find_byids(struct p4tc_pipeline *pipeline,
		    const u32 ext_id, const u32 inst_id);

struct p4tc_extern_tmpl_param;

struct p4tc_extern_tmpl_param_ops {
	int (*validate_val)(struct net *net, void *value,
			    struct netlink_ext_ack *extack);
	void * (*default_val)(void);
};

struct p4tc_extern_tmpl_param {
	struct p4tc_type			*type;
	void					*default_value;
	struct p4tc_type_mask_shift		*mask_shift;
	struct p4tc_extern_tmpl_param_ops	*ops;
	u32					id;
	u32					index;
	u32					bitsz;
	u32					flags;
	struct rcu_head				rcu;
	char					name[EXTPARAMNAMSIZ];
};

void p4tc_ext_tmpl_params_free(struct p4tc_extern_params *params);
int p4tc_datapath_extern_md_write(struct net *net,
				  struct p4tc_ext_bpf_params *params,
				  const u32 params__sz,
				  struct p4tc_ext_bpf_val *val,
				  const u32 val__sz);
struct p4tc_ext_bpf_val *
p4tc_datapath_extern_md_read(struct net *net,
			     struct p4tc_ext_bpf_params *params,
			     const u32 params__sz);
struct p4tc_extern_params *
p4tc_ext_params_copy(struct p4tc_extern_params *params_orig);

struct p4tc_extern_param {
	struct p4tc_extern_tmpl_param   *tmpl_param;
	struct p4tc_extern_param_ops    *ops;
	void				*value;
	struct rcu_head			rcu;
};

static inline bool p4tc_ext_param_is_key(struct p4tc_extern_param *param)
{
	return !!(param->tmpl_param->flags & P4TC_EXT_PARAMS_FLAG_ISKEY);
}

struct p4tc_extern_param_ops {
	int (*init_value)(struct net *net,
			  struct p4tc_extern_param *nparam, void *value,
			  struct netlink_ext_ack *extack);
	void (*copy_value)(struct p4tc_extern_param *nparam, const void *value);
	void (*copy_value_bpf)(void *bpf_mem,
			       const struct p4tc_extern_param *param);
	void (*default_value)(struct p4tc_extern_param *nparam);
	int (*dump_value)(struct sk_buff *skb, struct p4tc_extern_param_ops *op,
			  struct p4tc_extern_param *param);
	void (*free)(struct p4tc_extern_param *param);
	u32 len;
	u32 alloc_len;
};

extern const struct p4tc_extern_param_ops ext_param_ops[P4TC_T_MAX + 1];

static inline const struct p4tc_extern_param_ops *
p4tc_extern_param_type_ops_get(const u32 typeid)
{
	if (typeid > P4TC_T_MAX)
		return NULL;

	return &ext_param_ops[typeid];
}

#define to_pipeline(t) ((struct p4tc_pipeline *)t)
#define p4tc_to_act(t) ((struct p4tc_act *)t)
#define p4tc_to_table(t) ((struct p4tc_table *)t)

#define to_extern(t) ((struct p4tc_tmpl_extern *)t)
#define to_extern_inst(t) ((struct p4tc_extern_inst *)t)

#endif
