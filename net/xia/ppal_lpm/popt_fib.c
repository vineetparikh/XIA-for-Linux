#include <linux/slab.h>
#include <net/xia_dag.h>
#include <net/xia_lpm.h>
#include <linux/rwlock.h>

#include "poptrie.h"

#define POPT_INIT_SZ1	19
#define POPT_INIT_SZ0	22

static inline u32 xid_to_u32(const u8 *xid)
{
	return (xid[0] * (1 << 24)) + (xid[1] * (1 << 16)) +
		(xid[2] * (1 << 8)) + xid[3];
}

struct popt_fib_xid_table {
	/* The poptrie data structure. */
	struct poptrie	*poptrie;
	/* RCU is currently not used on the popt, so we use a rwlock. */
	rwlock_t	writers_lock;
};

static inline struct fib_xid_table *pxtbl_xtbl(struct popt_fib_xid_table *pxtbl)
{
	return likely(pxtbl)
		? container_of((void *)pxtbl, struct fib_xid_table, fxt_data)
		: NULL;
}

static inline struct popt_fib_xid_table *xtbl_pxtbl(struct fib_xid_table *xtbl)
{
	return (struct popt_fib_xid_table *)xtbl->fxt_data;
}

static void popt_xtbl_death_work(struct work_struct *work);

static int popt_xtbl_init(struct xip_ppal_ctx *ctx, struct net *net,
			  struct xia_lock_table *locktbl,
			  const xia_ppal_all_rt_eops_t all_eops,
			  const struct xia_ppal_rt_iops *all_iops)
{
	struct fib_xid_table *new_xtbl;
	struct popt_fib_xid_table *pxtbl;

	if (ctx->xpc_xtbl)
		return -EEXIST; /* Duplicate. */

	new_xtbl = kzalloc(sizeof(*new_xtbl) + sizeof(*pxtbl), GFP_KERNEL);
	if (!new_xtbl)
		return -ENOMEM;
	pxtbl = xtbl_pxtbl(new_xtbl);

	pxtbl->poptrie = poptrie_init(NULL, POPT_INIT_SZ1, POPT_INIT_SZ0);
	if (!pxtbl->poptrie) {
		kfree(new_xtbl);
		return -ENOMEM;
	}
	rwlock_init(&pxtbl->writers_lock);

	new_xtbl->fxt_ppal_type = ctx->xpc_ppal_type;
	new_xtbl->fxt_net = net;
	new_xtbl->all_eops = all_eops;
	new_xtbl->all_iops = all_iops;

	atomic_set(&new_xtbl->refcnt, 1);
	INIT_WORK(&new_xtbl->fxt_death_work, popt_xtbl_death_work);
	ctx->xpc_xtbl = new_xtbl;

	return 0;
}

static void *popt_fxid_ppal_alloc(size_t ppal_entry_size, gfp_t flags)
{
	return kmalloc(ppal_entry_size, flags);
}

static void popt_fxid_init(struct fib_xid *fxid, int table_id, int entry_type)
{
	BUILD_BUG_ON(XRTABLE_MAX_INDEX >= 0x100);
	BUG_ON(table_id >= XRTABLE_MAX_INDEX);
	fxid->fx_table_id = table_id;

	BUILD_BUG_ON(XIA_LPM_MAX_PREFIX_LEN >= 0x100);
	BUG_ON(entry_type > XIA_LPM_MAX_PREFIX_LEN);
	fxid->fx_entry_type = entry_type;

	fxid->dead.xtbl = NULL;
}

static void popt_xtbl_death_work(struct work_struct *work)
{
	struct fib_xid_table *xtbl = container_of(work, struct fib_xid_table,
		fxt_death_work);
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	poptrie_release(pxtbl->poptrie);
	kfree(xtbl);
}

/* No extra information is needed, so @parg is empty. */
static void popt_fib_unlock(struct fib_xid_table *xtbl, void *parg)
{
	return;
}

static struct fib_xid *popt_fxid_find_rcu(struct fib_xid_table *xtbl,
					  const u8 *xid)
{
	return (struct fib_xid *)poptrie_lookup(xtbl_pxtbl(xtbl)->poptrie,
						xid_to_u32(xid));
}

/* No extra information is needed, so @parg is empty. */
static struct fib_xid *popt_fxid_find_lock(void *parg,
	struct fib_xid_table *xtbl, const u8 *xid)
{
	return (struct fib_xid *)poptrie_lookup(xtbl_pxtbl(xtbl)->poptrie,
						xid_to_u32(xid));
}

static int popt_iterate_xids(struct fib_xid_table *xtbl,
			     int (*locked_callback)(struct fib_xid_table *xtbl,
						    struct fib_xid *fxid,
						    const void *arg),
			     const void *arg)
{
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	struct poptrie *poptrie = pxtbl->poptrie;
	int rc = 0;
	int i;

	for (i = 1 ; i < poptrie->fib.n; i++) {
		if (poptrie->fib.entries[i].refcnt > 0) {
			struct fib_xid *cur =
				(struct fib_xid *)poptrie->
					fib.entries[i].nexthop;
			rc = locked_callback(xtbl, cur, arg);
			if (rc)
				goto out;
		}
	}

out:
	return rc;
}

/* No extra information is needed, so @parg is empty. */
static int popt_fxid_add_locked(void *parg, struct fib_xid_table *xtbl,
				struct fib_xid *fxid)
{
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	int ret = poptrie_route_add(pxtbl->poptrie, xid_to_u32(fxid->fx_xid),
				    fxid->fx_entry_type, (void *)fxid);
	if (ret == 0)
		atomic_inc(&xtbl->fxt_count);
	return 0;
}

static int popt_fxid_add(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	return popt_fxid_add_locked(NULL, xtbl, fxid);
}

/* No extra information is needed, so @parg is empty. */
static void popt_fxid_rm_locked(void *parg, struct fib_xid_table *xtbl,
				struct fib_xid *fxid)
{
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	int ret = poptrie_route_del(pxtbl->poptrie, xid_to_u32(fxid->fx_xid),
				    fxid->fx_entry_type);
	if (ret == 0)
		atomic_dec(&xtbl->fxt_count);
}

static void popt_fxid_rm(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	popt_fxid_rm_locked(NULL, xtbl, fxid);
}

/* popt_xid_rm() removes the entry with the longest matching prefix,
 * since we have no prefix information for @xid.
 */
static struct fib_xid *popt_xid_rm(struct fib_xid_table *xtbl, const u8 *xid)
{
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	struct fib_xid *fxid = (struct fib_xid *)poptrie_lookup(pxtbl->poptrie,
		xid_to_u32(xid));
	if (!fxid)
		return NULL;
	popt_fxid_rm_locked(NULL, xtbl, fxid);
	return fxid;
}

static void popt_fxid_replace_locked(struct fib_xid_table *xtbl,
				     struct fib_xid *old_fxid,
				     struct fib_xid *new_fxid)
{
	/* XXX This can fail. Should the API for replace be changed? */
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	poptrie_route_change(pxtbl->poptrie, xid_to_u32(old_fxid->fx_xid),
			     old_fxid->fx_entry_type, (void *)new_fxid);
}

int popt_fib_newroute_lock(struct fib_xid *new_fxid, struct fib_xid_table *xtbl,
			   struct xia_fib_config *cfg, int *padded)
{
	struct fib_xid *cur_fxid;
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	
	const u8 *id;

	if (padded)
		*padded = 0;

	/* Acquire lock and do exact matching to find @cur_fxid. */
	id = cfg->xfc_dst->xid_id;
	cur_fxid = poptrie_exact_lookup(pxtbl->poptrie, xid_to_u32(id),
					new_fxid->fx_entry_type);
	if (cur_fxid) {
		if ((cfg->xfc_nlflags & NLM_F_EXCL) ||
		    !(cfg->xfc_nlflags & NLM_F_REPLACE))
			return -EEXIST;

		if (cur_fxid->fx_table_id != new_fxid->fx_table_id)
			return -EINVAL;

		popt_fxid_replace_locked(xtbl, cur_fxid, new_fxid);
		fxid_free(xtbl, cur_fxid);
		return 0;
	}

	if (!(cfg->xfc_nlflags & NLM_F_CREATE))
		return -ENOENT;

	/* Add new entry. */
	BUG_ON(popt_fxid_add_locked(NULL, xtbl, new_fxid));

	if (padded)
		*padded = 1;
	return 0;
}

static int popt_fib_newroute(struct fib_xid *new_fxid,
			     struct fib_xid_table *xtbl,
			     struct xia_fib_config *cfg, int *padded)
{
	return popt_fib_newroute_lock(new_fxid, xtbl, cfg, padded);
}

/* popt_fib_delroute() differs from all_fib_delroute() because its lookup
 * function has the option of doing longest prefix or exact matching, and
 * all_fib_delroute() is not flexible enough to do that.
 */
int popt_fib_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
		      struct xia_fib_config *cfg)
{
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	struct fib_xid *fxid;
	int rc;
	const u8 *id;
	if (!valid_prefix(cfg))
		return -EINVAL;

	/* Do exact matching to find @fxid. */
	id = cfg->xfc_dst->xid_id;
	fxid = (struct fib_xid *)poptrie_exact_lookup(pxtbl->poptrie,
		xid_to_u32(id), *(u8 *)cfg->xfc_protoinfo);
	if (!fxid) {
		rc = -ENOENT;
		goto unlock;
	}
	if (fxid->fx_table_id != cfg->xfc_table) {
		rc = -EINVAL;
		goto unlock;
	}
	
	popt_fxid_rm_locked(NULL, xtbl, fxid);
	popt_fib_unlock(xtbl, NULL);
	fxid_free(xtbl, fxid);
	return 0;

unlock:
	popt_fib_unlock(xtbl, NULL);
	return rc;
}

/* Dump all entries in the poptrie. */
static int popt_xtbl_dump_rcu(struct fib_xid_table *xtbl,
			      struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			      struct netlink_callback *cb)
{
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	int rc = 0;
	int i;
	for (i = 1; i < pxtbl->poptrie->fib.n; i++) {
		if (pxtbl->poptrie->fib.entries[i].refcnt > 0) {
			struct fib_xid *fxid =
				(struct fib_xid *)pxtbl->poptrie->
					fib.entries[i].nexthop;
			rc = xtbl->all_eops[fxid->fx_table_id].
					dump_fxid(fxid, xtbl, ctx, skb, cb);
			if (rc < 0)
				goto out;
		}
	}
out:
	return rc;
}

struct fib_xid *popt_fib_get_pred_locked(struct fib_xid_table *xtbl,
	struct fib_xid *fxid)
{
	struct popt_fib_xid_table *pxtbl = xtbl_pxtbl(xtbl);
	return poptrie_rib_lookup_prefix(pxtbl->poptrie,
					 xid_to_u32(fxid->fx_xid),
					 fxid->fx_entry_type - 1);
}

/* Main entries for LPM need to display the prefix length when dumped,
 * so popt_fib_mrd_dump() differs from fib_mrd_dump().
 */
int popt_fib_mrd_dump(struct fib_xid *fxid, struct fib_xid_table *xtbl,
		      struct xip_ppal_ctx *ctx, struct sk_buff *skb,
		      struct netlink_callback *cb)
{
	struct nlmsghdr *nlh;
	u32 portid = NETLINK_CB(cb->skb).portid;
	u32 seq = cb->nlh->nlmsg_seq;
	struct rtmsg *rtm;
	struct fib_xid_redirect_main *mrd = fxid_mrd(fxid);
	struct xia_xid dst;

	nlh = nlmsg_put(skb, portid, seq, RTM_NEWROUTE, sizeof(*rtm),
			NLM_F_MULTI);
	if (nlh == NULL)
		return -EMSGSIZE;

	rtm = nlmsg_data(nlh);
	rtm->rtm_family = AF_XIA;
	rtm->rtm_dst_len = sizeof(struct xia_xid);
	rtm->rtm_src_len = 0;
	rtm->rtm_tos = 0; /* XIA doesn't have a tos. */
	rtm->rtm_table = XRTABLE_MAIN_INDEX;
	/* XXX One may want to vary here. */
	rtm->rtm_protocol = RTPROT_UNSPEC;
	/* XXX One may want to vary here. */
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;
	/* XXX One may want to put something here, like RTM_F_CLONED. */
	rtm->rtm_flags = 0;

	dst.xid_type = xtbl_ppalty(xtbl);
	memmove(dst.xid_id, fxid->fx_xid, XIA_XID_MAX);

	if (unlikely(nla_put(skb, RTA_DST, sizeof(dst), &dst) ||
		     nla_put(skb, RTA_GATEWAY, sizeof(mrd->gw), &mrd->gw)))
		goto nla_put_failure;

	/* Add prefix length to packet. */
	if (unlikely(nla_put(skb, RTA_PROTOINFO, sizeof(fxid->fx_entry_type),
			     &(fxid->fx_entry_type))))
		goto nla_put_failure;

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;	
}

const struct xia_ppal_rt_iops xia_ppal_popt_rt_iops = {
	.xtbl_init = popt_xtbl_init,
	.xtbl_death_work = popt_xtbl_death_work,

	.fxid_ppal_alloc = popt_fxid_ppal_alloc,
	.fxid_init = popt_fxid_init,

	/* Note that there is no RCU-specific version. */
	.fxid_find_rcu = popt_fxid_find_rcu,
	.fxid_find_lock = popt_fxid_find_lock,
	.iterate_xids = popt_iterate_xids,
	/* Note that there is no RCU-specific version. */
	.iterate_xids_rcu = popt_iterate_xids,

	.fxid_add = popt_fxid_add,
	.fxid_add_locked = popt_fxid_add_locked,

	.fxid_rm = popt_fxid_rm,
	.fxid_rm_locked = popt_fxid_rm_locked,
	.xid_rm = popt_xid_rm,

	.fxid_replace_locked = popt_fxid_replace_locked,

	.fib_unlock = popt_fib_unlock,

	.fib_newroute = popt_fib_newroute,
	.fib_delroute = popt_fib_delroute,

	.xtbl_dump_rcu = popt_xtbl_dump_rcu,
};
