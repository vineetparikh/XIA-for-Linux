#include <linux/slab.h>
#include <net/xia_dag.h>
#include <net/xia_lpm.h>
#include <linux/rwlock.h>

#include "poptrie.h"

#define POPT_INIT_SZ1	19
#define POPT_INIT_SZ0	22

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
	write_unlock(&xtbl_pxtbl(xtbl)->writers_lock);
}

static struct fib_xid *popt_fxid_find_rcu(struct fib_xid_table *xtbl,
					  const u8 *xid)
{
	return NULL;
}

/* No extra information is needed, so @parg is empty. */
static struct fib_xid *popt_fxid_find_lock(void *parg,
	struct fib_xid_table *xtbl, const u8 *xid)
{
	return NULL;
}

static int popt_iterate_xids(struct fib_xid_table *xtbl,
			     int (*locked_callback)(struct fib_xid_table *xtbl,
						    struct fib_xid *fxid,
						    const void *arg),
			     const void *arg)
{
	return 0;
}

/* No extra information is needed, so @parg is empty. */
static int popt_fxid_add_locked(void *parg, struct fib_xid_table *xtbl,
				struct fib_xid *fxid)
{
	return 0;
}

static int popt_fxid_add(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	return 0;
}

/* No extra information is needed, so @parg is empty. */
static void popt_fxid_rm_locked(void *parg, struct fib_xid_table *xtbl,
				struct fib_xid *fxid)
{
	return;
}

static void popt_fxid_rm(struct fib_xid_table *xtbl, struct fib_xid *fxid)
{
	return;
}

/* popt_xid_rm() removes the entry with the longest matching prefix,
 * since we have no prefix information for @xid.
 */
static struct fib_xid *popt_xid_rm(struct fib_xid_table *xtbl, const u8 *xid)
{
	return NULL;
}

static void popt_fxid_replace_locked(struct fib_xid_table *xtbl,
				     struct fib_xid *old_fxid,
				     struct fib_xid *new_fxid)
{
	return;
}

int popt_fib_newroute_lock(struct fib_xid *new_fxid, struct fib_xid_table *xtbl,
			   struct xia_fib_config *cfg, int *padded)
{
	return 0;
}

static int popt_fib_newroute(struct fib_xid *new_fxid,
			     struct fib_xid_table *xtbl,
			     struct xia_fib_config *cfg, int *padded)
{
	return 0;
}

/* popt_fib_delroute() differs from all_fib_delroute() because its lookup
 * function has the option of doing longest prefix or exact matching, and
 * all_fib_delroute() is not flexible enough to do that.
 */
int popt_fib_delroute(struct xip_ppal_ctx *ctx, struct fib_xid_table *xtbl,
		      struct xia_fib_config *cfg)
{
	return 0;
}

/* Dump all entries in the poptrie. */
static int popt_xtbl_dump_rcu(struct fib_xid_table *xtbl,
			      struct xip_ppal_ctx *ctx, struct sk_buff *skb,
			      struct netlink_callback *cb)
{
	return 0;
}

struct fib_xid *popt_fib_get_pred_locked(struct fib_xid *fxid)
{
	return NULL;
}

/* Main entries for LPM need to display the prefix length when dumped,
 * so popt_fib_mrd_dump() differs from fib_mrd_dump().
 */
int popt_fib_mrd_dump(struct fib_xid *fxid, struct fib_xid_table *xtbl,
		      struct xip_ppal_ctx *ctx, struct sk_buff *skb,
		      struct netlink_callback *cb)
{
	return 0;
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
