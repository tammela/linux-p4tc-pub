/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_P4TYPES_H
#define __NET_P4TYPES_H

#include <linux/netlink.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>

#include <uapi/linux/p4tc.h>

#define P4TC_T_MAX_BITSZ 512

struct p4tc_type_mask_shift {
	void *mask;
	u8 shift;
};

struct p4tc_type;
struct p4tc_type_ops {
	int (*validate_p4t)(struct p4tc_type *container, void *value,
			    u16 startbit, u16 endbit,
			    struct netlink_ext_ack *extack);
	struct p4tc_type_mask_shift *(*create_bitops)(u16 bitsz, u16 bitstart,
						      u16 bitend,
						      struct netlink_ext_ack *extack);
	void (*host_read)(struct p4tc_type *container,
			  struct p4tc_type_mask_shift *mask_shift, void *sval,
			  void *dval);
	void (*host_write)(struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval);
};

#define P4TC_T_MAX_STR_SZ 32
struct p4tc_type {
	char name[P4TC_T_MAX_STR_SZ];
	const struct p4tc_type_ops *ops;
	size_t container_bitsz;
	size_t bitsz;
	int typeid;
};

struct p4tc_type *p4type_find_byid(int id);
bool p4tc_is_type_unsigned_he(int typeid);
bool p4tc_is_type_numeric(int typeid);

void p4t_copy(struct p4tc_type_mask_shift *dst_mask_shift,
	      struct p4tc_type *dst_t, void *dstv,
	      struct p4tc_type_mask_shift *src_mask_shift,
	      struct p4tc_type *src_t, void *srcv);
int p4t_cmp(struct p4tc_type_mask_shift *dst_mask_shift,
	    struct p4tc_type *dst_t, void *dstv,
	    struct p4tc_type_mask_shift *src_mask_shift,
	    struct p4tc_type *src_t, void *srcv);
void p4t_release(struct p4tc_type_mask_shift *mask_shift);

int p4tc_register_types(void);
void p4tc_unregister_types(void);

#ifdef CONFIG_RETPOLINE
void __p4tc_type_host_read(const struct p4tc_type_ops *ops,
			   struct p4tc_type *container,
			   struct p4tc_type_mask_shift *mask_shift, void *sval,
			   void *dval);
void __p4tc_type_host_write(const struct p4tc_type_ops *ops,
			    struct p4tc_type *container,
			    struct p4tc_type_mask_shift *mask_shift, void *sval,
			    void *dval);
#else
static inline void
__p4tc_type_host_read(const struct p4tc_type_ops *ops,
		      struct p4tc_type *container,
		      struct p4tc_type_mask_shift *mask_shift,
		      void *sval, void *dval)
{
	return ops->host_read(container, mask_shift, sval, dval);
}

static inline void
__p4tc_type_host_write(const struct p4tc_type_ops *ops,
		       struct p4tc_type *container,
		       struct p4tc_type_mask_shift *mask_shift,
		       void *sval, void *dval)
{
	return ops->host_write(container, mask_shift, sval, dval);
}
#endif

#endif
