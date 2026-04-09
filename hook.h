enum pid_type {
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

struct pid_namespace;

struct open_flags;

struct stack_trace {
	unsigned int nr_entries, max_entries;
	unsigned long *entries;
	unsigned int skip;
};

enum perf_type_id {
	PERF_TYPE_HARDWARE			= 0,
	PERF_TYPE_SOFTWARE			= 1,
	PERF_TYPE_TRACEPOINT			= 2,
	PERF_TYPE_HW_CACHE			= 3,
	PERF_TYPE_RAW				= 4,
	PERF_TYPE_BREAKPOINT			= 5,

	PERF_TYPE_MAX,				/* non-ABI */
};

enum {
	HW_BREAKPOINT_LEN_1 = 1,
	HW_BREAKPOINT_LEN_2 = 2,
	HW_BREAKPOINT_LEN_3 = 3,
	HW_BREAKPOINT_LEN_4 = 4,
	HW_BREAKPOINT_LEN_5 = 5,
	HW_BREAKPOINT_LEN_6 = 6,
	HW_BREAKPOINT_LEN_7 = 7,
	HW_BREAKPOINT_LEN_8 = 8,
};

enum {
	HW_BREAKPOINT_EMPTY	= 0,
	HW_BREAKPOINT_R		= 1,
	HW_BREAKPOINT_W		= 2,
	HW_BREAKPOINT_RW	= HW_BREAKPOINT_R | HW_BREAKPOINT_W,
	HW_BREAKPOINT_X		= 4,
	HW_BREAKPOINT_INVALID   = HW_BREAKPOINT_RW | HW_BREAKPOINT_X,
};

struct perf_event_attr {

	/*
	 * Major type: hardware/software/tracepoint/etc.
	 */
	__u32			type;

	/*
	 * Size of the attr structure, for fwd/bwd compat.
	 */
	__u32			size;

	/*
	 * Type specific configuration information.
	 */
	__u64			config;

	union {
		__u64		sample_period;
		__u64		sample_freq;
	};

	__u64			sample_type;
	__u64			read_format;

	__u64			disabled       :  1, /* off by default        */
				inherit	       :  1, /* children inherit it   */
				pinned	       :  1, /* must always be on PMU */
				exclusive      :  1, /* only group on PMU     */
				exclude_user   :  1, /* don't count user      */
				exclude_kernel :  1, /* ditto kernel          */
				exclude_hv     :  1, /* ditto hypervisor      */
				exclude_idle   :  1, /* don't count when idle */
				mmap           :  1, /* include mmap data     */
				comm	       :  1, /* include comm data     */
				freq           :  1, /* use freq, not period  */
				inherit_stat   :  1, /* per task counts       */
				enable_on_exec :  1, /* next exec enables     */
				task           :  1, /* trace fork/exit       */
				watermark      :  1, /* wakeup_watermark      */
				/*
				 * precise_ip:
				 *
				 *  0 - SAMPLE_IP can have arbitrary skid
				 *  1 - SAMPLE_IP must have constant skid
				 *  2 - SAMPLE_IP requested to have 0 skid
				 *  3 - SAMPLE_IP must have 0 skid
				 *
				 *  See also PERF_RECORD_MISC_EXACT_IP
				 */
				precise_ip     :  2, /* skid constraint       */
				mmap_data      :  1, /* non-exec mmap data    */
				sample_id_all  :  1, /* sample_type all events */

				exclude_host   :  1, /* don't count in host   */
				exclude_guest  :  1, /* don't count in guest  */

				exclude_callchain_kernel : 1, /* exclude kernel callchains */
				exclude_callchain_user   : 1, /* exclude user callchains */
				mmap2          :  1, /* include mmap with inode data     */
				comm_exec      :  1, /* flag comm events that are due to an exec */
				use_clockid    :  1, /* use @clockid for time fields */
				context_switch :  1, /* context switch data */
				write_backward :  1, /* Write ring buffer from end to beginning */
				namespaces     :  1, /* include namespaces data */
				__reserved_1   : 35;

	union {
		__u32		wakeup_events;	  /* wakeup every n events */
		__u32		wakeup_watermark; /* bytes before wakeup   */
	};

	__u32			bp_type;
	union {
		__u64		bp_addr;
		__u64		kprobe_func; /* for perf_kprobe */
		__u64		uprobe_path; /* for perf_uprobe */
		__u64		config1; /* extension of config */
	};
	union {
		__u64		bp_len;
		__u64		kprobe_addr; /* when kprobe_func == NULL */
		__u64		probe_offset; /* for perf_[k,u]probe */
		__u64		config2; /* extension of config1 */
	};
	__u64	branch_sample_type; /* enum perf_branch_sample_type */

	/*
	 * Defines set of user regs to dump on samples.
	 * See asm/perf_regs.h for details.
	 */
	__u64	sample_regs_user;

	/*
	 * Defines size of the user stack to dump on samples.
	 */
	__u32	sample_stack_user;

	__s32	clockid;
	/*
	 * Defines set of regs to dump for each sample
	 * state captured on:
	 *  - precise = 0: PMU interrupt
	 *  - precise > 0: sampled instruction
	 *
	 * See asm/perf_regs.h for details.
	 */
	__u64	sample_regs_intr;

	/*
	 * Wakeup watermark for AUX area
	 */
	__u32	aux_watermark;
	__u16	sample_max_stack;
	__u16	__reserved_2;	/* align to __u64 */
};

struct perf_event;

struct perf_sample_data;

typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *regs);

enum {
	POLICYDB_CAPABILITY_NETPEER,
	POLICYDB_CAPABILITY_OPENPERM,
	POLICYDB_CAPABILITY_EXTSOCKCLASS,
	POLICYDB_CAPABILITY_ALWAYSNETWORK,
	POLICYDB_CAPABILITY_CGROUPSECLABEL,
	POLICYDB_CAPABILITY_NNP_NOSUID_TRANSITION,
	__POLICYDB_CAPABILITY_MAX
};

struct selinux_avc;

struct selinux_ss;

struct selinux_state {
	bool disabled;
	bool enforcing;
	bool checkreqprot;
	bool initialized;
	bool policycap[__POLICYDB_CAPABILITY_MAX];
	struct selinux_avc *avc;
	struct selinux_ss *ss;
};

enum {
	DUMP_PREFIX_NONE,
	DUMP_PREFIX_ADDRESS,
	DUMP_PREFIX_OFFSET
};

struct frame_record {
	u64 fp;
	u64 lr;
};

#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN(x, a)			__ALIGN_KERNEL((x), (a))

#define PAGE_ALIGN(addr) ALIGN(addr, 4096)

struct pt_regs *_task_pt_reg(struct task_struct *task);
