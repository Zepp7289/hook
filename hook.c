#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <asm/ptrace.h>
#include "hook.h"


KPM_NAME("hook");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Zepp7289");
KPM_DESCRIPTION("hook");

pid_t (*__task_pid_nr_ns_ptr)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = NULL;
struct file *(*filp_open_ptr)(const char *filename, int flags, umode_t mode) = NULL;
int (*filp_close_ptr)(struct file *filp, fl_owner_t id) = NULL;
ssize_t (*vfs_read_ptr)(struct file *file, char __user *buf, size_t count, loff_t *pos) = NULL;
ssize_t (*vfs_write_ptr)(struct file *file, const char __user *buf, size_t count, loff_t *pos) = NULL;
ssize_t (*kernel_read_ptr)(struct file *file, void *buf, size_t count, loff_t *pos) = NULL;
ssize_t (*kernel_write_ptr)(struct file *file, const void *buf, size_t count, loff_t *pos) = NULL;
void *(*vmalloc_ptr)(unsigned long size) = NULL;
void (*vfree_ptr)(const void *addr) = NULL;
void (*msleep_ptr)(unsigned int msecs) = NULL;
struct file *(*do_filp_open_ptr)(int dfd, struct filename *pathname, const struct open_flags *op) = NULL;
unsigned long  (*__arch_copy_to_user_ptr)(void __user *to, const void *from, unsigned long n) = NULL;
unsigned long (*__arch_copy_from_user_ptr)(void *to, const void __user *from, unsigned long n) = NULL;
void (*save_stack_trace_user_ptr)(struct stack_trace *trace) = NULL;
struct perf_event * __percpu *(*register_wide_hw_breakpoint_ptr)(struct perf_event_attr *attr, perf_overflow_handler_t triggered, void *context) = NULL;
void (*unregister_wide_hw_breakpoint_ptr)(struct perf_event * __percpu *cpu_events) = NULL;
struct selinux_state *selinux_state = NULL;
void (*perf_event_disable_ptr)(struct perf_event *event) = NULL;
void (*perf_event_enable_ptr)(struct perf_event *event) = NULL;
void (*print_hex_dump_ptr)(const char *level, const char *prefix_str, int prefix_type, int rowsize, int groupsize, const void *buf, size_t len, bool ascii) = NULL;

static uid_t target_uid = 10588;
static bool is_delay = false;
static int open_count = 0;
static void *segment_addr = NULL;
static uint64_t segment_length = 0x0;
static uint64_t segment_func_offet = 0x237143C;
static unsigned char patch_code[] = {
    0x03, 0xf0, 0x67, 0x1e,
};
static bool is_hook = false;
static struct perf_event * __percpu *hbp = NULL;
static struct perf_event_attr attr;
static struct perf_event *hwbp = NULL;
static struct perf_event * __percpu *hbp_next = NULL;
static struct perf_event_attr attr_next;
static struct perf_event *hwbp_next = NULL;
static void *tmp_buf = NULL;
static size_t tmp_buf_size = 100 * 1024 * 1024;
struct file *tmp_filp = NULL;
static size_t tmp_filp_size = 0;
static size_t tmp_cur_size = 0;
static loff_t tmp_filp_pos = 0;

static void unwind(struct pt_regs *regs) {
    int depth = 0;
    struct frame_record *cur = (struct frame_record *)regs->regs[29];
    pr_info("depth: %02d LR: %px\n", depth++, regs->regs[30]);
    while (cur != 0 && depth < 32) {
        struct frame_record frame_record;
        if (__arch_copy_from_user_ptr(&frame_record, cur, sizeof(frame_record)) > 0) {
            break;
        }
        pr_info("depth: %02d LR: %px\n", depth, frame_record.lr);
        cur = (struct frame_record *)frame_record.fp;
        depth++;
    }
}

static void hbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    hwbp = bp;
    uid_t uid = current_uid();

    if (uid == target_uid) {
        // unwind(regs);
        // pr_info("regs[8]: %px\n", regs->regs[8]);
        // pr_info("regs[9]: %px\n", regs->regs[9]);
        // tmp_cur_size = regs->regs[9];
        
        // pr_info("regs[24]: %px\n", regs->regs[24]);
        // pr_info("regs[10]: %px\n", regs->regs[10]);
        // regs->regs[0] = 0x2;

        // regs->pc = (uint64_t)segment_addr + segment_length;

        // char buf[256];
        // pr_info("regs[0]: %px\n", regs->regs[0]);
        // __arch_copy_from_user_ptr(buf, (void *)(regs->regs[0]), sizeof(buf));
        // print_hex_dump_ptr(KERN_INFO, "regs[0]: ", DUMP_PREFIX_OFFSET, 16, 1, buf, sizeof(buf), true);
        // pr_info("regs[1]: %px\n", regs->regs[1]);
        // __arch_copy_from_user_ptr(buf, (void *)(regs->regs[1]), sizeof(buf));
        // print_hex_dump_ptr(KERN_INFO, "regs[1]: ", DUMP_PREFIX_OFFSET, 16, 1, buf, sizeof(buf), true);
        // pr_info("regs[2]: %px\n", regs->regs[2]);
        // __arch_copy_from_user_ptr(buf, (void *)(regs->regs[2]), sizeof(buf));
        // print_hex_dump_ptr(KERN_INFO, "regs[2]: ", DUMP_PREFIX_OFFSET, 16, 1, buf, sizeof(buf), true);
        // pr_info("regs[3]: %px\n", regs->regs[3]);

        // char buf[256];
        // pr_info("regs[0]: %px\n", regs->regs[0]);
        // __arch_copy_from_user_ptr(buf, (void *)(regs->regs[0]), sizeof(buf));
        // print_hex_dump_ptr(KERN_INFO, "regs[0]: ", DUMP_PREFIX_OFFSET, 16, 1, buf, sizeof(buf), true);
        // if (*(uint32_t *)buf == 0xfab11baf) {
        //     tmp_filp_size = tmp_buf_size;
        //     __arch_copy_from_user_ptr(tmp_buf, (void *)(regs->regs[0]), tmp_filp_size);
        // }

        // char buf[256];
        // pr_info("regs[20]: %px\n", regs->regs[20]);
        // __arch_copy_from_user_ptr(buf, (void *)(regs->regs[0]), sizeof(buf));
        // print_hex_dump_ptr(KERN_INFO, "regs[20]: ", DUMP_PREFIX_OFFSET, 16, 1, buf, sizeof(buf), true);
        // size_t dll_len = *(size_t *)&buf[0x18];
        // pr_info("dll_len: %zx\n", dll_len);
        // if (dll_len == 0x482400) {
        //     tmp_filp_size = dll_len + 0x20;
        //     __arch_copy_from_user_ptr(tmp_buf, (void *)(regs->regs[0]), tmp_filp_size);
        //     // __arch_copy_to_user_ptr((void *)(regs->regs[0] + 0x20 + 0x18D88C), patch_code, sizeof(patch_code));
        // }

        // char buf[256];
        // pr_info("regs[1]: %px\n", regs->regs[1]);
        // __arch_copy_from_user_ptr(buf, (void *)(regs->regs[1]), sizeof(buf));
        // print_hex_dump_ptr(KERN_INFO, "regs[1]: ", DUMP_PREFIX_OFFSET, 16, 1, buf, sizeof(buf), true);
        // pr_info("regs[2]: %px\n", regs->regs[2]);
        // compat_strncpy_from_user(buf, (void *)(regs->regs[4]), sizeof(buf));
        // pr_info("regs[4]: %s\n", buf);
        // if (strstr(buf, "assets/main/index.js")) {
        //     tmp_filp_size = (size_t)regs->regs[2];
        //     __arch_copy_from_user_ptr(tmp_buf, (void *)(regs->regs[1]), tmp_filp_size);
        //     // __arch_copy_to_user_ptr((void *)(regs->regs[1] + 0x8D8A), patch_code, sizeof(patch_code));
        // }
    }

    perf_event_disable_ptr(hwbp);
    if (hwbp_next) {
        perf_event_enable_ptr(hwbp_next);
    }
}

static void hbp_handler_next(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    hwbp_next = bp;
    uid_t uid = current_uid();

    if (uid == target_uid) {
        // pr_info("regs[0]: %px\n", regs->regs[0]);
        // pr_info("regs[17]: %px\n", regs->regs[17]);
        // pr_info("regs[14]: %px\n", regs->regs[14]);
        // pr_info("regs[15]: %px\n", regs->regs[15]);

        // __arch_copy_from_user_ptr((void *)((uint64_t)tmp_buf + (uint64_t)tmp_filp_size), (void *)(regs->regs[28] + 0xc), tmp_cur_size);
        // tmp_filp_size += tmp_cur_size;

        // regs->pc = (uint64_t)segment_addr + segment_func_offet + 0x4;

        // char buf[256];
        // pr_info("regs[19]: %px\n", regs->regs[19]);
        // __arch_copy_from_user_ptr(buf, (void *)(regs->regs[19]), sizeof(buf));
        // print_hex_dump_ptr(KERN_INFO, "regs[19]: ", DUMP_PREFIX_OFFSET, 16, 1, buf, sizeof(buf), true);
    }

    perf_event_disable_ptr(hwbp_next);
    perf_event_enable_ptr(hwbp);
}

static void init_attr(struct perf_event_attr *attr, void *addr) {
    memset(attr, 0, sizeof(*attr));
    attr->type = PERF_TYPE_BREAKPOINT;
    attr->size = sizeof(*attr);
    attr->bp_type = HW_BREAKPOINT_X;
    attr->bp_addr = (uint64_t)addr;
    attr->bp_len = HW_BREAKPOINT_LEN_4;
    attr->disabled = 0;
    attr->sample_period = 1;
    attr->exclude_kernel = 1;
    attr->exclude_user = 0;
}

static void before_do_filp_open(hook_fargs3_t *args, void *udata) {
    // args->local.data0 = NULL;
    // int dfd = (int)args->arg0;
    // struct filename *pathname = (struct filename *)args->arg1;

    // uid_t uid = current_uid();

    // if (uid == target_uid
    //     && strstr(pathname->name, "/data/app/~~Ig8noHry304p8ivYN8paHQ==/com.y10.hnly.sz06-X0BCYVLjXirRpkFBORt0oQ==/lib/arm64/libthemis.so")
    //     && open_count == 2
    // ) {
    //     args->local.data0 = (uint64_t)pathname->name;
    //     pathname->name = "/data/app/~~Ig8noHry304p8ivYN8paHQ==/com.y10.hnly.sz06-X0BCYVLjXirRpkFBORt0oQ==/lib/arm64/liblibc.so";
    // }

    // if (!is_delay && strstr(pathname->name, "libcocos2dlua.so")) {
    //     is_delay = true;
    //     msleep_ptr(10 * 1000);
    // }
}

static void after_do_filp_open(hook_fargs3_t *args, void *udata) {
    // if (args->local.data0) {
    //     struct filename *pathname = (struct filename *)args->arg1;
    //     pathname->name = (const char *)args->local.data0;
    // }
}

static void before_openat(hook_fargs4_t *args, void *udata) {
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    int flags = (int)syscall_argn(args, 2);
    umode_t mode = (umode_t)syscall_argn(args, 3);

    struct task_struct *task = current;
    pid_t pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, NULL);
    pid_t tgid = __task_pid_nr_ns_ptr(task, PIDTYPE_TGID, NULL);
    uid_t uid = current_uid();
    struct pt_regs *regs = _task_pt_reg(task);

    args->local.data0 = (uint64_t)pid;
    args->local.data1 = (uint64_t)tgid;
    args->local.data2 = (uint64_t)uid;
    args->local.data3 = (uint64_t)filename;

    // if (uid == target_uid) {
    //     char buf[256];
    //     compat_strncpy_from_user(buf, filename, sizeof(buf));

    //     // if (strstr(buf, "libthemis.so")) {
    //     //     open_count++;
    //     // }

    //     // if (strstr(buf, "5d38d6cd.0")) {
    //     //     args->skip_origin = true;
    //     //     args->ret = -2;
    //     // }

    //     if (strstr(buf, "global-metadata.dat")) {
    //         unwind(regs);
    //     }
    // }
}

static void after_openat(hook_fargs4_t *args, void *udata) {
    pid_t pid = (pid_t)args->local.data0;
    pid_t tgid = (pid_t)args->local.data1;
    uid_t uid = (uid_t)args->local.data2;
    const char __user *filename = (const char __user *)args->local.data3;

    if (uid == target_uid) {
        char buf[256];
        compat_strncpy_from_user(buf, filename, sizeof(buf));

        pr_info("openat pid: %d tgid: %d uid: %u filename: %s ret: %d\n", 
            pid, tgid, uid, buf, args->ret);
    }
}

static void before_mmap(hook_fargs6_t *args, void *udata) {
    void *addr = (void *)syscall_argn(args, 0);
    size_t length = (size_t)syscall_argn(args, 1);
    int prot = (int)syscall_argn(args, 2);
    int flags = (int)syscall_argn(args, 3);
    int fd = (int)syscall_argn(args, 4);
    off_t offset = (off_t)syscall_argn(args, 5);

    struct task_struct *task = current;
    pid_t pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, NULL);
    pid_t tgid = __task_pid_nr_ns_ptr(task, PIDTYPE_TGID, NULL);
    uid_t uid = current_uid();

    args->local.data0 = (uint64_t)pid;
    args->local.data1 = (uint64_t)tgid;
    args->local.data2 = (uint64_t)uid;
    args->local.data3 = (uint64_t)addr;
    args->local.data4 = (uint64_t)length;
    args->local.data5 = (uint64_t)prot;
    args->local.data6 = (uint64_t)fd;
    args->local.data7 = (uint64_t)offset;

    // if (uid == target_uid && length == 0x4711340 && offset == 0x2b9c000) {
    //     // set_syscall_argn(args, 1, 0x8bda8);
    //     set_syscall_argn(args, 2, 7);
    //     // set_syscall_argn(args, 5, 0x1);
    // }
}

static void after_mmap(hook_fargs6_t *args, void *udata) {
    pid_t pid = (pid_t)args->local.data0;
    pid_t tgid = (pid_t)args->local.data1;
    uid_t uid = (uid_t)args->local.data2;
    void *addr = (void *)args->local.data3;
    size_t length = (size_t)args->local.data4;
    int prot = (int)args->local.data5;
    int fd = (int)args->local.data6;
    off_t offset = (off_t)args->local.data7;

    if (uid == target_uid) {
        pr_info("mmap pid: %d tgid: %d uid: %u addr: %px length: %zx prot: %d fd: %d offset: %zx ret: %px\n", 
            pid, tgid, uid, addr, length, prot, fd, offset, args->ret);
    }

    // if (uid == target_uid && length == 0x4ba8000 && offset == 0x0) {
    //     segment_addr = (void *)(args->ret);
    //     segment_length = length;
    // }

    // if (uid == target_uid && length == 0x4ba8000 && offset == 0x0 && !is_hook) {
    //     init_attr(&attr, (void *)((uint64_t)segment_addr + segment_func_offet));
    //     init_attr(&attr_next, (void *)((uint64_t)segment_addr + segment_func_offet + 0x4));
    //     // init_attr(&attr_next, (void *)((uint64_t)segment_addr + segment_length + sizeof(patch_code)));
    //     selinux_state->enforcing = 0;
    //     hbp = register_wide_hw_breakpoint_ptr(&attr, hbp_handler, NULL);
    //     hbp_next = register_wide_hw_breakpoint_ptr(&attr_next, hbp_handler_next, NULL);
    //     selinux_state->enforcing = 1;
    //     is_hook = true;
    // }

    // if (uid == target_uid && length == 0x4711340 && offset == 0x2b9c000) {
    //     __arch_copy_to_user_ptr((void *)((uint64_t)segment_addr + segment_length), patch_code, sizeof(patch_code));
    // }
}

static void before_munmap(hook_fargs2_t *args, void *udata) {
    void *addr = (void *)syscall_argn(args, 0);
    size_t length = (size_t)syscall_argn(args, 1);

    struct task_struct *task = current;
    pid_t pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, NULL);
    pid_t tgid = __task_pid_nr_ns_ptr(task, PIDTYPE_TGID, NULL);
    uid_t uid = current_uid();

    if (uid == target_uid) {
        pr_info("munmap pid: %d tgid: %d uid: %u addr: %px length: %zx\n", 
            pid, tgid, uid, addr, length);
    }

    // if (uid == target_uid && addr == segment_addr) {
    //     args->skip_origin = true;
    //     args->ret = 0;
    // }
}

static void before_mprotect(hook_fargs3_t *args, void *udata) {
    void *addr = (void *)syscall_argn(args, 0);
    size_t length = (size_t)syscall_argn(args, 1);
    int prot = (int)syscall_argn(args, 2);

    struct task_struct *task = current;
    pid_t pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, NULL);
    pid_t tgid = __task_pid_nr_ns_ptr(task, PIDTYPE_TGID, NULL);
    uid_t uid = current_uid();

    if (uid == target_uid) {
        pr_info("mprotect pid: %d addr: %px length: %zx prot: %d\n", pid, addr, length, prot);
    }

    // if (uid == target_uid && addr == segment_addr && prot == 5) {
    //     args->skip_origin = true;
    //     args->ret = 0;
    // }

    // if (uid == target_uid && addr == segment_addr && prot == 5) {
    //     __arch_copy_to_user_ptr((void *)((uint64_t)segment_addr + segment_length), patch_code, sizeof(patch_code));
    //     set_syscall_argn(args, 1, PAGE_ALIGN(segment_length));
    // }

    // if (uid == target_uid && length == 0x5c515c8 && prot == 1) {
    //     char buf[128];
    //     static loff_t filp_pos = 0;
    //     snprintf(buf, sizeof(buf), "/sdcard/Download/%px", addr);
    //     struct file *filp = filp_open_ptr(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
    //     vfs_write_ptr(filp, addr, length, &filp_pos);
    //     filp_close_ptr(filp, NULL);
    // }
}

static void before_kill(hook_fargs2_t *args, void *udata) {
    // pid_t pid = (pid_t)syscall_argn(args, 0);
    // int sig = (int)syscall_argn(args, 1);

    // uid_t uid = current_uid();

    // if (uid == target_uid) {
    //     pr_info("kill pid: %d, sig: %d\n", pid, sig);
    // }

    // if (uid == target_uid) {
    //     args->skip_origin = true;
    //     args->ret = 0;
    // }
}

static void before_exit(hook_fargs1_t *args, void *udata) {
    // int status = (int)syscall_argn(args, 0);

    // struct task_struct *task = current;
    // pid_t pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, NULL);
    // pid_t tgid = __task_pid_nr_ns_ptr(task, PIDTYPE_TGID, NULL);
    // uid_t uid = current_uid();

    // if (uid == target_uid) {
    //     pr_info("exit pid: %d, status: %d\n", pid, status);
    // }
}

static void before_ptrace(hook_fargs4_t *args, void *udata) {
    // struct task_struct *task = current;
    // pid_t pid = __task_pid_nr_ns_ptr(task, PIDTYPE_PID, NULL);
    // pid_t tgid = __task_pid_nr_ns_ptr(task, PIDTYPE_TGID, NULL);
    // uid_t uid = current_uid();

    // if (uid == target_uid) {
    //     pr_info("ptrace pid: %d\n", pid);
    // }

    // if (uid == target_uid) {
    //     args->skip_origin = true;
    //     args->ret = 0;
    // }
}

static long hook_init(const char *args, const char *event, void *__user reserved) {
    pr_info("hook init ..., args: %s\n", args);

    __task_pid_nr_ns_ptr = (void *)kallsyms_lookup_name("__task_pid_nr_ns");
    pr_info("kernel function __task_pid_nr_ns addr: %px\n", __task_pid_nr_ns_ptr);
    filp_open_ptr = (void *)kallsyms_lookup_name("filp_open");
    pr_info("kernel function filp_open addr: %px\n", filp_open_ptr);
    filp_close_ptr = (void *)kallsyms_lookup_name("filp_close");
    pr_info("kernel function filp_close addr: %px\n", filp_close_ptr);
    vfs_read_ptr = (void *)kallsyms_lookup_name("vfs_read");
    pr_info("kernel function vfs_read addr: %px\n", vfs_read_ptr);
    vfs_write_ptr = (void *)kallsyms_lookup_name("vfs_write");
    pr_info("kernel function vfs_write addr: %px\n", vfs_write_ptr);
    kernel_read_ptr = (void *)kallsyms_lookup_name("kernel_read");
    pr_info("kernel function kernel_read addr: %px\n", kernel_read_ptr);
    kernel_write_ptr = (void *)kallsyms_lookup_name("kernel_write");
    pr_info("kernel function kernel_write addr: %px\n", kernel_write_ptr);
    vmalloc_ptr = (void *)kallsyms_lookup_name("vmalloc");
    pr_info("kernel function vmalloc addr: %px\n", vmalloc_ptr);
    vfree_ptr = (void *)kallsyms_lookup_name("vfree");
    pr_info("kernel function vfree addr: %px\n", vfree_ptr);
    do_filp_open_ptr = (void *)kallsyms_lookup_name("do_filp_open");
    pr_info("kernel function do_filp_open addr: %px\n", do_filp_open_ptr);
    msleep_ptr = (void *)kallsyms_lookup_name("msleep");
    pr_info("kernel function msleep addr: %px\n", msleep_ptr);
    __arch_copy_to_user_ptr = (void *)kallsyms_lookup_name("__arch_copy_to_user");
    pr_info("kernel function __arch_copy_to_user addr: %px\n", __arch_copy_to_user_ptr);
    __arch_copy_from_user_ptr = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    pr_info("kernel function __arch_copy_from_user addr: %px\n", __arch_copy_from_user_ptr);
    save_stack_trace_user_ptr = (void *)kallsyms_lookup_name("save_stack_trace_user");
    pr_info("kernel function save_stack_trace_user addr: %px\n", save_stack_trace_user_ptr);
    register_wide_hw_breakpoint_ptr = (void *)kallsyms_lookup_name("register_wide_hw_breakpoint");
    pr_info("kernel function register_wide_hw_breakpoint addr: %px\n", register_wide_hw_breakpoint_ptr);
    unregister_wide_hw_breakpoint_ptr = (void *)kallsyms_lookup_name("unregister_wide_hw_breakpoint");
    pr_info("kernel function unregister_wide_hw_breakpoint addr: %px\n", unregister_wide_hw_breakpoint_ptr);
    selinux_state = (void *)kallsyms_lookup_name("selinux_state");
    pr_info("kernel function selinux_state addr: %px\n", selinux_state);
    perf_event_disable_ptr = (void *)kallsyms_lookup_name("perf_event_disable");
    pr_info("kernel function perf_event_disable addr: %px\n", perf_event_disable_ptr);
    perf_event_enable_ptr = (void *)kallsyms_lookup_name("perf_event_enable");
    pr_info("kernel function perf_event_enable addr: %px\n", perf_event_enable_ptr);
    print_hex_dump_ptr = (void *)kallsyms_lookup_name("print_hex_dump");
    pr_info("kernel function print_hex_dump addr: %px\n", print_hex_dump_ptr);

    hook_err_t err = HOOK_NO_ERR;
    err = inline_hook_syscalln(__NR_openat, 4, before_openat, after_openat, NULL);
    if (err) {
        pr_err("hook openat error: %d\n", err);
    }
    err = inline_hook_syscalln(__NR3264_mmap, 6, before_mmap, after_mmap, NULL);
    if (err) {
        pr_err("hook mmap error: %d\n", err);
    }
    err = inline_hook_syscalln(__NR_munmap, 2, before_munmap, NULL, NULL);
    if (err) {
        pr_err("hook munmap error: %d\n", err);
    }
    err = inline_hook_syscalln(__NR_kill, 2, before_kill, NULL, NULL);
    if (err) {
        pr_err("hook kill error: %d\n", err);
    }
    err = inline_hook_syscalln(__NR_exit, 1, before_exit, NULL, NULL);
    if (err) {
        pr_err("hook exit error: %d\n", err);
    }
    err = inline_hook_syscalln(__NR_ptrace, 4, before_ptrace, NULL, NULL);
    if (err) {
        pr_err("hook ptrace error: %d\n", err);
    }
    err = inline_hook_syscalln(__NR_mprotect, 3, before_mprotect, NULL, NULL);
    if (err) {
        pr_err("hook mprotect error: %d\n", err);
    }
    err = hook_wrap3(do_filp_open_ptr, before_do_filp_open, after_do_filp_open, NULL);
    if (err) {
        pr_err("hook do_filp_open error: %d\n", err);
    }

    // tmp_buf = vmalloc_ptr(tmp_buf_size);
    // memset(tmp_buf, 0, tmp_buf_size);
    // tmp_filp = filp_open_ptr("/sdcard/Download/tmp.dll", O_RDWR | O_CREAT | O_TRUNC, 0644);

    return 0;
}

static long hook_control(const char *args, char *__user out_msg, int outlen) {
    return 0;
}

static long hook_exit(void *__user reserved) {
    pr_info("hook exit ...\n");

    // kernel_write_ptr(tmp_filp, tmp_buf, tmp_filp_size, &tmp_filp_pos);
    // vfree_ptr(tmp_buf);

    inline_unhook_syscalln(__NR_openat, before_openat, after_openat);
    inline_unhook_syscalln(__NR3264_mmap, before_mmap, after_mmap);
    inline_unhook_syscalln(__NR_munmap, before_munmap, NULL);
    inline_unhook_syscalln(__NR_kill, before_kill, NULL);
    inline_unhook_syscalln(__NR_exit, before_exit, NULL);
    inline_unhook_syscalln(__NR_ptrace, before_ptrace, NULL);
    inline_unhook_syscalln(__NR_mprotect, before_mprotect, NULL);
    unhook(do_filp_open_ptr);
    
    if (hbp) {
        unregister_wide_hw_breakpoint_ptr(hbp);
    }
    if (hbp_next) {
        unregister_wide_hw_breakpoint_ptr(hbp_next);
    }

    return 0;
}

KPM_INIT(hook_init);
KPM_CTL0(hook_control);
KPM_EXIT(hook_exit);
