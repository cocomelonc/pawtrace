#include "pawtrace.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

const char *pt_syscall_name(long nr) {
  switch (nr) {
  case 0: return "read";
  case 1: return "write";
  case 2: return "open";
  case 3: return "close";
  case 4: return "stat";
  case 5: return "fstat";
  case 6: return "lstat";
  case 7: return "poll";
  case 8: return "lseek";
  case 9: return "mmap";
  case 10: return "mprotect";
  case 11: return "munmap";
  case 12: return "brk";
  case 13: return "rt_sigaction";
  case 14: return "rt_sigprocmask";
  case 15: return "rt_sigreturn";
  case 16: return "ioctl";
  case 17: return "pread64";
  case 18: return "pwrite64";
  case 19: return "readv";
  case 20: return "writev";
  case 21: return "access";
  case 22: return "pipe";
  case 23: return "select";
  case 24: return "sched_yield";
  case 25: return "mremap";
  case 26: return "msync";
  case 27: return "mincore";
  case 28: return "madvise";
  case 29: return "shmget";
  case 30: return "shmat";
  case 31: return "shmctl";
  case 32: return "dup";
  case 33: return "dup2";
  case 34: return "pause";
  case 35: return "nanosleep";
  case 36: return "getitimer";
  case 37: return "alarm";
  case 38: return "setitimer";
  case 39: return "getpid";
  case 40: return "sendfile";
  case 41: return "socket";
  case 42: return "connect";
  case 43: return "accept";
  case 44: return "sendto";
  case 45: return "recvfrom";
  case 46: return "sendmsg";
  case 47: return "recvmsg";
  case 48: return "shutdown";
  case 49: return "bind";
  case 50: return "listen";
  case 51: return "getsockname";
  case 52: return "getpeername";
  case 53: return "socketpair";
  case 54: return "setsockopt";
  case 55: return "getsockopt";
  case 56: return "clone";
  case 57: return "fork";
  case 58: return "vfork";
  case 59: return "execve";
  case 60: return "exit";
  case 61: return "wait4";
  case 62: return "kill";
  case 63: return "uname";
  case 64: return "semget";
  case 65: return "semop";
  case 66: return "semctl";
  case 67: return "shmdt";
  case 68: return "msgget";
  case 69: return "msgsnd";
  case 70: return "msgrcv";
  case 71: return "msgctl";
  case 72: return "fcntl";
  case 73: return "flock";
  case 74: return "fsync";
  case 75: return "fdatasync";
  case 76: return "truncate";
  case 77: return "ftruncate";
  case 78: return "getdents";
  case 79: return "getcwd";
  case 80: return "chdir";
  case 81: return "fchdir";
  case 82: return "rename";
  case 83: return "mkdir";
  case 84: return "rmdir";
  case 85: return "creat";
  case 86: return "link";
  case 87: return "unlink";
  case 88: return "symlink";
  case 89: return "readlink";
  case 90: return "chmod";
  case 91: return "fchmod";
  case 92: return "chown";
  case 93: return "fchown";
  case 94: return "lchown";
  case 95: return "umask";
  case 96: return "gettimeofday";
  case 97: return "getrlimit";
  case 98: return "getrusage";
  case 99: return "sysinfo";
  case 100: return "times";
  case 101: return "ptrace";
  case 102: return "getuid";
  case 103: return "syslog";
  case 104: return "getgid";
  case 105: return "setuid";
  case 106: return "setgid";
  case 107: return "geteuid";
  case 108: return "getegid";
  case 109: return "setpgid";
  case 110: return "getppid";
  case 111: return "getpgrp";
  case 112: return "setsid";
  case 113: return "setreuid";
  case 114: return "setregid";
  case 115: return "getgroups";
  case 116: return "setgroups";
  case 117: return "setresuid";
  case 118: return "getresuid";
  case 119: return "setresgid";
  case 120: return "getresgid";
  case 121: return "getpgid";
  case 122: return "setfsuid";
  case 123: return "setfsgid";
  case 124: return "getsid";
  case 125: return "capget";
  case 126: return "capset";
  case 127: return "rt_sigpending";
  case 128: return "rt_sigtimedwait";
  case 129: return "rt_sigqueueinfo";
  case 130: return "rt_sigsuspend";
  case 131: return "sigaltstack";
  case 132: return "utime";
  case 133: return "mknod";
  case 134: return "uselib";
  case 135: return "personality";
  case 136: return "ustat";
  case 137: return "statfs";
  case 138: return "fstatfs";
  case 139: return "sysfs";
  case 140: return "getpriority";
  case 141: return "setpriority";
  case 142: return "sched_setparam";
  case 143: return "sched_getparam";
  case 144: return "sched_setscheduler";
  case 145: return "sched_getscheduler";
  case 146: return "sched_get_priority_max";
  case 147: return "sched_get_priority_min";
  case 148: return "sched_rr_get_interval";
  case 149: return "mlock";
  case 150: return "munlock";
  case 151: return "mlockall";
  case 152: return "munlockall";
  case 153: return "vhangup";
  case 154: return "modify_ldt";
  case 155: return "pivot_root";
  case 156: return "_sysctl";
  case 157: return "prctl";
  case 158: return "arch_prctl";
  case 159: return "adjtimex";
  case 160: return "setrlimit";
  case 161: return "chroot";
  case 162: return "sync";
  case 163: return "acct";
  case 164: return "settimeofday";
  case 165: return "mount";
  case 166: return "umount2";
  case 167: return "swapon";
  case 168: return "swapoff";
  case 169: return "reboot";
  case 170: return "sethostname";
  case 171: return "setdomainname";
  case 172: return "iopl";
  case 173: return "ioperm";
  case 174: return "create_module";
  case 175: return "init_module";
  case 176: return "delete_module";
  case 177: return "get_kernel_syms";
  case 178: return "query_module";
  case 179: return "quotactl";
  case 180: return "nfsservctl";
  case 181: return "getpmsg";
  case 182: return "putpmsg";
  case 183: return "afs_syscall";
  case 184: return "tuxcall";
  case 185: return "security";
  case 186: return "gettid";
  case 187: return "readahead";
  case 188: return "setxattr";
  case 189: return "lsetxattr";
  case 190: return "fsetxattr";
  case 191: return "getxattr";
  case 192: return "lgetxattr";
  case 193: return "fgetxattr";
  case 194: return "listxattr";
  case 195: return "llistxattr";
  case 196: return "flistxattr";
  case 197: return "removexattr";
  case 198: return "lremovexattr";
  case 199: return "fremovexattr";
  case 200: return "tkill";
  case 201: return "time";
  case 202: return "futex";
  case 203: return "sched_setaffinity";
  case 204: return "sched_getaffinity";
  case 205: return "set_thread_area";
  case 206: return "io_setup";
  case 207: return "io_destroy";
  case 208: return "io_getevents";
  case 209: return "io_submit";
  case 210: return "io_cancel";
  case 211: return "get_thread_area";
  case 212: return "lookup_dcookie";
  case 213: return "epoll_create";
  case 214: return "epoll_ctl_old";
  case 215: return "epoll_wait_old";
  case 216: return "remap_file_pages";
  case 217: return "getdents64";
  case 218: return "set_tid_address";
  case 219: return "restart_syscall";
  case 220: return "semtimedop";
  case 221: return "fadvise64";
  case 222: return "timer_create";
  case 223: return "timer_settime";
  case 224: return "timer_gettime";
  case 225: return "timer_getoverrun";
  case 226: return "timer_delete";
  case 227: return "clock_settime";
  case 228: return "clock_gettime";
  case 229: return "clock_getres";
  case 230: return "clock_nanosleep";
  case 231: return "exit_group";
  case 232: return "epoll_wait";
  case 233: return "epoll_ctl";
  case 234: return "tgkill";
  case 235: return "utimes";
  case 236: return "vserver";
  case 237: return "mbind";
  case 238: return "set_mempolicy";
  case 239: return "get_mempolicy";
  case 240: return "mq_open";
  case 241: return "mq_unlink";
  case 242: return "mq_timedsend";
  case 243: return "mq_timedreceive";
  case 244: return "mq_notify";
  case 245: return "mq_getsetattr";
  case 246: return "kexec_load";
  case 247: return "waitid";
  case 248: return "add_key";
  case 249: return "request_key";
  case 250: return "keyctl";
  case 251: return "ioprio_set";
  case 252: return "ioprio_get";
  case 253: return "inotify_init";
  case 254: return "inotify_add_watch";
  case 255: return "inotify_rm_watch";
  case 256: return "migrate_pages";
  case 257: return "openat";
  case 258: return "mkdirat";
  case 259: return "mknodat";
  case 260: return "fchownat";
  case 261: return "futimesat";
  case 262: return "newfstatat";
  case 263: return "unlinkat";
  case 264: return "renameat";
  case 265: return "linkat";
  case 266: return "symlinkat";
  case 267: return "readlinkat";
  case 268: return "fchmodat";
  case 269: return "faccessat";
  case 270: return "pselect6";
  case 271: return "ppoll";
  case 272: return "unshare";
  case 273: return "set_robust_list";
  case 274: return "get_robust_list";
  case 275: return "splice";
  case 276: return "tee";
  case 277: return "sync_file_range";
  case 278: return "vmsplice";
  case 279: return "move_pages";
  case 280: return "utimensat";
  case 281: return "epoll_pwait";
  case 282: return "signalfd";
  case 283: return "timerfd_create";
  case 284: return "eventfd";
  case 285: return "fallocate";
  case 286: return "timerfd_settime";
  case 287: return "timerfd_gettime";
  case 288: return "accept4";
  case 289: return "signalfd4";
  case 290: return "eventfd2";
  case 291: return "epoll_create1";
  case 292: return "dup3";
  case 293: return "pipe2";
  case 294: return "inotify_init1";
  case 295: return "preadv";
  case 296: return "pwritev";
  case 297: return "rt_tgsigqueueinfo";
  case 298: return "perf_event_open";
  case 299: return "recvmmsg";
  case 300: return "fanotify_init";
  case 301: return "fanotify_mark";
  case 302: return "prlimit64";
  case 303: return "name_to_handle_at";
  case 304: return "open_by_handle_at";
  case 305: return "clock_adjtime";
  case 306: return "syncfs";
  case 307: return "sendmmsg";
  case 308: return "setns";
  case 309: return "getcpu";
  case 310: return "process_vm_readv";
  case 311: return "process_vm_writev";
  case 312: return "kcmp";
  case 313: return "finit_module";
  case 314: return "sched_setattr";
  case 315: return "sched_getattr";
  case 316: return "renameat2";
  case 317: return "seccomp";
  case 318: return "getrandom";
  case 319: return "memfd_create";
  case 320: return "kexec_file_load";
  case 321: return "bpf";
  case 322: return "execveat";
  case 323: return "userfaultfd";
  case 324: return "membarrier";
  case 325: return "mlock2";
  case 326: return "copy_file_range";
  case 327: return "preadv2";
  case 328: return "pwritev2";
  case 329: return "pkey_mprotect";
  case 330: return "pkey_alloc";
  case 331: return "pkey_free";
  case 332: return "statx";
  case 333: return "io_pgetevents";
  case 334: return "rseq";
  case 335: return "uretprobe";
  case 424: return "pidfd_send_signal";
  case 425: return "io_uring_setup";
  case 426: return "io_uring_enter";
  case 427: return "io_uring_register";
  case 428: return "open_tree";
  case 429: return "move_mount";
  case 430: return "fsopen";
  case 431: return "fsconfig";
  case 432: return "fsmount";
  case 433: return "fspick";
  case 434: return "pidfd_open";
  case 435: return "clone3";
  case 436: return "close_range";
  case 437: return "openat2";
  case 438: return "pidfd_getfd";
  case 439: return "faccessat2";
  case 440: return "process_madvise";
  case 441: return "epoll_pwait2";
  case 442: return "mount_setattr";
  case 443: return "quotactl_fd";
  case 444: return "landlock_create_ruleset";
  case 445: return "landlock_add_rule";
  case 446: return "landlock_restrict_self";
  case 447: return "memfd_secret";
  case 448: return "process_mrelease";
  case 449: return "futex_waitv";
  case 450: return "set_mempolicy_home_node";
  case 451: return "cachestat";
  case 452: return "fchmodat2";
  case 453: return "map_shadow_stack";
  case 454: return "futex_wake";
  case 455: return "futex_wait";
  case 456: return "futex_requeue";
  case 457: return "statmount";
  case 458: return "listmount";
  case 459: return "lsm_get_self_attr";
  case 460: return "lsm_set_self_attr";
  case 461: return "lsm_list_modules";
  case 462: return "mseal";
  default: return "unknown";
  }
}

const char *pt_errno_name(long neg_ret) {
  if (neg_ret >= 0 || neg_ret < -4095) {
    return NULL;
  }
  switch (-neg_ret) {
  case EPERM: return "EPERM";
  case ENOENT: return "ENOENT";
  case ESRCH: return "ESRCH";
  case EINTR: return "EINTR";
  case EIO: return "EIO";
  case ENXIO: return "ENXIO";
  case E2BIG: return "E2BIG";
  case ENOEXEC: return "ENOEXEC";
  case EBADF: return "EBADF";
  case ECHILD: return "ECHILD";
  case EAGAIN: return "EAGAIN";
  case ENOMEM: return "ENOMEM";
  case EACCES: return "EACCES";
  case EFAULT: return "EFAULT";
  case EBUSY: return "EBUSY";
  case EEXIST: return "EEXIST";
  case ENODEV: return "ENODEV";
  case ENOTDIR: return "ENOTDIR";
  case EISDIR: return "EISDIR";
  case EINVAL: return "EINVAL";
  case EMFILE: return "EMFILE";
  case ENOTTY: return "ENOTTY";
  case ETXTBSY: return "ETXTBSY";
  case EFBIG: return "EFBIG";
  case ENOSPC: return "ENOSPC";
  case ESPIPE: return "ESPIPE";
  case EROFS: return "EROFS";
  case EMLINK: return "EMLINK";
  case EPIPE: return "EPIPE";
  default: return "ERR";
  }
}

void pt_json_escape(FILE *out, const char *s) {
  for (; s && *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') {
      fputc('\\', out);
      fputc(c, out);
    } else if (c == '\n') {
      fputs("\\n", out);
    } else if (c == '\t') {
      fputs("\\t", out);
    } else if (c < 32) {
      fprintf(out, "\\u%04x", c);
    } else {
      fputc(c, out);
    }
  }
}

struct pt_bit_name {
  unsigned long bit;
  const char *name;
};

static void print_named_bits(FILE *out, unsigned long v,
               const struct pt_bit_name *bits, size_t count) {
  bool first = true;
  fputc('[', out);
  for (size_t i = 0; i < count; i++) {
    if (v & bits[i].bit) {
      fprintf(out, "%s%s", first ? "" : "|", bits[i].name);
      first = false;
    }
  }
  if (first) {
    fputc('0', out);
  }
  fputc(']', out);
}

static void print_prot(FILE *out, unsigned long v) {
  static const struct pt_bit_name bits[] = {
    {PROT_READ, "PROT_READ"},
    {PROT_WRITE, "PROT_WRITE"},
    {PROT_EXEC, "PROT_EXEC"},
  };
  print_named_bits(out, v, bits, sizeof(bits) / sizeof(bits[0]));
}

static void print_mmap_flags(FILE *out, unsigned long v) {
  bool first = true;
  fputc('[', out);
  if ((v & MAP_TYPE) == MAP_PRIVATE) {
    fputs("MAP_PRIVATE", out);
    first = false;
  } else if ((v & MAP_TYPE) == MAP_SHARED) {
    fputs("MAP_SHARED", out);
    first = false;
  }
#ifdef MAP_SHARED_VALIDATE
  else if ((v & MAP_TYPE) == MAP_SHARED_VALIDATE) {
    fputs("MAP_SHARED_VALIDATE", out);
    first = false;
  }
#endif
  static const struct pt_bit_name bits[] = {
    {MAP_ANONYMOUS, "MAP_ANONYMOUS"},
    {MAP_FIXED, "MAP_FIXED"},
#ifdef MAP_FIXED_NOREPLACE
    {MAP_FIXED_NOREPLACE, "MAP_FIXED_NOREPLACE"},
#endif
    {MAP_GROWSDOWN, "MAP_GROWSDOWN"},
    {MAP_LOCKED, "MAP_LOCKED"},
    {MAP_NORESERVE, "MAP_NORESERVE"},
    {MAP_POPULATE, "MAP_POPULATE"},
    {MAP_STACK, "MAP_STACK"},
  };
  for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
    if (v & bits[i].bit) {
      fprintf(out, "%s%s", first ? "" : "|", bits[i].name);
      first = false;
    }
  }
  if (first) {
    fputc('0', out);
  }
  fputc(']', out);
}

static void print_open_flags(FILE *out, unsigned long v) {
  bool first = true;
  fputc('[', out);
  switch (v & O_ACCMODE) {
  case O_RDONLY: fputs("O_RDONLY", out); break;
  case O_WRONLY: fputs("O_WRONLY", out); break;
  case O_RDWR: fputs("O_RDWR", out); break;
  }
  first = false;

  static const struct pt_bit_name bits[] = {
    {O_CREAT, "O_CREAT"},
    {O_EXCL, "O_EXCL"},
    {O_TRUNC, "O_TRUNC"},
    {O_APPEND, "O_APPEND"},
    {O_NONBLOCK, "O_NONBLOCK"},
    {O_CLOEXEC, "O_CLOEXEC"},
    {O_DIRECTORY, "O_DIRECTORY"},
    {O_NOFOLLOW, "O_NOFOLLOW"},
  };
  for (size_t i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
    if (v & bits[i].bit) {
      fprintf(out, "%s%s", first ? "" : "|", bits[i].name);
      first = false;
    }
  }
  fputc(']', out);
}

static void print_path_arg(FILE *out, pid_t pid, unsigned long addr, const struct pt_config *cfg) {
  char *s = pt_remote_str(pid, addr, cfg->string_max);
  if (s) {
    fprintf(out, "\"%s\"", s);
    free(s);
  } else {
    fprintf(out, "0x%lx", addr);
  }
}

static void print_common_enter(FILE *out, pid_t pid, const struct pt_syscall_frame *f,
                 const struct pt_config *cfg) {
  switch (f->nr) {
  case 0:
  case 1: {
    char *fdp = pt_fd_path(pid, (int)f->args[0]);
    fprintf(out, " fd=%lu", f->args[0]);
    if (fdp) {
      fprintf(out, "<%s>", fdp);
      free(fdp);
    }
    fprintf(out, " buf=0x%lx count=%lu", f->args[1], f->args[2]);
    if (f->nr == 1) {
      char *p = pt_remote_preview(pid, f->args[1], f->args[2], cfg->preview_max);
      if (p) {
        fprintf(out, " preview=\"%s\"", p);
        free(p);
      }
    }
    break;
  }
  case 2:
    fputs(" path=", out);
    print_path_arg(out, pid, f->args[0], cfg);
    fputs(" flags=", out);
    print_open_flags(out, f->args[1]);
    fprintf(out, " mode=0%lo", f->args[2]);
    break;
  case 59:
    fputs(" path=", out);
    print_path_arg(out, pid, f->args[0], cfg);
    break;
  case 80:
  case 83:
  case 84:
  case 87:
  case 89:
    fputs(" path=", out);
    print_path_arg(out, pid, f->args[0], cfg);
    break;
  case 9:
    fprintf(out, " addr=0x%lx len=%lu prot=", f->args[0], f->args[1]);
    print_prot(out, f->args[2]);
    fputs(" flags=", out);
    print_mmap_flags(out, f->args[3]);
    fprintf(out, " fd=%d off=%lu", (int)f->args[4], f->args[5]);
    break;
  case 10:
    fprintf(out, " addr=0x%lx len=%lu prot=", f->args[0], f->args[1]);
    print_prot(out, f->args[2]);
    break;
  case 257:
    fprintf(out, " dirfd=%d path=", (int)f->args[0]);
    print_path_arg(out, pid, f->args[1], cfg);
    fputs(" flags=", out);
    print_open_flags(out, f->args[2]);
    fprintf(out, " mode=0%lo", f->args[3]);
    break;
  case 262:
    fprintf(out, " dirfd=%d path=", (int)f->args[0]);
    print_path_arg(out, pid, f->args[1], cfg);
    fprintf(out, " flags=0x%lx", f->args[3]);
    break;
  default:
    fprintf(out, " a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx a4=0x%lx a5=0x%lx",
        f->args[0], f->args[1], f->args[2], f->args[3], f->args[4], f->args[5]);
  }
}

void pt_print_syscall_enter(FILE *out, pid_t pid, const struct pt_syscall_frame *f,
              const struct pt_config *cfg) {
  if (cfg->json) {
    fprintf(out, "{\"event\":\"enter\",\"pid\":%d,\"nr\":%ld,\"name\":\"%s\",\"args\":[%lu,%lu,%lu,%lu,%lu,%lu]}\n",
        pid, f->nr, pt_syscall_name(f->nr), f->args[0], f->args[1], f->args[2],
        f->args[3], f->args[4], f->args[5]);
    return;
  }
  fprintf(out, "pid=%d -> %s(%ld)", pid, pt_syscall_name(f->nr), f->nr);
  print_common_enter(out, pid, f, cfg);
  fputc('\n', out);
}

void pt_print_syscall_exit(FILE *out, pid_t pid, const struct pt_syscall_frame *f,
               const struct pt_config *cfg) {
  if (cfg->json) {
    const char *err = pt_errno_name(f->ret);
    fprintf(out, "{\"event\":\"exit\",\"pid\":%d,\"nr\":%ld,\"name\":\"%s\",\"ret\":%ld",
        pid, f->nr, pt_syscall_name(f->nr), f->ret);
    if (err) {
      fprintf(out, ",\"errno\":\"%s\"", err);
    }
    if (f->ret > 0 && (f->nr == 0 || f->nr == 1)) {
      char *p = pt_remote_preview(pid, f->args[1], (size_t)f->ret, cfg->preview_max);
      if (p) {
        fputs(",\"preview\":\"", out);
        pt_json_escape(out, p);
        fputc('"', out);
        free(p);
      }
    }
    fputs("}\n", out);
    return;
  }

  const char *err = pt_errno_name(f->ret);
  fprintf(out, "pid=%d <- %s = %ld", pid, pt_syscall_name(f->nr), f->ret);
  if (err) {
    fprintf(out, " %s", err);
  }
  if (f->nr == 0 && f->ret > 0) {
    char *p = pt_remote_preview(pid, f->args[1], (size_t)f->ret, cfg->preview_max);
    if (p) {
      fprintf(out, " read=\"%s\"", p);
      free(p);
    }
  }
  fputc('\n', out);
}
