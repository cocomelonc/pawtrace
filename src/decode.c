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
  case 9: return "mmap";
  case 10: return "mprotect";
  case 11: return "munmap";
  case 12: return "brk";
  case 13: return "rt_sigaction";
  case 14: return "rt_sigprocmask";
  case 16: return "ioctl";
  case 17: return "pread64";
  case 18: return "pwrite64";
  case 21: return "access";
  case 22: return "pipe";
  case 24: return "sched_yield";
  case 32: return "dup";
  case 33: return "dup2";
  case 39: return "getpid";
  case 41: return "socket";
  case 42: return "connect";
  case 43: return "accept";
  case 44: return "sendto";
  case 45: return "recvfrom";
  case 49: return "bind";
  case 50: return "listen";
  case 56: return "clone";
  case 57: return "fork";
  case 58: return "vfork";
  case 59: return "execve";
  case 60: return "exit";
  case 61: return "wait4";
  case 62: return "kill";
  case 63: return "uname";
  case 72: return "fcntl";
  case 78: return "getdents";
  case 79: return "getcwd";
  case 80: return "chdir";
  case 82: return "rename";
  case 83: return "mkdir";
  case 84: return "rmdir";
  case 85: return "creat";
  case 86: return "link";
  case 87: return "unlink";
  case 88: return "symlink";
  case 89: return "readlink";
  case 90: return "chmod";
  case 97: return "getrlimit";
  case 102: return "getuid";
  case 104: return "getgid";
  case 110: return "getppid";
  case 157: return "prctl";
  case 158: return "arch_prctl";
  case 186: return "gettid";
  case 202: return "futex";
  case 217: return "getdents64";
  case 218: return "set_tid_address";
  case 231: return "exit_group";
  case 257: return "openat";
  case 262: return "newfstatat";
  case 263: return "unlinkat";
  case 273: return "set_robust_list";
  case 302: return "prlimit64";
  case 318: return "getrandom";
  case 334: return "rseq";
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

static void json_escape(FILE *out, const char *s) {
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
    if (f->nr == 1 || (f->nr == 0 && f->ret > 0)) {
      char *p = pt_remote_preview(pid, f->args[1],
                    f->nr == 0 ? (size_t)f->ret : f->args[2],
                    cfg->preview_max);
      if (p) {
        fputs(",\"preview\":\"", out);
        json_escape(out, p);
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
