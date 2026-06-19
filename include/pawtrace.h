#ifndef PAWTRACE_H
#define PAWTRACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define PT_MAX_ARGS 6
#define PT_DEFAULT_STRING_MAX 256
#define PT_DEFAULT_PREVIEW_MAX 64

struct pt_config {
  bool json;
  bool maps;
  size_t string_max;
  size_t preview_max;
  FILE *out;
};

struct pt_syscall_frame {
  long nr;
  unsigned long args[PT_MAX_ARGS];
  long ret;
};

struct pt_state {
  pid_t pid;
  bool in_syscall;
  struct pt_syscall_frame frame;
  struct pt_state *next;
};

struct pt_syscall_meta {
  long nr;
  const char *name;
};

long pt_raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5);
long pt_gettid_raw(void);
uint64_t pt_rdtsc(void);

int pt_trace_launch(char **argv, const struct pt_config *cfg);

const char *pt_syscall_name(long nr);
const char *pt_errno_name(long neg_ret);
void pt_print_syscall_enter(FILE *out, pid_t pid, const struct pt_syscall_frame *f,
              const struct pt_config *cfg);
void pt_print_syscall_exit(FILE *out, pid_t pid, const struct pt_syscall_frame *f,
               const struct pt_config *cfg);

ssize_t pt_remote_read(pid_t pid, unsigned long addr, void *buf, size_t len);
char *pt_remote_str(pid_t pid, unsigned long addr, size_t max);
char *pt_remote_preview(pid_t pid, unsigned long addr, size_t len, size_t max);

char *pt_fd_path(pid_t pid, int fd);
void pt_dump_maps(FILE *out, pid_t pid);
void pt_dump_maps_json(FILE *out, pid_t pid);

#endif
