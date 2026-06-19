#include "pawtrace.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

ssize_t pt_remote_read(pid_t pid, unsigned long addr, void *buf, size_t len) {
  if (!addr || !buf || len == 0) {
    return -1;
  }

  struct iovec local = {.iov_base = buf, .iov_len = len};
  struct iovec remote = {.iov_base = (void *)addr, .iov_len = len};
  ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
  if (n >= 0) {
    return n;
  }

  size_t off = 0;
  while (off < len) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + off), NULL);
    if (word == -1 && errno) {
      return off ? (ssize_t)off : -1;
    }
    size_t copy = sizeof(word);
    if (copy > len - off) {
      copy = len - off;
    }
    memcpy((unsigned char *)buf + off, &word, copy);
    off += copy;
  }
  return (ssize_t)off;
}

char *pt_remote_str(pid_t pid, unsigned long addr, size_t max) {
  if (!addr || max == 0) {
    return NULL;
  }

  char *s = calloc(max + 1, 1);
  if (!s) {
    return NULL;
  }

  ssize_t n = pt_remote_read(pid, addr, s, max);
  if (n <= 0) {
    free(s);
    return NULL;
  }

  s[max] = 0;
  for (ssize_t i = 0; i < n; i++) {
    if (s[i] == 0) {
      return s;
    }
  }
  s[max] = 0;
  return s;
}

char *pt_remote_preview(pid_t pid, unsigned long addr, size_t len, size_t max) {
  if (!addr || max == 0 || len == 0) {
    return NULL;
  }
  if (len > max) {
    len = max;
  }

  unsigned char *tmp = malloc(len);
  if (!tmp) {
    return NULL;
  }
  ssize_t n = pt_remote_read(pid, addr, tmp, len);
  if (n <= 0) {
    free(tmp);
    return NULL;
  }

  size_t out_cap = (size_t)n * 4 + 1;
  char *out = calloc(out_cap, 1);
  if (!out) {
    free(tmp);
    return NULL;
  }

  size_t o = 0;
  for (ssize_t i = 0; i < n && o + 5 < out_cap; i++) {
    unsigned char c = tmp[i];
    if (c >= 32 && c <= 126 && c != '\\' && c != '"') {
      out[o++] = (char)c;
    } else if (c == '\n') {
      out[o++] = '\\';
      out[o++] = 'n';
    } else if (c == '\t') {
      out[o++] = '\\';
      out[o++] = 't';
    } else {
      static const char hex[] = "0123456789abcdef";
      out[o++] = '\\';
      out[o++] = 'x';
      out[o++] = hex[c >> 4];
      out[o++] = hex[c & 0xf];
    }
  }
  out[o] = 0;
  free(tmp);
  return out;
}
