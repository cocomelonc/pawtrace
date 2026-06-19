#include "pawtrace.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *pt_fd_path(pid_t pid, int fd) {
  char link_path[64];
  snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", pid, fd);

  char *buf = calloc(PATH_MAX + 1, 1);
  if (!buf) {
    return NULL;
  }
  ssize_t n = readlink(link_path, buf, PATH_MAX);
  if (n < 0) {
    free(buf);
    return NULL;
  }
  buf[n] = 0;
  return buf;
}

void pt_dump_maps(FILE *out, pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(out, "pid=%d maps unavailable\n", pid);
    return;
  }

  fprintf(out, "pid=%d maps begin\n", pid);
  char line[4096];
  while (fgets(line, sizeof(line), f)) {
    fputs(line, out);
  }
  fprintf(out, "pid=%d maps end\n", pid);
  fclose(f);
}

void pt_dump_maps_json(FILE *out, pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(out, "{\"event\":\"maps-error\",\"pid\":%d}\n", pid);
    return;
  }

  char line[4096];
  while (fgets(line, sizeof(line), f)) {
    fprintf(out, "{\"event\":\"maps-line\",\"pid\":%d,\"line\":\"", pid);
    pt_json_escape(out, line);
    fputs("\"}\n", out);
  }
  fclose(f);
}
