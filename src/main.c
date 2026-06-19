// author: cocomelonc
#include "pawtrace.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out) {
  fprintf(out,
    "usage: pawtrace [options] -- program [args...]\n"
    "\n"
    "options:\n"
    "  -j, --json        emit JSONL records\n"
    "  -m, --maps        dump /proc/<pid>/maps at exec and exit events\n"
    "  -s, --string-max N    maximum remote string bytes (default %d)\n"
    "  -p, --preview-max N   maximum buffer preview bytes (default %d)\n"
    "  -o, --output FILE     write trace to FILE\n"
    "  -h, --help        show this help\n",
    PT_DEFAULT_STRING_MAX, PT_DEFAULT_PREVIEW_MAX);
}

static int parse_size(const char *s, size_t *out) {
  char *end = NULL;
  errno = 0;
  unsigned long v = strtoul(s, &end, 10);
  if (errno || !end || *end || v == 0 || v > 1024 * 1024) {
    return -1;
  }
  *out = (size_t)v;
  return 0;
}

int main(int argc, char **argv) {
  struct pt_config cfg = {
    .json = false,
    .maps = false,
    .string_max = PT_DEFAULT_STRING_MAX,
    .preview_max = PT_DEFAULT_PREVIEW_MAX,
    .out = stdout,
  };

  int i = 1;
  for (; i < argc; i++) {
    if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (!strcmp(argv[i], "-j") || !strcmp(argv[i], "--json")) {
      cfg.json = true;
    } else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--maps")) {
      cfg.maps = true;
    } else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--string-max")) {
      if (i + 1 >= argc) {
        fprintf(stderr, "%s requires an argument\n", argv[i]);
        return 2;
      }
      if (parse_size(argv[++i], &cfg.string_max) < 0) {
        fprintf(stderr, "invalid string max: %s\n", argv[i]);
        return 2;
      }
    } else if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--preview-max")) {
      if (i + 1 >= argc) {
        fprintf(stderr, "%s requires an argument\n", argv[i]);
        return 2;
      }
      if (parse_size(argv[++i], &cfg.preview_max) < 0) {
        fprintf(stderr, "invalid preview max: %s\n", argv[i]);
        return 2;
      }
    } else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
      if (i + 1 >= argc) {
        fprintf(stderr, "%s requires an argument\n", argv[i]);
        return 2;
      }
      cfg.out = fopen(argv[++i], "w");
      if (!cfg.out) {
        perror("fopen");
        return 2;
      }
    } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      usage(stdout);
      return 0;
    } else {
      break;
    }
  }

  if (i >= argc) {
    usage(stderr);
    return 2;
  }

  int rc = pt_trace_launch(&argv[i], &cfg);
  if (cfg.out && cfg.out != stdout) {
    fclose(cfg.out);
  }
  return rc;
}
