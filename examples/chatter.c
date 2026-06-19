// author: cocomelonc
#include "pawtrace.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  char buf[64] = {0};
  long tid = pt_gettid_raw();
  dprintf(STDOUT_FILENO, "chatter tid=%ld\n", tid);

  int fd = open("/etc/hostname", O_RDONLY);
  if (fd >= 0) {
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
      write(STDOUT_FILENO, buf, (size_t)n);
    }
    close(fd);
  }

  long pid = pt_raw_syscall6(SYS_getpid, 0, 0, 0, 0, 0, 0);
  dprintf(STDOUT_FILENO, "raw getpid=%ld\n", pid);
  return 0;
}
