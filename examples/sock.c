// author: cocomelonc
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(void) {
  // udp sendto an inet address
  int u = socket(AF_INET, SOCK_DGRAM, 0);
  if (u >= 0) {
    struct sockaddr_in in = {0};
    in.sin_family = AF_INET;
    in.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &in.sin_addr);
    sendto(u, "x", 1, 0, (struct sockaddr *)&in, sizeof(in));
    close(u);
  }

  // bind an inet socket to a loopback port
  int b = socket(AF_INET, SOCK_STREAM, 0);
  if (b >= 0) {
    struct sockaddr_in in = {0};
    in.sin_family = AF_INET;
    in.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &in.sin_addr);
    bind(b, (struct sockaddr *)&in, sizeof(in));
    close(b);
  }

  // connect to a unix socket path
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s >= 0) {
    struct sockaddr_un un = {0};
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, "/run/pawtrace-demo.sock", sizeof(un.sun_path) - 1);
    connect(s, (struct sockaddr *)&un, sizeof(un));
    close(s);
  }

  return 0;
}
