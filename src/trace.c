// author: cocomelonc
#include "pawtrace.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static struct pt_state *state_get(struct pt_state **head, pid_t pid) {
  for (struct pt_state *s = *head; s; s = s->next) {
    if (s->pid == pid) {
      return s;
    }
  }
  struct pt_state *s = calloc(1, sizeof(*s));
  if (!s) {
    return NULL;
  }
  s->pid = pid;
  s->next = *head;
  *head = s;
  return s;
}

static void state_del(struct pt_state **head, pid_t pid) {
  struct pt_state **pp = head;
  while (*pp) {
    if ((*pp)->pid == pid) {
      struct pt_state *victim = *pp;
      *pp = victim->next;
      free(victim);
      return;
    }
    pp = &(*pp)->next;
  }
}

static bool state_empty(const struct pt_state *head) {
  return head == NULL;
}

static int set_opts(pid_t pid) {
  long opts = PTRACE_O_TRACESYSGOOD |
    PTRACE_O_TRACEEXEC |
    PTRACE_O_TRACEFORK |
    PTRACE_O_TRACEVFORK |
    PTRACE_O_TRACECLONE |
    PTRACE_O_TRACEEXIT;
  return ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)opts);
}

static int resume_syscall(pid_t pid, int sig) {
  return ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)sig);
}

static void fill_enter(struct pt_syscall_frame *f, const struct user_regs_struct *r) {
  f->nr = (long)r->orig_rax;
  f->args[0] = r->rdi;
  f->args[1] = r->rsi;
  f->args[2] = r->rdx;
  f->args[3] = r->r10;
  f->args[4] = r->r8;
  f->args[5] = r->r9;
}

static int handle_syscall(pid_t pid, struct pt_state **states, const struct pt_config *cfg) {
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
    return -1;
  }

  struct pt_state *s = state_get(states, pid);
  if (!s) {
    return -1;
  }

  if (!s->in_syscall) {
    fill_enter(&s->frame, &regs);
    pt_print_syscall_enter(cfg->out, pid, &s->frame, cfg);
    s->in_syscall = true;
  } else {
    s->frame.ret = (long)regs.rax;
    pt_print_syscall_exit(cfg->out, pid, &s->frame, cfg);
    s->in_syscall = false;
  }
  fflush(cfg->out);
  return 0;
}

static void log_event(FILE *out, const struct pt_config *cfg, const char *event,
            pid_t pid, unsigned long msg) {
  if (cfg->json) {
    fprintf(out, "{\"event\":\"ptrace-%s\",\"pid\":%d,\"msg\":%lu}\n",
        event, pid, msg);
  } else {
    fprintf(out, "pid=%d event=%s msg=%lu\n", pid, event, msg);
  }
}

static const char *ptrace_event_name(int event) {
  switch (event) {
  case PTRACE_EVENT_FORK: return "fork";
  case PTRACE_EVENT_VFORK: return "vfork";
  case PTRACE_EVENT_CLONE: return "clone";
  case PTRACE_EVENT_EXEC: return "exec";
  case PTRACE_EVENT_EXIT: return "exit";
  default: return "ptrace-event";
  }
}

int pt_trace_launch(char **argv, const struct pt_config *cfg) {
  pid_t child = fork();
  if (child < 0) {
    perror("fork");
    return 1;
  }

  if (child == 0) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
      perror("PTRACE_TRACEME");
      _exit(127);
    }
    raise(SIGSTOP);
    execvp(argv[0], argv);
    perror("execvp");
    _exit(127);
  }

  int status = 0;
  if (waitpid(child, &status, 0) < 0) {
    perror("waitpid");
    return 1;
  }
  if (!WIFSTOPPED(status)) {
    fprintf(stderr, "child did not stop cleanly\n");
    return 1;
  }
  if (set_opts(child) < 0) {
    perror("PTRACE_SETOPTIONS");
    return 1;
  }

  struct pt_state *states = NULL;
  if (!state_get(&states, child)) {
    return 1;
  }
  if (resume_syscall(child, 0) < 0) {
    perror("PTRACE_SYSCALL");
    return 1;
  }

  while (!state_empty(states)) {
    pid_t pid = waitpid(-1, &status, __WALL);
    if (pid < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("waitpid");
      break;
    }

    if (WIFEXITED(status)) {
      if (cfg->json) {
        fprintf(cfg->out, "{\"event\":\"process-exit\",\"pid\":%d,\"status\":%d}\n",
            pid, WEXITSTATUS(status));
      } else {
        fprintf(cfg->out, "pid=%d exited status=%d\n", pid, WEXITSTATUS(status));
      }
      state_del(&states, pid);
      continue;
    }
    if (WIFSIGNALED(status)) {
      if (cfg->json) {
        fprintf(cfg->out, "{\"event\":\"process-signal\",\"pid\":%d,\"signal\":%d}\n",
            pid, WTERMSIG(status));
      } else {
        fprintf(cfg->out, "pid=%d killed signal=%d\n", pid, WTERMSIG(status));
      }
      state_del(&states, pid);
      continue;
    }
    if (!WIFSTOPPED(status)) {
      continue;
    }

    int sig = WSTOPSIG(status);
    if (sig == (SIGTRAP | 0x80)) {
      if (handle_syscall(pid, &states, cfg) < 0) {
        perror("handle_syscall");
        state_del(&states, pid);
        continue;
      }
      if (resume_syscall(pid, 0) < 0) {
        perror("PTRACE_SYSCALL");
        state_del(&states, pid);
      }
      continue;
    }

    if (sig == SIGTRAP) {
      int event = (status >> 16) & 0xffff;
      unsigned long msg = 0;
      (void)ptrace(PTRACE_GETEVENTMSG, pid, NULL, &msg);
      log_event(cfg->out, cfg, ptrace_event_name(event), pid, msg);

      if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
        event == PTRACE_EVENT_CLONE) {
        pid_t new_pid = (pid_t)msg;
        state_get(&states, new_pid);
        (void)set_opts(new_pid);
        (void)resume_syscall(new_pid, 0);
      } else if (cfg->maps &&
             (event == PTRACE_EVENT_EXEC || event == PTRACE_EVENT_EXIT)) {
        if (cfg->json) {
          pt_dump_maps_json(cfg->out, pid);
        } else {
          pt_dump_maps(cfg->out, pid);
        }
      }

      if (resume_syscall(pid, 0) < 0) {
        perror("PTRACE_SYSCALL");
        state_del(&states, pid);
      }
      continue;
    }

    if (resume_syscall(pid, sig) < 0) {
      perror("PTRACE_SYSCALL");
      state_del(&states, pid);
    }
  }

  while (states) {
    state_del(&states, states->pid);
  }
  return 0;
}
