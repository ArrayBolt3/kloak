/*
 * Copyright (c) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 */

/*
 * kloak-wl.c - Wayland adapter for kloak. Receives input device information
 * from kloak, and sends it to the Wayland compositor. Runs without privileges
 * to reduce the risk of compromise by a malicious compositor. This executable
 * should only ever be called by the core kloak executable, as it inherits the
 * read side of a pipe from the core executable.
 *
 * NOTES FOR DEVELOPERS:
 * - Use signed arithmetic wherever possible. Any form of integer
 *   over/underflow is dangerous here, thus kloak has -ftrapv enabled and thus
 *   signed arithmetic over/underflow will simply crash (and thus restart)
 *   kloak rather than resulting in memory corruption. Unsigned over/underflow
 *   however does NOT trap because it is well-defined in C. Thus avoid
 *   unsigned arithmetic wherever possible.
 * - Use an assert to check that a value is within bounds before every cast.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/capability.h>
#include <sched.h>
#include <unistd.h>
#include <limits.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <dirent.h>
#include <sys/resource.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include "kloak-wl.h"

static void setup_adapter(char *wl_sock_path) {
  struct sockaddr_un wl_sockaddr = { 0 };
  int wl_sock_fd = 0;
  int connect_success = 0;

  if (strlen(wl_sock_path) > (sizeof(wl_sockaddr.sun_path) - 1)) {
    fprintf(stderr, "FATAL ERROR: Path to Wayland socket is too long!\n");
    exit(1);
  }

  wl_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (wl_sock_fd == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not create UNIX socket: %s\n", strerror(errno));
    exit(1);
  }
  wl_sockaddr.sun_family = AF_UNIX;
  strcpy(wl_sockaddr.sun_path, wl_sock_path);

  connect_success = connect(wl_sock_fd,
    (const struct sockaddr *)(&wl_sockaddr), sizeof(wl_sockaddr));
  if (connect_success == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not connect to Wayland compositor: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * We want the socket to use the fd_wlsock FD so that we can close
   * everything above fd_wlsock to properly sandbox the code. This will close
   * whatever happens to be open in fd_wlsock (if anything), but we were going
   * to close that anyway, so it's not a problem.
   */
  if (dup2(wl_sock_fd, fd_wlsock) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not assign Wayland socket fd: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * We don't need the old fd anymore. Closing it will NOT close the
   * connection.
   */
  if(close(wl_sock_fd) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not close old socket fd: %s\n", strerror(errno));
    exit(1);
  }
}

static void drop_capabilities(void) {
  cap_t no_cap;
  no_cap = cap_init();
  if (no_cap == NULL) {
    fprintf(stderr, "FATAL ERROR: Cannot create empty capability set: %s\n",
      strerror(errno));
    exit(1);
  }
  if (cap_reset_ambient() == -1) {
    fprintf(stderr, "FATAL ERROR: Cannot drop ambient capabilities: %s\n",
      strerror(errno));
    exit(1);
  }
  if (cap_set_proc(no_cap) == -1) {
    fprintf(stderr, "FATAL ERROR: Cannot drop capabilities: %s\n",
      strerror(errno));
    exit(1);
  }
  if (cap_free(no_cap) == -1) {
    fprintf(stderr, "FATAL ERROR: Cannot free empty capability struct: %s\n",
      strerror(errno));
    exit(1);
  }
}

static void self_sandbox(void) {
  struct passwd *pw_data = NULL;
  struct group *gr_data = NULL;
  pid_t fork_pid = 0;
  struct rlimit rl_data = { 0 };
  rlim_t fd_max = 0;
  int fd_max_int = 0;
  rlim_t fd_idx = 0;
  pid_t wait_ret = 0;
  int wait_status = 0;

  /*
   * Don't allow us to regain any privileges we drop by executing something
   * else. This prevents us from escaping the sandbox by calling a SUID
   * binary.
   */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    fprintf(stderr, "FATAL ERROR: Could not set PR_SET_NO_NEW_PRIVS: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Close all open file descriptors above fd_wlsock.
   */
  if(getrlimit(RLIMIT_NOFILE, &rl_data) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not get highest possible fd number: %s\n",
      strerror(errno));
    exit(1);
  }
  if (rl_data.rlim_cur == RLIM_INFINITY) {
    errno = 0;
    fd_max_int = sysconf(_SC_OPEN_MAX);
    if (fd_max_int < 0) {
      if (errno == 0) {
        fprintf(stderr,
          "FATAL ERROR: No detectable maximum number of open files!\n");
      } else {
        fprintf(stderr,
          "FATAL ERROR: Could not get maximum number of open files: %s\n",
          strerror(errno));
      }
      exit(1);
    }
    fd_max = fd_max_int;
  } else {
    fd_max = rl_data.rlim_cur;
  }
  if (fd_max < _POSIX_OPEN_MAX) {
    fprintf(stderr,
      "FATAL ERROR: Maximum number of open files is invalid! Values is %ld, minimum valid value is %d",
      fd_max, _POSIX_OPEN_MAX);
    exit(1);
  }
  for (fd_idx = fd_wlsock + 1; fd_idx < fd_max; fd_idx++) {
    if (close(fd_idx) == -1 && errno != EBADF) {
      fprintf(stderr,
        "FATAL ERROR: Failed to close fd %ld: %s\n", fd_idx, strerror(errno));
      exit(1);
    }
  }

  /*
   * Disable core dumps.
   */
  rl_data.rlim_cur = 0;
  rl_data.rlim_max = 0;
  if (setrlimit(RLIMIT_CORE, &rl_data) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Failed to zero core dump size limits: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Disable core dumps harder.
   */
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Failed to fully disable core dumps in parent: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Change our user and group to kloakwl/kloakwl. This is better than
   * changing to nobody/nogroup, since nobody/nogroup allows anything else
   * running as nobody/nogroup to kill us. We get the user and group data
   * separately so that if the user has done something weird and set the UID
   * for the 'kloakwl' user to something different than the 'kloakwl' group,
   * it doesn't open up a compromise. We also don't allow tricking the
   * application into keeping root privileges by messing with the 'kloakwl'
   * UID/GID.
   */
  pw_data = getpwnam("kloakwl");
  if (pw_data == NULL) {
    fprintf(stderr,
      "FATAL ERROR: Could not get user information for 'kloakwl': %s\n",
      strerror(errno));
    exit(1);
  }
  if (pw_data->pw_uid == 0) {
    fprintf(stderr,
      "FATAL ERROR: 'kloakwl' UID is 0 (root), refusing to continue.");
    exit(1);
  }
  gr_data = getgrnam("kloakwl");
  if (gr_data == NULL) {
    fprintf(stderr,
      "FATAL ERROR: Could not get group information for 'kloakwl': %s\n",
      strerror(errno));
    exit(1);
  }
  if (gr_data->gr_gid == 0) {
    fprintf(stderr,
      "FATAL ERROR: 'kloakwl' GID is 0 (root), refusing to continue.");
    exit(1);
  }
  /* Drop supplementary groups. */
  if (setgroups(0, NULL) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not drop supplementary groups; %s\n",
      strerror(errno));
    exit(1);
  }
  /* Set our GID to kloakwl, this MUST be done before setting the UID */
  if (setresgid(gr_data->gr_gid, gr_data->gr_gid, gr_data->gr_gid) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not change group to 'kloakwl': %s\n",
      strerror(errno));
    exit(1);
  }
  /* Set our UID to kloakwl */
  if (setresuid(pw_data->pw_uid, pw_data->pw_uid, pw_data->pw_uid) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not change user to 'kloakwl': %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Drop all capabilities in our current namespace.
   */
  drop_capabilities();

  /*
   * Set up an unshare sandbox.
   *
   * WARNING: This will give us back a full set of capabilities, thus we need
   * to drop capabilities again after doing this.
   *
   * WARNING 2: Not all of the options to unshare actually put the calling
   * process into the new sandbox! We have to fork(), let the parent die, and
   * continue all work in the child to fully enter the sandbox.
   */
  if (unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWIPC
    | CLONE_NEWPID | CLONE_NEWUTS | CLONE_SYSVSEM | CLONE_NEWCGROUP
    | CLONE_NEWTIME) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not enter unshare sandbox: %s\n", strerror(errno));
    exit(1);
  }

  /*
   * Make the mount namespace stronger by preventing mount propagation.
   */
  if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not strengthen mount namespace: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Unmount /proc, we don't need it and may as well get it out of our mount
   * namespace.
   */
  if (umount("/proc") == -1 && errno != EINVAL && errno != ENOENT) {
    fprintf(stderr,
      "FATAL ERROR: Could not unmount /proc in sandbox: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Mount a tiny, empty, read-only tmpfs to /tmp. This will hide the contents
   * of /tmp from the process and give us a safe place to pivot root into.
   */
  if (mount("newroot", "/tmp", "tmpfs",
    MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOSYMFOLLOW,
    "size=4k,mode=100") == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not set up safe chroot zone: %s\n", strerror(errno));
    exit(1);
  }
  if (chdir("/tmp") == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not chdir to safe chroot zone: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Pivot into the empty read-only mountpoint we just made. The filesystem
   * will still be there, but we will be able to unmount it to trap ourselves
   * in the safe directory.
   */
  if (syscall(SYS_pivot_root, ".", ".") == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not pivot into safe root directory: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Unmount the old root directory. This will fully trap us in the safe
   * directory.
   */
  if (umount2(".", MNT_DETACH) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not unmount old root directory in sandbox: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Switch to the new root directory.
   */
  if (chdir("/") == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not switch to new root directory: %s\n",
      strerror(errno));
    exit(1);
  }

  /*
   * Drop capabilities again since we regained them when we called unshare.
   */
  drop_capabilities();

  /*
   * Fork into a child process so that we fully enter the unshare namespace
   * created earlier.
   */
  fork_pid = fork();
  if (fork_pid == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not fork into child process: %s\n",
      strerror(errno));
    exit(1);
  }
  if (fork_pid != 0) {
    /*
     * Wait for the child to exit. The child is now fully sandboxed.
     */
    wait_ret = waitpid(fork_pid, &wait_status, 0);
    if (wait_ret == -1) {
      fprintf(stderr, "FATAL ERROR: Could not wait for child to exit: %s\n",
        strerror(errno));

      if (kill(fork_pid, SIGKILL) == -1) {
        fprintf(stderr, "FATAL ERROR: Could not clean up child process: %s\n",
          strerror(errno));
        /* no exit, we exit 1 below */
      }
      exit(1);
    }

    if (!WIFEXITED(wait_status)) {
      fprintf(stderr, "FATAL ERROR: Child process crashed!\n");
      exit(1);
    }
    exit(WEXITSTATUS(wait_status));
  }

  /*
   * NOTE: Code after this point runs in the child process.
   */

  /*
   * Disable core dumps harder in the child too. This may be superfluous, but
   * in case the PID change when entering a PID namespace causes
   * PR_SET_DUMPABLE to be reset, we should still do this.
   */
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Failed to fully disable core dumps in child: %s\n",
      strerror(errno));
    exit(1);
  }
}

int main(int argc, char **argv) {
  /*
   * BIG FAT WARNING: Do not attempt to build kloak-wl with NDEBUG defined.
   * Many of the assertions in this code are essential for security, and
   * building kloak with NDEBUG defined will turn all of them off. Systems
   * running a build of kloak with NDEBUG defined should be treated as
   * compromised if they process any form of untrusted data.
   *
   * To lower the risk of this situation occurring, the following check will
   * render kloak non-functional if NDEBUG is defined. Think very carefully
   * about what you are doing if you are considering patching this check out.
   */
#ifdef NDEBUG
  fprintf(stderr,
    "FATAL ERROR: Built with NDEBUG set. kloak does not support this, please rebuild with NDEBUG unset.\n");
  exit(1);
#endif

  if (getuid() != 0) {
    fprintf(stderr, "FATAL ERROR: Must be run as root!\n");
    exit(1);
  }

  /*
  if (argc < 2) {
    fprintf(stderr, "FATAL ERROR: Wrong number of arguments!\n");
    exit(1);
  }

  setup_adapter(argv[1]);
  */

  self_sandbox();
  fprintf(stderr, "Made it!\n");
}
