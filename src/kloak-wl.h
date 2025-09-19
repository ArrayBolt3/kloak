/*
 * Copyright (c) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 */

/*********************************/
/* static defines, do not change */
/*********************************/
#define fd_stdin 0
#define fd_stdout 1
#define fd_stderr 2
#define fd_wlsock 3

/*************/
/* functions */
/*************/

/*
 * Sets up kloak-wl with the ability to communicate with the Wayland
 * compositor.
 */
static void setup_adapter(char *wl_sock_path);

/*
 * Drops all capabilities. This is split out into a function since it must be
 * called twice, once to drop capabilities in the initial namespace and once
 * to drop them again after using unshare.
 */
static void drop_capabilities(void);

/*
 * Wall off the process into a very tight sandbox and drops all privileges.
 * This makes compromising the kloak-wl process virtually pointless.
 *
 * Heavily inspired by
 * https://blog.habets.se/2022/03/Dropping-privileges.html and
 * https://github.com/ThomasHabets/libdropprivs/blob/main/src/drop.c.
 */
static void self_sandbox(void);
