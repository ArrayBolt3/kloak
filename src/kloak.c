/*
 * SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define _GNU_SOURCE
#define KLOAK

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <limits.h>
#include <regex.h>
#include <getopt.h>
#include <ctype.h>
#include <linux/input.h>
#include <time.h>
#include <sys/inotify.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <math.h>

#include <libinput.h>
#include <libevdev/libevdev.h>

#include "kloak-shared.h"
#include "kloak.h"

/********************/
/* Global variables */
/********************/

/*
 * To read from child, read ctp_pipe[0].
 * To write to child, write ptc_pipe[1].
 */
static int ctp_pipe[2] = { 0, 0 };
static int ptc_pipe[2] = { 0, 0 };

static int32_t max_delay = DEFAULT_MAX_DELAY_MS;
static int32_t startup_delay = DEFAULT_STARTUP_TIMEOUT_MS;
static uint32_t cursor_color = 0x00000000;
static bool enable_natural_scrolling = false;
static bool exit_on_wl_connect_failure = false;
static bool wl_connect_success = true;

static int inotify_fd = 0;
static struct libinput *li = NULL;
static regex_t evdev_reg = { 0 };
struct coord pointer_space_data = { 0 };
static LIST_HEAD(listhead_ldi, li_device_info) ldi_head;

static uint32_t **esc_key_list = NULL;
static size_t *esc_key_sublist_len = NULL;
static int8_t *active_esc_key_list = NULL;
static size_t esc_key_list_len = 0;

static struct pollfd *ev_fds = NULL;

uint8_t num_lock_state = 0;
bool num_lock_held = false;
uint8_t caps_lock_state = 0;
bool caps_lock_held = false;
enum libinput_led last_led_state = 0;

/*
 * WARNING: Do NOT attempt to kill child_pid during shutdown for any reason. It
 * is theoretically possible that it will have closed before being killed, and
 * some unrelated process may have claimed its PID. The child is designed to
 * exit of its own accord if the parent dies.
 */
static pid_t child_pid = 0;

static struct key_name_value key_table[] = {
  {"KEY_ESC", KEY_ESC},
  {"KEY_1", KEY_1},
  {"KEY_2", KEY_2},
  {"KEY_3", KEY_3},
  {"KEY_4", KEY_4},
  {"KEY_5", KEY_5},
  {"KEY_6", KEY_6},
  {"KEY_7", KEY_7},
  {"KEY_8", KEY_8},
  {"KEY_9", KEY_9},
  {"KEY_0", KEY_0},
  {"KEY_MINUS", KEY_MINUS},
  {"KEY_EQUAL", KEY_EQUAL},
  {"KEY_BACKSPACE", KEY_BACKSPACE},
  {"KEY_TAB", KEY_TAB},
  {"KEY_Q", KEY_Q},
  {"KEY_W", KEY_W},
  {"KEY_E", KEY_E},
  {"KEY_R", KEY_R},
  {"KEY_T", KEY_T},
  {"KEY_Y", KEY_Y},
  {"KEY_U", KEY_U},
  {"KEY_I", KEY_I},
  {"KEY_O", KEY_O},
  {"KEY_P", KEY_P},
  {"KEY_LEFTBRACE", KEY_LEFTBRACE},
  {"KEY_RIGHTBRACE", KEY_RIGHTBRACE},
  {"KEY_ENTER", KEY_ENTER},
  {"KEY_LEFTCTRL", KEY_LEFTCTRL},
  {"KEY_A", KEY_A},
  {"KEY_S", KEY_S},
  {"KEY_D", KEY_D},
  {"KEY_F", KEY_F},
  {"KEY_G", KEY_G},
  {"KEY_H", KEY_H},
  {"KEY_J", KEY_J},
  {"KEY_K", KEY_K},
  {"KEY_L", KEY_L},
  {"KEY_SEMICOLON", KEY_SEMICOLON},
  {"KEY_APOSTROPHE", KEY_APOSTROPHE},
  {"KEY_GRAVE", KEY_GRAVE},
  {"KEY_LEFTSHIFT", KEY_LEFTSHIFT},
  {"KEY_BACKSLASH", KEY_BACKSLASH},
  {"KEY_Z", KEY_Z},
  {"KEY_X", KEY_X},
  {"KEY_C", KEY_C},
  {"KEY_V", KEY_V},
  {"KEY_B", KEY_B},
  {"KEY_N", KEY_N},
  {"KEY_M", KEY_M},
  {"KEY_COMMA", KEY_COMMA},
  {"KEY_DOT", KEY_DOT},
  {"KEY_SLASH", KEY_SLASH},
  {"KEY_RIGHTSHIFT", KEY_RIGHTSHIFT},
  {"KEY_KPASTERISK", KEY_KPASTERISK},
  {"KEY_LEFTALT", KEY_LEFTALT},
  {"KEY_SPACE", KEY_SPACE},
  {"KEY_CAPSLOCK", KEY_CAPSLOCK},
  {"KEY_F1", KEY_F1},
  {"KEY_F2", KEY_F2},
  {"KEY_F3", KEY_F3},
  {"KEY_F4", KEY_F4},
  {"KEY_F5", KEY_F5},
  {"KEY_F6", KEY_F6},
  {"KEY_F7", KEY_F7},
  {"KEY_F8", KEY_F8},
  {"KEY_F9", KEY_F9},
  {"KEY_F10", KEY_F10},
  {"KEY_NUMLOCK", KEY_NUMLOCK},
  {"KEY_SCROLLLOCK", KEY_SCROLLLOCK},
  {"KEY_KP7", KEY_KP7},
  {"KEY_KP8", KEY_KP8},
  {"KEY_KP9", KEY_KP9},
  {"KEY_KPMINUS", KEY_KPMINUS},
  {"KEY_KP4", KEY_KP4},
  {"KEY_KP5", KEY_KP5},
  {"KEY_KP6", KEY_KP6},
  {"KEY_KPPLUS", KEY_KPPLUS},
  {"KEY_KP1", KEY_KP1},
  {"KEY_KP2", KEY_KP2},
  {"KEY_KP3", KEY_KP3},
  {"KEY_KP0", KEY_KP0},
  {"KEY_KPDOT", KEY_KPDOT},
  {"KEY_ZENKAKUHANKAKU", KEY_ZENKAKUHANKAKU},
  {"KEY_102ND", KEY_102ND},
  {"KEY_F11", KEY_F11},
  {"KEY_F12", KEY_F12},
  {"KEY_RO", KEY_RO},
  {"KEY_KATAKANA", KEY_KATAKANA},
  {"KEY_HIRAGANA", KEY_HIRAGANA},
  {"KEY_HENKAN", KEY_HENKAN},
  {"KEY_KATAKANAHIRAGANA", KEY_KATAKANAHIRAGANA},
  {"KEY_MUHENKAN", KEY_MUHENKAN},
  {"KEY_KPJPCOMMA", KEY_KPJPCOMMA},
  {"KEY_KPENTER", KEY_KPENTER},
  {"KEY_RIGHTCTRL", KEY_RIGHTCTRL},
  {"KEY_KPSLASH", KEY_KPSLASH},
  {"KEY_SYSRQ", KEY_SYSRQ},
  {"KEY_RIGHTALT", KEY_RIGHTALT},
  {"KEY_LINEFEED", KEY_LINEFEED},
  {"KEY_HOME", KEY_HOME},
  {"KEY_UP", KEY_UP},
  {"KEY_PAGEUP", KEY_PAGEUP},
  {"KEY_LEFT", KEY_LEFT},
  {"KEY_RIGHT", KEY_RIGHT},
  {"KEY_END", KEY_END},
  {"KEY_DOWN", KEY_DOWN},
  {"KEY_PAGEDOWN", KEY_PAGEDOWN},
  {"KEY_INSERT", KEY_INSERT},
  {"KEY_DELETE", KEY_DELETE},
  {"KEY_MACRO", KEY_MACRO},
  {"KEY_MUTE", KEY_MUTE},
  {"KEY_VOLUMEDOWN", KEY_VOLUMEDOWN},
  {"KEY_VOLUMEUP", KEY_VOLUMEUP},
  {"KEY_POWER", KEY_POWER},
  {"KEY_POWER2", KEY_POWER2},
  {"KEY_KPEQUAL", KEY_KPEQUAL},
  {"KEY_KPPLUSMINUS", KEY_KPPLUSMINUS},
  {"KEY_PAUSE", KEY_PAUSE},
  {"KEY_SCALE", KEY_SCALE},
  {"KEY_KPCOMMA", KEY_KPCOMMA},
  {"KEY_HANGEUL", KEY_HANGEUL},
  {"KEY_HANGUEL", KEY_HANGUEL},
  {"KEY_HANJA", KEY_HANJA},
  {"KEY_YEN", KEY_YEN},
  {"KEY_LEFTMETA", KEY_LEFTMETA},
  {"KEY_RIGHTMETA", KEY_RIGHTMETA},
  {"KEY_COMPOSE", KEY_COMPOSE},
  {"KEY_F13", KEY_F13},
  {"KEY_F14", KEY_F14},
  {"KEY_F15", KEY_F15},
  {"KEY_F16", KEY_F16},
  {"KEY_F17", KEY_F17},
  {"KEY_F18", KEY_F18},
  {"KEY_F19", KEY_F19},
  {"KEY_F20", KEY_F20},
  {"KEY_F21", KEY_F21},
  {"KEY_F22", KEY_F22},
  {"KEY_F23", KEY_F23},
  {"KEY_F24", KEY_F24},
  {"KEY_UNKNOWN", KEY_UNKNOWN},
  {NULL, 0}
};

/*********************/
/* Utility functions */
/*********************/

static void *safe_reallocarray(void *ptr, size_t nmemb, size_t size) {
  void *out_ptr = reallocarray(ptr, nmemb, size);
  if (out_ptr == NULL) {
    fprintf(stderr,
      "FATAL ERROR: Could not allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  return out_ptr;
}

static DIR *safe_opendir(const char *name) {
  DIR *out_ptr = opendir(name);
  int dir_fd = 0;
  if (out_ptr == NULL) {
    fprintf(stderr,
      "FATAL ERROR: Could not open directory '%s': %s\n", name,
      strerror(errno));
    exit(1);
  }

  dir_fd = dirfd(out_ptr);
  if (dir_fd == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not get file descriptor for directory '%s': %s\n",
      name, strerror(errno));
    exit(1);
  }
  if (fcntl(dir_fd, F_SETFD, FD_CLOEXEC) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not set FD_CLOEXEC on file descriptor for directory '%s': %s\n",
      name, strerror(errno));
    exit(1);
  }
  return out_ptr;
}

static void safe_closedir(DIR *dirp) {
  int rslt = closedir(dirp);
  if (rslt == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not close a directory: %s\n", strerror(errno));
    exit(1);
  }
}

static struct timespec ms_to_timespec(int64_t ms) {
  struct timespec ts = { 0 };
  assert(ms >= 0);
  ts.tv_sec = (time_t)(ms / 1000);
  ts.tv_nsec = (ms % 1000) * 1000000;
  return ts;
}

static uint32_t lookup_keycode(const char *name) {
  struct key_name_value *p = NULL;

  for (p = key_table; p->name != NULL; p++) {
    if (strcmp(p->name, name) == 0) {
      return p->value;
    }
  }
  return 0;
}

static void attach_input_device(const char *dev_name) {
  bool found_device = false;
  struct libinput_device *new_device = NULL;
  char *device_path = NULL;
  struct li_device_info *ldi_node = NULL;
  int can_tap = 0;

  ldi_node = LIST_FIRST(&ldi_head);
  while (ldi_node != NULL) {
    if (strcmp(ldi_node->device_name, dev_name) == 0) {
      found_device = true;
      break;
    }
    ldi_node = LIST_NEXT(ldi_node, ldi_entries);
  }

  if (found_device) {
    /*
     * This may mean a device was quickly detached and then attached again,
     * thus try removing and re-attaching it.
     */
    detach_input_device(dev_name);
  }

  device_path = sgenprintf(NULL, "/dev/input/%s", dev_name);
  new_device = libinput_path_add_device(li, device_path);
  free(device_path);

  if (new_device == NULL) {
    return;
  }

  /* Set any "special" input device settings. */
  if (enable_natural_scrolling == true
    && libinput_device_config_scroll_has_natural_scroll(new_device) != 0) {
    libinput_device_config_scroll_set_natural_scroll_enabled(new_device, 1);
  }
  can_tap = libinput_device_config_tap_get_finger_count(new_device);
  if (can_tap) {
    libinput_device_config_tap_set_enabled(new_device,
      LIBINPUT_CONFIG_TAP_ENABLED);
  }

  ldi_node = safe_calloc(1, sizeof(struct li_device_info));
  ldi_node->device = new_device;
  ldi_node->device_name = safe_strdup(dev_name);
  ldi_node->refcount = 1;
  libinput_device_set_user_data(new_device, ldi_node);
  LIST_INSERT_HEAD(&ldi_head, ldi_node, ldi_entries);
}

static void detach_input_device(const char *dev_name) {
  struct li_device_info *ldi_node = NULL;
  struct libinput_device *dev = NULL;
  bool found_device = false;

  ldi_node = LIST_FIRST(&ldi_head);
  while (ldi_node != NULL) {
    if (strcmp(ldi_node->device_name, dev_name) == 0) {
      found_device = true;
      break;
    }
    ldi_node = LIST_NEXT(ldi_node, ldi_entries);
  }

  if (!found_device) {
    return;
  }

  dev = ldi_node->device;
  LIST_REMOVE(ldi_node, ldi_entries);
  /*
   * 'ldi_node' MUST be unreferenced first, then the contained device can be
   * removed. li_device_info_unref() will null out the user data of 'dev'
   * before freeing 'ldi_node' if the reference count reaches 0, and libinput
   * is liable to free 'dev' if removing it causes its reference count to
   * reach 0. Thus reversing the below two lines would likely result in a
   * use-after-free.
   */
  li_device_info_unref(ldi_node);
  libinput_path_remove_device(dev);
}

/*static void li_device_info_ref(struct li_device_info *ldi) {
  ldi->refcount += 1;
  assert(ldi->refcount != 0);
}*/

static void li_device_info_unref(struct li_device_info *ldi) {
  ldi->refcount -= 1;
  assert(ldi->refcount != UINT32_MAX);
  if (ldi->refcount == 0) {
    /*
     * The user data for a device is the struct we're freeing, so NULL out the
     * user data for safety.
     */
    libinput_device_set_user_data(ldi->device, NULL);
    free(ldi->device_name);
    free(ldi);
  }
}

/*
 * Both this and parse_uint32_arg make it the caller's responsibility to
 * terminate the application if the parse fails. This it to make it easier to
 * fuzz kloak.
 */
static bool parse_uint31_arg(const char *val, int base, int32_t *out) {
  char *val_endchar = NULL;
  uint64_t val_int = 0;

  if (val == NULL || out == NULL) {
    return false;
  }
  if (*val == '\0'
    || *val == '-'
    || *val == '+'
    || isspace((unsigned char)(*val))) {
    return false;
  }
  errno = 0;
  val_int = strtoul(val, &val_endchar, base);
  if (errno == ERANGE) {
    return false;
  }
  if (*val_endchar != '\0') {
    return false;
  }
  if (val_int > INT32_MAX) {
    return false;
  }
  *out = (int32_t)(val_int);
  return true;
}

static bool parse_uint32_arg(const char *val, int base, uint32_t *out) {
  char *val_endchar = NULL;
  uint64_t val_int = 0;

  if (val == NULL || out == NULL) {
    return false;
  }
  if (*val == '\0'
    || *val == '-'
    || *val == '+'
    || isspace((unsigned char)(*val))) {
    return false;
  }
  errno = 0;
  val_int = strtoul(val, &val_endchar, base);
  if (errno == ERANGE) {
    return false;
  }
  if (*val_endchar != '\0') {
    return false;
  }
  if (val_int > UINT32_MAX) {
    return false;
  }
  *out = (uint32_t)(val_int);
  return true;
}

static int32_t sleep_ms(int64_t ms) {
  struct timespec ts = { 0 };
  int nanosleep_ret = 0;

  ts = ms_to_timespec(ms);
  do {
    nanosleep_ret = nanosleep(&ts, &ts);
  } while (nanosleep_ret == -1 && errno == EINTR);

  if (nanosleep_ret == -1) {
    return -1;
  }
  return 0;
}

/*******************************/
/* libinput handling functions */
/*******************************/

static int li_open_restricted(const char *path, int flags,
  __attribute__((unused)) void *user_data) {
  int fd = safe_open(path, flags | O_CLOEXEC);
  int one = 1;

  if (wl_connect_success) {
    if (ioctl(fd, EVIOCGRAB, &one) < 0) {
      fprintf(stderr,
        "FATAL ERROR: Could not grab evdev device '%s'!\n", path);
      exit(1);
    }
  }
  return fd < 0 ? -errno : fd;
}

static void li_close_restricted(int fd,
  __attribute__((unused)) void *user_data) {
  safe_close(fd);
}

/************************/
/* High-level functions */
/************************/

static void parse_esc_key_str(const char *esc_key_str) {
  char *esc_key_str_copy = safe_strdup(esc_key_str);
  char *orig_key_str_copy = esc_key_str_copy;
  char *root_token = NULL;
  const char *sub_token = NULL;
  size_t i = 0;
  size_t j = 0;

  for (i = 0; ((root_token = strsep(&esc_key_str_copy, ",")) != NULL); i++) {
    if (root_token[0] == '\0' ) {
      fprintf(stderr,
        "FATAL ERROR: Empty key name specified in escape key list!\n");
      exit(1);
    }

    esc_key_list_len++;
    esc_key_list = safe_reallocarray(esc_key_list, esc_key_list_len,
      sizeof(uint32_t *));
    esc_key_sublist_len = safe_reallocarray(esc_key_sublist_len,
      esc_key_list_len, sizeof(size_t));
    active_esc_key_list = safe_reallocarray(active_esc_key_list,
      esc_key_list_len, sizeof(int8_t));
    esc_key_list[i] = NULL;
    esc_key_sublist_len[i] = 0;
    active_esc_key_list[i] = 0;

    for (j = 0; ((sub_token = strsep(&root_token, "|")) != NULL); j++)  {
      if (sub_token[0] == '\0') {
        fprintf(stderr,
          "FATAL ERROR: Empty key name specified in escape key list!\n");
        exit(1);
      }

      esc_key_sublist_len[i]++;
      esc_key_list[i] = safe_reallocarray(esc_key_list[i],
        esc_key_sublist_len[i], sizeof(uint32_t));
      esc_key_list[i][j] = lookup_keycode(sub_token);
      if (esc_key_list[i][j] == 0) {
        fprintf(stderr, "FATAL ERROR: Unrecognized key name '%s'!\n",
          sub_token);
        exit(1);
      }
    }
  }

  free(orig_key_str_copy);
}

static void register_esc_combo_event(struct button_event key_event) {
  size_t i = 0;
  size_t j = 0;
  bool hit_exit = true;

  for (i = 0; i < esc_key_list_len; i++) {
    for (j = 0; j < esc_key_sublist_len[i]; j++) {
      if (esc_key_list[i][j] != key_event.button_code) {
        continue;
      }

      if (key_event.is_pressed) {
        active_esc_key_list[i]++;
      } else {
        active_esc_key_list[i]--;
        if (active_esc_key_list[i] < 0) {
          fprintf(stderr,
            "WARNING: Unexpected escape key release. If this didn't occur very soon after kloak startup, this is probably a kloak bug.\n");
          active_esc_key_list[i] = 0;
        }
      }
      break;
    }
  }

  for (i = 0; i < esc_key_list_len; i++) {
    if (!active_esc_key_list[i]) {
      hit_exit = false;
      break;
    }
  }

  if (hit_exit) {
    fprintf(stderr, "INFO: Escape combo pressed, exiting.\n");
    exit(0);
  }
}

static char *parse_inotify_events(char *inotify_buf, ssize_t buf_len,
  ssize_t *buf_pos_ptr, bool *do_attach_ptr) {
  /*
   * Note that this function intentionally does not use assert() to make it
   * easier to test.
   */

  ssize_t rem_len = buf_len - *buf_pos_ptr;
  struct inotify_event *ie = (void *)(inotify_buf + *buf_pos_ptr);
  ssize_t struct_len = 0;

  if (rem_len < 0) {
    *buf_pos_ptr = -1;
    return NULL;
  }

  while (true) {
    if (rem_len < (ssize_t)(sizeof(struct inotify_event))) {
      *buf_pos_ptr = -1;
      return NULL;
    }
    /* No need to check if ie->len fits in struct_len, uint32_t is too small */
    struct_len = ((ssize_t)(sizeof(struct inotify_event))
      + (ssize_t)(ie->len));
    if (struct_len > rem_len) {
      *buf_pos_ptr = -1;
      return NULL;
    }
    rem_len -= struct_len;
    if (rem_len < 0) {
      *buf_pos_ptr = -1;
      return NULL;
    }
    *(buf_pos_ptr) += struct_len;
    if (ie->len > 0 && regexec(&evdev_reg, ie->name, 0, NULL, 0) == 0) {
      if (ie->mask & IN_CREATE) {
        *(do_attach_ptr) = true;
      } else {
        *(do_attach_ptr) = false;
      }
      return ie->name;
    }

    if (rem_len == 0) {
      break;
    }

    /*
     * We can safely disable cast alignment checks here because the kernel
     * should only provide us properly aligned events. Quoting the manpage:
     *
     *     ...This filename is null-terminated, and may include further null
     *     bytes ('\0') to align subsequent reads to a suitable address
     *     boundary.
     */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
    ie = (struct inotify_event *)((char *)(ie) + struct_len);
#pragma GCC diagnostic pop
  }

  return NULL;
}

static void handle_inotify_events(void) {
  static char *read_buf = NULL;
  ssize_t read_len = 0;
  ssize_t buf_pos = 0;
  bool do_attach = false;
  char *dev_path = NULL;

  if (read_buf == NULL) {
    read_buf = safe_calloc(INOTIFY_READ_BUF_LEN, sizeof(char));
  }

  while (true) {
    read_len = read(inotify_fd, read_buf, INOTIFY_READ_BUF_LEN);
    if (read_len == -1) {
      if (errno == EINTR) {
        continue;
      }
      fprintf(stderr,
        "FATAL ERROR: Could not read from inotify file descriptor: %s\n",
        strerror(errno));
      exit(1);
    }
    break;
  }

  while (buf_pos != read_len) {
    dev_path = parse_inotify_events(read_buf, read_len, &buf_pos, &do_attach);
    assert(buf_pos != -1);
    if (dev_path == NULL) {
      continue; /* we could use break too in theory */
    }
    if (do_attach) {
      attach_input_device(dev_path);
    } else {
      detach_input_device(dev_path);
    }
  }
}

static enum libinput_led calc_next_led_state(struct button_event key_event) {
  enum libinput_led led_state = 0;

  /*
   * Generally, X11 and Wayland turn an LED on after a key press, and
   * off after a key release. The exact reason for this is unclear, but
   * we mimic that behavior here to make sure we don't trip any weird
   * edge cases that depend on this.
   */
  if (key_event.button_code == KEY_NUMLOCK) {
    if (key_event.is_pressed && !num_lock_held) {
      num_lock_held = true;
      num_lock_state += 1;
    } else if (!key_event.is_pressed) {
      num_lock_held = false;
      num_lock_state += 1;
    }
    if (num_lock_state == 4) {
      num_lock_state = 0;
    }
  } else if (key_event.button_code == KEY_CAPSLOCK) {
    if (key_event.is_pressed && !caps_lock_held) {
      caps_lock_held = true;
      caps_lock_state += 1;
    } else if (!key_event.is_pressed) {
      caps_lock_held = false;
      caps_lock_state += 1;
    }
    if (caps_lock_state == 4) {
      caps_lock_state = 0;
    }
  }
  if (num_lock_state != 0) {
    led_state |= LIBINPUT_LED_NUM_LOCK;
  }
  if (caps_lock_state != 0) {
    led_state |= LIBINPUT_LED_CAPS_LOCK;
  }

  return led_state;
}

static void register_keyboard_led_event(struct button_event key_event) {
  enum libinput_led led_state = calc_next_led_state(key_event);

  if (led_state != last_led_state) {
    struct li_device_info *trav_li_device_info = NULL;
    last_led_state = led_state;
    LIST_FOREACH(trav_li_device_info, &ldi_head, ldi_entries) {
      libinput_device_led_update(trav_li_device_info->device, led_state);
    }
  }
}

static void process_libinput_event(struct libinput_event *li_event) {
  enum libinput_event_type ev_type = libinput_event_get_type(li_event);
  struct libinput_event_pointer *pointer_event = NULL;
  struct libinput_event_keyboard *kb_event = NULL;
  struct double_coord cursor_coord = { 0 };
  struct button_event button_event = { 0 };
  enum libinput_button_state button_state = 0;
  enum libinput_key_state key_state = 0;
  uint32_t button_held_count = 0;

  if (ev_type == LIBINPUT_EVENT_KEYBOARD_KEY) {
    kb_event = libinput_event_get_keyboard_event(li_event);
    button_event.button_code = libinput_event_keyboard_get_key(kb_event);
    key_state = libinput_event_keyboard_get_key_state(kb_event);
    button_held_count
      = libinput_event_keyboard_get_seat_key_count(kb_event);
    switch (key_state) {
    case LIBINPUT_KEY_STATE_PRESSED:
      button_event.is_pressed = true;
      break;
    case LIBINPUT_KEY_STATE_RELEASED:
      button_event.is_pressed = false;
      break;
    default:
      assert(false);
      break;
    }
    if ((button_event.is_pressed && button_held_count > 1)
      || (!button_event.is_pressed && button_held_count > 0)) {
      return;
    }

    register_esc_combo_event(button_event);
    register_keyboard_led_event(button_event);
  }

  if (!wl_connect_success) {
    return;
  }

  switch (ev_type) {
  case LIBINPUT_EVENT_POINTER_MOTION:
    pointer_event = libinput_event_get_pointer_event(li_event);
    cursor_coord.x = libinput_event_pointer_get_dx(pointer_event);
    cursor_coord.y = libinput_event_pointer_get_dy(pointer_event);
    assert(isfinite(cursor_coord.x));
    assert(isfinite(cursor_coord.y));
    send_msg_to_peer(PTC_PACKET_CURSOR_REL_EVENT, 1, &cursor_coord);
    return;

  case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE:
    pointer_event = libinput_event_get_pointer_event(li_event);
    if (pointer_space_data.x == 0 || pointer_space_data.y == 0) {
      return;
    }
    cursor_coord.x = libinput_event_pointer_get_absolute_x_transformed(
      pointer_event, (uint32_t)(pointer_space_data.x - 1));
    cursor_coord.y = libinput_event_pointer_get_absolute_y_transformed(
      pointer_event, (uint32_t)(pointer_space_data.y - 1));
    assert(isfinite(cursor_coord.x));
    assert(isfinite(cursor_coord.y));
    send_msg_to_peer(PTC_PACKET_CURSOR_ABS_EVENT, 1, &cursor_coord);
    return;

  /*
   * Scroll event handling is somewhat tricky...
   *
   * We want to mask the kind of scrolling device the user is using. The
   * intended user experience is:
   *
   * - "Clicky" mouse wheel rotation: the page should scroll some quantity
   *   with every "click". Emphasis on "click" here. We do NOT want to output
   *   scroll events with values matching the user's actual scrolling too
   *   precisely, so we do NOT want to say "if the user's mouse wheel rotated
   *   7.33116 degrees, scroll 7.33116 units" or similar.
   * - Everything else (smooth mouse wheel rotation, two-finger scrolling,
   *   continuous scrolling, future high-resolution scrolling methods
   *   humanity dreams up in their nightmares): the page should scroll a
   *   "mouse click's worth" of distance after enough scroll distance has
   *   accumulated.
   *
   * libinput has at least four different ways of representing scroll
   * movement. Unfortunately, none of them are suitable in all situations.
   *
   * - libinput_event_pointer_get_scroll_value() returns a double indicating
   *   some distance of movement. For scroll wheels, this corresponds to the
   *   angle (in degrees) the wheel rotated. For touch and continuous inputs,
   *   this corresponds to some quantity of "relative motion" (an abstract
   *   term the libinput API documentation does not elaborate on, but one
   *   assumes it correlates reasonably with mouse wheel rotation angles).
   *   This is great until you realize that mouse wheels sometimes rotate
   *   different quantities with each "tick" (and mice that don't have mouse
   *   wheel ticks look the same as mice with "clicky" mouse wheels when
   *   using libinput). This means that if we just use this function for
   *   everything, some users will see no scrolling after rotating the scroll
   *   wheel one click, then after a few "working" clicks they'll get a click
   *   that scrolls twice as far as expected. Other users will always have to
   *   scroll multiple clicks to get one "click's worth" of scrolling, and
   *   other users will (almost) always get multiple "click's worth"s of
   *   scrolling.
   * - libinput_event_pointer_get_scroll_value_v120() fixes the above mess by
   *   representing scroll distance in terms of mouse wheel clicks rather
   *   than raw angles. The function returns a double equal to (number of
   *   mouse ticks * 120), with support for "fractional ticks" in the form of
   *   values not evenly divisible by 120. By using this function, we can
   *   translate scroll ticks directly into quantities of scroll movement on
   *   screen, no matter how many degrees the wheel turns per tick.
   *   Unfortunately, this function *only* supports scroll wheel events, it
   *   doesn't work with any other kind of scrolling.
   * - libinput_event_pointer_get_axis_value() and
   *   libinput_event_pointer_get_axis_value_discrete() are similar to the
   *   above, but the values they provide are different (their output is in
   *   "relative scroll units" and "discrete steps", respectively), the
   *   latter doesn't work with high-resolution scroll devices, and both are
   *   deprecated.
   *
   * To acheive the desired user experience given the above API, scroll
   * events sent to the child have scroll lengths expressed as 1/120ths of a
   * scroll tick (the same value used by the v120 function above). For scroll
   * wheels, we can use the output of the v120 function directly. For
   * everything else, we assume that a scroll wheel tick always corresponds
   * to 15 degrees of mouse wheel rotation from the standpoint of
   * libinput_event_pointer_get_scroll_value() (this is a blatantly false
   * assumption but it's close enough for our purposes, since the "default"
   * degrees of rotation per wheel click is 15 in libinput), and so we can
   * translate the output of libinput_event_pointer_get_scroll_value() into
   * a suitable value by multiplying it by 8 (because 120 / 15 = 8).
   *
   * This is further complicated by the fact that there are both vertical and
   * horizontal scroll events, so each scroll event sent to the child
   * contains information for both axes.
   */

  case LIBINPUT_EVENT_POINTER_SCROLL_WHEEL:
    pointer_event = libinput_event_get_pointer_event(li_event);
    if (libinput_event_pointer_has_axis(pointer_event,
      LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
      cursor_coord.y = libinput_event_pointer_get_scroll_value_v120(
        pointer_event, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
      assert(isfinite(cursor_coord.x));
    }
    if (libinput_event_pointer_has_axis(pointer_event,
      LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
      cursor_coord.x = libinput_event_pointer_get_scroll_value_v120(
        pointer_event, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
      assert(isfinite(cursor_coord.y));
    }
    send_msg_to_peer(PTC_PACKET_SCROLL_EVENT, 1, &cursor_coord);
    return;

  case LIBINPUT_EVENT_POINTER_SCROLL_FINGER:
  case LIBINPUT_EVENT_POINTER_SCROLL_CONTINUOUS:
    pointer_event = libinput_event_get_pointer_event(li_event);
    if (libinput_event_pointer_has_axis(pointer_event,
      LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
      /*
       * Note that IEEE-754 floating point math does not have undefined
       * behavior on overflow/underflow. If we're using some weird compiler
       * and CPU combination that doesn't use IEEE-754, this might be
       * undefined behavior, but this is pretty rare, see:
       * https://lwn.net/Articles/886516/
       */
      cursor_coord.y = libinput_event_pointer_get_scroll_value(
        pointer_event, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)
        * SCROLL_ANGLE_TO_UNITS_FACTOR_D;
      assert(isfinite(cursor_coord.x));
    }
    if (libinput_event_pointer_has_axis(pointer_event,
      LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
      cursor_coord.x = libinput_event_pointer_get_scroll_value(
        pointer_event, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)
        * SCROLL_ANGLE_TO_UNITS_FACTOR_D;
      assert(isfinite(cursor_coord.y));
    }
    send_msg_to_peer(PTC_PACKET_SCROLL_EVENT, 1, &cursor_coord);
    return;

  case LIBINPUT_EVENT_POINTER_BUTTON:
    pointer_event = libinput_event_get_pointer_event(li_event);
    button_event.button_code = libinput_event_pointer_get_button(
      pointer_event);
    button_state = libinput_event_pointer_get_button_state(pointer_event);
    switch (button_state) {
    case LIBINPUT_BUTTON_STATE_PRESSED:
      button_event.is_pressed = true;
      break;
    case LIBINPUT_BUTTON_STATE_RELEASED:
      button_event.is_pressed = false;
      break;
    default:
      assert(false);
    }
    button_held_count
      = libinput_event_pointer_get_seat_button_count(pointer_event);
    if ((button_event.is_pressed && button_held_count > 1)
      || (!button_event.is_pressed && button_held_count > 0)) {
      return;
    }
    send_msg_to_peer(PTC_PACKET_CLICK_EVENT, 1, &button_event);
    return;

  case LIBINPUT_EVENT_KEYBOARD_KEY:
    send_msg_to_peer(PTC_PACKET_KB_EVENT, 1, &button_event);
    return;

  default:
    return;
  }
}

static void process_child_message(void) {
  enum ctp_packet_type msg_type = 0;
  void *msg_obj = get_msg_from_peer(&msg_type, NULL);

  switch (msg_type) {
  case CTP_PACKET_NONE:
    return;
  case CTP_PACKET_WAYLAND_LOST:
    fprintf(stderr, "INFO: Child lost Wayland connection, exiting.\n");
    exit(0);
  case CTP_PACKET_POINTER_SPACE_DATA:
    memcpy(&pointer_space_data, msg_obj, sizeof(struct coord));
    free(msg_obj);
    return;
  default:
    fprintf(stderr, "FATAL ERROR: Unexpected message type %u from child!\n",
      msg_type);
    exit(1);
  }
}

static void print_usage(void) {
  fprintf(stderr, "Usage: kloak [options]\n");
  fprintf(stderr, "Anonymizes keyboard and mouse input patterns by injecting jitter into input\n");
  fprintf(stderr, "events. Designed specifically for wlroots-based Wayland compositors. Will NOT\n");
  fprintf(stderr, "work with X11.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -h, --help\n");
  fprintf(stderr, "    Print help.\n");
  fprintf(stderr, "  -d, --delay=milliseconds\n");
  fprintf(stderr, "    Configure the maximum delay of released events. Default is 100.\n");
  fprintf(stderr, "  -s, --start-delay=milliseconds\n");
  fprintf(stderr, "    Configure the time to wait before startup. Default is 500.\n");
  fprintf(stderr, "  -c, --color=AARRGGBB\n");
  fprintf(stderr, "    Configure the color to use for the virtual mouse cursor. Default is\n");
  fprintf(stderr, "    00000000 (fully transparent black, i.e. invisible).\n");
  fprintf(stderr, "  -n, --natural-scrolling=(true|false)\n");
  fprintf(stderr, "    Enable or disable natural scrolling on supported pointing devices. Default\n");
  fprintf(stderr, "    is false.\n");
  fprintf(stderr, "  -k, --esc-key-combo=KEY_1[,KEY_2|KEY_3...]\n");
  fprintf(stderr, "    Specify the key combination that will terminate kloak. Keys are separated\n");
  fprintf(stderr, "    by commas. Keys can be aliased to each other by separating them with a\n");
  fprintf(stderr, "    pipe (|) character. Default is KEY_RIGHTSHIFT,KEY_ESC.\n");
}

/****************************/
/* Initialization functions */
/****************************/

static void applayer_regex_init(void) {
  int comp_rslt = regcomp(&evdev_reg, "^event[0-9]\\+$", REG_NOSUB);
  assert(comp_rslt == 0);
}

static void applayer_kloakwl_init(void) {
  struct pollfd init_poll = { 0 };
  int poll_rslt = 0;
  int wait_pid = 0;
  int wait_rslt = 0;

  /* Set up communication pipes and ring buffer. */
  if (pipe(ctp_pipe) == -1) {
    fprintf(stderr, "FATAL ERROR: Could not create child-to-parent pipe: %s\n",
      strerror(errno));
    exit(1);
  }
  if (pipe(ptc_pipe) == -1) {
    fprintf(stderr, "FATAL ERROR: Could not create parent-to-child pipe: %s\n",
        strerror(errno));
    exit(1);
  }
  init_msg_ring();

  /* Launch the child process. */
  child_pid = fork();
  if (child_pid == -1) {
    fprintf(stderr, "FATAL ERROR: Could not fork: %s\n", strerror(errno));
    exit(1);
  }
  if (child_pid == 0) {
    /* child */
    char *kloakwl_path_dup = safe_strdup(KLOAKWL_PATH);
    char *child_argv[] = { kloakwl_path_dup, NULL };
    move_fd(ctp_pipe[1], 1);
    move_fd(ptc_pipe[0], 0);
    if (execve(KLOAKWL_PATH, child_argv, environ) == -1) {
      _exit(1);
    }
  }
  send_write_fd = ptc_pipe[1];
  recv_read_fd = ctp_pipe[0];
  /*
   * We need to close the unused ends of the pipe we've passed to the child,
   * or else we won't get a POLLHUP signal if the child terminates.
   */
  safe_close(ptc_pipe[0]);
  safe_close(ctp_pipe[1]);

  /* Configure child process. */
  send_msg_to_peer(PTC_PACKET_MAX_DELAY_CONFIG, 1, &max_delay);
  send_msg_to_peer(PTC_PACKET_CURSOR_COLOR_CONFIG, 1, &cursor_color);

  /* Wait for the child to either initialize or error out. */
  while (true) {
    enum ctp_packet_type recv_packet_type = 0;

    init_poll.fd = recv_read_fd;
    init_poll.events = POLLIN;
    do {
      poll_rslt = poll(&init_poll, 1, -1);
    } while (poll_rslt == -1 && errno == EINTR);
    if (poll_rslt == -1) {
      fprintf(stderr,
        "FATAL ERROR: Could not wait for data on child-to-parent pipe: %s\n",
        strerror(errno));
      exit(1);
    }
    if (!(init_poll.revents & POLLIN)) {
      if (init_poll.revents & POLLHUP) {
        /*
         * Child process aborted early, find out why. Note that the child could
         * theoretically close its stdout but then remain running, which would
         * deadlock this code. This is considered an acceptable risk for now.
         */
        wait_pid = waitpid(child_pid, &wait_rslt, 0);
        if (wait_pid != child_pid) {
          assert(false);
        }
        if (!WIFEXITED(wait_rslt)) {
          fprintf(stderr,
            "FATAL ERROR: Child process crashed during early init!\n");
          exit(1);
        }
        fprintf(stderr, "FATAL ERROR: Child aborted during early init!\n");
        exit(1);
      }

      fprintf(stderr, "FATAL ERROR: No init notification from child!\n");
      exit(1);
    }

    (void) get_msg_from_peer(&recv_packet_type, NULL);
    if (recv_packet_type == 0) {
      init_poll.revents = 0;
      continue;
    }
    if (recv_packet_type == CTP_PACKET_WAYLAND_LOST) {
      if (exit_on_wl_connect_failure) {
        fprintf(stderr,
          "FATAL ERROR: Could not connect to Wayland compositor, and KLOAK_EXIT_ON_WL_CONNECT_FAILURE is 1!\n");
        exit(1);
      }

      fprintf(stderr,
        "WARNING: Could not connect to Wayland compositor, will await escape key combo to exit.\n");
      wl_connect_success = false;
    } else if (recv_packet_type != CTP_PACKET_INIT_ACK) {
      fprintf(stderr, "FATAL ERROR: Child failed to initialize!\n");
      exit(1);
    }
    break;
  }
}

static void applayer_inotify_init(void) {
  inotify_fd = inotify_init1(IN_CLOEXEC);
  if (inotify_fd == -1) {
    fprintf(stderr, "FATAL ERROR: Could not initialize inotify: %s\n",
      strerror(errno));
    exit(1);
  }

  if (inotify_add_watch(inotify_fd, "/dev/input", IN_CREATE | IN_DELETE)
    == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not add inotify watch on /dev/input: %s\n",
      strerror(errno));
    exit(1);
  }
}

static void check_dup_arg_and_mark(int opt, int *seen_opts,
  ssize_t *seen_opts_pos_ptr) {
  for (ssize_t i = 0; i < *seen_opts_pos_ptr; i++) {
    if (seen_opts[i] == opt) {
      fprintf(stderr,
        "FATAL ERROR: Option '-%c' was specified multiple times!\n", opt);
      exit(1);
    }
  }

  seen_opts[*seen_opts_pos_ptr] = opt;
  (*seen_opts_pos_ptr)++;
}

static void applayer_libinput_init(void) {
  DIR *input_dir = NULL;
  const struct dirent *input_dir_entry = NULL;

  LIST_INIT(&ldi_head);

  li = libinput_path_create_context(&li_interface, NULL);

  input_dir = safe_opendir("/dev/input");
  for (input_dir_entry = readdir(input_dir); input_dir_entry != NULL;
    input_dir_entry = readdir(input_dir)) {
    if (input_dir_entry->d_type != DT_CHR) {
      continue;
    }

    if (regexec(&evdev_reg, input_dir_entry->d_name, 0, NULL, 0) != 0) {
      continue;
    }

    attach_input_device(input_dir_entry->d_name);
  }
  safe_closedir(input_dir);
}

static void applayer_poll_init(void) {
  ev_fds = safe_calloc(POLL_FD_COUNT, sizeof(struct pollfd));
  ev_fds[0].fd = libinput_get_fd(li);
  ev_fds[0].events = POLLIN;
  ev_fds[1].fd = inotify_fd;
  ev_fds[1].events = POLLIN;
  ev_fds[2].fd = recv_read_fd;
  ev_fds[2].events = POLLIN;
}

static void parse_cli_args(int argc, char **argv) {
  const char *optstring = "d:s:hc:k:n:";
  static struct option optarr[] = {
    {"delay", required_argument, NULL, 'd'},
    {"start-delay", required_argument, NULL, 's'},
    {"help", no_argument, NULL, 'h'},
    {"color", required_argument, NULL, 'c'},
    {"esc-key-combo", required_argument, NULL, 'k'},
    {"natural-scrolling", required_argument, NULL, 'n'},
    {0, 0, 0, 0}
  };
  /*
   * This must be incremented any time a new option is added above, and
   * decremented when an option is removed.
   */
  const ssize_t opts_count = 6;
  int getopt_rslt = 0;
  int *seen_opts = safe_calloc(opts_count, sizeof(int));
  ssize_t seen_opts_pos = 0;

  while(true) {
    getopt_rslt = getopt_long(argc, argv, optstring, optarr, NULL);
    if (getopt_rslt == -1) {
      break;
    } else if (getopt_rslt == '?') {
      print_usage();
      exit(1);
    }
    check_dup_arg_and_mark(getopt_rslt, seen_opts, &seen_opts_pos);
    if (getopt_rslt == 'd') {
      if (!parse_uint31_arg(optarg, 10, &max_delay)) {
        fprintf(stderr,
          "FATAL ERROR: Invalid value '%s' passed to parameter 'delay'!\n",
          optarg);
        exit(1);
      }
    } else if (getopt_rslt == 's') {
      if (!parse_uint31_arg(optarg, 10, &startup_delay)) {
        fprintf(stderr,
          "FATAL ERROR: Invalid value '%s' passed to parameter 'start-delay'!\n",
          optarg);
        exit(1);
      }
    } else if (getopt_rslt == 'c') {
      if (!parse_uint32_arg(optarg, 16, &cursor_color)) {
        fprintf(stderr,
          "FATAL ERROR: Invalid value '%s' passed to parameter 'color'!\n",
          optarg);
        exit(1);
      }
    } else if (getopt_rslt == 'n') {
      if (strcmp(optarg, "true") == 0) {
        enable_natural_scrolling = true;
      } else {
        enable_natural_scrolling = false;
      }
    } else if (getopt_rslt == 'k') {
      parse_esc_key_str(optarg);
    } else if (getopt_rslt == 'h') {
      print_usage();
      exit(0);
    } else {
      print_usage();
      exit(1);
    }
  }

  free(seen_opts);

  if (esc_key_list == NULL) {
    parse_esc_key_str(DEFAULT_ESC_KEY_STR);
  }
}

/**********/
/**********/
/** MAIN **/
/**********/
/**********/

int main(int argc, char **argv) {
  const char *env_val = NULL;
  int poll_ret = 0;

  /*
   * BIG FAT WARNING: Do not attempt to build kloak with NDEBUG defined. Many
   * of the assertions in this code are essential for security, and building
   * kloak with NDEBUG defined will turn all of them off. Systems running a
   * build of kloak with NDEBUG defined should be treated as compromised if
   * they process any form of untrusted data.
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

  /* Make sure that locales don't try to ruin our day */
  if (setenv("LC_ALL", "C", 1) == -1) {
    fprintf(stderr, "FATAL ERROR: Could not set LC_ALL=C!\n");
    exit(1);
  }

  parse_cli_args(argc, argv);
  env_val = getenv("KLOAK_EXIT_ON_WL_CONNECT_FAILURE");
  if (env_val != NULL && strcmp(env_val, "1") == 0) {
    exit_on_wl_connect_failure = true;
  }

  if (sleep_ms(startup_delay) != 0) {
    fprintf(stderr,
      "FATAL ERROR: Could not sleep for requested start duration!\n");
    exit(1);
  }

  applayer_regex_init();
  applayer_kloakwl_init();
  applayer_inotify_init();
  applayer_libinput_init();
  applayer_poll_init();

  while (true) {
    while (true) {
      enum libinput_event_type next_ev_type = libinput_next_event_type(li);
      struct libinput_event *li_event = NULL;

      if (next_ev_type == LIBINPUT_EVENT_NONE) {
        break;
      }

      li_event = libinput_get_event(li);
      process_libinput_event(li_event);
      libinput_event_destroy(li_event);
    }

    do {
      poll_ret = poll(ev_fds, POLL_FD_COUNT, -1);
    } while (poll_ret == -1 && errno == EINTR);
    if (poll_ret == -1) {
      fprintf(stderr, "FATAL ERROR: 'poll' errored out: %s\n",
        strerror(errno));
      exit(1);
    }

    if (ev_fds[0].revents & POLLIN) {
      libinput_dispatch(li);
    }
    ev_fds[0].revents = 0;

    if (ev_fds[1].revents & POLLIN) {
      handle_inotify_events();
    }
    ev_fds[1].revents = 0;

    if (wl_connect_success) {
      if (ev_fds[2].revents & POLLIN) {
        process_child_message();
      }
      if (ev_fds[2].revents & POLLHUP) {
        fprintf(stderr, "INFO: Peer disconnected, exiting.\n");
        exit(0);
      }
    }
  }

  assert(false);
}
