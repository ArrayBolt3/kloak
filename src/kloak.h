/*
 * SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*********************************/
/* Static defines, do not change */
/*********************************/

/*
 * Absolute path to the kloakwl executable.
 *
 * TODO: Make this somehow dependent on the prefix kloak is installed into, so
 * as to not break installation into locations other than /usr/bin.
 */
#define KLOAKWL_PATH "/usr/bin/kloakwl"
/* Number of fds watched by the main loop poll. */
#define POLL_FD_COUNT 3
/*
 * Number to multiply degrees of rotation by to get 120ths of a scroll tick.
 * See the comment about scroll handling in process_libinput_event for more
 * details.
 */
#define SCROLL_ANGLE_TO_UNITS_FACTOR_D 8.0
/* The length of the buffer to read inotify events into. */
#define INOTIFY_READ_BUF_LEN 16384

/*******************/
/* Tunable defines */
/*******************/

/*
 * Default value for the maximum delay between an input event's arrival and
 * release.
 */
#define DEFAULT_MAX_DELAY_MS 100
/* Default value for the delay between kloak start and initialization. */
#define DEFAULT_STARTUP_TIMEOUT_MS 500
/* Default escape key sequence to make kloak terminate. */
#define DEFAULT_ESC_KEY_STR "KEY_RIGHTSHIFT,KEY_ESC"

/***********/
/* Structs */
/***********/

/* Defines an evdev key code and the corresponding string. */
struct key_name_value {
    const char *name;
    const uint32_t value;
};

/*
 * Defines a libinput device on the system by its device pointer and file
 * name. Intended for use in a doubly-linked list.
 *
 * Note: This struct isn't terribly useful at the moment, but it gives us the
 * flexibility to attach data to libinput devices in the future if needed.
 */
struct li_device_info {
  struct libinput_device *device;
  char *device_name;
  uint32_t refcount;
  LIST_ENTRY(li_device_info) ldi_entries;
};


/*******************************/
/* Utility function prototypes */
/*******************************/

/*
 * Reallocates the requested amount of memory and returns a pointer to it.
 * Kills the process if the allocation fails.
 */
static void *safe_reallocarray(void *ptr, size_t nmemb, size_t size);

/* Opens a directory. Kills the process if the open fails. */
static DIR *safe_opendir(const char *name);

/* Closes a directory. Kills the process if the close fails. */
static void safe_closedir(DIR *dirp);

/* Converts a millisecond count to a timespec. */
static struct timespec ms_to_timespec(int64_t ms);

/* Looks up a key code in the key table. */
static uint32_t lookup_keycode(const char *name);

/* Attempts to add an input device to the current libinput context. */
static void attach_input_device(const char *dev_name);

/* Attempts to remove an input device from the current libinput context. */
static void detach_input_device(const char *dev_name);

/*
 * Increments the reference count of an li_device_info struct. Not currently
 * in use.
 */
/*static void li_device_info_ref(struct li_device_info *ldi);*/

/*
 * Decrements the reference count of an li_device_info struct, freeing it if
 * possible.
 */
static void li_device_info_unref(struct li_device_info *ldi);

/*
 * Parse an option parameter as an integer between 0 and INT32_MAX, and save
 * it at the address pointed to by "out". Returns true on success.
 */
static bool parse_uint31_arg(const char *val, int base, int32_t *out);

/*
 * Parse an option parameter as an integer between 0 and UINT32_MAX, and save
 * it at the address pointed to by "out". Returns true on success.
 */
static bool parse_uint32_arg(const char *val, int base, uint32_t *out);

/* Sleeps for the specified number of milliseconds. */
static int32_t sleep_ms(int64_t ms);

/*****************************************/
/* libinput handling function prototypes */
/*****************************************/

/*
 * Opens evdev devices for libinput, grabbing them with EVIOCGRAB so that they
 * can't be used by other applications on the system.
 */
static int li_open_restricted(const char *path, int flags, void * user_data);

/* Closes evdev devices for libinput. */
static void li_close_restricted(int fd, void *user_data);

/**********************************/
/* High-level function prototypes */
/**********************************/

/* Parses an escape key specification into the escape key globals. */
static void parse_esc_key_str(const char *esc_key_str);

/*
 * Tracks actively held down keys in the escape key list and terminates kloak
 * if all escape keys are actively being held down.
 */
static void register_esc_combo_event(struct button_event key_event);

/*
 * Searches for an evdev device name in an inotify buffer and returns it.
 * Advances buf_pos_ptr to record where it left off, sets buf_pos_ptr to -1 if
 * an error is encountered.
 */
static char *parse_inotify_events(char *inotify_buf, ssize_t buf_len,
  ssize_t *buf_pos_ptr, bool *do_attach_ptr, bool *inotify_overflow_ptr);

/*
 * Reads inotify events for /dev/input and attempts to add or remove libinput
 * devices as appropriate.
 */
static void handle_inotify_events(void);

/*
 * Adjusts keyboard LED globals and returns an LED state that should be applied
 * to all attached keyboards.
 */
static enum libinput_led calc_next_led_state(struct button_event key_event);

/* Adjusts keyboard LEDs in response to a keyboard event if appropriate. */
static void register_keyboard_led_event(struct button_event key_event);

/*
 * Dispatches libinput event details to handler functions and forwards them to
 * the child where appropriate.
 */
static void process_libinput_event(struct libinput_event *li_event);

/* Updates parent state with the contents of the next child message. */
static void process_child_message(void);

/* Prints usage information. */
static void print_usage(void);

/**************************************/
/* Initialization function prototypes */
/**************************************/

/* Compiles regexes. */
static void applayer_regex_init(void);

/* Sets up communication pipes and starts the kloakwl child process. */
static void applayer_kloakwl_init(void);

/* Watches /dev/input for device creation and deletion. */
static void applayer_inotify_init(void);

/*
 * Opens all available input devices with libinput and prepares to process
 * events from them.
 */
static void applayer_libinput_init(void);

/* Sets up poll fds. */
static void applayer_poll_init(void);

/*
 * Checks if an option has been specified twice. Terminates the program if so,
 * marks the option as having been seen otherwise.
 */
static void check_dup_arg_and_mark(int opt, int *seen_opts,
  ssize_t *seen_opts_pos_ptr);

/* Parses command-line arguments. */
static void parse_cli_args(int argc, char **argv);

/**********************/
/* libinput callbacks */
/**********************/

static const struct libinput_interface li_interface = {
  .open_restricted = li_open_restricted,
  .close_restricted = li_close_restricted,
};
