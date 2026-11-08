/*
 * SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Data and definitions for kloakwl.c.
 */

/*********************************/
/* Static defines, do not change */
/*********************************/

/*
 * File descriptor number for the Wayland socket.
 *
 * NOTE: This definition must ALWWAYS have the highest fd number of defined
 * fds used by kloakwl (including those in kloak-shared.h). kloakwl will
 * close_range() all file descriptors higher than this.
 */
#define CHILD_FD_WLSOCK 4

/* Number of fds watched by the main loop poll. */
#define POLL_FD_COUNT 2

/* Initializer value for an empty screen_local_coord (defined below). */
#define EMPTY_SCREEN_LOCAL_COORD { .x = 0, .y = 0, .output_idx = -1 }

/* Self-explanatory. */
#define SCROLL_UNITS_PER_TICK 120
#define SCROLL_UNITS_PER_TICK_D 120.0
#define SCROLL_ANGLE_PER_TICK 15

/* User/group name to switch to during sandboxing. */
#define SANDBOX_DEDICATED_USER "kloakwl"

/*******************/
/* Tunable defines */
/*******************/

/*
 * The maximum number of screens kloak can handle at once. More screens
 * requires more memory.
 *
 * Note that the maximum number of attached screens is also constrained by shm
 * allocation space, see the next define.
 */
#define MAX_SCREEN_COUNT 128

/*
 * Maximum number of times to roundtrip with the compositor during Wayland
 * initialization.
 */
#define MAX_INIT_ATTEMPTS 8

/* Number of frames to allow to be in-flight per screen. */
#define MAX_UNRELEASED_FRAMES 3

/*
 * The size of the tmpfs used for our root. This must be large enough for
 * shared memory regions to be allocated, holding various information including
 * pixel buffers covering all attached screens. Note that tmpfs filesystems do
 * not immediately take up their full size in system memory, so this number can
 * be much larger than what one would expect kloak to reasonably use at once.
 *
 * The correct value in megabytes for this size should be calculated as:
 *
 *     (number of screens * screen width in pixels * screen height in pixels
 *       * 4 * MAX_UNRELEASED_FRAMES) / 1024 / 1024
 *       + some headroom for the parsing ring buffer, filesystem overhead, etc.
 *
 * (The 4 multiplier is there because ARGB pixels are in use, with each channel
 * using 8 bits, so each pixel requires 32 bits to represent properly.)
 *
 * The current size allows two 8K displays to be used and offers about 2.5M
 * headroom. This is believed to be reasonably future-proof for the time being.
 */
#define SHM_TMPFS_SIZE "762M"

/*
 * Number of pixels the virtual cursor crosshair should extend beyond the
 * center pixel.
 */
#define CURSOR_RADIUS 15

/*
 * Number of messages the child will try to fetch and process from the parent
 * in a row before stopping to handle other things.
 */
#define MAX_PARENT_BATCH_MESSAGES 32

/**********************/
/* Structs and unions */
/**********************/

/*
 * A screen's position and size. x and y may both be negative, width and height
 * must never be negative.
 */
struct output_geometry {
  int32_t x;
  int32_t y;
  int32_t width;
  int32_t height;
};

/*
 * Defines a point in screen-local space, along with which screen the point is
 * located on. If output_idx is -1, the x and y coordinates do not point within
 * any known screen.
 */
struct screen_local_coord {
  int32_t x;
  int32_t y;
  int32_t output_idx;
};

/*
 * Defines the type of a buffered input event.
 *
 * NOTE: A packet type of 0 is used to mark the end of packet type lists.
 */
enum input_packet_type {
  KLOAK_PACKET_TYPE_MOUSEMOVE = 1,
  KLOAK_PACKET_TYPE_MOUSESCROLL,
  KLOAK_PACKET_TYPE_CLICK,
  KLOAK_PACKET_TYPE_KB,
};

/* A container for the data in an input packet. */
union input_packet_data {
  struct coord coord_data;
  struct button_event button_data;
};

/*
 * A buffered input event. Four types of events are supported:
 *
 * - Mouse movement events are defined as a cursor position in compositor
 *   global space. Uses input_packet_data.coord_data.
 * - Scroll events are defined as a pair of scroll "tick" values, one for each
 *   dimension (vertical and horizontal). Uses input_packet_data.coord_data.
 * - Click and keyboard events are defined as a code for the button or key in
 *   question, and a bool indicating whether it has been pressed or released.
 *   Uses input_packet_data.button_data.
 */
struct input_packet {
  enum input_packet_type packet_type;
  int64_t sched_time;
  TAILQ_ENTRY(input_packet) evq_entries;
  union input_packet_data data;
};

/*
 * A screen-local layer that the virtual cursor can be drawn on. When cursor
 * drawing is enabled, each screen will be allocated one drawable layer, which
 * will appear on top of all other screen content if possible.
 */
struct drawable_layer {
  /*
   * References to portions of the layer's pixbuf, each treated as a single
   * buffer by the compositor.
   */
  struct wl_buffer *buffer_list[MAX_UNRELEASED_FRAMES];

  /* The layer's dimensions. */
  int32_t width;
  int32_t height;

  /* The number of bytes in each pixel row. */
  int32_t stride;

  /*
   * The size of an individual wl_buffer, in bytes.
   */
  int32_t size;

  /*
   * The raw pixel buffer. Each integer in the buffer represents a single
   * pixel. All values for MAX_UNRELEASED_FRAMES buffers are laid out
   * end-to-end. This buffer contains shared memory.
   */
  uint32_t *pixbuf;

  /* The surface buffers will be rendered on. */
  struct wl_surface *surface;

  /* Manages the shared memory allocated to the pixbuf. */
  struct wl_shm_pool *shm_pool;

  /* Allows the surface to be treated as a layer. */
  struct zwlr_layer_surface_v1 *layer_surface;

  /*
   * Set to true after a 'configure' event has been received for this layer's
   * layer_surface and the pixbuf and associated metadata and management
   * objects have been initialized.
   */
  bool layer_surface_configured;

  /*
   * Marks buffers that have been sent to the compositor and that the
   * compositor has not yet released.
   */
  bool frame_in_use[MAX_UNRELEASED_FRAMES];

  /*
   * Whether this layer has been affected in some way that requires its
   * contents to be redrawn.
   */
  bool frame_pending;

  /*
   * The last position the virtual cursor was in on this layer. Used for
   * damaging the surface efficiently.
   */
  int32_t last_drawn_cursor_x;
  int32_t last_drawn_cursor_y;

  /*
   * The places the virtual cursor was at for each in-use wl_buffer. Used for
   * efficiently clearing pixbuf contents after a buffer is released.
   */
  int32_t cursor_x_pos_list[MAX_UNRELEASED_FRAMES];
  int32_t cursor_y_pos_list[MAX_UNRELEASED_FRAMES];
};

/* Monolithic Wayland state object. */
struct disp_state {
  /* The root Wayland display object. */
  struct wl_display *display;

  /*
   * The file descriptor for that object, this triggers POLLIN when new Wayland
   * events are available.
   */
  int display_fd;

  /* The global registry for the display. */
  struct wl_registry *registry;

  /* The shared memory management global. */
  struct wl_shm *shm;

  /* The surface compositing global. */
  struct wl_compositor *compositor;

  /* The seat global. */
  struct wl_seat *seat;

  /* Capabilities of the seat global. */
  uint32_t seat_caps;

  /* The keyboard interface of the seat. Used for getting keymap info. */
  struct wl_keyboard *kb;

  /* All displays the compositor is actively managing. */
  struct wl_output *outputs[MAX_SCREEN_COUNT];
  uint32_t output_names[MAX_SCREEN_COUNT];

  /*
   * Management object for xdg_outputs (which essentially extend the
   * functionality offered by wl_output).
   */
  struct zxdg_output_manager_v1 *xdg_output_manager;

  /* xdg_outputs corresponding to wl_outputs. */
  struct zxdg_output_v1 *xdg_outputs[MAX_SCREEN_COUNT];

  /*
   * Tracks which xdg_outputs are in the process of being reconfigured by the
   * compositor.
   */
  bool output_config_flag_list[MAX_SCREEN_COUNT];

  /*
   * Tracks wl_outputs that the compositor has removed but that kloak has not
   * yet handled the removal of.
   */
  bool wl_output_remove_flags[MAX_SCREEN_COUNT];

  /*
   * The size and location in compositor global space of each display. These
   * objects are guaranteed to be in-sync with the latest fully consistent
   * display state received from the compositor.
   */
  struct output_geometry *output_geometries[MAX_SCREEN_COUNT];

  /*
   * The size and location in compositor global space of each display. These
   * objects are kept up-to-date with the latest info from the compositor, but
   * will be in an inconsistent state if the compositor is mid-reconfiguring
   * displays.
   */
  struct output_geometry *pending_output_geometries[MAX_SCREEN_COUNT];

  /*
   * The location and size of the "pointer space". Pointer space is a rectangle
   * whose upper-left corner is defined by the highest and furthest-left
   * displays, and whose lower-right corner is defined by the lowest and
   * furthest-right displays, of the last received fully consistent display
   * state.
   */
  int32_t pointer_space_x;
  int32_t pointer_space_y;
  int32_t pointer_space_width;
  int32_t pointer_space_height;

  /* Interface for creating layer surfaces. */
  struct zwlr_layer_shell_v1 *layer_shell;

  /* Interfaces for creating virtual input devices. */
  struct zwlr_virtual_pointer_manager_v1 *virt_pointer_manager;
  struct zwp_virtual_keyboard_manager_v1 *virt_kb_manager;

  /* The virtual input devices. */
  struct zwp_virtual_keyboard_v1 *virt_kb;
  struct zwlr_virtual_pointer_v1 *virt_pointer;

  /* XKB state objects. These are used for proper handling of modifier keys. */
  struct xkb_context *xkb_ctx;
  struct xkb_keymap *xkb_keymap;
  struct xkb_state *xkb_state;

  /* Keymap shared memory buffer information. This is used by XKB. */
  char *old_kb_map_shm;
  int32_t old_kb_map_shm_size;

  /*
   * Drawable layers for each known screen. These are allocated immediately as
   * displays are connected, but are only freed when a fully consistent display
   * state is received.
   */
  struct drawable_layer *layers[MAX_SCREEN_COUNT];
};

/*******************************/
/* Utility function prototypes */
/*******************************/

/*
 * Creates a directory and all of its ancestors as needed. Aborts the program
 * if this fails. path_component_list must define an absolute path as one or
 * more '/'-prefixed strings, and must be terminated by a NULL item. This
 * intentionally does not support relative paths yet.
 */
static void safe_mkdir_p(const char **path_component_list);

/*
 * Converts a timespec to a millisecond count. Aborts the program if the
 * timespec is invalid or negative.
 */
static int64_t timespec_to_ms(struct timespec spec);

/*
 * Returns a monotonic 64-bit timestamp. Aborts the program if the current
 * monotonic time cannot be retrieved.
 */
static int64_t current_time_ms(void);

/* Generates a random 64-bit number between lower and upper inclusive. */
static int64_t random_between(int64_t lower, int64_t upper);

/*
 * Writes the printf-formatted string in content_template and subsequent args
 * to the file specified by file_path. Aborts the program if this fails.
 */
static void write_to_file(const char *file_path, const char *content_template,
  ...);

/*
 * Sets whether the process is dumpable or not. Aborts the program if this
 * fails.
 */
static void change_dumpable(bool is_dumpable);

/*
 * Grows a line segment by 1 pixel both forwards and backwards, clamping if one
 * end of the line segment is at an integer size boundary.
 */
static void grow_line_segment(int32_t *pos_point_ptr, int32_t *length_ptr);

/*
 * Determine if two screens are touching or overlapping given their
 * geometries.
 */
static bool check_screen_touch(struct output_geometry scr1,
  struct output_geometry scr2);

/*
 * Converts a set of coordinates in compositor global space to a set of
 * coordinates in screen-local space. The returned object is equal to
 * EMPTY_SCREEN_LOCAL_COORD if the coordinates do not point within any screen.
 */
static struct screen_local_coord abs_coord_to_screen_local_coord(int32_t x,
  int32_t y);

/*
 * Converts a set of coordinates in screen-local space to a set of coordinates
 * in compositor-global space. Sets *out_is_valid to true if the specified
 * parameters point within a valid screen, sets it to false otherwise.
 */
static struct coord screen_local_coord_to_abs_coord(int32_t x, int32_t y,
  int32_t output_idx, bool *out_is_valid);

/*
 * Takes two points that define a line on a 2d plane, and outputs the
 * coordinate corresponding to the pixel that is 'pos' pixels away from the
 * origin point. It is not possible to walk beyond the end coordinates, and the
 * end coordiante will always be included in the output. Sets *out_success to
 * true if the input parameters were valid, false otherwise.
 */
static struct coord traverse_line(struct coord start, struct coord end,
  int32_t pos, bool *out_success);

/*
 * Draws a crosshair or block of blank pixels on the specified pixel buffer at
 * the specified location in the buffer.
 */
static void draw_block(uint32_t * pixbuf, int32_t offset, int32_t x, int32_t y,
  int32_t layer_width, int32_t layer_height, int32_t rad, bool crosshair);

/*
 * Extracts a whole number of scroll ticks from a scroll accumulator,
 * modifying the accumulator's value as appropriate to remove that number of
 * ticks from it.
 */
static int32_t get_ticks_from_scroll_accum(double *accum_ptr);

/****************************************/
/* Wayland handling function prototypes */
/****************************************/

static void registry_handle_global(void * data, struct wl_registry * registry,
  uint32_t name, const char * interface, uint32_t version);
static void registry_handle_global_remove(void *data,
  struct wl_registry * registry, uint32_t name);
static void seat_handle_name(void *data, struct wl_seat *seat,
  const char *name);
static void seat_handle_capabilities(void *data, struct wl_seat *seat,
  uint32_t capabilities);
static void kb_handle_keymap(void *data, struct wl_keyboard *kb,
  uint32_t format, int32_t fd, uint32_t size);
static void kb_handle_enter(void *data, struct wl_keyboard *kb,
  uint32_t serial, struct wl_surface *surface, struct wl_array *keys);
static void kb_handle_leave(void *data, struct wl_keyboard *kb,
  uint32_t serial, struct wl_surface *surface);
static void kb_handle_key(void *data, struct wl_keyboard *kb, uint32_t serial,
  uint32_t time, uint32_t key, uint32_t state);
static void kb_handle_modifiers(void *data, struct wl_keyboard *kb,
  uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched,
  uint32_t mods_locked, uint32_t group);
static void kb_handle_repeat_info(void *data, struct wl_keyboard *kb,
  int32_t rate, int32_t delay);
static void wl_output_handle_geometry(void *data, struct wl_output *output,
  int32_t x, int32_t y, int32_t physical_width, int32_t physical_height,
  int32_t subpixel, const char *make, const char *model, int32_t transform);
static void wl_output_handle_mode(void *data, struct wl_output *output,
  uint32_t flags, int32_t width, int32_t height, int32_t refresh);
static void wl_output_info_done(void *data, struct wl_output *output);
static void wl_output_handle_scale(void *data, struct wl_output *output,
  int32_t factor);
static void wl_output_handle_name(void *data, struct wl_output *output,
  const char *name);
static void wl_output_handle_description(void *data, struct wl_output *output,
  const char *description);
static void xdg_output_handle_logical_position(void *data,
  struct zxdg_output_v1 *xdg_output, int32_t x, int32_t y);
static void xdg_output_handle_logical_size(void *data,
  struct zxdg_output_v1 *xdg_output, int32_t width, int32_t height);
static void xdg_output_info_done(void *data,
  struct zxdg_output_v1 *xdg_output);
static void xdg_output_handle_name(void *data,
  struct zxdg_output_v1 *xdg_output, const char *name);
static void xdg_output_handle_description(void *data,
  struct zxdg_output_v1 *xdg_output, const char *description);
static void layer_surface_configure(void *data,
  struct zwlr_layer_surface_v1 *layer_surface, uint32_t serial, uint32_t width,
  uint32_t height);
static void layer_surface_closed(void *data,
  struct zwlr_layer_surface_v1 *layer_surface);
static void wl_buffer_release(void *data, struct wl_buffer * buffer);

/**********************************/
/* High-level function prototypes */
/**********************************/

/*
 * Locates the Wayland socket using environment variables and opens it,
 * returning its file descriptor. Aborts the program on failure.
 */
static int open_wl_sock(void);

/*
 * Instructs the kernel to remove all capabilities from this process. Aborts
 * the program on failure.
 */
static void drop_capabilities(void);

/* Sets up objects and listeners for a newly attached display. */
static void init_new_display(ssize_t disp_idx);

/* Sends the width and height of the current pointer space to the parent. */
static void send_pointer_space_data(void);

/*
 * Checks if a display state sync can be done. If so, commits pending geometry
 * information, cleans up removed displays and their associated data, and
 * recalculates global space.
 */
static void display_sync_maybe(void);

/*
 * Checks screen continuity and calculates the current pointer space. Returns
 * true on success, false if there are gaps between displays.
 */
static bool recalc_global_space(void);

/*
 * Allocates a new drawable layer for the specified display, and registers it
 * with the compositor.
 */
static struct drawable_layer *allocate_drawable_layer(
  struct wl_output *output);

/*
 * Damages the specified region of the specified surface. Takes the same
 * arguments as wl_surface_damage_buffer, but clamps the x and y parameters to
 * 0 if they're below zero when passed in. This works around undesirable
 * behavior when passing negative x and y values to wl_surface_damage_buffer.
 */
static void damage_surface_enh(struct wl_surface *surface, int32_t x,
  int32_t y, int32_t width, int32_t height);

/*
 * Attempts to update the specified layer to display the virtual cursor at the
 * right location. May do nothing if the compositor has not yet acknowledged
 * previously sent frames, there is no pending changes that affect the
 * specified layer, or kloakwl hasn't yet negotiated an appropriate
 * configuration for the layer with the compositor.
 */
static void draw_frame(struct drawable_layer *layer);

/*
 * Attempts to flush the display queue. If an EAGAIN error is received, sets
 * up the ev_fds poll array to trigger on POLLOUT for the Wayland display's
 * fd, otherwise ensures that POLLOUT is unset on that fd.
 */
static inline void wl_display_flush_safe(struct wl_display *display);

/*
 * Attempts to dispatch pending Wayland events.
 */
static inline void wl_display_dispatch_pending_safe(
  struct wl_display *display);

/* Same as above, but for wl_display_roundtrip. */
static inline void wl_display_roundtrip_safe(struct wl_display *display);

/* Determines how long the core event loop's poll should sleep for. */
static int calc_poll_timeout(void);

/*
 * Adjusts a cursor position so that moving the cursor to it does not leave
 * pointer space, or land in or jump over a void in pointer space, while
 * leaving it as close as possible to the original target location.
 */
static void make_virtual_cursor_pos_sane(double prev_cursor_x_pos,
  double prev_cursor_y_pos, double *cursor_x_ptr, double *cursor_y_ptr);

/*
 * Finds an input packet that new input information should be merged into, by
 * searching backwards through the event queue, ignoring packet types in the
 * ignore list. Returns NULL if no candidate is found. ignore_packet_type_list
 * must be terminated by a 0.
 */
static struct input_packet *find_merge_target_packet(
  enum input_packet_type target_packet_type,
  const enum input_packet_type *ignore_packet_type_list);

/*
 * Updates the virtual cursor's position based on the global cursor_x and
 * cursor_y variables. If the cursor has moved, this will create a new mouse
 * movement event if there isn't one already queued, and update a queued mouse
 * movement event to reflect the current virtual cursor position otherwise.
 */
static struct input_packet *update_virtual_cursor(void);

/*
 * Updates the scroll accumulators. If enough scroll movement has accumulated
 * to scroll one or more ticks, this will create a new mouse scroll event if
 * there isn't an appropriate one already queued, and update a queued scroll
 * event to reflect the new scroll quantity otherwise.
 */
static struct input_packet *update_mouse_scroll(void);

/*
 * Receives a message from the parent and handles it as appropriate. Generally
 * this will queue an input event for future release. Returns true if a message
 * was processed, false if there were no more messages.
 */
static bool process_parent_message(void);

/*
 * Finds all queued input events whose timeouts have expired and sends them to
 * the compositor.
 */
static void release_scheduled_input_events(void);

/**************************************/
/* Initialization function prototypes */
/**************************************/

/* Handles configuration messages from the parent. */
static void applayer_config_init(void);

/* Opens and moves a file descriptor for the Wayland socket. */
static void applayer_wlsock_init(void);

/*
 * Isolates the process in a sandbox, allowing I/O access to only stdio,
 * previously opened urandom and Wayland fds, /dev/shm, and any fds provided by
 * the Wayland compositor.
 */
static void applayer_sandbox_init(void);

/* Initializes Wayland compositor state. */
static void applayer_wayland_init(void);

/* Sets up poll fds. */
static void applayer_poll_init(void);

/*********************/
/* Wayland callbacks */
/*********************/

static const struct wl_registry_listener registry_listener = {
  .global = registry_handle_global,
  .global_remove = registry_handle_global_remove,
};
static const struct wl_seat_listener seat_listener = {
  .name = seat_handle_name,
  .capabilities = seat_handle_capabilities,
};
static const struct wl_keyboard_listener kb_listener = {
  .keymap = kb_handle_keymap,
  .enter = kb_handle_enter,
  .leave = kb_handle_leave,
  .key = kb_handle_key,
  .modifiers = kb_handle_modifiers,
  .repeat_info = kb_handle_repeat_info,
};
static const struct wl_output_listener output_listener = {
  .geometry = wl_output_handle_geometry,
  .mode = wl_output_handle_mode,
  .done = wl_output_info_done,
  .scale = wl_output_handle_scale,
  .name = wl_output_handle_name,
  .description = wl_output_handle_description,
};
static const struct zxdg_output_v1_listener xdg_output_listener = {
  .logical_position = xdg_output_handle_logical_position,
  .logical_size = xdg_output_handle_logical_size,
  .done = xdg_output_info_done,
  .name = xdg_output_handle_name,
  .description = xdg_output_handle_description,
};
static const struct zwlr_layer_surface_v1_listener layer_surface_listener = {
  .configure = layer_surface_configure,
  .closed = layer_surface_closed,
};
static const struct wl_buffer_listener buffer_listener = {
  .release = wl_buffer_release,
};
