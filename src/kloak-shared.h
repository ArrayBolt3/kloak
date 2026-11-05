/*
 * SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Code shared between kloak and kloakwl.
 */

/****************/
/* Define guard */
/****************/

#if !defined(KLOAK) && !defined(KLOAKWL)
#error "Neither KLOAK nor KLOAKWL are defined."
#endif

/*******************/
/* Tunable defines */
/*******************/

/*
 * This should be comfortably larger than the largest possible message.
 */
#define PARSE_RING_LEN 4096

/***********/
/* Structs */
/***********/

/* A point in no particular space. */
struct coord {
  int32_t x;
  int32_t y;
};

/* As above, but with floating-point numbers instead of integers. */
struct double_coord {
  double x;
  double y;
};

/* A keyboard or mouse event. Which event depends on context. */
struct button_event {
  uint32_t button_code;
  bool is_pressed;
};

/******************/
/* Protocol enums */
/******************/

/*
 * Note: All protocol enums must start with an "unknown" message type with
 * value 0.
 */

/*
 * The type of packet being sent to the parent.
 *
 * CTP_PACKET_INIT_ACK: Child initialization succeeded. Sent by itself.
 * CTP_PACKET_WAYLAND_LOST: Wayland connection was lost. Sent by itself.
 * CTP_PACKET_POINTER_SPACE_DATA: Screen geometries have changed. Followed by
 *   two 32-bit signed integers greater than or equal to 0, indicating the
 *   width and height of space available for the pointer to move through,
 *   respectively.
 */
enum ctp_packet_type {
  CTP_PACKET_NONE = 0,
  CTP_PACKET_INIT_ACK,
  CTP_PACKET_WAYLAND_LOST,
  CTP_PACKET_POINTER_SPACE_DATA,
};

/*
 * The type of packet being sent to the child.
 *
 * PTC_PACKET_MAX_DELAY_CONFIG: Informs the child how long the maximum delay is
 *   between an input event arriving and that event being released. Followed by
 *   a single signed 32-bit integer that is greater than or equal to 0.
 * PTC_PACKET_CURSOR_COLOR_CONFIG: Informs the child what color of virtual
 *   cursor it should draw. Followed by a single 32-bit unsigned integer in
 *   0xAARRGGBB format.
 * PTC_PACKET_CURSOR_REL_EVENT: The cursor has moved relative to its previous
 *   position. Followed by a pair of double-precision floating point numbers
 *   representing the horizontal and vertical offsets, respectively.
 * PTC_PACKET_CURSOR_ABS_EVENT: The cursor has moved to exactly the specified
 *   position in compositor global space. Followed by a pair of
 *   double-precision floating point numbers representing the horizontal and
 *   vertical positions, respectively.
 * PTC_PACKET_SCROLL_EVENT: A scroll wheel has been rotated. Followed by a pair
 *   of double-precision floating point numbers representing the degrees
 *   rotated horizontally and vertically, respectively.
 * PTC_PACKET_CLICK_EVENT: The user has pressed or released a mouse button.
 *   Followed by a 32-bit unsigned integer specifying which button, and an
 *   8-bit unsigned integer that is either 0 if the button was released or 1 if
 *   it was pressed.
 * PTC_PACKET_KB_EVENT: The user has pressed or released a keyboard key.
 *   Followed by a 32-bit unsigned integer specifying which key, and an 8-bit
 *   unsigned integer that is either 0 if the button was released or 1 if it
 *   was pressed.
 */
enum ptc_packet_type {
  PTC_PACKET_NONE = 0,
  PTC_PACKET_MAX_DELAY_CONFIG,
  PTC_PACKET_CURSOR_COLOR_CONFIG,
  PTC_PACKET_CURSOR_REL_EVENT,
  PTC_PACKET_CURSOR_ABS_EVENT,
  PTC_PACKET_SCROLL_EVENT,
  PTC_PACKET_CLICK_EVENT,
  PTC_PACKET_KB_EVENT,
};

/*******************************/
/* Utility function prototypes */
/*******************************/

/*
 * Allocates a block of initialized memory, aborts the program if this fails.
 */
static void *safe_calloc(size_t nmemb, size_t size);

/* Duplicates a string. Kills the process if allocation fails. */
static char *safe_strdup(const char *s);

/* Opens a file, aborts the program if this fails. */
static int safe_open(const char *pathname, int flags);

/* Closes a file, aborts the program if this fails. */
static void safe_close(int fd);

/* Moves a file descriptor from one number to another. */
static void move_fd(int orig_fd, int new_fd);

/*
 * Creates a freshly allocated string from the printf template and arguments
 * provided.
 */
static char *vsgenprintf(int *out_len_ptr, const char *str, va_list ap);

/* Same as above but variadic. */
static char *sgenprintf(int *out_len_ptr, const char *str, ...);

/*
 * Writes the provided buffer to the given fd, ensuring all bytes are written
 * unless an error occurs.
 */
static ssize_t write_all(int fd, const void *buf, size_t count);

/*
 * Creates a memfd file of the specified size. Aborts the program if this
 * fails.
 */
static int create_memfd_file(ssize_t size);

/****************************************/
/* Message handling vars and prototypes */
/****************************************/

/*
 * NOTE: Communication between the parent and child is done over a pipe. Both
 * the parent and the child maintain ring buffers purely to make message
 * parsing more comfortable. A ring buffer in shared memory might be faster but
 * would come with security dangers as the child process is NOT trusted by the
 * parent.
 */

/*
 * File descriptors for peer data exchange. If we reimplement with shared
 * memory, these will go away.
 */
int send_write_fd = -1;
int recv_read_fd = -1;

/* Ring buffer block. */
char *parse_ring_block = NULL;

/*
 * Length of ring buffer (but note that due to using a magic buffer technique,
 * the parse ring block technically extends to twice the length of the buffer
 * itself
 */
ssize_t parse_ring_length = 0;

/* Location in the ring buffer to read from next. */
ssize_t parse_ring_read_loc = 0;

/* Length of data left in the ring buffer. */
ssize_t parse_ring_data_len = 0;

/* Prepares the parsing ring buffer. */
static void init_msg_ring(void);

/*
 * Sends a message to the peer. Terminates the program if the message cannot be
 * sent.
 */
#if defined(KLOAK)
static void send_msg_to_peer(enum ptc_packet_type msg_type,
  ssize_t arg_count, ...);
#elif defined(KLOAKWL)
static void send_msg_to_peer(enum ctp_packet_type msg_type,
  ssize_t arg_count, ...);
#endif

/*
 * Tries to get a message out of the ring buffer. Returns NULL if there isn't
 * a full message to pop.
 */
#if defined(KLOAK)
static void *pop_ring_buffer_msg(enum ctp_packet_type *out_type,
  ssize_t *out_obj_count);
#elif defined(KLOAKWL)
static void *pop_ring_buffer_msg(enum ptc_packet_type *out_type,
  ssize_t *out_obj_count);
#endif

/*
 * Reads new data from the peer into the ring buffer. Terminates the program if
 * something goes wrong in the process.
 */
static void read_peer_data_to_ring_buffer(void);

/*
 * Receives a message from the peer and validates it. Terminates the program if
 * the message is invalid for some reason. Returns NULL if there isn't a
 * message available yet.
 */
#if defined(KLOAK)
static void *get_msg_from_peer(enum ctp_packet_type *out_type,
  ssize_t *out_obj_count);
#elif defined(KLOAKWL)
static void *get_msg_from_peer(enum ptc_packet_type *out_type,
  ssize_t *out_obj_count);
#endif

/************************************/
/* Utility function implementations */
/************************************/

static void *safe_calloc(size_t nmemb, size_t size) {
  void *out_ptr = calloc(nmemb, size);
  if (out_ptr == NULL) {
    fprintf(stderr,
      "FATAL ERROR: Could not allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  return out_ptr;
}

static char *safe_strdup(const char *s) {
  char *out_ptr = strdup(s);
  if (out_ptr == NULL) {
    fprintf(stderr,
      "FATAL ERROR: Could not allocate memory: %s\n", strerror(errno));
    exit(1);
  }
  return out_ptr;
}

static int safe_open(const char *pathname, int flags) {
  int out_int = open(pathname, flags);
  if (out_int == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not open file '%s': %s\n", pathname,
      strerror(errno));
    exit(1);
  }
  return out_int;
}

static void safe_close(int fd) {
  int rslt = close(fd);
  if (rslt == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not close a file: %s\n", strerror(errno));
    exit(1);
  }
}

static void move_fd(int orig_fd, int new_fd) {
  if (orig_fd == new_fd) {
    return;
  }

  /* The caller is expected to manage new_fd. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
  if (dup2(orig_fd, new_fd) == -1) {
#pragma GCC diagnostic pop
    fprintf(stderr,
      "FATAL ERROR: Could not assign fd during move: %s\n",
      strerror(errno));
    exit(1);
  }

  if(close(orig_fd) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not close original fd during move: %s\n",
      strerror(errno));
    exit(1);
  }
}

/*
 * GCC issues a false-positive warning if the rslt_len check catches a -1
 * return from vsnprintf.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
static char *vsgenprintf(int *out_len_ptr, const char *str, va_list ap) {
  char *rslt = NULL;
  int rslt_len = 0;
  int rslt_writelen = 0;
  va_list extra_args;

  va_copy(extra_args, ap);
  rslt_len = vsnprintf(NULL, 0, str, extra_args);
  va_end(extra_args);
  if (rslt_len <= -1) {
    fprintf(stderr,
      "FATAL ERROR: String processing issue: %s\n", strerror(errno));
    exit(1);
  }
  rslt_len++; /* for the terminating null byte */
  rslt = safe_calloc(1, (size_t)(rslt_len));
  va_copy(extra_args, ap);
  rslt_writelen = vsnprintf(rslt, (size_t)(rslt_len), str, extra_args);
  va_end(extra_args);

  assert(rslt_writelen == rslt_len - 1);
  if (out_len_ptr != NULL) {
    *out_len_ptr = rslt_writelen;
  }
  return rslt;
}
#pragma GCC diagnostic pop

static char *sgenprintf(int *out_len_ptr, const char *str, ...) {
  va_list ap;
  char *out_str = NULL;

  va_start(ap, str);
  out_str = vsgenprintf(out_len_ptr, str, ap);
  va_end(ap);
  return out_str;
}

static ssize_t write_all(int fd, const void *buf, size_t count) {
  ssize_t total_write_len = 0;
  ssize_t current_write_len = 0;
  const char *char_buf = (const char *)(buf);

  assert(count < SSIZE_MAX);
  while (total_write_len != (ssize_t)(count)) {
    /* Note that pointer arithmetic on void * vars is allowed by GNU C. */
    current_write_len = write(fd, char_buf + total_write_len,
      (size_t)((ssize_t)(count) - total_write_len));
    if (current_write_len == -1) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    total_write_len += current_write_len;
  }
  return (ssize_t)(count);
}

static int create_memfd_file(ssize_t size) {
  int memfd = memfd_create("", MFD_CLOEXEC);
  if (memfd == -1) {
    fprintf(stderr, "FATAL ERROR: Could not allocate memfd file: %s\n",
      strerror(errno));
    exit(1);
  }
  if (ftruncate(memfd, size) == -1) {
    fprintf(stderr, "FATAL ERROR: Could not grow memfd file: %s\n",
      strerror(errno));
    exit(1);
  }
  return memfd;
}

/*********************************************/
/* Message handling function implementations */
/*********************************************/

/*
 * Uses magic ring buffer technique from
 * https://lo.calho.st/posts/black-magic-buffer/ to avoid continuity issues.
 */
static void init_msg_ring(void) {
  int page_size = getpagesize();
  int memfd = 0;

  parse_ring_length = page_size * (PARSE_RING_LEN / page_size);
  if (parse_ring_length < PARSE_RING_LEN) {
    parse_ring_length += page_size;
  }

  memfd = create_memfd_file(parse_ring_length);

  parse_ring_block = mmap(NULL, 2 * (size_t)(parse_ring_length), PROT_NONE,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (parse_ring_block == MAP_FAILED) {
    fprintf(stderr,
      "FATAL ERROR: Could not reserve memory mapping for parse ring: %s\n",
      strerror(errno));
    exit(1);
  }

  if (mmap(parse_ring_block, (size_t)(parse_ring_length),
    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, memfd, 0) == MAP_FAILED) {
    fprintf(stderr,
      "FATAL ERROR: Could not map parse ring to first address: %s\n",
      strerror(errno));
    exit(1);
  }

  if (mmap(parse_ring_block + parse_ring_length, (size_t)(parse_ring_length),
    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, memfd, 0) == MAP_FAILED) {
    fprintf(stderr,
      "FATAL ERROR: Could not map parse ring to second address: %s\n",
      strerror(errno));
    exit(1);
  }

  safe_close(memfd);
}

#if defined(KLOAK)
static void send_msg_to_peer(enum ptc_packet_type msg_type,
  ssize_t arg_count, ...) {
  int32_t *max_delay_ptr = NULL;
  uint32_t *cursor_color_ptr = NULL;
  struct double_coord *double_coord_ptr = NULL;
  struct button_event *button_event_ptr = NULL;
  uint8_t button_event_is_pressed_int = 0;
#elif defined(KLOAKWL)
static void send_msg_to_peer(enum ctp_packet_type msg_type,
  ssize_t arg_count, ...) {
  struct coord *coord_ptr = NULL;
#endif
  char *msg_buf = NULL;
  ssize_t msg_len = 0;
  ssize_t msg_pos = 0;
  va_list arg_list;

  va_start(arg_list, arg_count);

  switch(msg_type) {
#if defined(KLOAK)
  case PTC_PACKET_MAX_DELAY_CONFIG:
    assert(arg_count == 1);
    msg_len = (ssize_t)(sizeof(enum ptc_packet_type))
      + (ssize_t)(sizeof(int32_t));
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    max_delay_ptr = va_arg(arg_list, int32_t *);
    assert(*max_delay_ptr >= 0);

    memcpy(msg_buf, &msg_type, sizeof(enum ptc_packet_type));
    msg_pos += (ssize_t)(sizeof(enum ptc_packet_type));
    memcpy(msg_buf + msg_pos, max_delay_ptr, sizeof(int32_t));
    msg_pos += (ssize_t)(sizeof(int32_t));
    break;

  case PTC_PACKET_CURSOR_COLOR_CONFIG:
    assert(arg_count == 1);
    msg_len = (ssize_t)(sizeof(enum ptc_packet_type))
      + (ssize_t)(sizeof(uint32_t));
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    cursor_color_ptr = va_arg(arg_list, uint32_t *);

    memcpy(msg_buf, &msg_type, sizeof(enum ptc_packet_type));
    msg_pos += (ssize_t)(sizeof(enum ptc_packet_type));
    memcpy(msg_buf + msg_pos, cursor_color_ptr, sizeof(uint32_t));
    msg_pos += (ssize_t)(sizeof(uint32_t));
    break;

  case PTC_PACKET_CURSOR_REL_EVENT:
  case PTC_PACKET_CURSOR_ABS_EVENT:
  case PTC_PACKET_SCROLL_EVENT:
    assert(arg_count == 1);
    msg_len = (ssize_t)(sizeof(enum ptc_packet_type))
      + ((ssize_t)(sizeof(double)) * 2);
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    double_coord_ptr = va_arg(arg_list, struct double_coord *);

    memcpy(msg_buf, &msg_type, sizeof(enum ptc_packet_type));
    msg_pos += (ssize_t)(sizeof(enum ptc_packet_type));
    memcpy(msg_buf + msg_pos, &double_coord_ptr->x, sizeof(double));
    msg_pos += (ssize_t)(sizeof(double));
    memcpy(msg_buf + msg_pos, &double_coord_ptr->y, sizeof(double));
    msg_pos += (ssize_t)(sizeof(double));
    break;

  case PTC_PACKET_CLICK_EVENT:
  case PTC_PACKET_KB_EVENT:
    assert(arg_count == 1);
    msg_len = (ssize_t)(sizeof(enum ptc_packet_type))
      + (ssize_t)(sizeof(uint32_t)) + (ssize_t)(sizeof(uint8_t));
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    button_event_ptr = va_arg(arg_list, struct button_event *);

    memcpy(msg_buf, &msg_type, sizeof(enum ptc_packet_type));
    msg_pos += (ssize_t)(sizeof(enum ptc_packet_type));
    memcpy(msg_buf + msg_pos, &button_event_ptr->button_code,
      sizeof(uint32_t));
    msg_pos += (ssize_t)(sizeof(uint32_t));
    if (button_event_ptr->is_pressed) {
      button_event_is_pressed_int = 1;
    } else {
      button_event_is_pressed_int = 0;
    }
    memcpy(msg_buf + msg_pos, &button_event_is_pressed_int,
      sizeof(uint8_t));
    msg_pos += (ssize_t)(sizeof(uint8_t));
    break;
#elif defined(KLOAKWL)
  case CTP_PACKET_INIT_ACK:
  case CTP_PACKET_WAYLAND_LOST:
    assert(arg_count == 0);
    msg_len = (ssize_t)(sizeof(enum ctp_packet_type));
    msg_buf = safe_calloc(1, (size_t)(msg_len));
    memcpy(msg_buf, &msg_type, sizeof(enum ctp_packet_type));
    msg_pos += (ssize_t)(sizeof(enum ctp_packet_type));
    break;

  case CTP_PACKET_POINTER_SPACE_DATA:
    assert(arg_count == 1);

    msg_len = (ssize_t)(sizeof(enum ctp_packet_type))
      + (ssize_t)(sizeof(int32_t) * 2);
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    coord_ptr = va_arg(arg_list, struct coord *);

    memcpy(msg_buf, &msg_type, sizeof(enum ctp_packet_type));
    msg_pos += (ssize_t)(sizeof(enum ctp_packet_type));
    memcpy(msg_buf + msg_pos, &coord_ptr->x, sizeof(int32_t));
    msg_pos += (ssize_t)(sizeof(int32_t));
    memcpy(msg_buf + msg_pos, &coord_ptr->y, sizeof(int32_t));
    msg_pos += (ssize_t)(sizeof(int32_t));
    break;
#endif
  default:
    assert(false);
  }

  assert(msg_pos == msg_len);
  assert(msg_len > 0);
  va_end(arg_list);

  if (write_all(send_write_fd, msg_buf, (size_t)(msg_len)) == -1) {
    fprintf(stderr, "FATAL ERROR: Could not send message to peer: %s\n",
      strerror(errno));
    exit(1);
  }
  free(msg_buf);
}

#if defined(KLOAK)
static void *pop_ring_buffer_msg(enum ctp_packet_type *out_type,
  ssize_t *out_obj_count) {
#elif defined(KLOAKWL)
static void *pop_ring_buffer_msg(enum ptc_packet_type *out_type,
  ssize_t *out_obj_count) {
#endif
  void *out_ptr = NULL;
  ssize_t tmp_parse_ring_read_loc = parse_ring_read_loc;
  ssize_t tmp_parse_ring_data_len = parse_ring_data_len;
#if defined(KLOAK)
  enum ctp_packet_type packet_type;
  struct coord *coord_ptr = NULL;
#elif defined(KLOAKWL)
  enum ptc_packet_type packet_type;
  struct double_coord *double_coord_ptr = NULL;
  struct button_event *button_event_ptr = NULL;
  uint8_t is_pressed_int = 0;
#endif
  ssize_t obj_count = 0;

  *out_type = 0;
  if (out_obj_count != NULL) {
    *out_obj_count = 0;
  }
  if (tmp_parse_ring_data_len < (ssize_t)(sizeof(packet_type))) {
    return NULL;
  }

  memcpy(&packet_type, parse_ring_block + tmp_parse_ring_read_loc,
    sizeof(packet_type));
  tmp_parse_ring_read_loc += (ssize_t)(sizeof(packet_type));
  tmp_parse_ring_data_len -= (ssize_t)(sizeof(packet_type));

  switch (packet_type) {
#if defined(KLOAK)
  case CTP_PACKET_INIT_ACK:
  case CTP_PACKET_WAYLAND_LOST:
    break;

  case CTP_PACKET_POINTER_SPACE_DATA:
    if (tmp_parse_ring_data_len < (ssize_t)(sizeof(int32_t)) * 2) {
      return NULL;
    }
    obj_count = 1;
    out_ptr = safe_calloc(1, sizeof(struct coord));
    coord_ptr = (struct coord *)(out_ptr);
    memcpy(&coord_ptr->x, parse_ring_block + tmp_parse_ring_read_loc,
      sizeof(int32_t));
    assert(coord_ptr->x >= 0);
    tmp_parse_ring_read_loc += (ssize_t)(sizeof(int32_t));
    tmp_parse_ring_data_len -= (ssize_t)(sizeof(int32_t));
    memcpy(&coord_ptr->y, parse_ring_block + tmp_parse_ring_read_loc,
      sizeof(int32_t));
    assert(coord_ptr->y >= 0);
    tmp_parse_ring_read_loc += (ssize_t)(sizeof(int32_t));
    tmp_parse_ring_data_len -= (ssize_t)(sizeof(int32_t));
    break;

#elif defined(KLOAKWL)
  case PTC_PACKET_MAX_DELAY_CONFIG:
    if (tmp_parse_ring_data_len < (ssize_t)(sizeof(int32_t))) {
      return NULL;
    }
    obj_count = 1;
    out_ptr = safe_calloc(1, sizeof(int32_t));
    memcpy(out_ptr, parse_ring_block + tmp_parse_ring_read_loc,
      sizeof(int32_t));
    assert(*((int32_t *)(out_ptr)) >= 0);
    tmp_parse_ring_read_loc += (ssize_t)(sizeof(int32_t));
    tmp_parse_ring_data_len -= (ssize_t)(sizeof(int32_t));
    break;

  case PTC_PACKET_CURSOR_COLOR_CONFIG:
    if (tmp_parse_ring_data_len < (ssize_t)(sizeof(uint32_t))) {
      return NULL;
    }
    obj_count = 1;
    out_ptr = safe_calloc(1, sizeof(uint32_t));
    memcpy(out_ptr, parse_ring_block + tmp_parse_ring_read_loc,
      sizeof(uint32_t));
    tmp_parse_ring_read_loc += (ssize_t)(sizeof(uint32_t));
    tmp_parse_ring_data_len -= (ssize_t)(sizeof(uint32_t));
    break;

  case PTC_PACKET_CURSOR_REL_EVENT:
  case PTC_PACKET_CURSOR_ABS_EVENT:
  case PTC_PACKET_SCROLL_EVENT:
    if (tmp_parse_ring_data_len < (ssize_t)(sizeof(double)) * 2) {
      return NULL;
    }
    obj_count = 1;
    out_ptr = safe_calloc(1, sizeof(struct double_coord));
    double_coord_ptr = (struct double_coord *)(out_ptr);
    memcpy(&double_coord_ptr->x, parse_ring_block + tmp_parse_ring_read_loc,
      sizeof(double));
    tmp_parse_ring_read_loc += (ssize_t)(sizeof(double));
    tmp_parse_ring_data_len -= (ssize_t)(sizeof(double));
    memcpy(&double_coord_ptr->y, parse_ring_block + tmp_parse_ring_read_loc,
      sizeof(double));
    tmp_parse_ring_read_loc += (ssize_t)(sizeof(double));
    tmp_parse_ring_data_len -= (ssize_t)(sizeof(double));
    break;

  case PTC_PACKET_CLICK_EVENT:
  case PTC_PACKET_KB_EVENT:
    if (tmp_parse_ring_data_len
      < (ssize_t)(sizeof(uint32_t) + sizeof(uint8_t))) {
      return NULL;
    }
    obj_count = 1;
    out_ptr = safe_calloc(1, sizeof(struct button_event));
    button_event_ptr = (struct button_event *)(out_ptr);
    memcpy(&button_event_ptr->button_code,
      parse_ring_block + tmp_parse_ring_read_loc, sizeof(uint32_t));
    tmp_parse_ring_read_loc += (ssize_t)(sizeof(uint32_t));
    tmp_parse_ring_data_len -= (ssize_t)(sizeof(uint32_t));
    memcpy(&is_pressed_int, parse_ring_block + tmp_parse_ring_read_loc,
      sizeof(uint8_t));
    tmp_parse_ring_read_loc += (ssize_t)(sizeof(uint8_t));
    tmp_parse_ring_data_len -= (ssize_t)(sizeof(uint8_t));
    if (is_pressed_int == 0) {
      button_event_ptr->is_pressed = false;
    } else if (is_pressed_int == 1) {
      button_event_ptr->is_pressed = true;
    } else {
      assert(false);
    }
    break;

#endif
  default:
    assert(false);
  }

  *out_type = packet_type;
  if (out_obj_count != NULL) {
    *out_obj_count = obj_count;
  }
  if (tmp_parse_ring_read_loc < parse_ring_length) {
    parse_ring_read_loc = tmp_parse_ring_read_loc;
  } else {
    parse_ring_read_loc = tmp_parse_ring_read_loc - parse_ring_length;
  }
  parse_ring_data_len = tmp_parse_ring_data_len;
  return out_ptr;
}

static void read_peer_data_to_ring_buffer(void) {
  ssize_t capacity = parse_ring_length - parse_ring_data_len;
  ssize_t read_len = 0;
  int pipe_bytes_avail = 0;

  assert(capacity >= 0);
  if (capacity == 0) {
    return;
  }
  if (ioctl(recv_read_fd, FIONREAD, &pipe_bytes_avail) == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not check bytes in pipe: %s\n", strerror(errno));
    exit(1);
  }
  if (pipe_bytes_avail <= 0) {
    return;
  }

  do {
    read_len = read(recv_read_fd,
      parse_ring_block + parse_ring_read_loc + parse_ring_data_len,
      (size_t)(capacity));
  } while (read_len == -1 && errno == EINTR);
  if (read_len == -1) {
    fprintf(stderr,
      "FATAL ERROR: Could not read data from peer: %s\n",
      strerror(errno));
    exit(1);
  } else if (read_len == 0) {
    fprintf(stderr, "INFO: Peer disconnected, exiting.\n");
    exit(0);
  }

  parse_ring_data_len += read_len;
}

#if defined(KLOAK)
static void *get_msg_from_peer(enum ctp_packet_type *out_type,
  ssize_t *out_obj_count) {
#elif defined(KLOAKWL)
static void *get_msg_from_peer(enum ptc_packet_type *out_type,
  ssize_t *out_obj_count) {
#endif
  void *peer_msg_data = pop_ring_buffer_msg(out_type, out_obj_count);
  if (*out_type == 0) {
    read_peer_data_to_ring_buffer();
    peer_msg_data = pop_ring_buffer_msg(out_type, out_obj_count);
  }
  return peer_msg_data;
}
