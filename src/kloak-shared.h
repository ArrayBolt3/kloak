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

/*********************************/
/* Static defines, do not change */
/*********************************/

/*
 * NOTE: Any file descriptor numbers hardcoded here MUST be lower than
 * CHILD_FD_WLSOCK in kloakwl.h. See kloakwl.h for more information.
 */

/* File descriptor number for /dev/urandom. */
#define FD_URANDOM 3

/* Self-explanatory. */
#define ALPHABET_LEN 26
#define ASCII_UPPERCASE_START 65
#define ASCII_LOWERCASE_START 97

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
 * NOTE: 0 is a special value for all protocol enums meaning "no message". Enum
 * names are defined for 0, but do not use them, so that it remains clear that
 * this sentinel value is used across message types.
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
 *   position in pointer space. Followed by a pair of double-precision floating
 *   point numbers representing the horizontal and vertical positions,
 *   respectively.
 * PTC_PACKET_SCROLL_EVENT: A scrolling device has been used. Followed by a pair
 *   of double-precision floating point numbers representing the degrees
 *   rotated by a "scroll wheel" horizontally and vertically, respectively.
 *   Note that scrolling devices that do not involve wheels still have
 *   scrolling movements interpreted in terms of "degrees rotated".
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
 * Allocates a block of initialized memory. Aborts the program if this fails.
 */
static void *safe_calloc(size_t nmemb, size_t size);

/* Opens a file and returns the fd. Aborts the program if this fails. */
static int safe_open(const char *pathname, int flags);

/*
 * Closes a file. Aborts the program if this fails. fileinfo is used only as
 * part of an error message when aborting.
 */
static void safe_close(int fd, const char *fileinfo);

/*
 * Moves a file descriptor from one number to another. Aborts the program if
 * this fails.
 */
static void move_fd(int orig_fd, int new_fd);

/*
 * Opens /dev/urandom and moves its fd to FD_URANDOM. Must be called before
 * any other files are opened.
 */
static void init_fd_urandom(void);

/*
 * Reads the specified number of random bytes from /dev/urandom into the
 * specified buffer.
 */
static void read_random(char *buf, ssize_t len);

/*
 * Creates a freshly allocated string from the printf template and argument
 * list provided, and returns a pointer to the new string.
 */
static char *vsgenprintf(int *out_len_ptr, const char *str, va_list ap);

/* Same as above but variadic. */
static char *sgenprintf(int *out_len_ptr, const char *str, ...);

/*
 * Writes the provided buffer to the given fd, ensuring all bytes are written
 * unless an error occurs. Returns -1 on failure.
 */
static ssize_t write_all(int fd, const void *buf, size_t count);

/*
 * Fills in the specified number of bytes in the provided buffer with random
 * ASCII characters in the range [A-Za-z].
 */
static void fill_with_rand_alphabetic(char *buf, ssize_t len);

/*
 * Creates and unlinks a shm file of the specified size, and returns an fd to
 * the file. Aborts the program if this fails.
 */
static int allocate_shm(ssize_t size);

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

/* File descriptors for peer data exchange. */
int send_write_fd = -1;
int recv_read_fd = -1;

/* Ring buffer block. */
char *parse_ring_block = NULL;

/*
 * Length of ring buffer (but note that due to using a magic buffer technique,
 * the parse ring block technically extends to twice the length of the buffer
 * itself).
 */
ssize_t parse_ring_length = 0;

/* Location in the ring buffer to read from next. */
ssize_t parse_ring_read_loc = 0;

/* Length of data left in the ring buffer. */
ssize_t parse_ring_data_len = 0;

/* Prepares the parsing ring buffer. Aborts the program if this fails. */
static void init_msg_ring(void);

/* Sends a message to the peer. Aborts the program if this fails. */
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
 * Reads new data from the peer into the ring buffer. Aborts the program if
 * this fails.
 */
static void read_peer_data_to_ring_buffer(void);

/*
 * Receives a message from the peer and validates it. Aborts the program if a
 * received message is invalid. Returns NULL if no message is available.
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
    err(1, "FATAL ERROR: Could not allocate memory");
  }
  return out_ptr;
}

static int safe_open(const char *pathname, int flags) {
  int out_int = -1;

  assert(!(flags & O_CREAT));
  out_int = open(pathname, flags);
  if (out_int == -1) {
    err(1, "FATAL ERROR: Could not open file '%s'", pathname);
  }
  return out_int;
}

static void read_random(char *buf, ssize_t len) {
  ssize_t total_read_len = 0;
  ssize_t current_read_len = 0;

  assert(len >= 0);
  assert(buf != NULL);

  while (total_read_len != len) {
    current_read_len = read(FD_URANDOM, buf + (size_t)(total_read_len),
      (size_t)(len - total_read_len));
    if (current_read_len == -1) {
      err(1, "FATAL ERROR: Unable to read from /dev/urandom");
    }
    if (current_read_len == 0) {
      err(1, "FATAL ERROR: Unexpected EOF while reading from /dev/urandom");
    }
    total_read_len += current_read_len;
    assert(total_read_len <= len);
  }
}

static void safe_close(int fd, const char *fileinfo) {
  if (close(fd) == -1) {
    err(1, "FATAL ERROR: Could not close file '%s'", fileinfo);
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
    err(1, "FATAL ERROR: Could not assign fd during move");
  }

  safe_close(orig_fd, "Original fd during move");
}

/*
 * FD_URANDOM is intentionally hardcoded and never closed. See fd
 * definitions in kloakwl.h for more info.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
static void init_fd_urandom(void) {
  int randfd = safe_open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  move_fd(randfd, FD_URANDOM);
}
#pragma GCC diagnostic pop

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
    /* vsnprintf does not set errno. */
    errx(1, "FATAL ERROR: String processing issue");
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

  assert(count != 0);
  assert(count < SSIZE_MAX);
  while (total_write_len != (ssize_t)(count)) {
    current_write_len = write(fd, char_buf + total_write_len,
      (size_t)((ssize_t)(count) - total_write_len));
    if (current_write_len == -1) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    total_write_len += current_write_len;
    assert(total_write_len <= (ssize_t)(count));
  }
  return (ssize_t)(count);
}

static void fill_with_rand_alphabetic(char *buf, ssize_t len) {
  char randchar = 0;

  assert(len >= 0);
  assert(buf != NULL);

  for (ssize_t i = 0; i < len; i++) {
    /*
     * Getting a random number without modulo bias is hard and arguably not
     * that valuable here, but we do it anyway to reduce the risk of
     * collisions. The logic is:
     *
     * - read_random will give us a value between -128 and 127. We normalize
     *   this to a value between 0 and 127, which is 128 possible combinations.
     * - Simply taking this result modulo ALPHABET_LEN * 2 would bias the
     *   result in favor of lower values, as the high end of randchar will wrap
     *   around to the lower values but there aren't enough possible values at
     *   the high end of randchar to wrap all the way to ALPHABET_LEN * 2 - 1.
     * - To mitigate this, we calculate 128 mod (ALPHABET_LEN * 2) to get the
     *   number of lower values that will suffer modulo bias, then subtract
     *   that from 128 to get the number of values randchar can have that will
     *   not cause modulo bias.
     * - To avoid having to work with values larger than CHAR_MAX, we can get
     *   away with using 127 instead of 128 in these calculations. The modulo
     *   will be one smaller than it would be otherwise, but so will the number
     *   it is being subtracted from. If our range of values and range of
     *   desired values didn't suffer from modulo bias, this would result in a
     *   chunk of high acceptable values being mistakenly treated as
     *   unacceptable, but this is a mostly benign failure mode (only has a
     *   performance impact) even in the worst case, and since there is modulo
     *   bias being avoided here, that failure mode won't occur.
     * - If randchar contains a value greater than or equal to this boundary,
     *   we discard it. Otherwise, we use it.
     */
    do {
      read_random(&randchar, 1);
      if (randchar == CHAR_MIN) {
        randchar = 0;
      } else {
        randchar = (char)(abs(randchar));
      }
    } while (randchar >= (CHAR_MAX - (CHAR_MAX % (ALPHABET_LEN * 2))));

    randchar %= (ALPHABET_LEN * 2);
    if (randchar < ALPHABET_LEN) {
      randchar += ASCII_UPPERCASE_START;
    } else {
      randchar += (ASCII_LOWERCASE_START - ALPHABET_LEN);
    }
    buf[i] = randchar;
  }
}

static int allocate_shm(ssize_t size) {
  int32_t retries = 100;
  int fd = -1;
  /* 18 = length of string '/kloak-XXXXXXXXXX' + NULL terminator */
  char name[18];
  int snprintf_len = 0;
  int32_t ret = 0;

  assert(size >= 0);
  /*
   * This could seemingly be written more efficiently as
   * assert(size <= sizeof((off_t)(size))), but both gcc and clang are able
   * to completely optimize the more complex variant of this out on 64-bit
   * Intel-based platforms.
   */
  if (sizeof(off_t) == 4) {
    assert(size <= INT32_MAX);
  } else if (sizeof(off_t) == 8) {
    assert(size <= INT64_MAX);
  } else {
    errx(1, "FATAL ERROR: off_t is not 32-bit or 64-bit");
  }

  do {
    snprintf_len = snprintf(name, sizeof(name), "%s", "/kloak-XXXXXXXXXX");
    assert(snprintf_len > 0 && (size_t)(snprintf_len) == sizeof(name) - 1);
    /* 10 = length of 'XXXXXXXXXX', 11 = length + NULL terminator */
    fill_with_rand_alphabetic(name + sizeof(name) - 11, 10);
    --retries;
    fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd >= 0) {
      if (shm_unlink(name) == -1) {
        err(1, "FATAL ERROR: Could not shm_unlink '%s'", name);
      }
      break;
    }
  } while (retries > 0 && errno == EEXIST);

  if (fd == -1) {
    err(1, "FATAL ERROR: Could not create shared memory fd");
  }

  do {
    ret = ftruncate(fd, (off_t)(size));
  } while (ret < 0 && errno == EINTR);
  if (ret < 0) {
    safe_close(fd, name);
    err(1, "FATAL ERROR: Could not allocate shared memory block");
  }

  return fd;
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
  int shm_fd = -1;

  /*
   * parse_ring_length is a multiple of page_size, rounded up to the nearest
   * multiple.
   */
  parse_ring_length = (ssize_t)(page_size)
    * ((PARSE_RING_LEN + ((ssize_t)(page_size) - 1))
      / (ssize_t)(page_size));

  shm_fd = allocate_shm(parse_ring_length);

  parse_ring_block = mmap(NULL, 2 * (size_t)(parse_ring_length), PROT_NONE,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (parse_ring_block == MAP_FAILED) {
    err(1, "FATAL ERROR: Could not reserve memory mapping for parse ring");
  }

  /*
   * These two mappings MUST use MAP_SHARED. Even though they belong to the
   * same process, MAP_PRIVATE is copy-on-write, which would make the two
   * mappings effectively two distinct blocks of memory.
   */
  if (mmap(parse_ring_block, (size_t)(parse_ring_length),
    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, shm_fd, 0) == MAP_FAILED) {
    err(1, "FATAL ERROR: Could not map parse ring to first address");
  }

  if (mmap(parse_ring_block + parse_ring_length, (size_t)(parse_ring_length),
    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, shm_fd, 0) == MAP_FAILED) {
    err(1, "FATAL ERROR: Could not map parse ring to second address");
  }

  safe_close(shm_fd, "shm buffer fd");
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
    msg_len = (ssize_t)(sizeof(msg_type)) + (ssize_t)(sizeof(int32_t));
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    max_delay_ptr = va_arg(arg_list, int32_t *);
    assert(*max_delay_ptr >= 0);

    memcpy(msg_buf, &msg_type, sizeof(msg_type));
    msg_pos += (ssize_t)(sizeof(msg_type));
    memcpy(msg_buf + msg_pos, max_delay_ptr, sizeof(int32_t));
    msg_pos += (ssize_t)(sizeof(int32_t));
    break;

  case PTC_PACKET_CURSOR_COLOR_CONFIG:
    assert(arg_count == 1);
    msg_len = (ssize_t)(sizeof(msg_type)) + (ssize_t)(sizeof(uint32_t));
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    cursor_color_ptr = va_arg(arg_list, uint32_t *);

    memcpy(msg_buf, &msg_type, sizeof(msg_type));
    msg_pos += (ssize_t)(sizeof(msg_type));
    memcpy(msg_buf + msg_pos, cursor_color_ptr, sizeof(uint32_t));
    msg_pos += (ssize_t)(sizeof(uint32_t));
    break;

  case PTC_PACKET_CURSOR_REL_EVENT:
  case PTC_PACKET_CURSOR_ABS_EVENT:
  case PTC_PACKET_SCROLL_EVENT:
    assert(arg_count == 1);
    msg_len = (ssize_t)(sizeof(msg_type)) + ((ssize_t)(sizeof(double)) * 2);
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    double_coord_ptr = va_arg(arg_list, struct double_coord *);

    memcpy(msg_buf, &msg_type, sizeof(msg_type));
    msg_pos += (ssize_t)(sizeof(msg_type));
    memcpy(msg_buf + msg_pos, &double_coord_ptr->x, sizeof(double));
    msg_pos += (ssize_t)(sizeof(double));
    memcpy(msg_buf + msg_pos, &double_coord_ptr->y, sizeof(double));
    msg_pos += (ssize_t)(sizeof(double));
    break;

  case PTC_PACKET_CLICK_EVENT:
  case PTC_PACKET_KB_EVENT:
    assert(arg_count == 1);
    msg_len = (ssize_t)(sizeof(msg_type)) + (ssize_t)(sizeof(uint32_t))
      + (ssize_t)(sizeof(uint8_t));
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    button_event_ptr = va_arg(arg_list, struct button_event *);

    memcpy(msg_buf, &msg_type, sizeof(msg_type));
    msg_pos += (ssize_t)(sizeof(msg_type));
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

    msg_len = (ssize_t)(sizeof(msg_type));
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    memcpy(msg_buf, &msg_type, sizeof(msg_type));
    msg_pos += (ssize_t)(sizeof(msg_type));
    break;

  case CTP_PACKET_POINTER_SPACE_DATA:
    assert(arg_count == 1);

    msg_len = (ssize_t)(sizeof(msg_type)) + (ssize_t)(sizeof(int32_t) * 2);
    msg_buf = safe_calloc(1, (size_t)(msg_len));

    coord_ptr = va_arg(arg_list, struct coord *);
    assert(coord_ptr->x >= 0);
    assert(coord_ptr->y >= 0);

    memcpy(msg_buf, &msg_type, sizeof(msg_type));
    msg_pos += (ssize_t)(sizeof(msg_type));
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
    err(1, "FATAL ERROR: Could not send message to peer");
  }
  free(msg_buf);
}

#if defined(KLOAK)
static void *pop_ring_buffer_msg(enum ctp_packet_type *out_type,
  ssize_t *out_obj_count) {
  enum ctp_packet_type packet_type = 0;
  struct coord *coord_ptr = NULL;
#elif defined(KLOAKWL)
static void *pop_ring_buffer_msg(enum ptc_packet_type *out_type,
  ssize_t *out_obj_count) {
  enum ptc_packet_type packet_type = 0;
  struct double_coord *double_coord_ptr = NULL;
  struct button_event *button_event_ptr = NULL;
  uint8_t is_pressed_int = 0;
#endif
  ssize_t obj_count = 0;
  void *out_ptr = NULL;
  ssize_t tmp_parse_ring_read_loc = parse_ring_read_loc;
  ssize_t tmp_parse_ring_data_len = parse_ring_data_len;

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
    err(1, "FATAL ERROR: Could not check bytes in pipe");
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
    err(1, "FATAL ERROR: Could not read data from peer");
  } else if (read_len == 0) {
    errx(0, "INFO: Peer disconnected, exiting");
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
