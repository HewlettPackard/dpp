/*
 * cette -- the DPP configurette (mongoose turned into cette using
 *              some avahi calls for mDNS and DNS-SD)
 *
 * Copyright (c) Dan Harkins, 2014, 2021
 *
 *  Copyright holder grants permission for redistribution and use in source 
 *  and binary forms, with or without modification, provided that the 
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *
 *  This permission does not include a grant of any permissions, rights,
 *  or licenses by any employers or corporate entities affiliated with
 *  the copyright holder.
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under a different distribution
 * license (including the GNU public license).
 */
// Copyright (c) 2004-2011 Sergey Lyubka
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//static char s_listen_on[80];
//static const char *s_web_directory = ".";
int port = 8443;

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#ifdef HASAVAHI
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>
#endif  /* HASAVAHI */
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdint.h>
#include <inttypes.h>
#include <netdb.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#define DIRSEP   '/'
#define IS_DIRSEP_CHAR(c) ((c) == '/')
#ifndef O_BINARY
#define O_BINARY  0
#endif // O_BINARY
#define closesocket(a) close(a)
#define mg_fopen(x, y) fopen(x, y)
#define mg_mkdir(x, y) mkdir(x, y)
#define mg_remove(x) remove(x)
#define mg_rename(x, y) rename(x, y)
#define ERRNO errno
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
typedef int SOCKET;
#define WINCDECL

#include "cette.h"

#define MAX_OPTIONS 40
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

static int exit_flag;
static char server_name[40];        // Set by init_server_name()
static char config_file[PATH_MAX];  // Set by process_command_line_arguments()
static struct mg_context *ctx;      // Set by start_sest()

#if !defined(CONFIG_FILE)
#define CONFIG_FILE "cette.conf"
#endif /* !CONFIG_FILE */

#define PEM 1
#define DER 0

#define CETTE_VERSION "0.9"
#define PASSWORDS_FILE_NAME ".htpasswd"
#define CGI_ENVIRONMENT_SIZE 4096
#define MAX_CGI_ENVIR_VARS 64
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#if defined(DEBUG)
#define DEBUG_TRACE(x) do { \
  flockfile(stdout); \
  printf("*** %lu.%p.%s.%d: ", \
         (unsigned long) time(NULL), (void *) pthread_self(), \
         __func__, __LINE__); \
  printf x; \
  putchar('\n'); \
  fflush(stdout); \
  funlockfile(stdout); \
} while (0)
#else
#define DEBUG_TRACE(x)
#endif // DEBUG

// Darwin prior to 7.0 and Win32 do not have socklen_t
#ifdef NO_SOCKLEN_T
typedef int socklen_t;
#endif // NO_SOCKLEN_T

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

typedef void * (*mg_thread_func_t)(void *);

//static const char *http_500_error = "Internal Server Error";

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

// Unified socket address. For IPv6 support, add IPv6 address structure
// in the union u.
union usa {
  struct sockaddr sa;
  struct sockaddr_in sin;
#if defined(USE_IPV6)
  struct sockaddr_in6 sin6;
#endif
};

// Describes a string (chunk of memory).
struct vec {
  const char *ptr;
  size_t len;
};

// Structure used by mg_stat() function. Uses 64 bit file length.
struct mgstat {
  int is_directory;  // Directory marker
  int64_t size;      // File size
  time_t mtime;      // Modification time
};

// Describes listening socket, or socket which was accept()-ed by the master
// thread and queued for future handling by the worker thread.
struct socket {
  struct socket *next;  // Linkage
  SOCKET sock;          // Listening socket
  union usa lsa;        // Local socket address
  union usa rsa;        // Remote socket address
  int is_ssl;           // Is socket SSL-ed
};

enum {
  CGI_EXTENSIONS, CGI_ENVIRONMENT, PUT_DELETE_PASSWORDS_FILE, CGI_INTERPRETER,
  PROTECT_URI, AUTHENTICATION_DOMAIN, SSI_EXTENSIONS, ACCESS_LOG_FILE,
  SSL_CHAIN_FILE, ENABLE_DIRECTORY_LISTING, ERROR_LOG_FILE,
  GLOBAL_PASSWORDS_FILE, HASH_FCN, INDEX_FILES,
  ENABLE_KEEP_ALIVE, ACCESS_CONTROL_LIST, MAX_REQUEST_SIZE,
  EXTRA_MIME_TYPES, RANDOM_OID, CA_NAME, LISTENING_PORTS,
  DOCUMENT_ROOT, SSL_CERTIFICATE, NUM_THREADS, RUN_AS_USER, REWRITE, 
  TLSPWD, BSKEYFILE, NUM_OPTIONS
};

static const char *config_options[] = {
  "C", "cgi_pattern", "**.cgi$|**.pl$|**.php$",
  "E", "cgi_environment", NULL,
  "G", "put_delete_passwords_file", NULL,
  "I", "cgi_interpreter", NULL,
  "P", "protect_uri", NULL,
  "R", "authentication_domain", "lounge.org",
  "S", "ssi_pattern", "**.shtml$|**.shtm$",
  "a", "access_log_file", NULL,
  "c", "ssl_chain_file", NULL,
  "d", "enable_directory_listing", "yes",
  "e", "error_log_file", NULL,
  "g", "global_passwords_file", NULL,
  "h", "hash_function", NULL,
  "i", "index_files", "index.html,index.htm,index.cgi",
  "k", "enable_keep_alive", "yes",
  "l", "access_control_list", NULL,
  "M", "max_request_size", "16384",
  "m", "extra_mime_types", NULL,
  "o", "random_oid", NULL,
  "q", "CA name", "127.0.0.1",
  "p", "listening_ports", "8443",
  "r", "document_root",  ".",
  "s", "ssl_certificate", NULL,
  "t", "num_threads", "10",
  "u", "run_as_user", NULL,
  "w", "url_rewrite_patterns", NULL,
  "z", "support_tls_pwd", "no",
  "b", "bootstrap key file", NULL,
  NULL
};
#define ENTRIES_PER_CONFIG_OPTION 3

struct mg_context {
  volatile int stop_flag;       // Should we stop event loop
  SSL_CTX *ssl_ctx;             // SSL context
  char *config[NUM_OPTIONS];    // Mongoose configuration parameters
  mg_callback_t user_callback;  // User-defined callback function
  void *user_data;              // User-defined data

  struct socket *listening_sockets;

  volatile int num_threads;  // Number of threads
  pthread_mutex_t mutex;     // Protects (max|num)_threads
  pthread_cond_t  cond;      // Condvar for tracking workers terminations

  struct socket queue[20];   // Accepted sockets
  volatile int sq_head;      // Head of the socket queue
  volatile int sq_tail;      // Tail of the socket queue
  pthread_cond_t sq_full;    // Singaled when socket is produced
  pthread_cond_t sq_empty;   // Signaled when socket is consumed
};

struct mg_connection {
  struct mg_request_info request_info;
  struct mg_context *ctx;
  char username[80];          // username of client
  char cp[20];                // challengePassword
  int cp_len;                 // length of challengePassword
  SSL *ssl;                   // SSL descriptor
  struct socket client;       // Connected client
  time_t birth_time;          // Time connection was accepted
  int64_t num_bytes_sent;     // Total bytes sent to client
  int64_t content_len;        // Content-Length header value
  int64_t consumed_content;   // How many bytes of content is already read
  char *buf;                  // Buffer for received data
  char *path_info;            // PATH_INFO part of the URL
  int must_close;             // 1 if connection must be closed
  int buf_size;               // Buffer size
  int request_len;            // Size of the request + headers in a buffer
  int data_len;               // Total size of data in a buffer
};

static void close_connection(struct mg_connection *conn);

#ifdef HASAVAHI
static char *bsname = NULL;
static AvahiEntryGroup *bsgroup = NULL;
static AvahiSimplePoll *avpoll = NULL;
static void create_service(AvahiClient *c);

static void
bsgroup_callback (AvahiEntryGroup *g, AvahiEntryGroupState state, void *userdata)
{
    char *n;
    
    assert (g == bsgroup || bsgroup == NULL);
    bsgroup = g;
    switch (state) {
        case AVAHI_ENTRY_GROUP_UNCOMMITED:
            printf("service '%s' is uncommitted\n", bsname);
            break;
        case AVAHI_ENTRY_GROUP_REGISTERING:
            printf("registering service '%s'\n", bsname);
            break;
        case AVAHI_ENTRY_GROUP_ESTABLISHED:
            printf("our bootstrap service '%s' is established!\n", bsname);
            break;
        case AVAHI_ENTRY_GROUP_COLLISION:
            n = avahi_alternative_service_name(bsname);
            printf("service name '%s' collided, renaming to '%s'\n", bsname, n);
            avahi_free(bsname);
            bsname = n;
            create_service(avahi_entry_group_get_client(g));
            break;
        case AVAHI_ENTRY_GROUP_FAILURE:
            printf("group formation failed, bailing!\n");
            avahi_simple_poll_quit(avpoll);
            break;
        default:
            printf("some other weird avahi group message (%d)...\n", state);
            break;
    }
}

static void
create_service (AvahiClient *c)
{
    char *n;
    int ret;

    if (!bsgroup) {
        if ((bsgroup = avahi_entry_group_new(c, bsgroup_callback, NULL)) == NULL) {
            fprintf(stderr, "avahi_entry_group_new() failed: %s\n", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(avpoll);
            return;
        }
    }

    if (avahi_entry_group_is_empty(bsgroup)) {
        printf("adding bootstrap service '%s'\n", bsname);
        if ((ret = avahi_entry_group_add_service(bsgroup, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, 0, bsname,
                                                 "_dpp._tcp", NULL, NULL, port,
                                                 "txtversion=1", "organization=Industrial Lounge",
                                                 NULL)) < 0) {
            if (ret == AVAHI_ERR_COLLISION) {
                n = avahi_alternative_service_name(bsname);
                printf("got a name collision, renaming '%s' to '%s'\n", bsname, n);
                avahi_free(bsname);
                bsname = n;
                avahi_entry_group_reset(bsgroup);
                create_service(c);
                return;
            }
        }
        if ((ret = avahi_entry_group_add_service_subtype(bsgroup, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, 0, bsname,
                                                         "_dpp._tcp", NULL, "_bootstrapping._sub._dpp._tcp")) < 0) {
            if (ret == AVAHI_ERR_COLLISION) {
                n = avahi_alternative_service_name(bsname);
                printf("got a name collision, renaming '%s' to '%s'\n", bsname, n);
                avahi_free(bsname);
                bsname = n;
                avahi_entry_group_reset(bsgroup);
                create_service(c);
                return;
            }
        }
        if ((ret = avahi_entry_group_commit(bsgroup)) < 0) {
            fprintf(stderr, "failed to commit group: %s :-(\n", avahi_strerror(ret));
            avahi_simple_poll_quit(avpoll);
        }
    }

    return;
}

static void
bscallback (AvahiClient *c, AvahiClientState state, void *userdata)
{
    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            create_service(c);
            break;
        case AVAHI_CLIENT_FAILURE:
            printf("client failed: %s\n", avahi_strerror(avahi_client_errno(c)));
            avahi_simple_poll_quit(avpoll);
            break;
        case AVAHI_CLIENT_S_COLLISION:
            /* dropthru intentional */
        case AVAHI_CLIENT_S_REGISTERING:
            if (bsgroup) {
                avahi_entry_group_reset(bsgroup);
            }
            break;
        default:
            printf("other avahi state in bscallback: %d\n", state);
            break;
    }
}

static void
dump_callback (AvahiTimeout *e, void *userdata)
{
    AvahiClient *client = (AvahiClient *)userdata;
    if (avahi_client_get_state(client) == AVAHI_CLIENT_S_RUNNING) {
        printf("our client is running!\n");
    }
}

/*
 * since both avahi and mongoose have their own service context constructs
 * to handle events/timers and service put avahi in a thread and let it
 * do its own thing.
 */
void *
mdns_thread (void *userdata)
{
    AvahiClient *client = NULL;
    int err;
    struct timeval tv;

    if ((avpoll = avahi_simple_poll_new()) == NULL) {
        fprintf(stderr, "unable to create poll for mdns thread!\n");
        pthread_exit(NULL);
        return NULL;
    }
    bsname = avahi_strdup("DPP for Lounge");

    if ((client = avahi_client_new(avahi_simple_poll_get(avpoll), 0, bscallback,
                                   userdata, &err)) == NULL) {
        fprintf(stderr, "can't create avahi client for mdns thread!\n");
        pthread_exit(NULL);
        return NULL;
    }
    avahi_simple_poll_get(avpoll)->timeout_new(avahi_simple_poll_get(avpoll),
                                             avahi_elapse_time(&tv, 1000*10, 0),
                                             dump_callback,
                                             client);
    avahi_simple_poll_loop(avpoll);

    pthread_exit(NULL);
    return NULL;
}
#endif  /* AVAHI */

const char **mg_get_valid_option_names(void) {
  return config_options;
}

static void *call_user(struct mg_connection *conn, enum mg_event event) {
  conn->request_info.user_data = conn->ctx->user_data;
  return conn->ctx->user_callback == NULL ? NULL :
    conn->ctx->user_callback(event, conn, &conn->request_info);
}

static int get_option_index(const char *name) {
  int i;

  for (i = 0; config_options[i] != NULL; i += ENTRIES_PER_CONFIG_OPTION) {
    if (strcmp(config_options[i], name) == 0 ||
        strcmp(config_options[i + 1], name) == 0) {
      return i / ENTRIES_PER_CONFIG_OPTION;
    }
  }
  return -1;
}

const char *mg_get_option(const struct mg_context *ctx, const char *name) {
  int i;
  if ((i = get_option_index(name)) == -1) {
    return NULL;
  } else if (ctx->config[i] == NULL) {
    return "";
  } else {
    return ctx->config[i];
  }
}

static void sockaddr_to_string(char *buf, size_t len,
                                     const union usa *usa) {
  buf[0] = '\0';
#if defined(USE_IPV6)
  inet_ntop(usa->sa.sa_family, usa->sa.sa_family == AF_INET ?
            (void *) &usa->sin.sin_addr :
            (void *) &usa->sin6.sin6_addr, buf, len);
#else
  inet_ntop(usa->sa.sa_family, (void *) &usa->sin.sin_addr, buf, len);
#endif
}

// Print error message to the opened error log stream.
static void cry(struct mg_connection *conn, const char *fmt, ...) {
  char buf[BUFSIZ], src_addr[20];
  va_list ap;
  FILE *fp;
  time_t timestamp;

  va_start(ap, fmt);
  (void) vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  // Do not lock when getting the callback value, here and below.
  // I suppose this is fine, since function cannot disappear in the
  // same way string option can.
  conn->request_info.log_message = buf;
  if (call_user(conn, MG_EVENT_LOG) == NULL) {
    fp = conn->ctx->config[ERROR_LOG_FILE] == NULL ? NULL :
      mg_fopen(conn->ctx->config[ERROR_LOG_FILE], "a+");

    if (fp != NULL) {
      flockfile(fp);
      timestamp = time(NULL);

      sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);
      fprintf(fp, "[%010lu] [error] [client %s] ", (unsigned long) timestamp,
              src_addr);

      if (conn->request_info.request_method != NULL) {
        fprintf(fp, "%s %s: ", conn->request_info.request_method,
                conn->request_info.uri);
      }

      (void) fprintf(fp, "%s", buf);
      fputc('\n', fp);
      funlockfile(fp);
      if (fp != stderr) {
        fclose(fp);
      }
    }
  }
  conn->request_info.log_message = NULL;
}

// Return OpenSSL error message
static const char *ssl_error(void) {
  unsigned long err;
  err = ERR_get_error();
  return err == 0 ? "" : ERR_error_string(err, NULL);
}

// Return fake connection structure. Used for logging, if connection
// is not applicable at the moment of logging.
static struct mg_connection *fc(struct mg_context *ctx) {
  static struct mg_connection fake_connection;
  fake_connection.ctx = ctx;
  return &fake_connection;
}

const char *mg_version(void) {
  return CETTE_VERSION;
}

static void mg_strlcpy(register char *dst, register const char *src, size_t n) {
  for (; *src != '\0' && n > 1; n--) {
    *dst++ = *src++;
  }
  *dst = '\0';
}

static int lowercase(const char *s) {
  return tolower(* (const unsigned char *) s);
}

static int mg_strncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0)
    do {
      diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

static int mg_strcasecmp(const char *s1, const char *s2) {
  int diff;

  do {
    diff = lowercase(s1++) - lowercase(s2++);
  } while (diff == 0 && s1[-1] != '\0');

  return diff;
}

static char * mg_strndup(const char *ptr, size_t len) {
  char *p;

  if ((p = (char *) malloc(len + 1)) != NULL) {
    mg_strlcpy(p, ptr, len + 1);
  }

  return p;
}

static char * mg_strdup(const char *str) {
  return mg_strndup(str, strlen(str));
}

// Like snprintf(), but never returns negative value, or the value
// that is larger than a supplied buffer.
// Thanks to Adam Zeldis to pointing snprintf()-caused vulnerability
// in his audit report.
static int mg_vsnprintf(struct mg_connection *conn, char *buf, size_t buflen,
                        const char *fmt, va_list ap) {
  int n;

  if (buflen == 0)
    return 0;

  n = vsnprintf(buf, buflen, fmt, ap);

  if (n < 0) {
    cry(conn, "vsnprintf error");
    n = 0;
  } else if (n >= (int) buflen) {
    cry(conn, "truncating vsnprintf buffer: [%.*s]",
        n > 200 ? 200 : n, buf);
    n = (int) buflen - 1;
  }
  buf[n] = '\0';

  return n;
}

static int mg_snprintf(struct mg_connection *conn, char *buf, size_t buflen,
                       const char *fmt, ...) {
  va_list ap;
  int n;

  va_start(ap, fmt);
  n = mg_vsnprintf(conn, buf, buflen, fmt, ap);
  va_end(ap);

  return n;
}

// Skip the characters until one of the delimiters characters found.
// 0-terminate resulting word. Skip the delimiter and following whitespaces if any.
// Advance pointer to buffer to the next word. Return found 0-terminated word.
// Delimiters can be quoted with quotechar.
static char *skip_quoted(char **buf, const char *delimiters, const char *whitespace, char quotechar) {
  char *p, *begin_word, *end_word, *end_whitespace;

  begin_word = *buf;
  end_word = begin_word + strcspn(begin_word, delimiters);

  // Check for quotechar
  if (end_word > begin_word) {
    p = end_word - 1;
    while (*p == quotechar) {
      // If there is anything beyond end_word, copy it
      if (*end_word == '\0') {
        *p = '\0';
        break;
      } else {
        size_t end_off = strcspn(end_word + 1, delimiters);
        memmove (p, end_word, end_off + 1);
        p += end_off; // p must correspond to end_word - 1
        end_word += end_off + 1;
      }
    }
    for (p++; p < end_word; p++) {
      *p = '\0';
    }
  }

  if (*end_word == '\0') {
    *buf = end_word;
  } else {
    end_whitespace = end_word + 1 + strspn(end_word + 1, whitespace);

    for (p = end_word; p < end_whitespace; p++) {
      *p = '\0';
    }

    *buf = end_whitespace;
  }

  return begin_word;
}

// Simplified version of skip_quoted without quote char
// and whitespace == delimiters
static char *skip(char **buf, const char *delimiters) {
  return skip_quoted(buf, delimiters, delimiters, 0);
}


// Return HTTP header value, or NULL if not found.
static const char *get_header(const struct mg_request_info *ri,
                              const char *name) {
  int i;

  for (i = 0; i < ri->num_headers; i++)
    if (!mg_strcasecmp(name, ri->http_headers[i].name))
      return ri->http_headers[i].value;

  return NULL;
}

const char *mg_get_header(const struct mg_connection *conn, const char *name) {
  return get_header(&conn->request_info, name);
}

// A helper function for traversing comma separated list of values.
// It returns a list pointer shifted to the next value, of NULL if the end
// of the list found.
// Value is stored in val vector. If value has form "x=y", then eq_val
// vector is initialized to point to the "y" part, and val vector length
// is adjusted to point only to "x".
static const char *next_option(const char *list, struct vec *val,
                               struct vec *eq_val) {
  if (list == NULL || *list == '\0') {
    // End of the list
    list = NULL;
  } else {
    val->ptr = list;
    if ((list = strchr(val->ptr, ',')) != NULL) {
      // Comma found. Store length and shift the list ptr
      val->len = list - val->ptr;
      list++;
    } else {
      // This value is the last one
      list = val->ptr + strlen(val->ptr);
      val->len = list - val->ptr;
    }

    if (eq_val != NULL) {
      // Value has form "x=y", adjust pointers and lengths
      // so that val points to "x", and eq_val points to "y".
      eq_val->len = 0;
      eq_val->ptr = (const char *) memchr(val->ptr, '=', val->len);
      if (eq_val->ptr != NULL) {
        eq_val->ptr++;  // Skip over '=' character
        eq_val->len = val->ptr + val->len - eq_val->ptr;
        val->len = (eq_val->ptr - val->ptr) - 1;
      }
    }
  }

  return list;
}

static int match_prefix(const char *pattern, int pattern_len, const char *str) {
  const char *or_str;
  int i, j, len, res;

  if ((or_str = (const char *) memchr(pattern, '|', pattern_len)) != NULL) {
    res = match_prefix(pattern, or_str - pattern, str);
    return res > 0 ? res :
        match_prefix(or_str + 1, (pattern + pattern_len) - (or_str + 1), str);
  }

  i = j = 0;
  res = -1;
  for (; i < pattern_len; i++, j++) {
    if (pattern[i] == '?' && str[j] != '\0') {
      continue;
    } else if (pattern[i] == '$') {
      return str[j] == '\0' ? j : -1;
    } else if (pattern[i] == '*') {
      i++;
      if (pattern[i] == '*') {
        i++;
        len = strlen(str + j);
      } else {
        len = strcspn(str + j, "/");
      }
      if (i == pattern_len) {
        return j + len;
      }
      do {
        res = match_prefix(pattern + i, pattern_len - i, str + j + len);
      } while (res == -1 && len-- > 0);
      return res == -1 ? -1 : j + res + len;
    } else if (pattern[i] != str[j]) {
      return -1;
    }
  }
  return j;
}

// HTTP 1.1 assumes keep alive if "Connection:" header is not set
// This function must tolerate situations when connection info is not
// set up, for example if request parsing failed.
static int should_keep_alive(const struct mg_connection *conn) {
  const char *http_version = conn->request_info.http_version;
  const char *header = mg_get_header(conn, "Connection");
  return (!conn->must_close &&
//          !(conn->request_info.status_code != 401) &&
          !mg_strcasecmp(conn->ctx->config[ENABLE_KEEP_ALIVE], "yes") &&
          (header == NULL && http_version && !strcmp(http_version, "1.1"))) ||
          (header != NULL && !mg_strcasecmp(header, "keep-alive"));
}

static const char *suggest_connection_header(const struct mg_connection *conn) {
    int foo;

    foo = should_keep_alive(conn);
    if (foo) {
        return "keep-alive";
    } else {
        return "close";
    }
}

static void send_http_error(struct mg_connection *conn, int status,
                            const char *reason, const char *fmt, ...) {
  char buf[BUFSIZ];
  va_list ap;
  int len;

  conn->request_info.status_code = status;

  if (call_user(conn, MG_HTTP_ERROR) == NULL) {
    buf[0] = '\0';
    len = 0;

    // Errors 1xx, 204 and 304 MUST NOT send a body
    if (status > 199 && status != 204 && status != 304) {
      len = mg_snprintf(conn, buf, sizeof(buf), "Error %d: %s", status, reason);
      cry(conn, "%s", buf);
      buf[len++] = '\n';

      va_start(ap, fmt);
      len += mg_vsnprintf(conn, buf + len, sizeof(buf) - len, fmt, ap);
      va_end(ap);
    }
    DEBUG_TRACE(("[%s]", buf));

    mg_printf(conn, "HTTP/1.1 %d %s\r\n"
              "Content-Type: text/plain\r\n"
              "Content-Length: %d\r\n"
              "Connection: %s\r\n\r\n", status, reason, len,
              suggest_connection_header(conn));
    conn->num_bytes_sent += mg_printf(conn, "%s", buf);
  }
}

static int mg_stat(const char *path, struct mgstat *stp) {
  struct stat st;
  int ok;

  if (stat(path, &st) == 0) {
    ok = 0;
    stp->size = st.st_size;
    stp->mtime = st.st_mtime;
    stp->is_directory = S_ISDIR(st.st_mode);
  } else {
    ok = -1;
  }

  return ok;
}

static void set_close_on_exec(int fd) {
  (void) fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static int start_thread(struct mg_context *ctx, mg_thread_func_t func,
                        void *param) {
  pthread_t thread_id;
  pthread_attr_t attr;
  int retval;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  // TODO(lsm): figure out why mongoose dies on Linux if next line is enabled
  // (void) pthread_attr_setstacksize(&attr, sizeof(struct mg_connection) * 5);

  if ((retval = pthread_create(&thread_id, &attr, func, param)) != 0) {
    cry(fc(ctx), "%s: %s", __func__, strerror(retval));
  }

  return retval;
}

static int set_non_blocking_mode(SOCKET sock) {
  int flags;

  flags = fcntl(sock, F_GETFL, 0);
  (void) fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  return 0;
}

// Write data to the IO channel - opened file descriptor, socket or SSL
// descriptor. Return number of bytes written.
static int64_t push(FILE *fp, SOCKET sock, SSL *ssl, const char *buf,
                    int64_t len) {
  int64_t sent;
  int n, k;

  sent = 0;
  while (sent < len) {

    // How many bytes we send in this iteration
    k = len - sent > INT_MAX ? INT_MAX : (int) (len - sent);

    if (ssl != NULL) {
      n = SSL_write(ssl, buf + sent, k);
    } else if (fp != NULL) {
      n = fwrite(buf + sent, 1, (size_t) k, fp);
      if (ferror(fp))
        n = -1;
    } else {
      n = send(sock, buf + sent, (size_t) k, MSG_NOSIGNAL);
    }

    if (n < 0)
      break;

    sent += n;
  }

  return sent;
}

// Read from IO channel - opened file descriptor, socket, or SSL descriptor.
// Return number of bytes read.
static int pull(FILE *fp, SOCKET sock, SSL *ssl, char *buf, int len) {
  int nread;

  if (ssl != NULL) {
    nread = SSL_read(ssl, buf, len);
  } else if (fp != NULL) {
    // Use read() instead of fread(), because if we're reading from the CGI
    // pipe, fread() may block until IO buffer is filled up. We cannot afford
    // to block and must pass all read bytes immediately to the client.
    nread = read(fileno(fp), buf, (size_t) len);
    if (ferror(fp))
      nread = -1;
  } else {
    nread = recv(sock, buf, (size_t) len, 0);
  }

  return nread;
}

int mg_read(struct mg_connection *conn, void *buf, size_t len) {
  int n, buffered_len, nread;
  const char *buffered;

  assert((conn->content_len == -1 && conn->consumed_content == 0) ||
         conn->consumed_content <= conn->content_len);
  DEBUG_TRACE(("%p %zu %lld %lld", buf, len,
               conn->content_len, conn->consumed_content));
  nread = 0;
  if (conn->consumed_content < conn->content_len) {

    // Adjust number of bytes to read.
    int64_t to_read = conn->content_len - conn->consumed_content;
    if (to_read < (int64_t) len) {
      len = (int) to_read;
    }

    // How many bytes of data we have buffered in the request buffer?
    buffered = conn->buf + conn->request_len + conn->consumed_content;
    buffered_len = conn->data_len - conn->request_len;
    assert(buffered_len >= 0);

    // Return buffered data back if we haven't done that yet.
    if (conn->consumed_content < (int64_t) buffered_len) {
      buffered_len -= (int) conn->consumed_content;
      if (len < (size_t) buffered_len) {
        buffered_len = len;
      }
      memcpy(buf, buffered, (size_t)buffered_len);
      len -= buffered_len;
      buf = (char *) buf + buffered_len;
      conn->consumed_content += buffered_len;
      nread = buffered_len;
    }

    // We have returned all buffered data. Read new data from the remote socket.
    while (len > 0) {
      n = pull(NULL, conn->client.sock, conn->ssl, (char *) buf, (int) len);
      if (n <= 0) {
        break;
      }
      buf = (char *) buf + n;
      conn->consumed_content += n;
      nread += n;
      len -= n;
    }
  }
  return nread;
}

int mg_write(struct mg_connection *conn, const void *buf, size_t len) {
  return (int) push(NULL, conn->client.sock, conn->ssl, (const char *) buf,
                    (int64_t) len);
}

int mg_printf(struct mg_connection *conn, const char *fmt, ...) {
  char buf[BUFSIZ];
  int len;
  va_list ap;

  va_start(ap, fmt);
  len = mg_vsnprintf(conn, buf, sizeof(buf), fmt, ap);
  va_end(ap);

  return mg_write(conn, buf, (size_t)len);
}

// URL-decode input buffer into destination buffer.
// 0-terminate the destination buffer. Return the length of decoded data.
// form-url-encoded data differs from URI encoding in a way that it
// uses '+' as character for space, see RFC 1866 section 8.2.1
// http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
static size_t url_decode(const char *src, size_t src_len, char *dst,
                         size_t dst_len, int is_form_url_encoded) {
  size_t i, j;
  int a, b;
#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

  for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
    if (src[i] == '%' &&
        isxdigit(* (const unsigned char *) (src + i + 1)) &&
        isxdigit(* (const unsigned char *) (src + i + 2))) {
      a = tolower(* (const unsigned char *) (src + i + 1));
      b = tolower(* (const unsigned char *) (src + i + 2));
      dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
      i += 2;
    } else if (is_form_url_encoded && src[i] == '+') {
      dst[j] = ' ';
    } else {
      dst[j] = src[i];
    }
  }

  dst[j] = '\0'; // Null-terminate the destination

  return j;
}

// Scan given buffer and fetch the value of the given variable.
// It can be specified in query string, or in the POST data.
// Return NULL if the variable not found, or allocated 0-terminated value.
// It is caller's responsibility to free the returned value.
int mg_get_var(const char *buf, size_t buf_len, const char *name,
               char *dst, size_t dst_len) {
  const char *p, *e, *s;
  size_t name_len, len;

  name_len = strlen(name);
  e = buf + buf_len;
  len = -1;
  dst[0] = '\0';

  // buf is "var1=val1&var2=val2...". Find variable first
  for (p = buf; p != NULL && p + name_len < e; p++) {
    if ((p == buf || p[-1] == '&') && p[name_len] == '=' &&
        !mg_strncasecmp(name, p, name_len)) {

      // Point p to variable value
      p += name_len + 1;

      // Point s to the end of the value
      s = (const char *) memchr(p, '&', (size_t)(e - p));
      if (s == NULL) {
        s = e;
      }
      assert(s >= p);

      // Decode variable into destination buffer
      if ((size_t) (s - p) < dst_len) {
        len = url_decode(p, (size_t)(s - p), dst, dst_len, 1);
      }
      break;
    }
  }

  return len;
}

static int convert_uri_to_file_name(struct mg_connection *conn, char *buf,
                                    size_t buf_len, struct mgstat *st) {
  struct vec a, b;
  const char *rewrite, *uri = conn->request_info.uri;
  char *p;
  int match_len, stat_result;

  buf_len--;  // This is because memmove() for PATH_INFO may shift part
              // of the path one byte on the right.
  mg_snprintf(conn, buf, buf_len, "%s%s", conn->ctx->config[DOCUMENT_ROOT],
              uri);

  rewrite = conn->ctx->config[REWRITE];
  while ((rewrite = next_option(rewrite, &a, &b)) != NULL) {
    if ((match_len = match_prefix(a.ptr, a.len, uri)) > 0) {
      mg_snprintf(conn, buf, buf_len, "%.*s%s", b.len, b.ptr, uri + match_len);
      break;
    }
  }

  if ((stat_result = mg_stat(buf, st)) != 0) {
    // Support PATH_INFO for CGI scripts.
    for (p = buf + strlen(buf); p > buf + 1; p--) {
      if (*p == '/') {
        *p = '\0';
        if (match_prefix(conn->ctx->config[CGI_EXTENSIONS],
                         strlen(conn->ctx->config[CGI_EXTENSIONS]), buf) > 0 &&
            (stat_result = mg_stat(buf, st)) == 0) {
          conn->path_info = p + 1;
          memmove(p + 2, p + 1, strlen(p + 1));
          p[1] = '/';
          break;
        } else {
          *p = '/';
          stat_result = -1;
        }
      }
    }
  }

  return stat_result;
}

static int sslize(struct mg_connection *conn, int (*func)(SSL *)) {
    if (((conn->ssl = SSL_new(conn->ctx->ssl_ctx)) != NULL) &&
        (SSL_set_fd(conn->ssl, conn->client.sock) == 1)) {
        SSL_set_verify(conn->ssl, SSL_VERIFY_PEER, NULL);
        SSL_CTX_load_verify_locations(conn->ctx->ssl_ctx, "./cacert.pem", NULL);
        printf("loading cacert.pem for SSL verification\n");
        return func(conn->ssl) == 1;
    } else {
        return 0;
    }
}

// Check whether full request is buffered. Return:
//   -1  if request is malformed
//    0  if request is not yet fully buffered
//   >0  actual request length, including last \r\n\r\n
static int get_request_len(const char *buf, int buflen) {
  const char *s, *e;
  int len = 0;

  DEBUG_TRACE(("buf: %p, len: %d", buf, buflen));
  for (s = buf, e = s + buflen - 1; len <= 0 && s < e; s++)
    // Control characters are not allowed but >=128 is.
    if (!isprint(* (const unsigned char *) s) && *s != '\r' &&
        *s != '\n' && * (const unsigned char *) s < 128) {
      len = -1;
    } else if (s[0] == '\n' && s[1] == '\n') {
      len = (int) (s - buf) + 2;
    } else if (s[0] == '\n' && &s[1] < e &&
        s[1] == '\r' && s[2] == '\n') {
      len = (int) (s - buf) + 3;
    }

  return len;
}

// Protect against directory disclosure attack by removing '..',
// excessive '/' and '\' characters
static void remove_double_dots_and_double_slashes(char *s) {
  char *p = s;

  while (*s != '\0') {
    *p++ = *s++;
    if (IS_DIRSEP_CHAR(s[-1])) {
      // Skip all following slashes and backslashes
      while (IS_DIRSEP_CHAR(s[0])) {
        s++;
      }

      // Skip all double-dots
      while (*s == '.' && s[1] == '.') {
        s += 2;
      }
    }
  }
  *p = '\0';
}

static const struct {
  const char *extension;
  size_t ext_len;
  const char *mime_type;
  size_t mime_type_len;
} builtin_mime_types[] = {
  {".dpp", 4, "application/dpp", 15},
  {".html", 5, "text/html",   9},
  {".htm", 4, "text/html",   9},
  {".shtm", 5, "text/html",   9},
  {".shtml", 6, "text/html",   9},
  {".css", 4, "text/css",   8},
  {".js",  3, "application/x-javascript", 24},
  {".ico", 4, "image/x-icon",   12},
  {".gif", 4, "image/gif",   9},
  {".jpg", 4, "image/jpeg",   10},
  {".jpeg", 5, "image/jpeg",   10},
  {".png", 4, "image/png",   9},
  {".svg", 4, "image/svg+xml",  13},
  {".torrent", 8, "application/x-bittorrent", 24},
  {".wav", 4, "audio/x-wav",   11},
  {".mp3", 4, "audio/x-mp3",   11},
  {".mid", 4, "audio/mid",   9},
  {".m3u", 4, "audio/x-mpegurl",  15},
  {".ram", 4, "audio/x-pn-realaudio",  20},
  {".xml", 4, "text/xml",   8},
  {".xslt", 5, "application/xml",  15},
  {".ra",  3, "audio/x-pn-realaudio",  20},
  {".doc", 4, "application/msword",  19},
  {".exe", 4, "application/octet-stream", 24},
  {".zip", 4, "application/x-zip-compressed", 28},
  {".xls", 4, "application/excel",  17},
  {".tgz", 4, "application/x-tar-gz",  20},
  {".tar", 4, "application/x-tar",  17},
  {".gz",  3, "application/x-gunzip",  20},
  {".arj", 4, "application/x-arj-compressed", 28},
  {".rar", 4, "application/x-arj-compressed", 28},
  {".rtf", 4, "application/rtf",  15},
  {".pdf", 4, "application/pdf",  15},
  {".swf", 4, "application/x-shockwave-flash",29},
  {".mpg", 4, "video/mpeg",   10},
  {".mpeg", 5, "video/mpeg",   10},
  {".mp4", 4, "video/mp4", 9},
  {".m4v", 4, "video/x-m4v", 11},
  {".asf", 4, "video/x-ms-asf",  14},
  {".avi", 4, "video/x-msvideo",  15},
  {".bmp", 4, "image/bmp",   9},
  {".p7", 3, "application/pkcs7-mime", 23},
  {".cattr", 6,"application/csrattrs", 21},
  {NULL,  0, NULL,    0}
};

// Look at the "path" extension and figure what mime type it has.
// Store mime type in the vector.
static void get_mime_type(struct mg_context *ctx, const char *path,
                          struct vec *vec) {
  struct vec ext_vec, mime_vec;
  const char *list, *ext;
  size_t i, path_len;

  path_len = strlen(path);

  // Scan user-defined mime types first, in case user wants to
  // override default mime types.
  list = ctx->config[EXTRA_MIME_TYPES];
  while ((list = next_option(list, &ext_vec, &mime_vec)) != NULL) {
    // ext now points to the path suffix
    ext = path + path_len - ext_vec.len;
    if (mg_strncasecmp(ext, ext_vec.ptr, ext_vec.len) == 0) {
      *vec = mime_vec;
      return;
    }
  }

  // Now scan built-in mime types
  for (i = 0; builtin_mime_types[i].extension != NULL; i++) {
    ext = path + (path_len - builtin_mime_types[i].ext_len);
    if (path_len > builtin_mime_types[i].ext_len &&
        mg_strcasecmp(ext, builtin_mime_types[i].extension) == 0) {
      vec->ptr = builtin_mime_types[i].mime_type;
      vec->len = builtin_mime_types[i].mime_type_len;
      return;
    }
  }

  // Nothing found. Fall back to "text/plain"
  vec->ptr = "text/plain";
  vec->len = 10;
}

#ifndef HAVE_MD5
typedef struct MD5Context {
  uint32_t buf[4];
  uint32_t bits[2];
  unsigned char in[64];
} MD5_CTX;

#if defined(__BYTE_ORDER) && (__BYTE_ORDER == 1234)
#define byteReverse(buf, len) // Do nothing
#else
static void byteReverse(unsigned char *buf, unsigned longs) {
  uint32_t t;
  do {
    t = (uint32_t) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
      ((unsigned) buf[1] << 8 | buf[0]);
    *(uint32_t *) buf = t;
    buf += 4;
  } while (--longs);
}
#endif

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, data, s) \
  ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

// Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
// initialization constants.
static void MD5Init(MD5_CTX *ctx) {
  ctx->buf[0] = 0x67452301;
  ctx->buf[1] = 0xefcdab89;
  ctx->buf[2] = 0x98badcfe;
  ctx->buf[3] = 0x10325476;

  ctx->bits[0] = 0;
  ctx->bits[1] = 0;
}

static void MD5Transform(uint32_t buf[4], uint32_t const in[16]) {
  register uint32_t a, b, c, d;

  a = buf[0];
  b = buf[1];
  c = buf[2];
  d = buf[3];

  MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
  MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
  MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
  MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
  MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
  MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
  MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
  MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
  MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
  MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
  MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
  MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
  MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
  MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
  MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
  MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

  MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
  MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
  MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
  MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
  MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
  MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
  MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
  MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
  MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
  MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
  MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
  MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
  MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
  MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
  MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
  MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

  MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
  MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
  MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
  MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
  MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
  MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
  MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
  MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
  MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
  MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
  MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
  MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
  MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
  MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
  MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
  MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

  MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
  MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
  MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
  MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
  MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
  MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
  MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
  MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
  MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
  MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
  MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
  MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
  MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
  MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
  MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
  MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}

static void MD5Update(MD5_CTX *ctx, unsigned char const *buf, unsigned len) {
  uint32_t t;

  t = ctx->bits[0];
  if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
    ctx->bits[1]++;
  ctx->bits[1] += len >> 29;

  t = (t >> 3) & 0x3f;

  if (t) {
    unsigned char *p = (unsigned char *) ctx->in + t;

    t = 64 - t;
    if (len < t) {
      memcpy(p, buf, len);
      return;
    }
    memcpy(p, buf, t);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    buf += t;
    len -= t;
  }

  while (len >= 64) {
    memcpy(ctx->in, buf, 64);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    buf += 64;
    len -= 64;
  }

  memcpy(ctx->in, buf, len);
}

static void MD5Final(unsigned char digest[16], MD5_CTX *ctx) {
  unsigned count;
  unsigned char *p;

  count = (ctx->bits[0] >> 3) & 0x3F;

  p = ctx->in + count;
  *p++ = 0x80;
  count = 64 - 1 - count;
  if (count < 8) {
    memset(p, 0, count);
    byteReverse(ctx->in, 16);
    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    memset(ctx->in, 0, 56);
  } else {
    memset(p, 0, count - 8);
  }
  byteReverse(ctx->in, 14);

  ((uint32_t *) ctx->in)[14] = ctx->bits[0];
  ((uint32_t *) ctx->in)[15] = ctx->bits[1];

  MD5Transform(ctx->buf, (uint32_t *) ctx->in);
  byteReverse((unsigned char *) ctx->buf, 4);
  memcpy(digest, ctx->buf, 16);
  memset((char *) ctx, 0, sizeof(*ctx));
}
#endif // !HAVE_MD5

// Stringify binary data. Output buffer must be twice as big as input,
// because each byte takes 2 bytes in string representation
static void bin2str(char *to, const unsigned char *p, size_t len) {
  static const char *hex = "0123456789abcdef";

  for (; len--; p++) {
    *to++ = hex[p[0] >> 4];
    *to++ = hex[p[0] & 0x0f];
  }
  *to = '\0';
}

// Return stringified MD5 hash for list of vectors. Buffer must be 33 bytes.
void mg_md5(char *buf, ...) {
  unsigned char hash[16];
  const char *p;
  va_list ap;
  MD5_CTX ctx;

  MD5Init(&ctx);

  va_start(ap, buf);
  while ((p = va_arg(ap, const char *)) != NULL) {
    MD5Update(&ctx, (const unsigned char *) p, (unsigned) strlen(p));
  }
  va_end(ap);

  MD5Final(hash, &ctx);
  bin2str(buf, hash, sizeof(hash));
}

// Check the user's password, return 1 if OK
static int check_password(const char *method, const char *ha1, const char *uri,
                          const char *nonce, const char *nc, const char *cnonce,
                          const char *qop, const char *response) {
  char ha2[32 + 1], expected_response[32 + 1];

  // Some of the parameters may be NULL
  if (method == NULL || nonce == NULL || nc == NULL || cnonce == NULL ||
      qop == NULL || response == NULL) {
    return 0;
  }

  // NOTE(lsm): due to a bug in MSIE, we do not compare the URI
  // TODO(lsm): check for authentication timeout
  if (// strcmp(dig->uri, c->ouri) != 0 ||
      strlen(response) != 32
      // || now - strtoul(dig->nonce, NULL, 10) > 3600
      ) {
    return 0;
  }

  mg_md5(ha2, method, ":", uri, NULL);
  mg_md5(expected_response, ha1, ":", nonce, ":", nc,
      ":", cnonce, ":", qop, ":", ha2, NULL);

  return mg_strcasecmp(response, expected_response) == 0;
}

// Use the global passwords file, if specified by auth_gpass option,
// or search for .htpasswd in the requested directory.
static FILE *open_auth_file(struct mg_connection *conn, const char *path) {
  struct mg_context *ctx = conn->ctx;
  char name[PATH_MAX];
  const char *p, *e;
  struct mgstat st;
  FILE *fp;

  if (ctx->config[GLOBAL_PASSWORDS_FILE] != NULL) {
    // Use global passwords file
    fp =  mg_fopen(ctx->config[GLOBAL_PASSWORDS_FILE], "r");
    if (fp == NULL)
      cry(fc(ctx), "fopen(%s): %s",
          ctx->config[GLOBAL_PASSWORDS_FILE], strerror(ERRNO));
  } else if (!mg_stat(path, &st) && st.is_directory) {
    (void) mg_snprintf(conn, name, sizeof(name), "%s%c%s",
        path, DIRSEP, PASSWORDS_FILE_NAME);
    fp = mg_fopen(name, "r");
  } else {
     // Try to find .htpasswd in requested directory.
    for (p = path, e = p + strlen(p) - 1; e > p; e--)
      if (IS_DIRSEP_CHAR(*e))
        break;
    (void) mg_snprintf(conn, name, sizeof(name), "%.*s%c%s",
        (int) (e - p), p, DIRSEP, PASSWORDS_FILE_NAME);
    fp = mg_fopen(name, "r");
  }

  return fp;
}

// Parsed Authorization header
struct ah {
  char *user, *uri, *cnonce, *response, *qop, *nc, *nonce;
};

static int parse_auth_header(struct mg_connection *conn, char *buf,
                             size_t buf_size, struct ah *ah) {
  char *name, *value, *s;
  const char *auth_header;

  if ((auth_header = mg_get_header(conn, "Authorization")) == NULL ||
      mg_strncasecmp(auth_header, "Digest ", 7) != 0) {
    return 0;
  }

  // Make modifiable copy of the auth header
  (void) mg_strlcpy(buf, auth_header + 7, buf_size);

  s = buf;
  (void) memset(ah, 0, sizeof(*ah));

  // Parse authorization header
  for (;;) {
    // Gobble initial spaces
    while (isspace(* (unsigned char *) s)) {
      s++;
    }
    name = skip_quoted(&s, "=", " ", 0);
    // Value is either quote-delimited, or ends at first comma or space.
    if (s[0] == '\"') {
      s++;
      value = skip_quoted(&s, "\"", " ", '\\');
      if (s[0] == ',') {
        s++;
      }
    } else {
      value = skip_quoted(&s, ", ", " ", 0);  // IE uses commas, FF uses spaces
    }
    if (*name == '\0') {
      break;
    }

    if (!strcmp(name, "username")) {
      ah->user = value;
    } else if (!strcmp(name, "cnonce")) {
      ah->cnonce = value;
    } else if (!strcmp(name, "response")) {
      ah->response = value;
    } else if (!strcmp(name, "uri")) {
      ah->uri = value;
    } else if (!strcmp(name, "qop")) {
      ah->qop = value;
    } else if (!strcmp(name, "nc")) {
      ah->nc = value;
    } else if (!strcmp(name, "nonce")) {
      ah->nonce = value;
    }
  }

  // CGI needs it as REMOTE_USER
  if (ah->user != NULL) {
    conn->request_info.remote_user = mg_strdup(ah->user);
  } else {
    return 0;
  }

  return 1;
}

// Authorize against the opened passwords file. Return 1 if authorized.
static int authorize(struct mg_connection *conn, FILE *fp) {
  struct ah ah;
  char line[256], f_user[256], ha1[256], f_domain[256], buf[BUFSIZ];

  if (!parse_auth_header(conn, buf, sizeof(buf), &ah)) {
    return 0;
  }

  // Loop over passwords file
  while (fgets(line, sizeof(line), fp) != NULL) {
    if (sscanf(line, "%[^:]:%[^:]:%s", f_user, f_domain, ha1) != 3) {
      continue;
    }

    if (!strcmp(ah.user, f_user) &&
        !strcmp(conn->ctx->config[AUTHENTICATION_DOMAIN], f_domain))
      return check_password(
            conn->request_info.request_method,
            ha1, ah.uri, ah.nonce, ah.nc, ah.cnonce, ah.qop,
            ah.response);
  }

  return 0;
}

// Return 1 if request is authorised, 0 otherwise.
static int check_authorization(struct mg_connection *conn, const char *path) {
  FILE *fp;
  char fname[PATH_MAX];
  struct vec uri_vec, filename_vec;
  const char *list;
  int authorized;
  X509 *peercert;

  fp = NULL;
  authorized = 1;       // for testing, default to 1

  /*
   * cette-related access requires TLS
   */
  printf("checking authorization, path = %s\n", path);
  if ((strstr(path, "dummy") == 0) ||
      (strstr(path, "bskey") == 0)) {
      if (conn->client.is_ssl == 0) {
          return 0;
      }
      printf("it's an SSL request!\n");
      /*
       * let an unauthenticated client get /cacerts but not any
       * of the other EST-related URLs. 
       */
      if (strstr(path, "dummy") != NULL) {
          return 1;
      }
#ifdef OPENSSL_HAS_TLS_PWD
      if (SSL_is_tls_pwd_cipher(conn->ssl)) {
          /*
           * TLS-pwd authentication, record the username
           */
          conn->request_info.remote_user = mg_strdup(conn->ssl->ctx->pwd_ctx.login);
          return 1;
      }
#endif  /* OPENSSL_HAS_TLS_PWD */
      if ((peercert = SSL_get_peer_certificate(conn->ssl)) != NULL) {
          return 1;
      }
      printf("we didn't get the peer certificate though!\n");
  }

  list = conn->ctx->config[PROTECT_URI];
  while ((list = next_option(list, &uri_vec, &filename_vec)) != NULL) {
    if (!memcmp(conn->request_info.uri, uri_vec.ptr, uri_vec.len)) {
      (void) mg_snprintf(conn, fname, sizeof(fname), "%.*s",
          filename_vec.len, filename_vec.ptr);
      printf("checking protected uri...%s\n", fname);
      if ((fp = mg_fopen(fname, "r")) == NULL) {
        cry(conn, "%s: cannot open %s: %s", __func__, fname, strerror(errno));
      }
      break;
    }
  }

  if (fp == NULL) {
    fp = open_auth_file(conn, path);
  }
  printf("fp is %s\n", fp == NULL ? "NULL" : "not NULL");
  if (fp != NULL) {
    authorized = authorize(conn, fp);
    (void) fclose(fp);
  }
  printf("connection is %s\n", authorized ? "authorized" : "not authorized");
  return authorized;
}

static void send_authorization_request(struct mg_connection *conn) {
  conn->request_info.status_code = 401;
  (void) mg_printf(conn,
      "HTTP/1.1 401 Unauthorized\r\n"
      "Content-Length: 0\r\n"
      "WWW-Authenticate: Digest qop=\"auth\", "
      "realm=\"%s\", nonce=\"%lu\"\r\n\r\n",
      conn->ctx->config[AUTHENTICATION_DOMAIN],
      (unsigned long) time(NULL));
}

int mg_modify_passwords_file(const char *fname, const char *domain,
                             const char *user, const char *pass) {
  int found;
  char line[512], u[512], d[512], ha1[33], tmp[PATH_MAX];
  FILE *fp, *fp2;

  found = 0;
  fp = fp2 = NULL;

  // Regard empty password as no password - remove user record.
  if (pass != NULL && pass[0] == '\0') {
    pass = NULL;
  }

  (void) snprintf(tmp, sizeof(tmp), "%s.tmp", fname);

  // Create the file if does not exist
  if ((fp = mg_fopen(fname, "a+")) != NULL) {
    (void) fclose(fp);
  }

  // Open the given file and temporary file
  if ((fp = mg_fopen(fname, "r")) == NULL) {
    return 0;
  } else if ((fp2 = mg_fopen(tmp, "w+")) == NULL) {
    fclose(fp);
    return 0;
  }

  // Copy the stuff to temporary file
  while (fgets(line, sizeof(line), fp) != NULL) {
    if (sscanf(line, "%[^:]:%[^:]:%*s", u, d) != 2) {
      continue;
    }

    if (!strcmp(u, user) && !strcmp(d, domain)) {
      found++;
      if (pass != NULL) {
        mg_md5(ha1, user, ":", domain, ":", pass, NULL);
        fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
      }
    } else {
      (void) fprintf(fp2, "%s", line);
    }
  }

  // If new user, just add it
  if (!found && pass != NULL) {
    mg_md5(ha1, user, ":", domain, ":", pass, NULL);
    (void) fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
  }

  // Close files
  (void) fclose(fp);
  (void) fclose(fp2);

  // Put the temp file in place of real file
  (void) mg_remove(fname);
  (void) mg_rename(tmp, fname);

  return 1;
}

struct de {
  struct mg_connection *conn;
  char *file_name;
  struct mgstat st;
};

// Send len bytes from the opened file to the client.
static void send_file_data(struct mg_connection *conn, FILE *fp, int64_t len) {
  char buf[BUFSIZ];
  int to_read, num_read, num_written;

  while (len > 0) {
    // Calculate how much to read from the file in the buffer
    to_read = sizeof(buf);
    if ((int64_t) to_read > len)
      to_read = (int) len;

    // Read from file, exit the loop on error
    if ((num_read = fread(buf, 1, (size_t)to_read, fp)) == 0)
      break;

    // Send read bytes to the client, exit the loop on error
    if ((num_written = mg_write(conn, buf, (size_t)num_read)) != num_read)
      break;

    // Both read and were successful, adjust counters
    conn->num_bytes_sent += num_written;
    len -= num_written;
  }
}

static void gmt_time_string(char *buf, size_t buf_len, time_t *t) { 
  strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", gmtime(t));
}

static void 
send_data_to_peer (struct mg_connection *conn,  
                   unsigned char *data, int64_t datalen, struct vec *mime_vec) 
{ 
    int len; 
    char date[64], range[64]; 
    time_t curtime = time(NULL); 
    
    conn->request_info.status_code = 200; 
    // Prepare Etag, Date, Last-Modified headers. Must be in UTC, according to 
    // http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.3 
    gmt_time_string(date, sizeof(date), &curtime); 

    range[0] = '\0'; 
    (void) mg_printf(conn, 
                     "HTTP/1.1 %d OK\r\n" 
                     "Date: %s\r\n" 
                     "Content-Type: %.*s\r\n" 
                     "Content-Length: %" INT64_FMT "\r\n" 
                     "Content-Transfer-Encoding: base64\n" 
                     "Connection: %s\r\n" 
                     "Accept-Ranges: bytes\r\n" 
                     "%s\r\n", 
                     conn->request_info.status_code, date, (int) mime_vec->len, 
                     mime_vec->ptr, datalen, suggest_connection_header(conn), range); 

    if (strcmp(conn->request_info.request_method, "HEAD") != 0) { 
        len = mg_write(conn, data, (size_t)datalen); 
        conn->num_bytes_sent += len; 
        printf("sending %d bytes (out of %" INT64_FMT ") to client\n", len, datalen); 
    } else { 
        printf("not sending data to client, request method is %s\n",  
               conn->request_info.request_method); 
    } 
    
    return; 
} 

static void  
handle_file_request(struct mg_connection *conn, const char *path, 
                    struct mgstat *stp, int type)  
{ 
    int64_t cl; 
    struct vec mime_vec; 
    FILE *fp; 
    int len; 
    char *data = NULL, *foo = NULL; 
    EVP_ENCODE_CTX *ctx; 

    get_mime_type(conn->ctx, path, &mime_vec); 
    cl = stp->size; 

    if ((fp = mg_fopen(path, "rb")) == NULL) { 
        goto err; 
    } 
    set_close_on_exec(fileno(fp)); 

    if (type == PEM) { 
        if ((data = malloc(cl)) == NULL) { 
            fprintf(stderr, "cannot malloc space to read file!\n"); 
            goto err; 
        } 
        if (fread(data, 1, (size_t)cl, fp) < cl) { 
            fprintf(stderr, "cannot read %" INT64_FMT " bytes from file!\n", cl); 
            goto err; 
        } 
    } else { 
        if ((foo = malloc(cl)) == NULL) { 
            fprintf(stderr, "cannot malloc space to read file!\n"); 
            goto err; 
        } 
        if ((data = malloc(2*cl)) == NULL) { 
            fprintf(stderr, "cannot malloc space to read file!\n"); 
            goto err; 
        } 
        if (fread(foo, 1, (size_t)cl, fp) < cl) { 
            fprintf(stderr, "cannot read %" INT64_FMT " bytes from file!\n", cl); 
            goto err; 
        } 
        if ((ctx = EVP_ENCODE_CTX_new()) == NULL) {
            goto err;
        }
        EVP_EncodeInit(ctx); 
        EVP_EncodeUpdate(ctx, (unsigned char *)data, &len, (unsigned char *)foo, cl); 
        cl = len; 
        EVP_EncodeFinal(ctx, (unsigned char *)&(data[len]), &len); 
        cl += len; 
        EVP_ENCODE_CTX_free(ctx);
    } 
    send_data_to_peer(conn, (unsigned char *)data, cl, &mime_vec); 

    if (0) { 
err: 
        send_http_error(conn, 444, "No Response", "File Not Found"); 
    } 
  
    if (data != NULL) { 
        free(data); 
    } 
    if (foo != NULL) { 
        free(foo); 
    } 
    (void) fclose(fp); 
} 

void mg_send_file(struct mg_connection *conn, const char *path, int type) { 
  struct mgstat st; 
  if (mg_stat(path, &st) == 0) { 
      handle_file_request(conn, path, &st, type); 
  } else { 
    send_http_error(conn, 404, "Not Found", "%s", "File not found"); 
  } 
} 


// Parse HTTP headers from the given buffer, advance buffer to the point 
// where parsing stopped. 
static void parse_http_headers(char **buf, struct mg_request_info *ri) { 
  int i; 

  for (i = 0; i < (int) ARRAY_SIZE(ri->http_headers); i++) { 
    ri->http_headers[i].name = skip_quoted(buf, ":", " ", 0); 
    ri->http_headers[i].value = skip(buf, "\r\n"); 
    if (ri->http_headers[i].name[0] == '\0') 
      break; 
    ri->num_headers = i + 1; 
  } 
} 

static int is_valid_http_method(const char *method) { 
  return !strcmp(method, "GET") || !strcmp(method, "POST") || 
    !strcmp(method, "HEAD") || !strcmp(method, "CONNECT") || 
    !strcmp(method, "PUT") || !strcmp(method, "DELETE") || 
    !strcmp(method, "OPTIONS") || !strcmp(method, "PROPFIND"); 
} 

// Parse HTTP request, fill in mg_request_info structure. 
static int parse_http_request(char *buf, struct mg_request_info *ri) { 
  int status = 0; 

  // RFC says that all initial whitespaces should be ingored 
  while (*buf != '\0' && isspace(* (unsigned char *) buf)) { 
    buf++; 
  } 

  ri->request_method = skip(&buf, " "); 
  ri->uri = skip(&buf, " "); 
  ri->http_version = skip(&buf, "\r\n"); 

  if (is_valid_http_method(ri->request_method) && 
      strncmp(ri->http_version, "HTTP/", 5) == 0) { 
    ri->http_version += 5;   // Skip "HTTP/" 
    parse_http_headers(&buf, ri); 
    status = 1; 
  } 

  return status; 
} 

// Keep reading the input (either opened file descriptor fd, or socket sock, 
// or SSL descriptor ssl) into buffer buf, until \r\n\r\n appears in the 
// buffer (which marks the end of HTTP request). Buffer buf may already 
// have some data. The length of the data is stored in nread. 
// Upon every read operation, increase nread by the number of bytes read. 
static int read_request(FILE *fp, SOCKET sock, SSL *ssl, char *buf, int bufsiz, 
                        int *nread) { 
  int n, request_len; 

  request_len = 0; 
  while (*nread < bufsiz && request_len == 0) { 
    n = pull(fp, sock, ssl, buf + *nread, bufsiz - *nread); 
    if (n <= 0) { 
      break; 
    } else { 
      *nread += n; 
      request_len = get_request_len(buf, *nread); 
    } 
  } 

  return request_len; 
} 

#if !defined(NO_CGI) 
// This structure helps to create an environment for the spawned CGI program. 
// Environment is an array of "VARIABLE=VALUE\0" ASCIIZ strings, 
// last element must be NULL. 
// However, on Windows there is a requirement that all these VARIABLE=VALUE\0 
// strings must reside in a contiguous buffer. The end of the buffer is 
// marked by two '\0' characters. 
// We satisfy both worlds: we create an envp array (which is vars), all 
// entries are actually pointers inside buf. 
struct cgi_env_block { 
  struct mg_connection *conn; 
  char buf[CGI_ENVIRONMENT_SIZE]; // Environment buffer 
  int len; // Space taken 
  char *vars[MAX_CGI_ENVIR_VARS]; // char **envp 
  int nvars; // Number of variables 
}; 

#if 0 
static void handle_cgi_request(struct mg_connection *conn, const char *prog) { 
  int headers_len, data_len, i, fd_stdin[2], fd_stdout[2]; 
  const char *status, *status_text; 
  char buf[BUFSIZ], *pbuf, dir[PATH_MAX], *p; 
  struct mg_request_info ri; 
  struct cgi_env_block blk; 
  FILE *in, *out; 
  pid_t pid; 

  prepare_cgi_environment(conn, prog, &blk); 

  // CGI must be executed in its own directory. 'dir' must point to the 
  // directory containing executable program, 'p' must point to the 
  // executable program name relative to 'dir'. 
  (void) mg_snprintf(conn, dir, sizeof(dir), "%s", prog); 
  if ((p = strrchr(dir, DIRSEP)) != NULL) { 
    *p++ = '\0'; 
  } else { 
    dir[0] = '.', dir[1] = '\0'; 
    p = (char *) prog; 
  } 

  pid = (pid_t) -1; 
  fd_stdin[0] = fd_stdin[1] = fd_stdout[0] = fd_stdout[1] = -1; 
  in = out = NULL; 

  if (pipe(fd_stdin) != 0 || pipe(fd_stdout) != 0) { 
    send_http_error(conn, 500, http_500_error, 
        "Cannot create CGI pipe: %s", strerror(ERRNO)); 
    goto done; 
  } else if ((pid = spawn_process(conn, p, blk.buf, blk.vars, 
          fd_stdin[0], fd_stdout[1], dir)) == (pid_t) -1) { 
    goto done; 
  } else if ((in = fdopen(fd_stdin[1], "wb")) == NULL || 
      (out = fdopen(fd_stdout[0], "rb")) == NULL) { 
    send_http_error(conn, 500, http_500_error, 
        "fopen: %s", strerror(ERRNO)); 
    goto done; 
  } 

  setbuf(in, NULL); 
  setbuf(out, NULL); 

  // spawn_process() must close those! 
  // If we don't mark them as closed, close() attempt before 
  // return from this function throws an exception on Windows. 
  // Windows does not like when closed descriptor is closed again. 
  fd_stdin[0] = fd_stdout[1] = -1; 

  // Send POST data to the CGI process if needed 
  if (!strcmp(conn->request_info.request_method, "POST") && 
      !forward_body_data(conn, in, INVALID_SOCKET, NULL)) { 
    goto done; 
  } 

  // Now read CGI reply into a buffer. We need to set correct 
  // status code, thus we need to see all HTTP headers first. 
  // Do not send anything back to client, until we buffer in all 
  // HTTP headers. 
  data_len = 0; 
  headers_len = read_request(out, INVALID_SOCKET, NULL, 
      buf, sizeof(buf), &data_len); 
  if (headers_len <= 0) { 
    send_http_error(conn, 500, http_500_error, 
                    "CGI program sent malformed HTTP headers: [%.*s]", 
                    data_len, buf); 
    goto done; 
  } 
  pbuf = buf; 
  buf[headers_len - 1] = '\0'; 
  parse_http_headers(&pbuf, &ri); 

  // Make up and send the status line 
  status_text = "OK"; 
  if ((status = get_header(&ri, "Status")) != NULL) { 
    conn->request_info.status_code = atoi(status); 
    status_text = status; 
    while (isdigit(* (unsigned char *) status_text) || *status_text == ' ') { 
      status_text++; 
    } 
  } else if (get_header(&ri, "Location") != NULL) { 
    conn->request_info.status_code = 302; 
  } else { 
    conn->request_info.status_code = 200; 
  } 
  if (get_header(&ri, "Connection") != NULL && 
      !mg_strcasecmp(get_header(&ri, "Connection"), "keep-alive")) { 
    conn->must_close = 1; 
  } 
  (void) mg_printf(conn, "HTTP/1.1 %d %s\r\n", conn->request_info.status_code, 
                   status_text); 

  // Send headers 
  for (i = 0; i < ri.num_headers; i++) { 
    mg_printf(conn, "%s: %s\r\n", 
              ri.http_headers[i].name, ri.http_headers[i].value); */
  }
  (void) mg_write(conn, "\r\n", 2);

  // Send chunk of data that may be read after the headers
  conn->num_bytes_sent += mg_write(conn, buf + headers_len,
                                   (size_t)(data_len - headers_len));

  // Read the rest of CGI output and send to the client
  send_file_data(conn, out, INT64_MAX);

done:
  if (pid != (pid_t) -1) {
    kill(pid, SIGKILL);
  }
  if (fd_stdin[0] != -1) {
    (void) close(fd_stdin[0]);
  }
  if (fd_stdout[1] != -1) {
    (void) close(fd_stdout[1]);
  }

  if (in != NULL) {
    (void) fclose(in);
  } else if (fd_stdin[1] != -1) {
    (void) close(fd_stdin[1]);
  }

  if (out != NULL) {
    (void) fclose(out);
  } else if (fd_stdout[0] != -1) {
    (void) close(fd_stdout[0]);
  }
}
#endif /* 0 */
#endif // !NO_CGI

static void send_ssi_file(struct mg_connection *, const char *, FILE *, int);

static void do_ssi_include(struct mg_connection *conn, const char *ssi,
                           char *tag, int include_level) {
  char file_name[BUFSIZ], path[PATH_MAX], *p;
  FILE *fp;

  // sscanf() is safe here, since send_ssi_file() also uses buffer
  // of size BUFSIZ to get the tag. So strlen(tag) is always < BUFSIZ.
  if (sscanf(tag, " virtual=\"%[^\"]\"", file_name) == 1) {
    // File name is relative to the webserver root
    (void) mg_snprintf(conn, path, sizeof(path), "%s%c%s",
        conn->ctx->config[DOCUMENT_ROOT], DIRSEP, file_name);
  } else if (sscanf(tag, " file=\"%[^\"]\"", file_name) == 1) {
    // File name is relative to the webserver working directory
    // or it is absolute system path
    (void) mg_snprintf(conn, path, sizeof(path), "%s", file_name);
  } else if (sscanf(tag, " \"%[^\"]\"", file_name) == 1) {
    // File name is relative to the currect document
    (void) mg_snprintf(conn, path, sizeof(path), "%s", ssi);
    if ((p = strrchr(path, DIRSEP)) != NULL) {
      p[1] = '\0';
    }
    (void) mg_snprintf(conn, path + strlen(path),
        sizeof(path) - strlen(path), "%s", file_name);
  } else {
    cry(conn, "Bad SSI #include: [%s]", tag);
    return;
  }

  if ((fp = mg_fopen(path, "rb")) == NULL) {
    cry(conn, "Cannot open SSI #include: [%s]: fopen(%s): %s",
        tag, path, strerror(ERRNO));
  } else {
    set_close_on_exec(fileno(fp));
    if (match_prefix(conn->ctx->config[SSI_EXTENSIONS],
                     strlen(conn->ctx->config[SSI_EXTENSIONS]), path) > 0) {
      send_ssi_file(conn, path, fp, include_level + 1);
    } else {
      send_file_data(conn, fp, INT64_MAX);
    }
    (void) fclose(fp);
  }
}

#if !defined(NO_POPEN)
static void do_ssi_exec(struct mg_connection *conn, char *tag) {
  char cmd[BUFSIZ];
  FILE *fp;

  if (sscanf(tag, " \"%[^\"]\"", cmd) != 1) {
    cry(conn, "Bad SSI #exec: [%s]", tag);
  } else if ((fp = popen(cmd, "r")) == NULL) {
    cry(conn, "Cannot SSI #exec: [%s]: %s", cmd, strerror(ERRNO));
  } else {
    send_file_data(conn, fp, INT64_MAX);
    (void) pclose(fp);
  }
}
#endif // !NO_POPEN

static void send_ssi_file(struct mg_connection *conn, const char *path,
                          FILE *fp, int include_level) {
  char buf[BUFSIZ];
  int ch, len, in_ssi_tag;

  if (include_level > 10) {
    cry(conn, "SSI #include level is too deep (%s)", path);
    return;
  }

  in_ssi_tag = 0;
  len = 0;

  while ((ch = fgetc(fp)) != EOF) {
    if (in_ssi_tag && ch == '>') {
      in_ssi_tag = 0;
      buf[len++] = (char) ch;
      buf[len] = '\0';
      assert(len <= (int) sizeof(buf));
      if (len < 6 || memcmp(buf, "<!--#", 5) != 0) {
        // Not an SSI tag, pass it
        (void) mg_write(conn, buf, (size_t)len);
      } else {
        if (!memcmp(buf + 5, "include", 7)) {
          do_ssi_include(conn, path, buf + 12, include_level);
#if !defined(NO_POPEN)
        } else if (!memcmp(buf + 5, "exec", 4)) {
          do_ssi_exec(conn, buf + 9);
#endif // !NO_POPEN
        } else {
          cry(conn, "%s: unknown SSI " "command: \"%s\"", path, buf);
        }
      }
      len = 0;
    } else if (in_ssi_tag) {
      if (len == 5 && memcmp(buf, "<!--#", 5) != 0) {
        // Not an SSI tag
        in_ssi_tag = 0;
      } else if (len == (int) sizeof(buf) - 2) {
        cry(conn, "%s: SSI tag is too large", path);
        len = 0;
      }
      buf[len++] = ch & 0xff;
    } else if (ch == '<') {
      in_ssi_tag = 1;
      if (len > 0) {
        (void) mg_write(conn, buf, (size_t)len);
      }
      len = 0;
      buf[len++] = ch & 0xff;
    } else {
      buf[len++] = ch & 0xff;
      if (len == (int) sizeof(buf)) {
        (void) mg_write(conn, buf, (size_t)len);
        len = 0;
      }
    }
  }

  // Send the rest of buffered data
  if (len > 0) {
    (void) mg_write(conn, buf, (size_t)len);
  }
}

static void
mg_bskey (struct mg_connection *conn)
{
    char *msg, *dppuri, mac[20], *str1, *str2, key[250];
    struct vec mime_vec;
    int len, next, class, channel;
    FILE *fp;

    if (conn->content_len < 1) {
        fprintf(stderr, "content length is less than one\n");
        goto no_workypoo;
    }
    
    if ((msg = malloc(conn->content_len)) == NULL) {
        fprintf(stderr, "unable to malloc data to get POST\n");
        goto no_workypoo;
    }
    len = mg_read(conn, msg, conn->content_len);
    printf("just read %d bytes from the connection\n", len);

    printf("read:\n\t%s\nadding to the URI database\n", msg);
    if ((fp = mg_fopen(conn->ctx->config[BSKEYFILE], "a+")) == NULL) {
        fprintf(stderr, "can't open bootstrap key file %s\n",
                conn->ctx->config[BSKEYFILE]);
        goto no_workypoo;
    }
    /*
     * go to the end of the file, keeping track of the index as "next"
     */
    printf("bootstrap key file: %s\n", conn->ctx->config[BSKEYFILE]);
    do {
        if (fscanf(fp, "%d %d %d %s %s", &next, &class, &channel, mac, key) < 0) {
            break;
        }
        printf("scanned %d %d %d %s and %s\n", next, class, channel, mac, key);
    } while (!feof(fp));
    /*
     * parse the DPP URI for the stuff we want to put into the file....
     */
    if ((dppuri = strstr(msg, "dppuri=")) == NULL) {
        fprintf(stderr, "can't find DPPURI in message\n");
        goto no_workypoo;
    }
    dppuri += 7;        /* skip past the key to the value */

    next++;
    if ((str1 = strstr(dppuri, "C:")) != NULL) {
        if ((str2 = strstr(str1+2, ";")) == NULL) {
            fprintf(stderr, "error parsing for class/channel in %s\n", dppuri);
            goto no_workypoo;
        }
        sscanf(str1+2, "%d/%d", &class, &channel);
    } else {
        class = channel = 0;
    }
    if ((str1 = strstr(dppuri, "M:")) != NULL) {
        if ((str2 = strstr(str1+2, ";")) == NULL) {
            fprintf(stderr, "error parsing for MAC address in %s\n", dppuri);
            goto no_workypoo;
        }
        printf("we found MAC %.*s in the URI\n", (int)(str2 - (str1+2)), str1+2);
        strncpy(mac, str1+2, (int)(str2 - (str1+2)));
    } else {
        strcpy(mac, "ffffffffffff");
    }
    if ((str1 = strstr(dppuri, "K:")) != NULL) {
        if ((str2 = strstr(str1+2, ";")) == NULL) {
            fprintf(stderr, "error parsing for key in %s\n", dppuri);
            goto no_workypoo;
        }
        printf("we found key %.*s in the URI\n", (int)(str2 - (str1+2)), str1+2);
        strncpy(key, str1+2, (int)(str2 - (str1+2)));
    } else {
        fprintf(stderr, "no key in dpp uri!\n");
        goto no_workypoo;
    }
    /*
     * add the goo to the file
     */
    printf("adding: %d %d %d %s %s\n", next, class, channel, mac, key);
    fprintf(fp, "%d %d %d %s %s\n", next, class, channel, mac, key);
    fclose(fp);

    mime_vec.ptr = builtin_mime_types[0].mime_type;
    mime_vec.len = builtin_mime_types[0].mime_type_len;
//    send_data_to_peer(conn, (unsigned char *)"ack\n", strlen("ack\n"), &mime_vec);
    send_data_to_peer(conn, NULL, 0, &mime_vec);
    if (0) {
  no_workypoo:
        send_http_error(conn, 444, "No Response", "No URI stored");
    }
    
}

// This is the heart of the Mongoose's logic.
// This function is called when the request is read, parsed and validated,
// and Mongoose must decide what action to take: serve a file, or
// a directory, or call embedded function, etcetera.
static void handle_request(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;
  char path[PATH_MAX];
  int uri_len;
  struct mgstat st;
  struct in_addr addr;

  if ((conn->request_info.query_string = strchr(ri->uri, '?')) != NULL) {
    * conn->request_info.query_string++ = '\0';
  }
  uri_len = strlen(ri->uri);
  url_decode(ri->uri, (size_t)uri_len, ri->uri, (size_t)(uri_len + 1), 0);
  remove_double_dots_and_double_slashes(ri->uri);
  (void)convert_uri_to_file_name(conn, path, sizeof(path), &st);

  addr.s_addr = ntohl(conn->request_info.remote_ip);
  printf("handling a request for %s from %s port %d\n", ri->uri,
         inet_ntoa(addr), conn->request_info.remote_port);

  if (strncmp(path, "./dpp", strlen("./dpp")) != 0) {
      send_http_error(conn, 501, "Not Implemented", "not DPP");
      return;
  }

  /*
   * process cette request according to the URL path
   */
  DEBUG_TRACE(("%s", ri->uri));
  if (!check_authorization(conn, path)) {
    send_authorization_request(conn);
  } else if (strstr(path, "dummy") != NULL) {
      mg_send_file(conn, "cettecert.pem", PEM);
  } else if (strstr(path, "bskey") != NULL) {
      mg_bskey(conn);
  } else {
      send_http_error(conn, 501, "Not Implemented",
                      "Nocando");
  }

}

static void close_all_listening_sockets(struct mg_context *ctx) {
  struct socket *sp, *tmp;
  for (sp = ctx->listening_sockets; sp != NULL; sp = tmp) {
    tmp = sp->next;
    (void) closesocket(sp->sock);
    free(sp);
  }
}

// Valid listening port specification is: [ip_address:]port[s]
// Examples: 80, 443s, 127.0.0.1:3128,1.2.3.4:8080s
// TODO(lsm): add parsing of the IPv6 address
static int parse_port_string(const struct vec *vec, struct socket *so) {
  int a, b, c, d, port, len;

  // MacOS needs that. If we do not zero it, subsequent bind() will fail.
  // Also, all-zeroes in the socket address means binding to all addresses
  // for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT).
  memset(so, 0, sizeof(*so));

  if (sscanf(vec->ptr, "%d.%d.%d.%d:%d%n", &a, &b, &c, &d, &port, &len) == 5) {
    // Bind to a specific IPv4 address
    so->lsa.sin.sin_addr.s_addr = htonl((a << 24) | (b << 16) | (c << 8) | d);
  } else if (sscanf(vec->ptr, "%d%n", &port, &len) != 1 ||
             len <= 0 ||
             len > (int) vec->len ||
             (vec->ptr[len] && vec->ptr[len] != 's' && vec->ptr[len] != ',')) {
    return 0;
  }

  so->is_ssl = vec->ptr[len] == 's';
  
#if defined(USE_IPV6)
  so->lsa.sin6.sin6_family = AF_INET6;
  so->lsa.sin6.sin6_port = htons((uint16_t) port);
#else
  so->lsa.sin.sin_family = AF_INET;
  so->lsa.sin.sin_port = htons((uint16_t) port);
#endif

  return 1;
}

static int set_ports_option(struct mg_context *ctx) {
  const char *list = ctx->config[LISTENING_PORTS];
  int on = 1, success = 1;
  SOCKET sock;
  struct vec vec;
  struct socket so, *listener;

  while (success && (list = next_option(list, &vec, NULL)) != NULL) {
    if (!parse_port_string(&vec, &so)) {
      cry(fc(ctx), "%s: %.*s: invalid port spec. Expecting list of: %s",
          __func__, vec.len, vec.ptr, "[IP_ADDRESS:]PORT[s|p]");
      success = 0;
    } else if (so.is_ssl && ctx->ssl_ctx == NULL) {
      cry(fc(ctx), "Cannot add SSL socket, is -ssl_certificate option set?");
      success = 0;
    } else if ((sock = socket(so.lsa.sa.sa_family, SOCK_STREAM, 6)) ==
               INVALID_SOCKET ||
               setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
                          sizeof(on)) != 0 ||
               // Set TCP keep-alive. This is needed because if HTTP-level
               // keep-alive is enabled, and client resets the connection,
               // server won't get TCP FIN or RST and will keep the connection
               // open forever. With TCP keep-alive, next keep-alive
               // handshake will figure out that the client is down and
               // will close the server end.
               // Thanks to Igor Klopov who suggested the patch.
               setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *) &on,
                          sizeof(on)) != 0 ||
               bind(sock, &so.lsa.sa, sizeof(so.lsa)) != 0 ||
               listen(sock, 100) != 0) {
      closesocket(sock);
      cry(fc(ctx), "%s: cannot bind to %.*s: %s", __func__,
          vec.len, vec.ptr, strerror(ERRNO));
      success = 0;
    } else if ((listener = (struct socket *)
                calloc(1, sizeof(*listener))) == NULL) {
      closesocket(sock);
      cry(fc(ctx), "%s: %s", __func__, strerror(ERRNO));
      success = 0;
    } else {
      *listener = so;
      listener->sock = sock;
      set_close_on_exec(listener->sock);
      listener->next = ctx->listening_sockets;
      ctx->listening_sockets = listener;
    }
  }

  if (!success) {
    close_all_listening_sockets(ctx);
  }

  return success;
}

static void log_header(const struct mg_connection *conn, const char *header,
                       FILE *fp) {
  const char *header_value;

  if ((header_value = mg_get_header(conn, header)) == NULL) {
    (void) fprintf(fp, "%s", " -");
  } else {
    (void) fprintf(fp, " \"%s\"", header_value);
  }
}

static void log_access(const struct mg_connection *conn) {
  const struct mg_request_info *ri;
  FILE *fp;
  char date[64], src_addr[20];

  fp = conn->ctx->config[ACCESS_LOG_FILE] == NULL ?  NULL :
    mg_fopen(conn->ctx->config[ACCESS_LOG_FILE], "a+");

  if (fp == NULL)
    return;

  strftime(date, sizeof(date), "%d/%b/%Y:%H:%M:%S %z",
           localtime(&conn->birth_time));

  ri = &conn->request_info;
  flockfile(fp);

  sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);
  fprintf(fp, "%s - %s [%s] \"%s %s HTTP/%s\" %d %" INT64_FMT,
//  fprintf(fp, "%s - %s [%s] \"%s %s HTTP/%s\" %d %d",
          src_addr, ri->remote_user == NULL ? "-" : ri->remote_user, date,
          ri->request_method ? ri->request_method : "-",
          ri->uri ? ri->uri : "-", ri->http_version,
          conn->request_info.status_code, conn->num_bytes_sent);
  log_header(conn, "Referer", fp);
  log_header(conn, "User-Agent", fp);
  fputc('\n', fp);
  fflush(fp);

  funlockfile(fp);
  fclose(fp);
}

static int isbyte(int n) {
  return n >= 0 && n <= 255;
}

// Verify given socket address against the ACL.
// Return -1 if ACL is malformed, 0 if address is disallowed, 1 if allowed.
static int check_acl(struct mg_context *ctx, const union usa *usa) {
  int a, b, c, d, n, mask, allowed;
  char flag;
  uint32_t acl_subnet, acl_mask, remote_ip;
  struct vec vec;
  const char *list = ctx->config[ACCESS_CONTROL_LIST];

  if (list == NULL) {
    return 1;
  }

  (void) memcpy(&remote_ip, &usa->sin.sin_addr, sizeof(remote_ip));

  // If any ACL is set, deny by default
  allowed = '-';

  while ((list = next_option(list, &vec, NULL)) != NULL) {
    mask = 32;

    if (sscanf(vec.ptr, "%c%d.%d.%d.%d%n", &flag, &a, &b, &c, &d, &n) != 5) {
      cry(fc(ctx), "%s: subnet must be [+|-]x.x.x.x[/x]", __func__);
      return -1;
    } else if (flag != '+' && flag != '-') {
      cry(fc(ctx), "%s: flag must be + or -: [%s]", __func__, vec.ptr);
      return -1;
    } else if (!isbyte(a)||!isbyte(b)||!isbyte(c)||!isbyte(d)) {
      cry(fc(ctx), "%s: bad ip address: [%s]", __func__, vec.ptr);
      return -1;
    } else if (sscanf(vec.ptr + n, "/%d", &mask) == 0) {
      // Do nothing, no mask specified
    } else if (mask < 0 || mask > 32) {
      cry(fc(ctx), "%s: bad subnet mask: %d [%s]", __func__, n, vec.ptr);
      return -1;
    }

    acl_subnet = (a << 24) | (b << 16) | (c << 8) | d;
    acl_mask = mask ? 0xffffffffU << (32 - mask) : 0;

    if (acl_subnet == (ntohl(remote_ip) & acl_mask)) {
      allowed = flag;
    }
  }

  return allowed == '+';
}

static void add_to_set(SOCKET fd, fd_set *set, int *max_fd) {
  FD_SET(fd, set);
  if (fd > (SOCKET) *max_fd) {
    *max_fd = (int) fd;
  }
}

static int set_uid_option(struct mg_context *ctx) {
  struct passwd *pw;
  const char *uid = ctx->config[RUN_AS_USER];
  int success = 0;

  if (uid == NULL) {
    success = 1;
  } else {
    if ((pw = getpwnam(uid)) == NULL) {
      cry(fc(ctx), "%s: unknown user [%s]", __func__, uid);
    } else if (setgid(pw->pw_gid) == -1) {
      cry(fc(ctx), "%s: setgid(%s): %s", __func__, uid, strerror(errno));
    } else if (setuid(pw->pw_uid) == -1) {
      cry(fc(ctx), "%s: setuid(%s): %s", __func__, uid, strerror(errno));
    } else {
      success = 1;
    }
  }

  return success;
}

static pthread_mutex_t *ssl_mutexes;

#if 0
static void ssl_locking_callback(int mode, int mutex_num, const char *file,
                                 int line) {
  line = 0;    // Unused
  file = NULL; // Unused

  if (mode & CRYPTO_LOCK) {
    (void) pthread_mutex_lock(&ssl_mutexes[mutex_num]);
  } else {
    (void) pthread_mutex_unlock(&ssl_mutexes[mutex_num]);
  }
}

static unsigned long ssl_id_callback(void) {
  return (unsigned long) pthread_self();
}
#endif

#ifdef OPENSSL_HAS_TLS_PWD
static int ssl_pwd_server_username_cb(SSL *s, void *arg)
{
    PWD_CTX *ctx = (PWD_CTX *)arg;
    FILE *fp;
    char user[20];
    char base[65], salt[65];   /* 2 * SHA256 digest len + 1 */
    int ret = -1;

    if (ctx->login == NULL) {
        return -1;
    }
    if ((fp = fopen("pwdfile", "r")) == NULL) {
        return -1;
    }
    memset(base, 0, sizeof(base));
    memset(salt, 0, sizeof(salt));
    while (!feof(fp)) {
        memset(user, 0, sizeof(user));
        (void)fscanf(fp, "%s", user);
        if (feof(fp)) {
            goto fin;
        }
        (void)fscanf(fp, "%s", base);
        (void)fscanf(fp, "%s", salt);
        if (strcmp(ctx->login, user) == 0) {
            if (((ctx->base = BN_new()) == NULL) ||
                ((ctx->salt = BN_new()) == NULL)) {
                goto fin;
            }
            BN_hex2bn(&ctx->base, base);
            BN_hex2bn(&ctx->salt, salt);
            ret = 1;
            break;
        }
    }
fin:
    fclose(fp);
    return ret;
}
#endif  /* OPENSSL_HAS_TLS_PWD */

// Dynamically load SSL library. Set up ctx->ssl_ctx pointer.
static int
set_ssl_option(struct mg_context *ctx) {
  struct mg_request_info request_info;
  SSL_CTX *CTX;
  int i, size;
  const char *pem = ctx->config[SSL_CERTIFICATE];
  const char *chain = ctx->config[SSL_CHAIN_FILE];

  if (pem == NULL) {
    return 1;
  }

  // Initialize SSL 
  SSL_library_init();
  SSL_load_error_strings();

  if ((CTX = SSL_CTX_new(TLS_server_method())) == NULL) {
    cry(fc(ctx), "SSL_CTX_new error: %s", ssl_error());
  } else if (ctx->user_callback != NULL) {
    memset(&request_info, 0, sizeof(request_info));
    request_info.user_data = ctx->user_data;
    ctx->user_callback(MG_INIT_SSL, (struct mg_connection *) CTX,
                       &request_info);
  }
  
#ifdef OPENSSL_HAS_TLS_PWD
  if (strcmp(ctx->config[TLSPWD], "yes") == 0) {
      SSL_CTX_set_pwd_username_callback(CTX, ssl_pwd_server_username_cb);
  }
#endif  /* OPENSSL_HAS_TLS_PWD */
  
  if (CTX != NULL && SSL_CTX_use_certificate_file(CTX, pem,
        SSL_FILETYPE_PEM) == 0) {
    cry(fc(ctx), "%s: cannot open %s: %s", __func__, pem, ssl_error());
    return 0;
  } else if (CTX != NULL && SSL_CTX_use_PrivateKey_file(CTX, pem,
        SSL_FILETYPE_PEM) == 0) {
    cry(fc(ctx), "%s: cannot open %s: %s", NULL, pem, ssl_error());
    return 0;
  }

  if (CTX != NULL && chain != NULL &&
      SSL_CTX_use_certificate_chain_file(CTX, chain) == 0) {
    cry(fc(ctx), "%s: cannot open %s: %s", NULL, chain, ssl_error());
    return 0;
  }

  // Initialize locking callbacks, needed for thread safety.
  // http://www.openssl.org/support/faq.html#PROG1
  size = sizeof(pthread_mutex_t) * CRYPTO_num_locks();
  if ((ssl_mutexes = (pthread_mutex_t *) malloc((size_t)size)) == NULL) {
    cry(fc(ctx), "%s: cannot allocate mutexes: %s", __func__, ssl_error());
    return 0;
  }

  for (i = 0; i < CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&ssl_mutexes[i], NULL);
  }

#if 0
  CRYPTO_set_locking_callback(&ssl_locking_callback);
  CRYPTO_set_id_callback(&ssl_id_callback);
#endif

  // Done with everything. Save the context.
  ctx->ssl_ctx = CTX;

  return 1;
}

static void uninitialize_ssl(struct mg_context *ctx) {
  int i;
  if (ctx->ssl_ctx != NULL) {
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
      pthread_mutex_destroy(&ssl_mutexes[i]);
    }
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
  }
}

static int set_gpass_option(struct mg_context *ctx) {
  struct mgstat mgstat;
  const char *path = ctx->config[GLOBAL_PASSWORDS_FILE];
  return path == NULL || mg_stat(path, &mgstat) == 0;
}

static int set_acl_option(struct mg_context *ctx) {
  union usa fake;
  return check_acl(ctx, &fake) != -1;
}

static void reset_per_request_attributes(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;

  // Reset request info attributes. DO NOT TOUCH is_ssl, remote_ip, remote_port
  ri->remote_user = ri->request_method = ri->uri = ri->http_version =
    conn->path_info = NULL;
  ri->num_headers = 0;
  ri->status_code = -1;

  conn->num_bytes_sent = conn->consumed_content = 0;
  conn->content_len = -1;
  conn->request_len = conn->data_len = 0;
  conn->must_close = 0;
}

static void close_socket_gracefully(SOCKET sock) {
  char buf[BUFSIZ];
  struct linger linger;
  int n;

  // Set linger option to avoid socket hanging out after close. This prevent
  // ephemeral port exhaust problem under high QPS.
  linger.l_onoff = 1;
  linger.l_linger = 1;
  setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *) &linger, sizeof(linger));

  // Send FIN to the client
  (void) shutdown(sock, SHUT_WR);
  set_non_blocking_mode(sock);

  // Read and discard pending data. If we do not do that and close the
  // socket, the data in the send buffer may be discarded. This
  // behaviour is seen on Windows, when client keeps sending data
  // when server decide to close the connection; then when client
  // does recv() it gets no data back.
  do {
    n = pull(NULL, sock, NULL, buf, sizeof(buf));
  } while (n > 0);

  // Now we know that our FIN is ACK-ed, safe to close
  (void) closesocket(sock);
}

static void close_connection(struct mg_connection *conn) {
  if (conn->ssl) {
    SSL_free(conn->ssl);
    conn->ssl = NULL;
  }

  if (conn->client.sock != INVALID_SOCKET) {
    close_socket_gracefully(conn->client.sock);
  }
}

static void discard_current_request_from_buffer(struct mg_connection *conn) {
  int buffered_len, body_len;

  buffered_len = conn->data_len - conn->request_len;
  assert(buffered_len >= 0);

  if (conn->content_len == -1) {
    body_len = 0;
  } else if (conn->content_len < (int64_t) buffered_len) {
    body_len = (int) conn->content_len;
  } else {
    body_len = buffered_len;
  }

  conn->data_len -= conn->request_len + body_len;
  memmove(conn->buf, conn->buf + conn->request_len + body_len,
          (size_t) conn->data_len);
}

static int is_valid_uri(const char *uri) {
  // Conform to http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
  // URI can be an asterisk (*) or should start with slash.
  return uri[0] == '/' || (uri[0] == '*' && uri[1] == '\0');
}

static void process_new_connection(struct mg_connection *conn) {
  struct mg_request_info *ri = &conn->request_info;
  int keep_alive_enabled;
  const char *cl;

  keep_alive_enabled = !strcmp(conn->ctx->config[ENABLE_KEEP_ALIVE], "yes");

  do {
    reset_per_request_attributes(conn);

    // If next request is not pipelined, read it in
    if ((conn->request_len = get_request_len(conn->buf, conn->data_len)) == 0) {
      conn->request_len = read_request(NULL, conn->client.sock, conn->ssl,
          conn->buf, conn->buf_size, &conn->data_len);
    }
    assert(conn->data_len >= conn->request_len);
    if (conn->request_len == 0 && conn->data_len == conn->buf_size) {
      send_http_error(conn, 413, "Request Too Large", "");
      return;
    } if (conn->request_len <= 0) {
      return;  // Remote end closed the connection
    }

    // Nul-terminate the request cause parse_http_request() uses sscanf
    conn->buf[conn->request_len - 1] = '\0';
    if (!parse_http_request(conn->buf, ri) || !is_valid_uri(ri->uri)) {
      // Do not put garbage in the access log, just send it back to the client
      send_http_error(conn, 400, "Bad Request",
          "Cannot parse HTTP request: [%.*s]", conn->data_len, conn->buf);
    } else if (strcmp(ri->http_version, "1.0") &&
               strcmp(ri->http_version, "1.1")) {
      // Request seems valid, but HTTP version is strange
      send_http_error(conn, 505, "HTTP version not supported", "");
      log_access(conn);
    } else {
      // Request is valid, handle it
      cl = get_header(ri, "Content-Length");
      conn->content_len = cl == NULL ? -1 : strtoll(cl, NULL, 10);
      conn->birth_time = time(NULL);
      handle_request(conn);
      call_user(conn, MG_REQUEST_COMPLETE);
      log_access(conn);
      discard_current_request_from_buffer(conn);
    }
    if (ri->remote_user != NULL) {
      free((void *) ri->remote_user);
    }
  } while (conn->ctx->stop_flag == 0 &&
           keep_alive_enabled &&
           should_keep_alive(conn));
}

// Worker threads take accepted socket from the queue
static int consume_socket(struct mg_context *ctx, struct socket *sp) {
  (void) pthread_mutex_lock(&ctx->mutex);
  DEBUG_TRACE(("going idle"));

  // If the queue is empty, wait. We're idle at this point.
  while (ctx->sq_head == ctx->sq_tail && ctx->stop_flag == 0) {
    pthread_cond_wait(&ctx->sq_full, &ctx->mutex);
  }

  // If we're stopping, sq_head may be equal to sq_tail.
  if (ctx->sq_head > ctx->sq_tail) {
    // Copy socket from the queue and increment tail
    *sp = ctx->queue[ctx->sq_tail % ARRAY_SIZE(ctx->queue)];
    ctx->sq_tail++;
    DEBUG_TRACE(("grabbed socket %d, going busy", sp->sock));

    // Wrap pointers if needed
    while (ctx->sq_tail > (int) ARRAY_SIZE(ctx->queue)) {
      ctx->sq_tail -= ARRAY_SIZE(ctx->queue);
      ctx->sq_head -= ARRAY_SIZE(ctx->queue);
    }
  }

  (void) pthread_cond_signal(&ctx->sq_empty);
  (void) pthread_mutex_unlock(&ctx->mutex);

  return !ctx->stop_flag;
}

static void worker_thread(struct mg_context *ctx) {
  struct mg_connection *conn;
  int buf_size = atoi(ctx->config[MAX_REQUEST_SIZE]);

  conn = (struct mg_connection *) calloc(1, sizeof(*conn) + buf_size);
  if (conn == NULL) {
    cry(fc(ctx), "%s", "Cannot create new connection struct, OOM");
    return;
  }
  conn->buf_size = buf_size;
  conn->buf = (char *) (conn + 1);

  // Call consume_socket() even when ctx->stop_flag > 0, to let it signal
  // sq_empty condvar to wake up the master waiting in produce_socket()
  while (consume_socket(ctx, &conn->client)) {
    conn->birth_time = time(NULL);
    conn->ctx = ctx;

    // Fill in IP, port info early so even if SSL setup below fails,
    // error handler would have the corresponding info.
    // Thanks to Johannes Winkelmann for the patch.
    // TODO(lsm): Fix IPv6 case
    conn->request_info.remote_port = ntohs(conn->client.rsa.sin.sin_port);
    memcpy(&conn->request_info.remote_ip,
           &conn->client.rsa.sin.sin_addr.s_addr, 4);
    conn->request_info.remote_ip = ntohl(conn->request_info.remote_ip);
    conn->request_info.is_ssl = conn->client.is_ssl;

    if (!conn->client.is_ssl ||
        (conn->client.is_ssl && sslize(conn, SSL_accept))) {
      process_new_connection(conn);
    }

    close_connection(conn);
  }
  free(conn);

  // Signal master that we're done with connection and exiting
  (void) pthread_mutex_lock(&ctx->mutex);
  ctx->num_threads--;
  (void) pthread_cond_signal(&ctx->cond);
  assert(ctx->num_threads >= 0);
  (void) pthread_mutex_unlock(&ctx->mutex);

  DEBUG_TRACE(("exiting"));
}

// Master thread adds accepted socket to a queue
static void produce_socket(struct mg_context *ctx, const struct socket *sp) {
  (void) pthread_mutex_lock(&ctx->mutex);

  // If the queue is full, wait
  while (ctx->stop_flag == 0 &&
         ctx->sq_head - ctx->sq_tail >= (int) ARRAY_SIZE(ctx->queue)) {
    (void) pthread_cond_wait(&ctx->sq_empty, &ctx->mutex);
  }

  if (ctx->sq_head - ctx->sq_tail < (int) ARRAY_SIZE(ctx->queue)) {
    // Copy socket to the queue and increment head
    ctx->queue[ctx->sq_head % ARRAY_SIZE(ctx->queue)] = *sp;
    ctx->sq_head++;
    DEBUG_TRACE(("queued socket %d", sp->sock));
  }

  (void) pthread_cond_signal(&ctx->sq_full);
  (void) pthread_mutex_unlock(&ctx->mutex);
}

static void accept_new_connection(const struct socket *listener,
                                  struct mg_context *ctx) {
  struct socket accepted;
  char src_addr[20];
  socklen_t len;
  int allowed;

  len = sizeof(accepted.rsa);
  accepted.lsa = listener->lsa;
  accepted.sock = accept(listener->sock, &accepted.rsa.sa, &len);
  if (accepted.sock != INVALID_SOCKET) {
    allowed = check_acl(ctx, &accepted.rsa);
    if (allowed) {
      // Put accepted socket structure into the queue
      DEBUG_TRACE(("accepted socket %d", accepted.sock));
      accepted.is_ssl = listener->is_ssl;
      produce_socket(ctx, &accepted);
    } else {
      sockaddr_to_string(src_addr, sizeof(src_addr), &accepted.rsa);
      cry(fc(ctx), "%s: %s is not allowed to connect", __func__, src_addr);
      (void) closesocket(accepted.sock);
    }
  }
}

static void master_thread(struct mg_context *ctx) {
  fd_set read_set;
  struct timeval tv;
  struct socket *sp;
  int max_fd;

#if defined(ISSUE_317)
  struct sched_param sched_param;
  sched_param.sched_priority = sched_get_priority_max(SCHED_RR);
  pthread_setschedparam(pthread_self(), SCHED_RR, &sched_param);
#endif

  while (ctx->stop_flag == 0) {
    FD_ZERO(&read_set);
    max_fd = -1;

    // Add listening sockets to the read set
    for (sp = ctx->listening_sockets; sp != NULL; sp = sp->next) {
      add_to_set(sp->sock, &read_set, &max_fd);
    }

    tv.tv_sec = 0;
    tv.tv_usec = 200 * 1000;

    if (select(max_fd + 1, &read_set, NULL, NULL, &tv) < 0) {
        continue;
    } else {
      for (sp = ctx->listening_sockets; sp != NULL; sp = sp->next) {
        if (ctx->stop_flag == 0 && FD_ISSET(sp->sock, &read_set)) {
          accept_new_connection(sp, ctx);
        }
      }
    }
  }
  DEBUG_TRACE(("stopping workers"));

  // Stop signal received: somebody called mg_stop. Quit.
  close_all_listening_sockets(ctx);

  // Wakeup workers that are waiting for connections to handle.
  pthread_cond_broadcast(&ctx->sq_full);

  // Wait until all threads finish
  (void) pthread_mutex_lock(&ctx->mutex);
  while (ctx->num_threads > 0) {
    (void) pthread_cond_wait(&ctx->cond, &ctx->mutex);
  }
  (void) pthread_mutex_unlock(&ctx->mutex);

  // All threads exited, no sync is needed. Destroy mutex and condvars
  (void) pthread_mutex_destroy(&ctx->mutex);
  (void) pthread_cond_destroy(&ctx->cond);
  (void) pthread_cond_destroy(&ctx->sq_empty);
  (void) pthread_cond_destroy(&ctx->sq_full);

  uninitialize_ssl(ctx);

  // Signal mg_stop() that we're done
  ctx->stop_flag = 2;

  DEBUG_TRACE(("exiting"));
}

static void free_context(struct mg_context *ctx) {
  int i;

  // Deallocate config parameters
  for (i = 0; i < NUM_OPTIONS; i++) {
    if (ctx->config[i] != NULL)
      free(ctx->config[i]);
  }

  // Deallocate SSL context
  if (ctx->ssl_ctx != NULL) {
    SSL_CTX_free(ctx->ssl_ctx);
  }
  if (ssl_mutexes != NULL) {
    free(ssl_mutexes);
  }

  // Deallocate context itself
  free(ctx);
}

void mg_stop(struct mg_context *ctx) {
  ctx->stop_flag = 1;

  // Wait until mg_fini() stops
  while (ctx->stop_flag != 2) {
    (void) sleep(0);
  }
  free_context(ctx);
}

struct mg_context *mg_start(mg_callback_t user_callback, void *user_data,
                            const char **options) {
  struct mg_context *ctx;
  const char *name, *value, *default_value;
  int i;

  // Allocate context and initialize reasonable general case defaults.
  // TODO(lsm): do proper error handling here.
  ctx = (struct mg_context *) calloc(1, sizeof(*ctx));
  ctx->user_callback = user_callback;
  ctx->user_data = user_data;

  while (options && (name = *options++) != NULL) {
    if ((i = get_option_index(name)) == -1) {
      cry(fc(ctx), "Invalid option: %s", name);
      free_context(ctx);
      return NULL;
    } else if ((value = *options++) == NULL) {
      cry(fc(ctx), "%s: option value cannot be NULL", name);
      free_context(ctx);
      return NULL;
    }
    if (ctx->config[i] != NULL) {
      cry(fc(ctx), "%s: duplicate option", name);
    }
    ctx->config[i] = mg_strdup(value);
    DEBUG_TRACE(("[%s] -> [%s]", name, value));
  }

  // Set default value if needed
  for (i = 0; config_options[i * ENTRIES_PER_CONFIG_OPTION] != NULL; i++) {
    default_value = config_options[i * ENTRIES_PER_CONFIG_OPTION + 2];
    if (ctx->config[i] == NULL && default_value != NULL) {
      ctx->config[i] = mg_strdup(default_value);
      DEBUG_TRACE(("Setting default: [%s] -> [%s]",
                   config_options[i * ENTRIES_PER_CONFIG_OPTION + 1],
                   default_value));
    }
  }

  // NOTE(lsm): order is important here. SSL certificates must
  // be initialized before listening ports. UID must be set last.
  if (!set_gpass_option(ctx) ||
      !set_ssl_option(ctx) ||
      !set_ports_option(ctx) ||
      !set_uid_option(ctx) ||
      !set_acl_option(ctx)) {
    free_context(ctx);
    return NULL;
  }

  // Ignore SIGPIPE signal, so if browser cancels the request, it
  // won't kill the whole process.
  (void) signal(SIGPIPE, SIG_IGN);
  // Also ignoring SIGCHLD to let the OS to reap zombies properly.
  (void) signal(SIGCHLD, SIG_IGN);

  (void) pthread_mutex_init(&ctx->mutex, NULL);
  (void) pthread_cond_init(&ctx->cond, NULL);
  (void) pthread_cond_init(&ctx->sq_empty, NULL);
  (void) pthread_cond_init(&ctx->sq_full, NULL);

  // Start master (listening) thread
  start_thread(ctx, (mg_thread_func_t) master_thread, ctx);

  // Start worker threads
  for (i = 0; i < atoi(ctx->config[NUM_THREADS]); i++) {
    if (start_thread(ctx, (mg_thread_func_t) worker_thread, ctx) != 0) {
      cry(fc(ctx), "Cannot start worker thread: %d", ERRNO);
    } else {
      ctx->num_threads++;
    }
  }

  return ctx;
}

static void WINCDECL signal_handler(int sig_num) {
  exit_flag = sig_num;
}

static void die(const char *fmt, ...) {
  va_list ap;
  char msg[200];

  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

#if defined(_WIN32)
  MessageBox(NULL, msg, "Error", MB_OK);
#else
  fprintf(stderr, "%s\n", msg);
#endif

  exit(EXIT_FAILURE);
}

static void show_usage_and_exit(void) {
  const char **names;
  int i;

  fprintf(stderr, "Implementation of a DPP configurette\n");
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  cette -A <htpasswd_file> <realm> <user> <passwd>\n");
  fprintf(stderr, "  cette <config_file>\n");
  fprintf(stderr, "  cette [-option value ...]\n");
  fprintf(stderr, "OPTIONS:\n");

  names = mg_get_valid_option_names();
  for (i = 0; names[i] != NULL; i += 3) {
    fprintf(stderr, "  -%s %s (default: \"%s\")\n",
            names[i], names[i + 1], names[i + 2] == NULL ? "" : names[i + 2]);
  }
  fprintf(stderr, "Example:\n  cette -s cert.pem -p 80,443s\n");
  exit(EXIT_FAILURE);
}

static void verify_document_root(const char *root) {
  const char *p, *path;
  char buf[PATH_MAX];
  struct stat st;

  path = root;
  if ((p = strchr(root, ',')) != NULL && (size_t) (p - root) < sizeof(buf)) {
    memcpy(buf, root, p - root);
    buf[p - root] = '\0';
    path = buf;
  }

  if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
    die("Invalid root directory: [%s]: %s", root, strerror(errno));
  }
}

static char *sdup(const char *str) {
  char *p;
  if ((p = (char *) malloc(strlen(str) + 1)) != NULL) {
    strcpy(p, str);
  }
  return p;
}

static void set_option(char **options, const char *name, const char *value) {
  int i;

  if (!strcmp(name, "document_root") || !(strcmp(name, "r"))) {
    verify_document_root(value);
  }

  for (i = 0; i < MAX_OPTIONS - 3; i++) {
    if (options[i] == NULL) {
      options[i] = sdup(name);
      options[i + 1] = sdup(value);
      options[i + 2] = NULL;
      break;
    }
  }

  if (i == MAX_OPTIONS - 3) {
    die("%s", "Too many options specified");
  }
}

static void process_command_line_arguments(char *argv[], char **options) {
  char line[MAX_CONF_FILE_LINE_SIZE], opt[sizeof(line)], val[sizeof(line)], *p;
  FILE *fp = NULL;
  size_t i, cmd_line_opts_start = 1, line_no = 0;

  options[0] = NULL;

  // Should we use a config file ?
  if (argv[1] != NULL && argv[1][0] != '-') {
    snprintf(config_file, sizeof(config_file), "%s", argv[1]);
    cmd_line_opts_start = 2;
  } else if ((p = strrchr(argv[0], DIRSEP)) == NULL) {
    // No command line flags specified. Look where binary lives
    snprintf(config_file, sizeof(config_file), "%s", CONFIG_FILE);
  } else {
    snprintf(config_file, sizeof(config_file), "%.*s%c%s",
             (int) (p - argv[0]), argv[0], DIRSEP, CONFIG_FILE);
  }

  fp = fopen(config_file, "r");

  // If config file was set in command line and open failed, die
  if (cmd_line_opts_start == 2 && fp == NULL) {
    die("Cannot open config file %s: %s", config_file, strerror(errno));
  }

  // Load config file settings first
  if (fp != NULL) {
    fprintf(stderr, "Loading config file %s\n", config_file);

    // Loop over the lines in config file
    while (fgets(line, sizeof(line), fp) != NULL) {

      line_no++;

      // Ignore empty lines and comments
      if (line[0] == '#' || line[0] == '\n')
        continue;

      if (sscanf(line, "%s %[^\r\n#]", opt, val) != 2) {
        die("%s: line %d is invalid", config_file, (int) line_no);
      }
      set_option(options, opt, val);
    }

    (void) fclose(fp);
  }

  // Now handle command line flags. They override config file settings.
  for (i = cmd_line_opts_start; argv[i] != NULL; i += 2) {
    if (argv[i][0] != '-' || argv[i + 1] == NULL) {
      show_usage_and_exit();
    }
    set_option(options, &argv[i][1], argv[i + 1]);
  }
}

static void init_server_name(void) {
  snprintf(server_name, sizeof(server_name), "cette v. %s",
           mg_version());
}

static void start_cette(int argc, char *argv[]) {
  char *options[MAX_OPTIONS];
  int i;

  // Edit passwords file if -A option is specified
  if (argc > 1 && !strcmp(argv[1], "-A")) {
    if (argc != 6) {
      show_usage_and_exit();
    }
    exit(mg_modify_passwords_file(argv[2], argv[3], argv[4], argv[5]) ?
         EXIT_SUCCESS : EXIT_FAILURE);
  }

  // Show usage if -h or --help options are specified
  if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
    show_usage_and_exit();
  }

  /* Update config based on command line arguments */
  process_command_line_arguments(argv, options);

  /* Setup signal handler: quit on Ctrl-C */
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  /* Start cette */
  ctx = mg_start(NULL, NULL, (const char **) options);
  for (i = 0; options[i] != NULL; i++) {
    free(options[i]);
  }

  if (ctx == NULL) {
    die("%s", "Failed to start cette server. Maybe some options are "
        "assigned bad values?\nTry to run with '-e error_log.txt' "
        "and check error_log.txt for more information.");
  }
}

int
main(int argc, char **argv) {
#ifdef HASAVAHI
    int rc;
    pthread_t t;
#endif  /* HASAVAHI */

    init_server_name();
    start_cette(argc, argv);
#ifdef HASAVAHI
    if ((rc = pthread_create(&t, NULL, mdns_thread, NULL)) > 0) {
        fprintf(stderr, "%s: unable to create thread!\n", argv[0]);
    }
#endif  /* HASAVAHI */
    printf("%s started on port(s) %s with web root [%s]\n",
           server_name, mg_get_option(ctx, "listening_ports"),
           mg_get_option(ctx, "document_root"));
    while (exit_flag == 0) {
        sleep(1);
    }
    printf("Exiting on signal %d, waiting for all threads to finish...",
           exit_flag);
    fflush(stdout);
    mg_stop(ctx);
    printf("%s", " done.\n");

    return EXIT_SUCCESS;
}
