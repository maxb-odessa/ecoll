/**********************************************************
 *
 * Linux FS File Monitor
 *
 * Files Integrity Monitor (inotify events collector)
 *
 * HEADER FILE
 *
 ***********************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/inotify.h>

#include <yaml.h>
#include <sqlite3.h>
#include <fnmatch.h>
#include <search.h>

#ifndef PATH_MAX
 #define PATH_MAX 4096
#endif

#ifndef NAME_MAX
 #define NAME_MAX 4096
#endif

// inotify event data
typedef struct {
  char       path[PATH_MAX + NAME_MAX + 1];  // dir(/file) full path 
  const char *event;                         // event that happened
  int        is_dir;                         // !0 if a directory
  time_t     ts;                             // event timestamp
} ievent_t;

// watched dirs tree node
typedef struct {
  int  wd;       // inotify watch descriptor
  char *dir;     // watched full dir name
} wdir_t;

// configuration settings and common runtime variables
struct config {

  // preserved args for re-execit self
  char *execpath;     // full path to our executable
  char *argv[3];      // argv[] from main() (note: our binary expects exactly 1 arg)

  // configured general settings
  char *config_file;  // our config file
  char *pid_file;     // pid file location
  char *log_file;     // log file location
  int  daemon;        // become a daemon after start?
  int  debug;         // is debug on?

  // configured ievents cache related settings
  int cache_size;          // ievents cache max entries
  int cache_flush_delay;   // save ievents into db after that time period

  // configured sqlite3 db related settings
  char *db_config;           // config db connection string
  char *db_events;           // events db connection string
  char *db_q_get_dirs;       // query to get dirs to monitor from config db
  char *db_q_get_includes;   // query to get files include patterns from config db
  char *db_q_get_excludes;   // query to get files exclude patterns from config db
  char *db_q_store_ievents;  // query to store collected events in events db

  // runtime ievents data
  int inotify_fd;         // inotify file descriptor

  // dirs, files, exludes, etc...
  void *watch_dirs;       // tree of dirs that are watched by inotify
  char **dirs;            // dirs to monitor loaded from db
  char **inc_patterns;    // include patterns loaded from db
  char **exc_patterns;    // exclude patterns loaded from db

  // mutextes and other threads stuff
  pthread_mutex_t log_mutex;        // mutex for logging
  pthread_mutex_t db_mutex;         // db writes serialization mutex
  pthread_mutex_t tcounter_mutex;   // mutex for threads counter var
  pthread_cond_t  tcounter_condvar; // condvar for threads counter var
  int             tcounter;         // running DB writing threads counter var
  int             need_exit_sig;    // exit requested, contains caught signal or 0

};


// read and parse config file
int config_read(void);

// load dirs, patterns, etc from DB
int db_load_data(void);

// logging and debug funcs and macros
void wlog(const char *, ...);

#define WLOG(s, ...) do { \
  pthread_mutex_lock(&config->log_mutex); \
  time_t t = time(NULL); \
  wlog("%24.24s [%lu](%s:%d) " s "\n", ctime(&t), getpid(), __FUNCTION__, __LINE__, ##__VA_ARGS__); \
  pthread_mutex_unlock(&config->log_mutex); \
} while (0)

#define DLOG(s, ...) do {\
  if (config->debug) \
    WLOG("DEBUG: " s, ##__VA_ARGS__); \
} while (0)

// max number of threads for flushing events cache
#define MAX_FLUSH_THREADS     32

// init inotify mech
int ievent_init(void);

// find files and set up inotify on them
int ievent_add_dirs(void);

// start inotify loop
int ievent_start(void);

// events buf must be large enough to hold several events in chain
// so we can read() max 64 events at a time, the rest will be silently
// discarded
#define INOTIFY_EVENTS_MAX   64


