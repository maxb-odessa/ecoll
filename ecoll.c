/**********************************************************
 *
 * Linux FS File Monitor
 *
 * Files Integrity Monitor (inotify events collector)
 *
 * MAIN FILE
 *
 ***********************************************************/

#include "ecoll.h"

// init configuration and runtime data
struct config *config;

/*******************************************************************/
/*******************************************************************/
/*******************************************************************/

// cleanup on exit
void cleanup(void) {

  // remove pid file if have one
  if (config->pid_file)
    unlink(config->pid_file);

  // destroy inotify handler (if opened)
  if (config->inotify_fd >= 0)
    close(config->inotify_fd);
}

// signal handler to do graceful exit
// args: signal
// ret: nothing
sighandler_t sig_exit(int sig) {

  // raise 'we are sinking!' flag
  config->need_exit_sig = sig;

  // no working threads found - exit normally
  if (config->tcounter < 0) {
    WLOG("INFO: Got signal %d, exiting", sig);
    exit(0);
  }

  // we must return in case some threads are still
  // working and wait for them to finish jobs
  return 0;
}


// signal handler for reexec self
// args: signal
// ret: nothing
void sig_hup(int sig) {
  // logger mutex may be locked by some thread - have to unlock it
  if (! pthread_mutex_trylock(&(config->log_mutex)))
    pthread_mutex_unlock(&(config->log_mutex));

  WLOG("INFO: Got SIGHUP, re-executing self '%s %s'", config->execpath, config->argv[1]);

  // nothing to care about: all opened fds (except 0,1,2 will be closed,
  // malloced() mem will be freed, and much more; the pid will remain so
  // no need to delete/update pidfile

  // re-exec self now
  execve(config->execpath, config->argv, NULL);

  // exec() must not return - too bad
  WLOG("CRITICAL: execve() failed: %s", strerror(errno));

  exit(1);
}



/*******************************************************************/
/*******************************************************************/
/*******************************************************************/


// main part
// we all know what argc and argv means, don't we? :)
// NOTE: the 'weak' attribute here is for unit tests that have
// their own main() funcs which must overrride our main()
__attribute__((weak))
int main(int argc, char *argv[]) {

struct config cnf = {
  NULL,
  {NULL, NULL, NULL},
  NULL,
  NULL,
  NULL,
  0,
  0,
  8192,
  60,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  -1,
  NULL,
  NULL,
  NULL,
  NULL,
  PTHREAD_MUTEX_INITIALIZER,
  PTHREAD_MUTEX_INITIALIZER,
  PTHREAD_MUTEX_INITIALIZER,
  PTHREAD_COND_INITIALIZER,
  -1,
  0,
};

config = &cnf;

  // we expect exactly one mandatory argument - config file path
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <config-file-path>\n", argv[0]);
    exit(1);
  } else {
    config->config_file = strdup(argv[1]);
    assert(config->config_file);
  }

  // set exit() handler for cleanups
  atexit(&cleanup);

  // read and parse config file
  if (config_read()) {
    WLOG("ERROR: Configuration failed, exiting.");
    fputs("ERROR: Configuration failed (see log file)! Exiting.\n", stderr);
    exit(1);
  } else
    WLOG("INFO: STARTING");

  // guess our exec path (needed for execve())
  // or if this fails we disable SIGHUP handling
  config->execpath = realpath(argv[0], NULL);
  if (config->execpath) {

    // preserve args for future execve() call
    config->argv[0] = strdup(argv[0]);
    assert(config->argv[0]);
    config->argv[1] = realpath(argv[1], NULL);
    if (! config->argv[1])
      config->argv[1] = strdup(argv[1]);
    assert(config->argv[1]);

    // we do have our exec and config file paths, so we can setup SIGHUP handler
    struct sigaction sig_action;
    sig_action.sa_handler = sig_hup;
    sigemptyset(&sig_action.sa_mask);
    sig_action.sa_flags = SA_NODEFER;
    sigaction(SIGHUP, &sig_action, NULL);

  } else
    WLOG("WARNING: Failed to guess our full path, disbling SIGHUP handling.");

  // check pid file (if configured)
  if (config->pid_file) {
    // open pid file
    FILE *pidfp = fopen(config->pid_file, "r");
    if (pidfp) {
      // ok, pid file opened, get pid from it
      long unsigned pid;
      if (fscanf(pidfp, "%lu", &pid) == 1) {
        // got pid, check is it alive
        // mind that we may be here after exec() and our pid is the same as strored in
        // pidfile, so we must not check the pid here
        if (pid != getpid() && ! kill((pid_t)pid, 0)) {
          // alive!
          WLOG("ERROR: Another copy is running, pid %lu. Exiting.", pid);
          fputs("ERROR: Another copy is running (see log file)! Exiting.\n", stderr);
          exit(1);
        }
      }
      fclose(pidfp);
    }
    // all ok: no pidfile or no pid in file or no valid pid
  }

  // become a daemon (if configured)
  if (config->daemon) {
    pid_t pid = fork();
    // fork failed...
    if (pid < 0) {
      WLOG("ERROR: fork() failed: %s", strerror(errno));
      fputs("ERROR: Failed to become a daemon (see log file)! Exiting.\n", stderr);
      exit(1);
    // child spawned
    } else if (pid > 0) {
      WLOG("INFO: Daemonized, child pid %lu", pid);
      exit(0);
    // we are the child
    } else {
      // close stdin, stdout (but we might still use 'stderr')
      fclose(stdin);
      fclose(stdout);
      // detach from parent proc group
      setsid();
    }
  }

  // create pid file (if confgured)
  if (config->pid_file) {
    FILE *pidfp = fopen(config->pid_file, "w");
    if (! pidfp) {
      WLOG("ERROR: Failed to create pid file '%s': %s", config->pid_file, strerror(errno));
      fputs("ERROR: Failed to create pid file (see log file)! Exiting.\n", stderr);
      exit(1);
    } else {
      fprintf(pidfp, "%lu", (unsigned long)getpid());
      fclose(pidfp);
    }
  }

  // load dirs and patterns from db
  if (db_load_data()) {
    WLOG("ERROR: Failed to load data from DB, exiting.");
    fputs("ERROR: Failed to load data from DB! Exiting.\n", stderr);
    exit(1);
  }
 
  // init inotify mech
  if (ievent_init()) {
    WLOG("ERORR: failed to init inotify subsystem, exiting.");
    fputs("ERORR: failed to init inotify subsystem (see log file)! Exiting.\n", stderr);
    exit(1);
  }
 
  // find files to monitor and set up inotify handlers on them
  if (ievent_add_dirs()) {
    WLOG("ERROR: Failed to to set up inotify handlers on files, exiting.");
    fputs("ERROR: Failed to to set up inotify handlers on files (see log file)! Exiting.\n", stderr);
    exit(1);
  }

  // setup signal handlers
  signal(SIGINT, (void *)&sig_exit);
  signal(SIGQUIT, (void *)&sig_exit);
  signal(SIGABRT, (void *)&sig_exit);
  signal(SIGTERM, (void *)&sig_exit);

  // start files monitoring
  if (ievent_start()) {
    WLOG("ERROR: Dirs monitoring failed, exiting.");
    fputs("ERROR: Dirs monitoring failed (see log file)! Exiting.\n", stderr);
    exit(1);
  }
  

  // must not be reached, but who knows...
  return 0;
}





/******************************************************************/
/******************************************************************/
/******************************************************************/

// logging func
// will log to file if it specified in config and if we _can_ do so
// or log to stderr otherwise
// args: format, optional data
// ret: nothing
void wlog(const char *format, ...) {

  va_list ap;
  va_start(ap, format);

  // try to open logfile if specified
  FILE *logfp = NULL;
  if (config->log_file)
    logfp = fopen(config->log_file, "a");

  // print to stderr if log open failed
  if (! logfp)
    vfprintf(stderr, format, ap);
  // or to logfile
  else {
    vfprintf(logfp, format, ap);
    fclose(logfp);
  }

  va_end(ap);
}






/************************************************************************/
/************************************************************************/
/************************************************************************/

// read and parse config file (it is in YAML format)
// fill in global `config' structure
// args: none
// ret: 0 if ok, !0 otherwise
int config_read(void) {

  // open config file
  FILE *conffp = fopen(config->config_file, "r");
  if (! conffp) {
    WLOG("ERROR: failed to open %s: %s", config->config_file, strerror(errno));
    return 1;
  }

  // init YAML parser
  yaml_parser_t yaml_parser;
  yaml_token_t yaml_token;
  if (! yaml_parser_initialize(&yaml_parser)) {
    WLOG("ERROR: failed to init YAML parser: %s", yaml_parser.problem);
    return 1;
  }

  // set config file to parser
  yaml_parser_set_input_file(&yaml_parser, conffp);

  enum {
    SECTION_NONE,
    SECTION_MAIN,
    SECTION_CACHE,
    SECTION_DB,
  };
  char *key = NULL;
  int section = SECTION_NONE, prev_token = -1, block_level = -1, into_block = 0, found_main = 0;

  // start parsing
  do {

    if (! yaml_parser_scan(&yaml_parser, &yaml_token)) {
      WLOG("ERROR: Error in config file: %s (%d:%d)", 
           yaml_parser.problem, 
           yaml_parser.problem_mark.line,
           yaml_parser.problem_mark.column);
      return 1;
    }

    switch(yaml_token.type) {

      // block start
      case YAML_BLOCK_MAPPING_START_TOKEN:
        prev_token = YAML_BLOCK_MAPPING_START_TOKEN;
        block_level ++;
        break;

      // key
      case YAML_KEY_TOKEN:
        if (prev_token == YAML_BLOCK_MAPPING_START_TOKEN)
          into_block = 1;
        prev_token = YAML_KEY_TOKEN;
        break;

      // value
      case YAML_VALUE_TOKEN:
        prev_token = YAML_VALUE_TOKEN;
        break;

      // block end
      case YAML_BLOCK_END_TOKEN:
        prev_token = -1;
        if (section == SECTION_DB || section == SECTION_CACHE)
          section = SECTION_MAIN;
        else
          section = SECTION_NONE;
        block_level --;
        if (key)
        into_block = 0;
          free(key);
        key = NULL;
        break;

      // key or value data 
      case YAML_SCALAR_TOKEN:

         // got value
         if (prev_token == YAML_VALUE_TOKEN) {

           // ignore unknown sections
           if (section == SECTION_NONE)
             break;

           // value = yaml_token.data.scalar.value;
           //WLOG(" section: %d, key: %s, value: %s", section, key, value);

           // main section params
           if (section == SECTION_MAIN) {

             if (! strcmp(key, "pid-file")) {
               config->pid_file = strdup((char *)yaml_token.data.scalar.value);
               assert(config->pid_file);
             } else if (! strcmp(key, "log-file")) {
               config->log_file = strdup((char *)yaml_token.data.scalar.value);
               assert(config->log_file);
             } else if (! strcmp(key, "debug")) {
               config->debug = atoi((char *)yaml_token.data.scalar.value);
             } else if (! strcmp(key, "daemon")) {
               config->daemon = atoi((char *)yaml_token.data.scalar.value);
             }
             // and silently ignore unknown options

           // cache section params
           } else if (section == SECTION_CACHE) {

             if (! strcmp(key, "size")) {
               config->cache_size = atoi((char *)yaml_token.data.scalar.value);
             } else if (! strcmp(key, "flush-delay")) {
               config->cache_flush_delay = atoi((char *)yaml_token.data.scalar.value);
             }
             // and silently ignore unknown options

           // db section params
           } else if (section == SECTION_DB) {

             if (! strcmp(key, "config")) {
               config->db_config = strdup((char *)yaml_token.data.scalar.value);
               assert(config->db_config);
             } else if (! strcmp(key, "events")) {
               config->db_events = strdup((char *)yaml_token.data.scalar.value);
               assert(config->db_events);
             } else if (! strcmp(key, "get-dirs")) {
               config->db_q_get_dirs = strdup((char *)yaml_token.data.scalar.value);
               assert(config->db_q_get_dirs);
             } else if (! strcmp(key, "get-inc")) {
               config->db_q_get_includes = strdup((char *)yaml_token.data.scalar.value);
               assert(config->db_q_get_includes);
             } else if (! strcmp(key, "get-exc")) {
               config->db_q_get_excludes = strdup((char *)yaml_token.data.scalar.value);
               assert(config->db_q_get_excludes);
             } else if (! strcmp(key, "store-events")) {
               config->db_q_store_ievents = strdup((char *)yaml_token.data.scalar.value);
               assert(config->db_q_store_ievents);
             }

             // and silently ignore unknown options

           }
             
           // no need in key anymore
           free(key);
           key = NULL;
           break;
         }
 
         // got block
         if (into_block && key) {
           into_block = 0;
           // we'r in our main block 
           if (block_level == 1 && ! strcmp(key, "ecoll")) {
             found_main ++;
             section = SECTION_MAIN;
           // we'r in our cache subblock
           } else if (block_level == 2 && ! strcmp(key, "cache")) {
             section = SECTION_CACHE;
           // we'r in our db subblock
           } else if (block_level == 2 && ! strcmp(key, "db")) {
             section = SECTION_DB;
           // not our block at all
           } else {
             section = SECTION_NONE;
           }
         }
 
         // got key
         if (prev_token == YAML_KEY_TOKEN) {
           // free prev copy of key
           if (key)
             free(key);
           // save new key
           key = strdup((char *)yaml_token.data.scalar.value);
           assert(key);
         } 

         break;

      // other
      default:
        break;

    } //switch(...)

    if (yaml_token.type != YAML_STREAM_END_TOKEN)
      yaml_token_delete(&yaml_token);

  } while(yaml_token.type != YAML_STREAM_END_TOKEN);

  // cleanups
  yaml_token_delete(&yaml_token);
  yaml_parser_delete(&yaml_parser);
  fclose(conffp);

  // no main section found at all
  if (! found_main) {
    WLOG("ERROR: No 'ecoll' section found in config file");
    return 1;
  }

  // check mandatory options presense
  if (! config->db_config ||
      ! config->db_events ||
      ! config->db_q_get_dirs ||
      ! config->db_q_store_ievents) {
    WLOG("ERROR: Some required DB settings missed");
    return 1;
  }

  // check events cache size
  if (config->cache_size < 8) {
    WLOG("WARNING: Events cache size is too small, using 8");
    config->cache_size = 8;
  }
  if (config->cache_flush_delay <= 0) {
    WLOG("WARNING: Invalid 'cache-flush-delay', using 60");
    config->cache_flush_delay = 60;
  }

  // all ok
  return 0;
}






/************************************************************************/
/************************************************************************/
/************************************************************************/

// this func loads var data from sqlite3db:
// dirs to monitor and file patterns (excludes and includes)
// results will be placed in config structrure as arrays
// args: none
// ret: 0 if ok, !0 otherwise
int db_load_data(void) {

  // sqlite3 db and query handlers
  sqlite3 *dbh;
  sqlite3_stmt *sth;

  // fetched rows counted
  int idx = 0;

  // enable URI support for file openings
#ifdef SQLITE_CONFIG_URI
  sqlite3_config(SQLITE_CONFIG_URI, 1);
#endif

  // open the db
  if (sqlite3_open(config->db_config, &dbh) != SQLITE_OK) {
    WLOG("ERROR: Failed to open DB '%s': %s", config->db_config, sqlite3_errmsg(dbh));
    return 1;
  } else
    DLOG("DB '%s' opened OK", config->db_config);
   
  /////// FIRST: get dirs (this may NOT fail, but empty list is OK)
 
  // prepare the query
  idx = 0;
  if (sqlite3_prepare(dbh, config->db_q_get_dirs, -1, &sth, NULL) != SQLITE_OK) {
    // failure, critical
    WLOG("ERROR: Failed to prepare SQL query '%s': %s", config->db_q_get_dirs, sqlite3_errmsg(dbh));
    sqlite3_close(dbh);
    return 1;
  } else {

    DLOG("Fetching dirs from DB");

    // init dirs storage array
    config->dirs = calloc(1, sizeof(char *));
    assert(config->dirs);
 
    // do the query and fetch dirs
    while (sqlite3_step(sth) == SQLITE_ROW) {

      // fetch a dir row
      char *dir = (char *)sqlite3_column_text(sth, 0);
      DLOG(" => fetched dir: '%s'", dir);

      // allocate space for new dir and store it in dirs array
      if (dir && *dir) {

        // resize dirs array to hold one more element
        config->dirs = realloc(config->dirs, (idx + 2) * sizeof(char *));
        assert(config->dirs);

        // add new dir to dirs array
        config->dirs[idx] = strdup(dir);
        assert(config->dirs[idx]);
        idx ++;
      }
    }

    // terminate dirs array
    config->dirs[idx] = NULL;

    // reset db query struct for next use
    sqlite3_finalize(sth);
  }

  WLOG("INFO: Loaded %d dir(s) from DB", idx);


  /////// SECOND: fetch 'include' patterns (this MAY fail, we can live with it) 

  // prepare the query
  idx = 0;
  if (sqlite3_prepare(dbh, config->db_q_get_includes, -1, &sth, NULL) != SQLITE_OK) {
    WLOG("WARNING: Failed to prepare SQL query '%s': %s", config->db_q_get_includes, sqlite3_errmsg(dbh));
  } else {

    DLOG("Fetching files include patterns from DB");

    // init incl storage array
    config->inc_patterns = calloc(1, sizeof(char *));
    assert(config->inc_patterns);

    // do the query and fetch includes
    while (sqlite3_step(sth) == SQLITE_ROW) {

      // fetch a include row
      char *incp = (char *)sqlite3_column_text(sth, 0);
      DLOG(" => fetched inc pattern: '%s'", incp);

      // allocate space for new pattern and store it in include patterns array
      if (incp && *incp) {

        // resize patterns array to hold one more element
        config->inc_patterns = realloc(config->inc_patterns, (idx + 2) * sizeof(char *));
        assert(config->inc_patterns);

        // add new inc pattern to patterns array
        config->inc_patterns[idx] = strdup(incp);
        assert(config->inc_patterns[idx]);
        idx ++;
      }
    }

    // terminate include patterns array
    config->inc_patterns[idx] = NULL;

    // reset db query struct for next use
    sqlite3_finalize(sth);
  }
    
  WLOG("INFO: Loaded %d include pattern(s) from DB", idx);


  /////// THIRD: fetch 'exclude' patterns (this MAY fail, we can live with it) 

  // prepare the query
  idx = 0;
  if (sqlite3_prepare(dbh, config->db_q_get_excludes, -1, &sth, NULL) != SQLITE_OK) {
    WLOG("WARNING: Failed to prepare SQL query '%s': %s", config->db_q_get_excludes, sqlite3_errmsg(dbh));
  } else {

    DLOG("Fetching files exclude patterns from DB");

    // init excl storage array
    config->exc_patterns = calloc(1, sizeof(char *));
    assert(config->exc_patterns);

    // do the query and fetch excludes
    while (sqlite3_step(sth) == SQLITE_ROW) {

      // fetch a include row
      char *excp = (char *)sqlite3_column_text(sth, 0);
      DLOG(" => fetched exc pattern: '%s'", excp);

      // allocate space for new pattern and store it in exclude patterns array
      if (excp && *excp) {

        // resize patterns array to hold one more element
        config->exc_patterns = realloc(config->exc_patterns, (idx + 2) * sizeof(char *));
        assert(config->exc_patterns);

        // add new exc pattern to patterns array
        config->exc_patterns[idx] = strdup(excp);
        assert(config->exc_patterns[idx]);
        idx ++;
      }
    }

    // terminate exc patterns array
    config->exc_patterns[idx] = NULL;

    // reset db query struct
    sqlite3_finalize(sth);
  }
    
  WLOG("INFO: Loaded %d exclude pattern(s) from DB", idx);

  // done, destroy sqlite3 related structs
  sqlite3_close(dbh);

  return 0;
}





/************************************************************************/
/************************************************************************/
/************************************************************************/

// cmp func for tsearch()/tfind()
// search a tree by watch descriptor
int wdir_cmp_f(const void *wf1, const void *wf2) {
  return ((wdir_t *)wf1)->wd - ((wdir_t *)wf2)->wd;
}


// add dir to inotify cache AND to local dirs tree
// args: path to dir
// ret: new wdir_t* or NULL on failure
__attribute__((always_inline))
wdir_t inline *wdir_add(char *dir) {

  // events to monitor (IN_EXCL_UNLINK IN_ALL_EVENTS IN_ONLYDIR IN_MOVE_SELF|IN_MOVED_FROM|IN_MOVED_TO)
  uint32_t flags = IN_ONLYDIR|IN_ATTRIB|IN_CLOSE_WRITE|IN_CREATE|IN_DELETE|IN_DELETE_SELF;

  // add handler
  int wd = inotify_add_watch(config->inotify_fd, dir, flags);
  if (wd < 0) {
    WLOG("ERROR: Failed to add inotify() on '%s': %s", dir, strerror(errno));
    return NULL;
  }

  // create new tree node
  wdir_t *wdir = calloc(1, sizeof(wdir_t));
  assert(wdir);
  wdir->dir = strdup(dir);
  assert(wdir->dir);
  wdir->wd = wd;

  // add file to the tree
  wdir_t **nwdir = (wdir_t **)tsearch((void *)wdir, &(config->watch_dirs), wdir_cmp_f);

  // we already have this dir; it could be because of i.e. symlink and is not a case
  // to abort dirs scan; so print a warning and return already installed dir node
  if (*nwdir != wdir) {
    WLOG("WARNING: Failed to install '%s' in watched dirs tree: %s", dir, strerror(errno));
    free(wdir->dir);
    free(wdir);
    return *nwdir;
  }

  // all ok
  return wdir;
}



// cmp func for tdelte()
// search a tree by watch descriptor and free its data
int wdir_cmp_df(const void *wf1, const void *wf2) {
  int diff = ((wdir_t *)wf1)->wd - ((wdir_t *)wf2)->wd;
  if (diff == 0) {
    if (((wdir_t *)wf2)->dir)
      free(((wdir_t *)wf2)->dir);
    inotify_rm_watch(config->inotify_fd, ((wdir_t *)wf2)->wd);
    free((wdir_t *)wf2);
  }
  return diff;
}



// remove watched dir from inotify cache AND from local dirs tree
// args: watch descriptor
// ret: 0 if ok, !0 otherwise
int wdir_del(int wd) {

  // prepare node data for search
  wdir_t *wdp = calloc(1, sizeof(wdir_t));
  assert(wdp);
  wdp->wd = wd;
  
  // search and delete, also free node memory
  wdir_t **nwd = (wdir_t **)tdelete((void *)wdp, &(config->watch_dirs), wdir_cmp_df);

  // free pattern tree node (real node data will be freed in wdir_cmp_df())
  free(wdp);

  // not found!
  if (! nwd)
    return 1;

  // ok, deleted
  return 0;
}


// search watched dirs for specific watch descriptor
// args: watch descriptor
// ret: found entry
__attribute__((always_inline))
wdir_t inline *wdir_get(int wd) {

  // prepare node data for search
  wdir_t *wdp = calloc(1, sizeof(wdir_t));
  assert(wdp);
  wdp->wd = wd;

  // search for a node
  wdir_t **wdf = (wdir_t **)tfind((void *)wdp, &(config->watch_dirs), wdir_cmp_f);

  free(wdp);

  // found, return node data
  if (wdf)
    return *wdf;

  // return found node
  return NULL;
}






/************************************************************************/
/************************************************************************/
/************************************************************************/

// init inotify mech
// args: none
// ret: 0 if ok, !0 otherwise
int ievent_init(void) {

  config->inotify_fd = inotify_init();
  if (config->inotify_fd == -1) {
    WLOG("ERRROR: inotify_init() failed: %s", strerror(errno));
    return 1;
  }

  return 0;
}


// do patterns matching
// args: string, patterns array
// ret: 0 if match, !0 otherwise
__attribute__((always_inline))
int inline match_string(char *str, char **patterns) {

  // safety first :)
  if (! patterns || ! *patterns || ! str)
    return 1;

  int i;
  for (i = 0; patterns[i]; i ++) {
    if (! fnmatch(patterns[i], str, FNM_CASEFOLD))
      return 0;
  }

  return 1;
}



// read directory content, add inotify handler to each dir
// args: dir path
// ret: num of processed dirs or -1 on error
int read_dir_r(char *dir) {

  int num = 0;
 
  // open dir
  DIR *dp = opendir(dir);
  if (! dp) {
    WLOG("WARNING: opendir('%s') failed: %s", dir, strerror(errno));
    return 0;
  }

  // read dir content
  char path[PATH_MAX + NAME_MAX + 2];
  struct dirent *de;
  while ((de = readdir(dp))) {

    // skip . and ..
    if (! strcmp(".", de->d_name) || ! strcmp("..", de->d_name))
       continue;

    // make full path of object
    if (strlen(dir) + strlen(de->d_name) + 1 >= sizeof(path)) {
      WLOG("WARNING: Path '%s/%s' is too long, skipped", dir, de->d_name);
      continue;
    } else {
      strcpy(path, dir);
      strcat(path, "/");
      strcat(path, de->d_name);
    }

#if 0
    // apply pattern filters at path to include or exclue dirs from
    // being watched

    //#warning TBD: problem is: we need to monitor ALL dirs if mask, ex, *.js. How? (dirs are not in inc patterns)
    // *** TEMP SOLUTION! WE'LL MONITOR ALL DIRS AND FILTER OUT INTERESTING EVENTS IN EVENTS HANDLER

    // skip path if NOT in INCLUDE patterns list
    if (match_string(path, config->inc_patterns))
      continue;

    // skip path if IS in EXCLUDE patterns list
    if (! match_string(path, config->exc_patterns))
      continue;
#endif

    // stat an obj (we don't use de->d_type because it is unreliable)
    struct stat st;
    if (lstat(path, &st)) {
      WLOG("WARNING: lstat('%s') failed: %s", path, strerror(errno));
      continue;
    }

    // object is a dir - go recursive
    if (S_ISDIR(st.st_mode))
      num += read_dir_r(path);
  }

  // close dir
  closedir(dp);

  // add directory itself for monitoring
  if (wdir_add(dir) == NULL)
    return -1;

  // return num of object added for monitoring
  return ++ num;
}



// search configured dirs for subdirs and set up
// inotify handlers on them
// args: none
// ret: 0 if ok, !0 otherwise
int ievent_add_dirs(void) {

  // read directories
  int i, total = 0;
  for (i = 0; config->dirs[i]; i ++) {

    WLOG("INFO: scanning dir '%s'", config->dirs[i]);

    int n = read_dir_r(config->dirs[i]);

    // bad: failed to add file
    if (n < 0)
      return 1;

    WLOG("INFO: scanned %d subdirs", n);

    total += n;

    free(config->dirs[i]);
  }

  WLOG("INFO: total %d dirs set to monitor", total);

  free(config->dirs);

  return 0;
}



/************************************************************************/
/************************************************************************/
/************************************************************************/

   
// flush collected events to DB (thread!)
// args: events list
// ret: 0 if ok, !0 otherwise
void *ievent_flush(void *datap) {
 
  // this is for readability :)
  ievent_t *ievents = datap;

  // sqlite3 db and query handlers
  sqlite3 *dbh = NULL;
  sqlite3_stmt *sth = NULL;

#ifdef SQLITE_CONFIG_URI
  // enable URI support for file openings
  sqlite3_config(SQLITE_CONFIG_URI, 1);
#else
  // enable shared cache
  sqlite3_enable_shared_cache(1);
#endif

  // disable sqlite3 internal serialization
  sqlite3_config(SQLITE_CONFIG_MULTITHREAD, 1);

  // lock the DB
  // sqlite3 itself can't properly handle simultanious DB writes
  // from many threads, so we have no choise other then to do
  // db writes serialization ourself using mutexes
  pthread_mutex_lock(&(config->db_mutex));

  // open the db
  if (sqlite3_open(config->db_events, &dbh) != SQLITE_OK) {
    WLOG("ERROR: Failed to open DB '%s': %s", config->db_events, sqlite3_errmsg(dbh));
    goto BAIL_OUT;
  } else
    DLOG("DB '%s' opened OK", config->db_events);


  // begin transaction
  sqlite3_exec(dbh, "BEGIN TRANSACTION", NULL, NULL, NULL);

  // prepare insert statement
  if (sqlite3_prepare(dbh, config->db_q_store_ievents, -1, &sth, NULL) != SQLITE_OK) {
    WLOG("ERROR: Failed to prepare SQL query '%s': %s", config->db_q_store_ievents, sqlite3_errmsg(dbh));
    goto BAIL_OUT;
  }

  // insert events (last free array slot has empty file path)
  int i;
  for (i = 0; ievents[i].path[0]; i ++) {

    //DLOG("DB: storing %s %s", ievents[i].event, ievents[i].path);

    // bind data to sql query anchors
    if (sqlite3_bind_text(sth, 1, ievents[i].path, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int(sth, 2, ievents[i].is_dir) != SQLITE_OK ||
        sqlite3_bind_text(sth, 3, ievents[i].event, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int64(sth, 4, ievents[i].ts) != SQLITE_OK) {
      WLOG("ERROR: Failed to bind values to anchors in '%s': %s", config->db_q_store_ievents, sqlite3_errmsg(dbh));
      goto BAIL_OUT;
    }

    // exec the query, try to aquire db lock 3 times
    int rc = sqlite3_step(sth);
    if (rc != SQLITE_OK && rc != SQLITE_DONE) {
      WLOG("WARNING: Failed to insert ('%s', %d, '%s', %lu): %s",
           ievents[i].path, ievents[i].is_dir, ievents[i].event, ievents[i].ts, sqlite3_errmsg(dbh));
      goto BAIL_OUT;
    }

    // reset prepared query for reuse
    sqlite3_reset(sth);

  }

  // commit transaction
  sqlite3_exec(dbh, "COMMIT TRANSACTION", NULL, NULL, NULL);
  WLOG("INFO: Stored %d events in DB", i);

BAIL_OUT:

  // close db
  if (dbh)
    sqlite3_finalize(sth);
  if (sth)
    sqlite3_close(dbh);

  // unlock the DB
  pthread_mutex_unlock(&(config->db_mutex));

  // decrease flushing threads counter
  pthread_mutex_lock(&(config->tcounter_mutex));
  config->tcounter --;
  pthread_cond_signal(&(config->tcounter_condvar));
  pthread_mutex_unlock(&(config->tcounter_mutex));

  // free saved events list
  free(datap);

  // destroy thread
  pthread_exit(NULL);
}


// inotify events buffer len
#define INOTIFY_BUF_LEN  65536

// collect and process inotify events
// args: events array, index to place event entry
// ret: num of events processed 
int ievent_process(ievent_t *ievents, int idx) {

  // events buffer
  __attribute__ ((aligned(__alignof__(struct inotify_event)))) char buf[INOTIFY_BUF_LEN];

  // get an events data (get all events!)
  ssize_t bytes_read = read(config->inotify_fd, buf, INOTIFY_BUF_LEN);
  if (bytes_read < 0) {
    WLOG("ERROR: read() failed: %s", strerror(errno));
    return 0;
  }
  // DLOG("read() = %d", bytes_read);

  // processed events counter
  int events_num = 0;

  // walk over all fetched events buf not more than INOTIFY_EVENTS_MAX at once
  char *evp;
  for (evp = buf; evp < buf + bytes_read && events_num < INOTIFY_EVENTS_MAX; ) {

    // this is our current event in chain
    struct inotify_event *ev = (struct inotify_event *)evp;

    // prepare pointer to be set at next event struct in buf
    evp += sizeof(struct inotify_event) + ev->len;

    // ignore `bad' events
    if (ev->wd < 0 || (ev->mask & IN_IGNORED))
      continue;
    else if (ev->mask & IN_Q_OVERFLOW) {
      WLOG("WARNING: Inotify queue overflown!");
      break;
    }

    // find event wd in our watched dirs tree
    wdir_t *wdir = wdir_get(ev->wd);
    if (! wdir) {
      WLOG("WARNING: got event we'r not monitoring, strange...");
      continue;
    }

    // convert event string to a string appropriate to store in DB
    char *event_str = NULL;
    if (ev->mask & IN_ATTRIB)
      event_str = "ATTRIB";
    else if (ev->mask & IN_CLOSE_WRITE)
      event_str = "MODIFY";
    else if (ev->mask & IN_CREATE)
      event_str = "CREATE";
    else if (ev->mask & IN_DELETE)
      event_str = "DELETE";
    else if (ev->mask & IN_DELETE_SELF)
      event_str = "DELETE_SELF";
#if 0  // for debug
    else if (ev->mask & IN_MOVED_TO)
      event_str = "RENAME";
    else if (ev->mask & IN_MOVE_SELF)
      event_str = "RENAME_SELF";
    else if (ev->mask & IN_MOVED_FROM)
      event_str = "RENAME";
    if (ev->mask & IN_ACCESS)
      event_str = "IN_ACCESS";
    if (ev->mask & IN_CLOSE_NOWRITE)
      event_str = "IN_CLOSE_NOWRITE";
    if (ev->mask & IN_MODIFY)
      event_str = "IN_MODIFY";
    if (ev->mask & IN_OPEN)
      event_str = "IN_OPEN";
    if (ev->mask & IN_IGNORED)
      event_str = "IN_IGNORED";
    if (ev->mask & IN_Q_OVERFLOW)
      event_str = "IN_Q_OVERFLOW";
    if (ev->mask & IN_UNMOUNT)
      event_str = "IN_UNMOUNT";
#endif
      
    // a flag indicating the event must be stored and reported
    int good_event = 0;

    // now let's see what action arrived
    while (event_str) {

      // compose full event object path - add (possibly) present ev->name to watched dir
      // name associated with ev->wd
      strncpy(ievents[idx].path, wdir->dir, PATH_MAX);
      if (ev->len) {
        strcat(ievents[idx].path, "/");
        strncat(ievents[idx].path, ev->name, ev->len);
      }

      // also init event object data
      ievents[idx].is_dir = !!(ev->mask & IN_ISDIR);
      ievents[idx].event = event_str;
      ievents[idx].ts = time(NULL);

      DLOG("EV: wd:%d ev:%s dir:%d path:%s", ev->wd, event_str, ievents[idx].is_dir,  ievents[idx].path);

      // watched dir itself was deleted - unwatch it!
      // we monitor dirs only, so any 'delete_self' event may happen on dir only
      if (ev->mask & IN_DELETE_SELF) {
        DLOG("dir %s itself was deleted, unwatching it", ievents[idx].path);
        wdir_del(wdir->wd);
        break;
      }
 
      // an object is DIR
      if (ievents[idx].is_dir) {
        // new subdir created - add it to watched dirs tree recursively
        if (ev->mask & IN_CREATE) {
          int n = read_dir_r(ievents[idx].path);
          DLOG("dir %s was created, watching +%d subdirs", ievents[idx].path, n);
        }
#if 0
        // subdir deleted: no action here, we'll get IN_DELETE_SELF event and process it 
        else if (ev->mask & IN_DELETE) {
          DLOG("dir %s was deleted", ievents[idx].path);
          //wdir_del(wdir->wd);
        // dir renamed - TBD!
        } else if (ev->mask & (IN_MOVED_TO | IN_MOVED_FROM | IN_MOVE_SELF)) {
          DLOG("dir %s moved from/to/self - TBD!", ievents[idx].path);
          break;
        }
#endif
      }

      // all other supported events MAY be stored: either files or dirs.
      // we don't monitor files directly, and dirs was processed above;
      // so we let them all simply to be filtered out
      // and stored if they match our patterns.
 

      // skip event if path is NOT in INCLUDE patterns list
      if (match_string(ievents[idx].path, config->inc_patterns))
        break;

      // skip event if path IS in EXCLUDE patterns list
      if (! match_string(ievents[idx].path, config->exc_patterns))
        break;

      // filters passed - event is good
      good_event = 1;

      break;

    } //while(events_str...)

    // good event, advance its stored index
    if (good_event) {
      events_num ++;
      idx ++;
    // useless event - get rid of it and release related ievenets node
    } else
      ievents[idx].path[0] = '\0';

  } //for(events...)

  // return num of stored events
  DLOG("%d events processed", events_num);
  return events_num;
}


// wait for inotify events to happen and store them in DB
// we will create a thread for storing events
// args: none
// ret: 0 if ok, !0 if failed
int ievent_start() {

  // thread init vars
  pthread_t thread_id;
  pthread_attr_t thread_attr;

  // create detached threads by default
  pthread_attr_init(&thread_attr);
  pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

  // indicate that threading mech is turned on
  config->tcounter = 0;

  // init cache and other vars
  ievent_t *ievents = (ievent_t *)calloc(config->cache_size + 1, sizeof(ievent_t));
  assert(ievents);
  time_t flush_time = time(NULL) + config->cache_flush_delay;

  // this must point at next free events array entry!
  int ievents_idx = 0;

  // for select()
  fd_set fds;
  struct timeval tv;

  // start loop
  while (1) {

    // finita-la-comedia flag raised - wait for our doom
    if (config->need_exit_sig) {
      while(config->tcounter > 0) {
        WLOG("INFO: Waiting for %d thread(s) to finish", config->tcounter);
        sleep(1);
      }
      WLOG("INFO: Exiting by signal %d", config->need_exit_sig);
      exit(0);
    }

    // prepare select() args
    FD_ZERO(&fds);
    FD_SET(config->inotify_fd, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    // wait for events
    if (select(config->inotify_fd + 1, &fds, NULL, NULL, &tv) < 0) {
      if (errno != EINTR) {
        WLOG("ERROR: select() failed: %s", strerror(errno));
        return 1;
      } else
        continue;
    }

    // got an event!
    if (FD_ISSET(config->inotify_fd, &fds))
      ievents_idx += ievent_process(ievents, ievents_idx);

    // must flush cache if:
    // - flush deadline reached
    // - events cache is full
    // - have to exit
    if (config->need_exit_sig ||
        (ievents_idx > 0 && flush_time <= time(NULL)) ||
        ievents_idx >= config->cache_size - INOTIFY_EVENTS_MAX) {

      // wait for threads num to go down (if too many running)
      pthread_mutex_lock(&(config->tcounter_mutex));
      if (config->tcounter > MAX_FLUSH_THREADS) {
        WLOG("WARNING: All %d flushing threads are busy! Idling...", MAX_FLUSH_THREADS);
        pthread_cond_wait(&(config->tcounter_condvar), &(config->tcounter_mutex));
      }

      WLOG("INFO: Flushing %d event(s) (thread %d/%d)", ievents_idx, config->tcounter, MAX_FLUSH_THREADS);

      // increase threads counter
      config->tcounter ++;
      pthread_mutex_unlock(&(config->tcounter_mutex));

      // create a cache flushing thread (will detach itself)
      if (pthread_create(&thread_id , &thread_attr, ievent_flush, (void *)ievents) < 0) {
        WLOG("ERROR: Failed to create new thread: %s", strerror(errno));
        return 1;
      }

      // reinit events cache (old cache wil be freed by above call)
      ievents = (ievent_t *)calloc(config->cache_size + 1, sizeof(ievent_t));
      assert(ievents);

      // reset events index to first array element
      ievents_idx = 0;

      // reinit flush deadline
      flush_time = time(NULL) + config->cache_flush_delay;
    }

  }

  // should not be reached
  return 0;
}



