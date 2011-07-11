#define _ATFILE_SOURCE
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/fanotify.h>
#include <string>
#include <map>
#include <assert.h>
#include <vector>
#include <iostream>

using namespace std;

/*
  protocol: 
  * promise <worker_pid> file
  This will suspend accesses to that particular file to everybody except a worker_pid(or child of it). Once waitpid(worker_pid) succeeds access is restored..if it failed, processes blocked on it will be killed
*/

int fan_fd;

bool opt_child, opt_on_mount, opt_add_perms, opt_fast, opt_ignore_perm;
int opt_sleep;

int mark_object(int fan_fd, const char *path, int fd, uint64_t mask, unsigned int flags)
{
  fprintf(stderr, "mark_object %s\n", path);
  return fanotify_mark(fan_fd, flags, mask, fd, path);
}

int set_ignored_mask(int fan_fd, int fd, uint64_t mask)
{
  unsigned int flags = (FAN_MARK_ADD | FAN_MARK_IGNORED_MASK);

  return mark_object(fan_fd, NULL, fd, mask, flags);
}

int handle_perm(int fan_fd, int fd)
{
  struct fanotify_response response_struct;
  int ret;

  response_struct.fd = fd;
  response_struct.response = FAN_ALLOW;

  ret = write(fan_fd, &response_struct, sizeof(response_struct));
  return ret >= 0;
}

bool read_proc_stat(const char *proc_pid_stat, pid_t *pid, pid_t *ppid) {
  char buf[PATH_MAX];
  int fd = open(proc_pid_stat, O_RDONLY);
  if (fd == -1)
    return false;
  int ret = read(fd, buf, sizeof(buf) - 1);
  if (ret > 0) {
    buf[ret] = 0;
    ret = sscanf(buf, "%d %*s %*c %d", pid, ppid);
  }
  close(fd);
  return ret == 2;
}

pid_t find_child(pid_t parent) {
  char buf[PATH_MAX];
  DIR *dirp = opendir("/proc");
  pid_t child = 0;
  if (!dirp)
    return 0;

  for (struct dirent *dp = readdir(dirp); dp; dp = readdir(dirp)) { 
    const char *name = dp->d_name;
    if (!(name && *name && name[0] >= '1' && name[0] <= '9'))
      continue;
    sprintf(buf, "/proc/%s/stat", name);
    pid_t pid, ppid;
    if (!read_proc_stat(buf, &pid, &ppid))
      continue;
    if (ppid == parent) {
      child = pid;
      break;
    }
  }
  closedir(dirp);
  return child;
}

char* fs2string(int fd, char *path, size_t len)
{
  sprintf(path, "/proc/self/fd/%d", fd);
  int path_len = readlink(path, path, len);
  assert(path_len > 0);
  path[path_len] = 0;
  return path;
}

struct Promise {
  Promise():fulfiller(0) {
  }
  Promise(pid_t fulfiller):fulfiller(fulfiller) {
  }
  pid_t fulfiller;
  vector<int> fdqueue;
};
typedef map<string, Promise> promise_map;
promise_map promises;

void check_promises() {
  for(promise_map::iterator it = promises.begin();it != promises.end();it++) {
    Promise &p = it->second;
    int ret = kill(p.fulfiller, 0);
    cerr << "kill " << p.fulfiller << " = "<< ret << endl;
    // process must exist
    if (ret == 0) continue;
    for(size_t i = 0;i<p.fdqueue.size();i++) {
      int fd = p.fdqueue[i];
      // these can now proceed
      handle_perm(fan_fd, fd);
      close(fd);
    }
    cerr << p.fulfiller << " finished" << endl;
    promises.erase(it);
    // since it's a non-mutable operator, can't continue enumeration
    check_promises();
    return;
  }
}

bool is_descendant_of(pid_t child, pid_t parent) {
  if (child == parent)
    return true;
  int pid, ppid;
  char buf[PATH_MAX];
  sprintf(buf, "/proc/%d/stat", child);
  if (!read_proc_stat(buf, &pid, &ppid))
    return false;
  if (!ppid)
    return false;
  return is_descendant_of(ppid, parent);
}

struct PermHandler {
  PermHandler(struct fanotify_event_metadata *metadata):
    fd(metadata->fd),
    active(metadata->mask & FAN_ALL_PERM_EVENTS)
  {
  }

  ~PermHandler() {
    if (active)
      assert(handle_perm(fan_fd, fd));
  }
  int fd;
  bool active;
};


bool handle_one_event(struct fanotify_event_metadata *metadata)
{
  char path[PATH_MAX];
  int path_len;

  const char* PROMISE = "/promise";
  static size_t promise_len = strlen(PROMISE);

  PermHandler permHandler(metadata);
  if (!(metadata->mask & FAN_OPEN_PERM && metadata->fd >= 0)) {
    return true;
  }

  check_promises();        

  sprintf(path, "/proc/%d/exe", metadata->pid);
  path_len = readlink(path, path, sizeof(path)-1);
  string exename;
  if (path_len) {
    path[path_len] = 0;
    exename = path;
  }

  string filepath = fs2string(metadata->fd, path, sizeof(path) - 1);
  cerr << exename << ": " << filepath;
  if (metadata->mask & FAN_ACCESS)
    cerr <<(" access");
  if (metadata->mask & FAN_OPEN)
    cerr <<(" open");
  if (metadata->mask & FAN_MODIFY)
    cerr <<(" modify {  }");
  if (metadata->mask & FAN_CLOSE) {
    if (metadata->mask & FAN_CLOSE_WRITE)
      cerr <<(" close(writable) {}");
    if (metadata->mask & FAN_CLOSE_NOWRITE)
      cerr <<(" close");
  }
  if (metadata->mask & FAN_OPEN_PERM)
    cerr <<(" open_perm");
  if (metadata->mask & FAN_ACCESS_PERM)
    cerr <<(" access_perm");

  cerr << endl;


  if (exename.length() > promise_len &&
      0 == strncmp(exename.c_str() + path_len - promise_len, PROMISE, promise_len)) {
    path[path_len] = '\0';
    string strpath(path, path_len);
    pid_t child = find_child(metadata->pid);
    if (child) {
      cerr << "promise that "<<child<<" will deliver " << filepath << endl;
      assert(promises.find(filepath) == promises.end());
      promises[filepath] = Promise(child);
    }
    return true;
  } 
  promise_map::iterator it = promises.find(filepath);
  if (it != promises.end()) {
    if (is_descendant_of(metadata->pid, it->second.fulfiller)) {
      cerr << "Letting " << exename << "(" << metadata->pid << " of " << it->second.fulfiller <<")"
           << " deliver " << filepath << endl;
      return true;
    }
    it->second.fdqueue.push_back(metadata->fd);
    cerr << exename << " will wait on " << filepath << endl;
    permHandler.active = false;
    return false;
  }

  return true;
}

int main(int argc, char *argv[])
{
  uint64_t fan_mask =  FAN_ACCESS|  FAN_ALL_PERM_EVENTS | FAN_EVENT_ON_CHILD;
  unsigned int mark_flags = FAN_MARK_ADD, init_flags = 0;
  ssize_t len;
  char buf[4096];
  fd_set rfds;

  opt_child = opt_on_mount = opt_add_perms = opt_fast = false;
  opt_ignore_perm = false;
  opt_sleep = 0;

  if (fan_mask & FAN_ALL_PERM_EVENTS)
    init_flags |= FAN_CLASS_CONTENT;
  else
    init_flags |= FAN_CLASS_NOTIF;

  fan_fd = fanotify_init(init_flags, O_RDONLY | O_LARGEFILE);
  if (fan_fd < 0)
    goto fail;

  if (mark_object(fan_fd, argv[1], AT_FDCWD, fan_mask, mark_flags) != 0)
    goto fail;

  FD_ZERO(&rfds);
  FD_SET(fan_fd, &rfds);

  while (select(fan_fd+1, &rfds, NULL, NULL, NULL) < 0)
    if (errno != EINTR)
      goto fail;

  while ((len = read(fan_fd, buf, sizeof(buf))) > 0) {
    struct fanotify_event_metadata *meta;
    for (meta = (struct fanotify_event_metadata *) buf;   
         FAN_EVENT_OK(meta, len); meta = FAN_EVENT_NEXT(meta, len)) {
                  
      if (meta->vers < 3) {
        fprintf(stderr, "Kernel fanotify version too old\n");
        goto fail;
      }
      // only close fds if they are ready to be closed
      if (handle_one_event(meta)) {
        if (meta->fd >= 0 && close(meta->fd) != 0)
          goto fail;
      } else {
        cerr << "handle_one_event returned false" << endl;

      }
      cerr.flush();
    }

                
    do {
      struct timeval tv = {1, 0};
      FD_ZERO(&rfds);
      FD_SET(fan_fd, &rfds);

      int ret = select(fan_fd+1, &rfds, NULL, NULL,  promises.empty() ? NULL : &tv);
      if (ret == 0) { 
        check_promises();
        continue;
      }
      else if (ret < 0 && errno == EINTR)
        continue;
    } while (false);
  }                  
  if (len < 0)
    goto fail;
  return 0;

 fail:
  fprintf(stderr, "%s\n", strerror(errno));
  return 1;
}
