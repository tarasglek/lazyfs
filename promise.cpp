#include <unistd.h>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

using namespace std;

typedef vector<string> strvec;

strvec promised_files;

void fail(const string &reason) {
  cerr << reason << endl;
  _exit(1);
}

void promise(const string &file) {
  promised_files.push_back(file);
}

void gcc(strvec &args) {
  strvec::iterator it = find(args.begin(), args.end(), string("-o"));
  if (it == args.end() || ++it == args.end())
    fail("Can't figure out gcc output from invocation");
  promise(*it);
}

void parse_args(int argc, char **argv) {
  strvec args;
  for(int i = 1;i < argc;i++)
    args.push_back(argv[i]);

  if (argc < 3)
    fail("Usage " + string(argv[0]) + " cmd args");

  const string &cmd = args[0];
  if (cmd == "g++" || cmd == "gcc")
    gcc(args);
  
  
  if (!promised_files.size())
    fail("Can't promise anything for " + cmd);
}

int main(int argc, char **argv) {
  parse_args(argc, argv);
  /**
     Fork the child process early so lazyfs can get the pid for it
   */
  if (pid_t cpid = fork()) {
    //parent 
    for(size_t i = 0;i < promised_files.size();i++) {
      const char *f = promised_files[0].c_str();
      int fd = open(f, O_WRONLY | O_CREAT);
      if (!fd)
        cerr << "Failed to open " << promised_files[i] << endl;
      close(fd);
      //unlink(f);
    }
    cerr << "finished " << getpid() <<  endl;
    // kill(cpid, SIGCONT);
    waitpid(cpid, NULL, 0);
    _exit(0);
  }
  // child
  // wait for parent to setup with lazyfs and exit
  cerr << "going to sleep" << endl;
  //kill(getpid(), SIGSTOP);
  sleep(5);
  cerr << "woke up" << endl;
  if (-1 == execvp(argv[1], argv + 1))
    perror("execvp");
  return 0;
}
