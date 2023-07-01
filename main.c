#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "interface.h"

static void
usage (const char *progname)
{
  printf ("%s [-h|--help] <file|url> \n\
\n\
Brings a ncurses interface to inspect Gitlab's SAST reports. \n\
\n\
You can either provide a path to a downloaded JSON report, \n\
or provide its url, provided it's publicly accessible. \n\
  ", progname);
}

int
main (int argc, char **argv)
{
  if (argc != 2)
    {
      usage (argv[0]);
      return 1;
    }

  if (strncmp (argv[1], "--help", 6) == 0 || strncmp (argv[1], "-h", 2) == 0)
    {
      usage (argv[0]);
      return 0;
    }

  init_ncurses ();

  while (true)
    {
      bool quit = handle_key ();
      if (quit)
        break;
    }

  cleanup_ncurses ();
}
