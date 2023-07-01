#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "data.h"
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
  int err = 0;
  vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT] = {0};
  size_t vulnerabilities_count = 0;

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

  err = parse_data (argv[1], vulnerabilities, &vulnerabilities_count);
  if (err)
    {
      fprintf (stderr, "main.c : main() : can't parse data.\n");
      goto cleanup;
    }

  init_ncurses (vulnerabilities, vulnerabilities_count);

  while (true)
    {
      bool quit = handle_key ();
      if (quit)
        break;
    }

  cleanup:
  cleanup_ncurses ();
  free_data (vulnerabilities, vulnerabilities_count);
  return err;
}
