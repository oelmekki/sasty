#include <stdlib.h>
#include <stdio.h>

/*
 * Safely allocates memory.
 */
void *
xalloc (size_t len)
{
  void *mem = calloc (1, len);
  if (!mem)
    {
      fprintf (stderr, "xalloc() : can't allocated memory\n");
      exit (1);
    }

  return mem;
}
