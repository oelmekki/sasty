#ifndef _DATA_H_
#define _DATA_H_

#include <stddef.h>

#define MAX_VULNERABILITY_COUNT 100
#define MAX_CATEGORY_LENGTH 500
#define MAX_TITLE_LENGTH 1000
#define MAX_DESC_LENGTH 100000
#define MAX_LOCATION_LENGTH 1000

typedef struct {
  char *category;
  char *title;
  char *description;
  char *file;
} vulnerability_t;

int parse_data (const char *uri, vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t *vulnerabilities_count);
void free_data (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count);

#endif
