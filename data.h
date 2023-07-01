#ifndef _DATA_H_
#define _DATA_H_

#define MAX_VULNERABILITY_COUNT 100

typedef struct {
  char *category;
  char *title;
  char *description;
} vulnerability_t;

int parse_data (const char *uri, vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t *vulnerabilities_count);
void free_data (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count);

#endif
