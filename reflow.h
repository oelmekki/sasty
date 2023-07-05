#ifndef _REFLOW_H_
#define _REFLOW_H_

#define MAX_LINES 2000

typedef struct {
  char *content;
  bool heading;
} line_t;

int reflow (size_t max_width, vulnerability_t *vulnerability, line_t lines[MAX_LINES], size_t *count, char **err_msg);

#endif
