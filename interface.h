#ifndef _INTERFACE_H_
#define _INTERFACE_H_

void init_ncurses (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count);
bool handle_key (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count, size_t *current_vulnerability, size_t *current_line);
void cleanup_ncurses ();

#endif
