#ifndef _INTERFACE_H_
#define _INTERFACE_H_

void init_ncurses (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count);
bool handle_key ();
void cleanup_ncurses ();

#endif
