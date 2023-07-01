#include <locale.h>
#include <ncurses.h>
#include <menu.h>
#include <stdbool.h>
#include <stdlib.h>

#include "data.h"
#include "utils.h"

WINDOW *list_win = NULL;
MENU *list_menu = NULL;
ITEM **items = NULL;

WINDOW *details_win = NULL;

static void
create_list_window ()
{
  list_win = newwin (LINES-1, COLS / 3, 0, 0);
  keypad (list_win, TRUE);
  box (list_win, 0, 0);
  wrefresh (list_win);
}

static void
create_details_window ()
{
  details_win = newwin (LINES-1, COLS / 3 * 2, 0, COLS / 3 + 1);
  keypad (details_win, TRUE);
  box (details_win, 0, 0);
  wrefresh (details_win);
}


/*
 * Fill the left menu with the names of vulnerabilities found.
 */
static void
populate_list (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count)
{
  int err = 0;
  (void) vulnerabilities;
  (void) vulnerabilities_count;

  items = xalloc ((vulnerabilities_count + 1) * sizeof (ITEM *));
  for (size_t i = 0; i < vulnerabilities_count; i++)
    items[i] = new_item (vulnerabilities[i].title, NULL);

  list_menu = new_menu (items);
  set_menu_win (list_menu, list_win);

  WINDOW *sub = derwin (list_win, LINES - 3, COLS / 3 - 2, 1, 1);
  set_menu_sub (list_menu, sub);
	set_menu_format (list_menu, LINES - 3, 1);
  post_menu (list_menu);

  wrefresh (list_win);
  refresh ();
}

/*
 * Get ncurses interface ready.
 */
void
init_ncurses (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count)
{
  setlocale(LC_CTYPE, "");
  initscr ();
  cbreak ();
  keypad (stdscr, true);
  noecho ();
  start_color ();
  init_pair (1, COLOR_WHITE, COLOR_BLACK);
  init_pair (2, COLOR_BLACK, COLOR_WHITE);
  attron (COLOR_PAIR(1));
  refresh ();

  create_list_window ();
  create_details_window ();
  mvprintw (LINES-1, 1, "Press q to quit");
  
  populate_list (vulnerabilities, vulnerabilities_count);
  move (LINES-1, COLS-1);
  refresh ();
}

/*
 * Handle user input.
 *
 * Returns true if the program needs to quit.
 */
bool
handle_key ()
{
  int key = getch ();

  switch (key)
    {
      case 'q':
        return true;
    }

  return false;
}

void
cleanup_ncurses ()
{
  endwin ();
  if (list_menu) free_menu (list_menu);

  if (items)
    {
      for (size_t i = 0; i < MAX_VULNERABILITY_COUNT; i++)
        {
          ITEM *item = items[i];
          if (!item)
            break;

          free_item (item);
        }

      free (items);
    }
}
