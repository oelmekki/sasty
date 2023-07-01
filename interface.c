#include <locale.h>
#include <ncurses.h>
#include <panel.h>
#include <stdbool.h>

WINDOW *list_win = NULL;
PANEL *list_pan = NULL;

WINDOW *details_win = NULL;
PANEL *details_pan = NULL;

static void
create_list_window ()
{
  list_win = newwin (LINES-1, COLS / 3, 0, 0);
  list_pan = new_panel (list_win);
  keypad (list_win, TRUE);
  box (list_win, 0, 0);
  wrefresh (list_win);
}

static void
create_details_window ()
{
  details_win = newwin (LINES-1, COLS / 3 * 2, 0, COLS / 3 + 1);
  details_pan = new_panel (details_win);
  keypad (details_win, TRUE);
  box (details_win, 0, 0);
  wrefresh (details_win);
}

/*
 * Get ncurses interface ready.
 */
void
init_ncurses ()
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

  create_list_window ();
  create_details_window ();
  mvprintw (LINES-1, 1, "Press q to quit");
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
}
