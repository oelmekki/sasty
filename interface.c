#include <locale.h>
#include <ncurses.h>
#include <menu.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "data.h"
#include "reflow.h"
#include "utils.h"

WINDOW *list_win = NULL;
MENU *list_menu = NULL;
ITEM **items = NULL;

WINDOW *report_win = NULL;

static void
create_list_window ()
{
  list_win = newwin (LINES-1, COLS / 3, 0, 0);
  wattron (list_win, COLOR_PAIR (1));
  keypad (list_win, TRUE);
  box (list_win, 0, 0);
  wrefresh (list_win);
}

static void
create_report_window ()
{
  report_win = newwin (LINES-1, COLS / 3 * 2, 0, COLS / 3 + 1);
  wattron (report_win, COLOR_PAIR (1));
  keypad (report_win, TRUE);
  box (report_win, 0, 0);
  wrefresh (report_win);
}

/*
 * Fill the left menu with the names of vulnerabilities found.
 */
static void
populate_list (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count)
{
  if (vulnerabilities_count == 0)
    return;

  items = xalloc ((vulnerabilities_count + 1) * sizeof (ITEM *));
  for (size_t i = 0; i < vulnerabilities_count; i++)
    items[i] = new_item (vulnerabilities[i].title, NULL);

  list_menu = new_menu (items);
  set_menu_win (list_menu, list_win);
  set_menu_back (list_menu, COLOR_PAIR (1));

  WINDOW *sub = derwin (list_win, LINES - 3, COLS / 3 - 2, 1, 1);
  set_menu_sub (list_menu, sub);
	set_menu_format (list_menu, LINES - 3, 1);
  post_menu (list_menu);

  wrefresh (list_win);
  refresh ();
}

/*
 * Display given vulnerability in main window.
 */
static int
show_report (vulnerability_t *vulnerability, size_t y)
{
  int err = 0;

  wclear (report_win);
  size_t max_width = (COLS / 3 * 2) - 2;
  size_t max_height = LINES - 2;
  line_t lines[MAX_LINES] = {0};
  size_t line_count = 0;

  char *err_msg = NULL;
  err = reflow (max_width, vulnerability, lines, &line_count, &err_msg);
  if (err)
    {
      mvwprintw (report_win, 1, 1, "%s", err_msg);
      wrefresh (report_win);
      fprintf (stderr, "interface.c : show_report() : can't format lines.\n");
      goto cleanup;
    }

  if (y >= line_count - 2)
    y = line_count - 2;

  for (size_t i = 0; i < max_height && i + y < line_count; i++)
    {
      if (lines[i + y].heading)
        {
          wattron (report_win, COLOR_PAIR (2));
          wattron (report_win, A_BOLD);
        }

      mvwprintw (report_win, i + 1, 1, "%s", lines[i + y].content);

      if (lines[i + y].heading)
        {
          wattroff (report_win, A_BOLD);
          wattroff (report_win, COLOR_PAIR (2));
          wattron (report_win, COLOR_PAIR (1));
        }
    }

  box (report_win, 0, 0);
  wrefresh (report_win);

  cleanup:
  for (size_t i = 0; i < line_count; i++)
    free (lines[i].content);

  return err;
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
  init_pair (2, COLOR_YELLOW, COLOR_BLACK);
  attron (COLOR_PAIR (1));
  refresh ();

  create_list_window ();
  create_report_window ();
  mvprintw (LINES - 1, 1, "Press q to quit, J/K/tab/S-tab to navigate reports, j/k/DOWN/UP to scroll down/up the report");
  
  populate_list (vulnerabilities, vulnerabilities_count);

  if (vulnerabilities_count > 0)
    show_report (&vulnerabilities[0], 0);
  else
    {
      mvwprintw (report_win, 1, 1, "No vulnerability found.");
      wrefresh (report_win);
    }

  move (LINES - 1, COLS - 1);
  refresh ();
}

/*
 * Handle user input.
 *
 * Returns true if the program needs to quit.
 */
bool
handle_key (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count, size_t *current_vulnerability, size_t *current_line)
{
  int key = getch ();


  switch (key)
    {
      case 'q':
        return true;

      case 'j':
      case KEY_DOWN:
        if (vulnerabilities_count > 0)
          {
            (*current_line)++;
            show_report (&vulnerabilities[*current_vulnerability], *current_line);
            move (LINES - 1, COLS - 1);
          }
        break;

      case 'k':
      case KEY_UP:
        if (vulnerabilities_count > 0)
          {
            if (*current_line > 0)
              {
                (*current_line)--;
                show_report (&vulnerabilities[*current_vulnerability], *current_line);
                move (LINES - 1, COLS - 1);
              }
          }
        break;

      case 'J':
      case '\t':
        if (vulnerabilities_count > 0)
          if (*current_vulnerability < vulnerabilities_count - 1)
            {
              (*current_vulnerability)++;
              *current_line = 0;
              menu_driver (list_menu, REQ_DOWN_ITEM);
              wrefresh (list_win);
              show_report (&vulnerabilities[*current_vulnerability], *current_line);
              move (LINES - 1, COLS - 1);
            }

        break;

      case 'K':
      case KEY_BTAB:
        if (vulnerabilities_count > 0)
          if (*current_vulnerability > 0)
            {
              (*current_vulnerability)--;
              *current_line = 0;
              menu_driver (list_menu, REQ_UP_ITEM);
              wrefresh (list_win);
              show_report (&vulnerabilities[*current_vulnerability], *current_line);
              move (LINES - 1, COLS - 1);
            }

        break;
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
