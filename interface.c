#include <locale.h>
#include <ncurses.h>
#include <menu.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "data.h"
#include "utils.h"

#define MAX_LINES 2000
#define MAX_LINE_LENGTH 1000

WINDOW *list_win = NULL;
MENU *list_menu = NULL;
ITEM **items = NULL;

WINDOW *report_win = NULL;

static void
create_list_window ()
{
  list_win = newwin (LINES-1, COLS / 3, 0, 0);
  keypad (list_win, TRUE);
  box (list_win, 0, 0);
  wrefresh (list_win);
}

static void
create_report_window ()
{
  report_win = newwin (LINES-1, COLS / 3 * 2, 0, COLS / 3 + 1);
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
 * Reformat lines to fit the available `max_width`, so we know exactly
 * how many lines we need.
 *
 * That number of lines will be put into `count`, and the lines
 * will be in `lines`.
 *
 * You're responsible for freeing the strings contains in `lines`.
 *
 * Returns non-zero in case of error.
 */
static int
format_lines (size_t max_width, vulnerability_t *vulnerability, char *lines[MAX_LINES], size_t *count)
{
  int err = 0;
  char *desc_copy = NULL;

  lines[*count] = xalloc (max_width + 1);
  snprintf (lines[*count], max_width, "Category: %s", vulnerability->category);
  (*count)++;

  char *part = vulnerability->title;
  while (true)
    {
      if (*count + 1 == MAX_LINES)
        {
          err = 1;
          mvwprintw (report_win, 1, 1, "report contains too many lines (max allowed: %d).", MAX_LINES);
          wrefresh (report_win);
          goto cleanup;
        }

      lines[*count] = xalloc (max_width + 1);
      size_t would_write = snprintf (lines[*count], max_width, "%s", part);
      (*count)++;
      if (would_write > max_width)
        part += max_width;
      else
        break;
    }

  lines[*count] = xalloc (1);
  (*count)++;

  desc_copy = strdup (vulnerability->description);
  char *start = desc_copy;

  while (start)
    {
      char *end = strstr (start, "\n");
      size_t len = end ? (size_t) (end - start) : strlen (start);
      if (len > MAX_LINE_LENGTH)
        len = MAX_LINE_LENGTH;

      char line[len + 2];
      memset (line, 0, len + 2);
      snprintf (line, len + 1, "%s", start);

      char *part = line;

      while (true)
        {
          if (*count + 1 == MAX_LINES)
            {
              err = 1;
              mvwprintw (report_win, 1, 1, "report contains too many lines (max allowed: %d).", MAX_LINES);
              wrefresh (report_win);
              goto cleanup;
            }

          lines[*count] = xalloc (max_width + 2);
          size_t would_write = snprintf (lines[*count], max_width + 1, "%s", part);
          (*count)++;
          if (would_write > max_width)
            part += max_width;
          else
            break;
        }

      start = end;
      if (start && start[0] != 0)
        start++; // eat the \n character.
    }

  cleanup:
  if (desc_copy) free (desc_copy);
  return err;
}

/*
 * Display given vulnerability in main window.
 */
static int
show_report (vulnerability_t *vulnerability, size_t y)
{
  int err = 0;
  (void) y;

  wclear (report_win);
  size_t max_width = (COLS / 3 * 2) - 2;
  size_t max_height = LINES - 2;
  char *lines[MAX_LINES] = {0};
  size_t line_count = 0;

  err = format_lines (max_width, vulnerability, lines, &line_count);
  if (err)
    {
      fprintf (stderr, "interface.c : show_report() : can't format lines.\n");
      goto cleanup;
    }


  wattron (report_win, COLOR_PAIR(2));
  wattron (report_win, A_BOLD);
  for (size_t i = 0; i < max_height && i + y < line_count; i++)
    {
      mvwprintw (report_win, i + 1, 1, "%s", lines[i + y]);
      if (strlen (lines[i + y]) == 0)
        {
          wattroff (report_win, A_BOLD);
          wattroff (report_win, COLOR_PAIR(2));
        }
    }

  box (report_win, 0, 0);
  wrefresh (report_win);

  cleanup:
  for (size_t i = 0; i < line_count; i++)
    free (lines[i]);

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
  attron (COLOR_PAIR(1));
  refresh ();

  create_list_window ();
  create_report_window ();
  mvprintw (LINES - 1, 1, "Press q to quit");
  
  populate_list (vulnerabilities, vulnerabilities_count);

  if (vulnerabilities_count > 0)
    show_report (&vulnerabilities[0], 0);
  else
    mvwprintw (report_win, 1, 1, "No vulnerability found.");

  move (LINES - 1, COLS - 1);
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
