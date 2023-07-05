#include <ctype.h>
#include <locale.h>
#include <ncurses.h>
#include <menu.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "data.h"
#include "reflow.h"
#include "utils.h"

#define MAX_LINE_LENGTH 1000
char TOO_MANY_LINES[1000] = "report contains too many lines (max allowed: 1000).";

static void
remove_breaks_within_paragraphs (size_t len, char *string)
{
  if (len == 0)
    return;

  bool inside_code_block = false;

  for (size_t i = 0; i < len; i++)
    {
      if (strncmp (string + i, "```", 3) == 0)
        inside_code_block = !inside_code_block;

      if (string[i] == '\n')
        {
          if (strncmp (string + i, "\n```", 4) == 0)
            continue;

          if (strncmp (string + i, "\n\n", 2) == 0)
            i++;
          else
            {
              if (!inside_code_block)
                string[i] = ' ';
            }
        }
    }
}

static int
wrap (char *content, size_t max_width, line_t lines[MAX_LINES], size_t *count, char **err_msg, bool is_heading)
{
  int err = 0;
  char *start = content;
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
              *err_msg = TOO_MANY_LINES;
              goto cleanup;
            }

          lines[*count].content = xalloc (max_width + 2);
          lines[*count].heading = is_heading;
          if (strnlen (part, MAX_LINE_LENGTH) > max_width)
            {
              int last_space = max_width;
              for (int i = (int) max_width; i > 0; i--)
                {
                  if (isspace (part[i]))
                    {
                      last_space = i;
                      break;
                    }
                }

              snprintf (lines[*count].content, last_space + 1, "%s", part);
              (*count)++;
              part += last_space + 1;
            }
          else
            {
              snprintf (lines[*count].content, max_width + 1, "%s", part);
              (*count)++;
              break;
            }
        }

      start = end;
      if (start && start[0] != 0)
        start++; // eat the \n character.
    }

  cleanup:
  return err;
}

/*
 * Add location information as header.
 *
 * Parameters are the same than reflow().
 *
 * Returns non-zero in case of error.
 */
static int
process_filename (size_t max_width, vulnerability_t *vulnerability, line_t lines[MAX_LINES], size_t *count, char **err_msg)
{
  char copy[MAX_LOCATION_LENGTH] = {0};
  snprintf (copy, MAX_LOCATION_LENGTH - 1, "%s", vulnerability->file);
  remove_breaks_within_paragraphs (MAX_LOCATION_LENGTH, copy);
  return wrap (copy, max_width, lines, count, err_msg, true);
}

/*
 * Add category information as header.
 *
 * Parameters are the same than reflow(), minus error handling.
 */
static void
process_category (size_t max_width, vulnerability_t *vulnerability, line_t lines[MAX_LINES], size_t *count)
{
  lines[*count].content = xalloc (max_width + 1);
  lines[*count].heading = true;
  snprintf (lines[*count].content, max_width, "Category: %s", vulnerability->category);
  remove_breaks_within_paragraphs (max_width + 1, lines[*count].content);
  (*count)++;
}

/*
 * Add title as header.
 *
 * Parameters are the same than reflow().
 *
 * Returns non-zero in case of error.
 */
static int
process_title (size_t max_width, vulnerability_t *vulnerability, line_t lines[MAX_LINES], size_t *count, char **err_msg)
{
  char copy[MAX_TITLE_LENGTH] = {0};
  snprintf (copy, MAX_TITLE_LENGTH - 1, "%s", vulnerability->title);
  remove_breaks_within_paragraphs (MAX_TITLE_LENGTH, copy);
  return wrap (copy, max_width, lines, count, err_msg, true);
}

/*
 * Add body content.
 *
 * Parameters are the same than reflow().
 *
 * Returns non-zero in case of error.
 */
static int
process_body (size_t max_width, vulnerability_t *vulnerability, line_t lines[MAX_LINES], size_t *count, char **err_msg)
{
  int err = 0;
  char *desc_copy = NULL;

  desc_copy = strndup (vulnerability->description, MAX_DESC_LENGTH);
  remove_breaks_within_paragraphs (strlen (desc_copy) + 1, desc_copy);

  err = wrap (desc_copy, max_width, lines, count, err_msg, false);
  if (desc_copy) free (desc_copy);
  return err;
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
 * Returns non-zero in case of error. An error message will be in
 * `err_msg`. It's statically allocated, you don't need to free it.
 */
int
reflow (size_t max_width, vulnerability_t *vulnerability, line_t lines[MAX_LINES], size_t *count, char **err_msg)
{
  int err = process_filename (max_width, vulnerability, lines, count, err_msg);
  if (err)
    return err;

  process_category (max_width, vulnerability, lines, count);

  err = process_title (max_width, vulnerability, lines, count, err_msg);
  if (err)
    return err;

  // blank line between headers and body
  lines[*count].content = xalloc (1);
  (*count)++;

  err = process_body (max_width, vulnerability, lines, count, err_msg);
  if (err)
    return err;

  return 0;
}
