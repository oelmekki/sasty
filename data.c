#include <json.h>
#include <json_pointer.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "data.h"

#define MAX_DESC_LENGTH 100000

enum {
  ANALYZER_SEMGREP,
  ANALYZER_FLAWFINDER,
};

int analyzer_format = 0;

/*
 * Makes sure the provided semgrep data is formatted as expected.
 *
 * Returns non-zero in case of error.
 */
static int
validate_semgrep_json (const json_object *vulns)
{
  size_t array_len = json_object_array_length (vulns);
  if (array_len > MAX_VULNERABILITY_COUNT)
    array_len = MAX_VULNERABILITY_COUNT;

  for (size_t i = 0; i < array_len; i++)
    {
      json_object *vuln = json_object_array_get_idx (vulns, i);
      if (json_object_get_type (vuln) != json_type_object)
        {
          fprintf (stderr, "data.c : validate_semgrep_json() : malformed json : vulnerability %ld is not an object.\n", i);
          return 1;
        }

      json_object *category = json_object_object_get (vuln, "category");
      if (!category || json_object_get_type (category) != json_type_string)
        {
          fprintf (stderr, "data.c : validate_semgrep_json() : malformed json : key `category` in vulnerability %ld either missing or not a string.\n", i);
          return 1;
        }

      json_object *title = json_object_object_get (vuln, "title");
      if (!title || json_object_get_type (title) != json_type_string)
        {
          fprintf (stderr, "data.c : validate_semgrep_json() : malformed json : key `title` in vulnerability %ld either missing or not a string.\n", i);
          return 1;
        }

      json_object *description = json_object_object_get (vuln, "description");
      if (!description || json_object_get_type (description) != json_type_string)
        {
          fprintf (stderr, "data.c : validate_semgrep_json() : malformed json : key `description` in vulnerability %ld either missing or not a string.\n", i);
          return 1;
        }

      json_object *location = json_object_object_get (vuln, "location");
      if (!location || json_object_get_type (location) != json_type_object)
        {
          fprintf (stderr, "data.c : validate_semgrep_json() : malformed json : key `location` in vulnerability %ld either missing or not an object.\n", i);
          return 1;
        }

      json_object *file = json_object_object_get (location, "file");
      if (!file || json_object_get_type (file) != json_type_string)
        {
          fprintf (stderr, "data.c : validate_semgrep_json() : malformed json : key `file` in vulnerability %ld's location either missing or not a string.\n", i);
          return 1;
        }

      json_object *line = json_object_object_get (location, "start_line");
      if (!line || json_object_get_type (line) != json_type_int)
        {
          fprintf (stderr, "data.c : validate_semgrep_json() : malformed json : key `start_line` in vulnerability %ld's location either missing or not an integer.\n", i);
          return 1;
        }
    }

  return 0;
}

/*
 * Makes sure the provided flawfinder data is formatted as expected.
 *
 * Returns non-zero in case of error.
 */
static int
validate_flawfinder_json (const json_object *vulns)
{
  size_t array_len = json_object_array_length (vulns);
  if (array_len > MAX_VULNERABILITY_COUNT)
    array_len = MAX_VULNERABILITY_COUNT;

  for (size_t i = 0; i < array_len; i++)
    {
      json_object *vuln = json_object_array_get_idx (vulns, i);
      if (json_object_get_type (vuln) != json_type_object)
        {
          fprintf (stderr, "data.c : validate_flawfinder_json() : malformed json : vulnerability %ld is not an object.\n", i);
          return 1;
        }

      json_object *category = json_object_object_get (vuln, "category");
      if (!category || json_object_get_type (category) != json_type_string)
        {
          fprintf (stderr, "data.c : validate_flawfinder_json() : malformed json : key `category` in vulnerability %ld either missing or not a string.\n", i);
          return 1;
        }

      json_object *cve = json_object_object_get (vuln, "cve");
      if (!cve || json_object_get_type (cve) != json_type_string)
        {
          fprintf (stderr, "data.c : validate_flawfinder_json() : malformed json : key `cve` in vulnerability %ld either missing or not a string.\n", i);
          return 1;
        }

      json_object *message = json_object_object_get (vuln, "message");
      if (!message || json_object_get_type (message) != json_type_string)
        {
          fprintf (stderr, "data.c : validate_flawfinder_json() : malformed json : key `message` in vulnerability %ld either missing or not a string.\n", i);
          return 1;
        }

      json_object *location = json_object_object_get (vuln, "location");
      if (!location || json_object_get_type (location) != json_type_object)
        {
          fprintf (stderr, "data.c : validate_flawfinder_json() : malformed json : key `location` in vulnerability %ld either missing or not an object.\n", i);
          return 1;
        }

      json_object *file = json_object_object_get (location, "file");
      if (!file || json_object_get_type (file) != json_type_string)
        {
          fprintf (stderr, "data.c : validate_flawfinder_json() : malformed json : key `file` in vulnerability %ld's location either missing or not a string.\n", i);
          return 1;
        }

      json_object *line = json_object_object_get (location, "start_line");
      if (!line || json_object_get_type (line) != json_type_int)
        {
          fprintf (stderr, "data.c : validate_flawfinder_json() : malformed json : key `start_line` in vulnerability %ld's location either missing or not an integer.\n", i);
          return 1;
        }
    }

  return 0;
}

/*
 * Makes sure the provided data is formatted as expected.
 *
 * Returns non-zero in case of error.
 */
static int
validate_json (const json_object *data)
{
  if (!json_object_object_get (data, "version") || !json_object_object_get (data, "vulnerabilities"))
    {
      fprintf (stderr, "data.c : validate_json() : this does not seem to be a Gitlab's SAST file.\n");
      return 1;
    }

  json_object *vulns = json_object_object_get (data, "vulnerabilities");
  if (json_object_get_type (vulns) != json_type_array)
    {
      fprintf (stderr, "data.c : validate_json() : malformed json : `vulnerabilities` is not an array.\n");
      return 1;
    }

  json_object *analyzer = NULL;
  int err = json_pointer_get ((json_object *) data, "/scan/analyzer/id", &analyzer);
  if (err)
    {
      fprintf (stderr, "data.c : validate_json() : malformed json : `no analyzer info.\n");
      return 1;
    }

  if (json_object_get_type (analyzer) != json_type_string)
    {
      fprintf (stderr, "data.c : validate_json() : malformed json : `analyzer id is not a string.\n");
      return 1;
    }

  if (strncmp (json_object_get_string (analyzer), "semgrep", 100) == 0)
    {
      analyzer_format = ANALYZER_SEMGREP;
      return validate_semgrep_json (vulns);
    }

  if (strncmp (json_object_get_string (analyzer), "flawfinder", 100) == 0)
    {
      analyzer_format = ANALYZER_FLAWFINDER;
      return validate_flawfinder_json (vulns);
    }

  printf ("Sorry, this analyzer is not supported.\n\n");
  fprintf (stderr, "data.c : validate_json() : unsupported analyzer.\n");

  return 1;
}

/*
 * Retrieve flawfinder data in json file.
 */
static void
fill_flawfinder_data (const json_object *vuln, size_t i, vulnerability_t vulns[MAX_VULNERABILITY_COUNT], size_t *vulns_count)
{
  vulns[i].category = strdup (json_object_get_string (json_object_object_get (vuln, "category")));
  vulns[i].title = strdup (json_object_get_string (json_object_object_get (vuln, "cve")));
  char description[MAX_DESC_LENGTH] = {0};
  const char *message = json_object_get_string (json_object_object_get (vuln, "message"));
  const char *solution = "?";
  json_object *jsolution = json_object_object_get (vuln, "solution");
  if (jsolution)
    solution = json_object_get_string (jsolution);
  snprintf (description, MAX_DESC_LENGTH - 1, "Message: %s\n\nSolution: %s\n", message, solution);
  vulns[i].description = strdup (description);

  json_object *location = json_object_object_get (vuln, "location");
  json_object *file = json_object_object_get (location, "file");
  json_object *line = json_object_object_get (location, "start_line");
  char file_location[BUFSIZ] = {0};
  snprintf (file_location, BUFSIZ - 1, "%s:%d", json_object_get_string (file), json_object_get_int (line));
  vulns[i].file = strdup (file_location);

  (*vulns_count)++;
}

/*
 * Retrieve semgrep data in json file.
 */
static void
fill_semgrep_data (const json_object *vuln, size_t i, vulnerability_t vulns[MAX_VULNERABILITY_COUNT], size_t *vulns_count)
{
  vulns[i].category = strdup (json_object_get_string (json_object_object_get (vuln, "category")));
  vulns[i].title = strdup (json_object_get_string (json_object_object_get (vuln, "title")));
  vulns[i].description = strdup (json_object_get_string (json_object_object_get (vuln, "description")));

  json_object *location = json_object_object_get (vuln, "location");
  json_object *file = json_object_object_get (location, "file");
  json_object *line = json_object_object_get (location, "start_line");
  char file_location[BUFSIZ] = {0};
  snprintf (file_location, BUFSIZ - 1, "%s:%d", json_object_get_string (file), json_object_get_int (line));
  vulns[i].file = strdup (file_location);

  (*vulns_count)++;
}

/*
 * Populate the data structure with data fetched from json file.
 *
 * Returns non-zero in case of error.
 */
static int
fill_data (const json_object *data, vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t *vulnerabilities_count)
{
  json_object *vulns = json_object_object_get (data, "vulnerabilities");
  size_t array_len = json_object_array_length (vulns);
  if (array_len > MAX_VULNERABILITY_COUNT)
    array_len = MAX_VULNERABILITY_COUNT;

  for (size_t i = 0; i < array_len; i++)
    {
      json_object *vuln = json_object_array_get_idx (vulns, i);

      switch (analyzer_format)
        {
          case ANALYZER_FLAWFINDER:
            fill_flawfinder_data (vuln, i, vulnerabilities, vulnerabilities_count);
            break;

          case ANALYZER_SEMGREP:
            fill_semgrep_data (vuln, i, vulnerabilities, vulnerabilities_count);
            break;

          default:
            fprintf (stderr, "data.c : fill_data() : unkown analyzer: %d\n", analyzer_format);
            return 1;
        }

    }

  return 0;
}

/*
 * Parse data at uri.
 *
 * If everything goes as expected, vulnerabilities will be stored in
 * `vulnerabilities` and their count will be in `vulnerabilities_count`.
 * You're responsible to provide memory for both, and to free vulnerabilities
 * content with `free_data()`.
 *
 * Returns non-zero in case of error.
 */
int
parse_data (const char *uri, vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t *vulnerabilities_count)
{
  int err = 0;
  json_object *data = NULL;

  err = access (uri, R_OK);
  if (err)
    {
      fprintf (stderr, "data.c : parse_data() : file does not exist or is not readable : %s\n", uri);
      goto cleanup;
    }

  data = json_object_from_file (uri);

  err = validate_json (data);
  if (err)
    {
      fprintf (stderr, "data.c : parse_data() : error while validating data.\n");
      goto cleanup;
    }

  err = fill_data (data, vulnerabilities, vulnerabilities_count);
  if (err)
    {
      fprintf (stderr, "data.c : parse_data() : error while filling data.\n");
      goto cleanup;
    }

  cleanup:
  json_object_put (data);
  return err;
}

/*
 * Free vulnerabilities memory.
 */
void
free_data (vulnerability_t vulnerabilities[MAX_VULNERABILITY_COUNT], size_t vulnerabilities_count)
{
  for (size_t i = 0; i < vulnerabilities_count; i++)
    {
      vulnerability_t *vuln = &vulnerabilities[i];
      if (vuln->category) free (vuln->category);
      if (vuln->title) free (vuln->title);
      if (vuln->description) free (vuln->description);
      if (vuln->file) free (vuln->file);
    }
}
