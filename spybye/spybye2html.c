/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>

#include <event.h>
#include <evhttp.h>

#include "spybye2html.h"
#include "spybye.gen.h"
#include "log.h"

static struct event ev_timeout;
static char *input = NULL;
static char *output = NULL;

void
print_header(FILE *outp)
{
	fprintf(outp, "<html><head>");
	fprintf(outp,
	    "<style type=\"text/css\">"
	    "<!--"
	    "table.sites {"
	    "  border-width: 0px 0px 1px 1px;"
	    "  border-spacing: 2px;"
	    "  border-style: inset;"
	    "  border-color: black;"
	    "  border-collapse: collapse;"
	    "}"
	    "table.sites td {"
	    "  border-width: 1px 1px 0px 0px;"
	    "  padding: 2px;"
	    "  border-style: inset;"
	    "  border-color: black;"
	    "  background-color: rgb(255, 250, 220);"
	    "  font-family: Verdana, Arial;\n"
	    "  font-size: small;\n"
	    "}\n"
	    "table.sites tr {"
	    "  border-width: 1px 1px 0px 0px;"
	    "  padding: 2px;"
	    "  border-style: inset;"
	    "  border-color: black;"
	    "  background-color: rgb(235, 170, 200);"
	    "  font-family: Verdana, Arial;\n"
	    "  font-size: 0.9em;\n"
	    "}\n"
	    "--></style></head>");

	fprintf(outp,
	    "<body><table class=sites>"
	    "<tr>"
	    "<th>Report Time</th><th>Origin URL</th><th>Danger URL</th>"
	    "<th>Virus</th>"
	    "</tr>"
	    );
}

void
print_footer(FILE *outp)
{
	fprintf(outp, "</table></body></html>");
}

int
format_dangerousload(FILE *outp, struct dangerousload *dl)
{
	static char *previous_parent, *previous_danger;
	char output[64];
	struct tm *tm;
	u_int tmp;
	time_t seconds;
	char *parent_url, *danger_url, *escaped;
	char *virus_scan = "unknown";

	EVTAG_GET(dl, time_in_seconds, &tmp);
	EVTAG_GET(dl, parent_url, &parent_url);
	EVTAG_GET(dl, dangerous_url, &danger_url);
	if (EVTAG_HAS(dl, virus_result))
		EVTAG_GET(dl, virus_result, &virus_scan);

	/* Simple way to detect duplicates */
	if (previous_parent && previous_danger &&
	    !strcmp(previous_parent, parent_url) &&
	    !strcmp(previous_danger, danger_url))
		return (-1);
	
	seconds = tmp;
	tm = localtime(&seconds);
	strftime(output, sizeof(output), "%Y-%m-%d %H:%M:%S", tm);

	fprintf(outp, "<tr>");
	fprintf(outp, "<td><span class=time>%s</span></td>", output);
	escaped = evhttp_htmlescape(parent_url);
	fprintf(outp, "<td><span class=source>%s</span></td>", escaped);
	free(escaped);
	escaped = evhttp_htmlescape(danger_url);
	fprintf(outp, "<td><span class=danger>%s</span></td>", escaped);
	free(escaped);
	fprintf(outp, "<td><span class=source>%s</span></td>", virus_scan);
	fprintf(outp, "</tr>\n");

	previous_parent = parent_url;
	previous_danger = danger_url;

	return (0);
}

int
format_dangerous_report(FILE *outp, struct dangerous_report *dr)
{
	struct dangerousload *dl;

	EVTAG_GET(dr, report, &dl);

	return (format_dangerousload(outp, dl));
}

void
transform(FILE *inp, FILE *outp)
{
	struct logentryq entries;
	struct evbuffer *data = evbuffer_new();
	struct logentry *entry;
	int count;
	assert(data != NULL);

	TAILQ_INIT(&entries);

	count = 0;
	while (!feof(inp)) {
		u_int32_t length;
		char buffer[1024];
		size_t n = fread(buffer, 1, 1024, inp);
		/* why would this be - oh no */
		if (n == 0)
			continue;
		evbuffer_add(data, buffer, n);

		while (evtag_peek_length(data, &length) != -1) {
			struct dangerous_report *dr = NULL;
			struct dangerousload *dl = NULL;
			u_char tag;

			if (EVBUFFER_LENGTH(data) < length)
				break;

			evtag_peek(data, &tag);

			count++;
			
			if (tag == DANGEROUS_REPORT_TAG) {	
				if ((dr = dangerous_report_new()) == NULL)
					err(1, "malloc");

				if (evtag_unmarshal_dangerous_report(data,
					DANGEROUS_REPORT_TAG, dr) == -1) {
					fprintf(stderr,
					    "Failed to read entry %d\n",
					    count);
					dangerous_report_free(dr);
					continue;
				}
			} else if (tag == DANGEROUS_TAG) {
				if ((dl = dangerousload_new()) == NULL)
					err(1, "malloc");

				if (evtag_unmarshal_dangerousload(data,
					DANGEROUS_TAG, dl) == -1) {
					fprintf(stderr,
					    "Failed to read entry %d\n",
					    count);
					dangerousload_free(dl);
					continue;
				}
			}

			if (dr == NULL && dl == NULL)
				continue;

			entry = malloc(sizeof(struct logentry));
			if (entry == NULL)
				err(1, "malloc");
			entry->dl = dl;
			entry->dr = dr;

			TAILQ_INSERT_HEAD(&entries, entry, next);
		}
	}

	fprintf(stderr, " ... read %d entries\n", count);

	print_header(outp);

	count = 0;
	TAILQ_FOREACH(entry, &entries, next) {
		int res = 0;
		if (entry->dr)
			res = format_dangerous_report(outp, entry->dr);
		else if (entry->dl)
			res = format_dangerousload(outp, entry->dl);

		if (res == 0) {
			if (++count >= MAX_OUTPUT)
				break;
		}
	}

	print_footer(outp);

	/* free everything */
	while ((entry = TAILQ_FIRST(&entries)) != NULL) {
		TAILQ_REMOVE(&entries, entry, next);
		if (entry->dr)
			dangerous_report_free(entry->dr);
		if (entry->dl)
			dangerousload_free(entry->dl);
		free(entry);
	}

	evbuffer_free(data);
}

void
transform_cb(int fd, short what, void *arg)
{
	struct timeval tv;
	FILE *inputp = fopen(input, "r");
	FILE *outputp = fopen(output, "w+");

	timerclear(&tv);
	tv.tv_sec = TIME_INTERVAL;
	event_add(&ev_timeout, &tv);

	if (inputp == NULL)
		goto done;
	if (outputp == NULL)
		goto done;

	fprintf(stderr, "Reading data from %s to %s\n",
	    input, output);

	transform(inputp, outputp);

	fclose(outputp);
	fclose(inputp);

done:
	if (inputp != NULL)
		fclose(inputp);
	if (outputp != NULL)
		fclose(outputp);
}

void
usage(const char *progname)
{
	fprintf(stderr,
	    "%s: [-i input] [-o output]\n"
	    "\t -i input file\n"
	    "\t -o output file\n"
	    "\t for documentation of all options consult the man page\n",
	    progname);
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int ch;
	struct timeval tv;

	while ((ch = getopt(argc, argv, "i:o:")) != -1)
		switch(ch) {
		case 'i':
			input = optarg;
			break;
		case 'o':
			output = optarg;
			break;

		default:
			usage(argv[0]);
			exit(1);
		}

	event_init();
	evtag_init();

	if (input == NULL || output == NULL) {
		FILE *inputp = input ? fopen(input, "r") : stdin;
		FILE *outputp = output ? fopen(output, "w") : stdout;
		if (inputp == NULL) {
			fprintf(stderr, "Cannot open %s\n", input);
			usage(argv[0]);
			exit(1);
		}
		if (outputp == NULL) {
			fprintf(stderr, "Cannot open %s\n", output);
			usage(argv[0]);
			exit(1);
		}
		transform(inputp, outputp);
		exit(0);
	}

	argc -= optind;
	argv += optind;

	fprintf(stderr, "spybye2html %s starting up ...\n", VERSION);

	evtimer_set(&ev_timeout, transform_cb, NULL);
	timerclear(&tv);
	event_add(&ev_timeout, &tv);
	
	event_dispatch();

	exit (0);
}
