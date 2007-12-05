/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#ifndef SPYBYE2HTML_H_
#define SPYBYE2HTML_H_

#define TIME_INTERVAL	60
#define MAX_OUTPUT	50

/* allows us to reshuffle stuff */
struct logentry {
	TAILQ_ENTRY(logentry) (next);

	struct dangerousload *dl;
	struct dangerous_report *dr;
};

TAILQ_HEAD(logentryq, logentry);

#endif /* SPYBYE2HTML_H_ */
