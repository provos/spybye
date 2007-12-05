AUTOMAKE_OPTIONS = foreign

spybye.gen.c spybye.gen.h: spybye.rpc
	event_rpcgen.py spybye.rpc || echo "No Python installed"

BUILT_SOURCES = spybye.gen.c spybye.gen.h control.js.h sarissa.js.h
bin_PROGRAMS = spybye spybye2html
spybye_SOURCES= spybye.c spybye.h utils.c utils.h status.c status.h \
	spybye.gen.c spybye.gen.h log.c log.h atomicio.c virus.c virus.h \
	proxy.c proxy.h
spybye_LDADD= @LIBOBJS@ @EVENTLIB@ @CLAMAVLIB@

# SpyBye2Html
spybye2html_SOURCES= spybye2html.c spybye2html.h log.h spybye.gen.c spybye.gen.h
spybye2html_LDADD= @LIBOBJS@ @EVENTLIB@

# Flags and other stuff
CFLAGS = -O2 -g -Wall
INCLUDES = -I$(top_srcdir)/compat @EVENTINC@ @CLAMAVINC@

man_MANS = spybye.1

# data file
spybyedir = $(datadir)/spybye
spybye_DATA = good_patterns bad_patterns

CLEANFILES = spybye.gen.c spybye.gen.h

EXTRA_DIST = $(man_MANS) \
	good_patterns bad_patterns spybye.rpc \
	md5.c strlcat.c strlcpy.c strsep.c strnstr.c \
	compat/err.h compat/md5.h \
	compat/sys/queue.h compat/sys/tree.h \
	control.js sarissa.js

DISTCLEANFILES = *~

# generate inline javascript for us
control.js.h: control.js
	sed -e 's/\\/\\\\/g' -e 's/\"/\\\"/g' -e 's/^/\"/' -e 's/$$/\\n\"/' control.js > control.js.h
sarissa.js.h: sarissa.js
	sed -e 's/\\/\\\\/g' -e 's/\"/\\\"/g' -e 's/^/\"/' -e 's/$$/\\n\"/' sarissa.js > sarissa.js.h
