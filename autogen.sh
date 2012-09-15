#!/bin/sh -e
if test -z "$srcdir"; then
	srcdir=`dirname "$0"`
	if test -z "$srcdir"; then
		srcdir=.
	fi
fi
autoreconf --force --install --verbose "$srcdir"
test -n "$NOCONFIGURE" || "$srcdir/configure" "$@"
