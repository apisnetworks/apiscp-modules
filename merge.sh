#!/bin/sh
set -euo pipefail

APNSCP_HOME="/usr/local/apnscp"
pushd `dirname $0`
git pull
LAST=$(git log -n 1 modules/ | grep '^Date:' | cut -d' ' -f1 --complement)
rm -rf modules
git clone --depth=0 $APNSCP_HOME/lib/modules modules
pushd $APNSCP_HOME/lib/modules
TMPFILE=`/bin/mktemp`
trap (){ rm -f $TMPFILE; }
git log --after="$LAST" . | apnscp_php $APNSCP_HOME/bin/scripts/changelogparser.php | php -R '$line = strip_tags($argn); $line && print($line."\n");' > $TMPFILE
popd
if [[ ! -s $TMPFILE ]]; then
	echo "empty commit"
	exit 255
fi
git add -A
git commit -a -F $TMPFILE
git push origin


