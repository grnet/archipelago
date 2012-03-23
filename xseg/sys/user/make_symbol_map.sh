#!/bin/sh

echo '{'
echo 'global:'
sed -e 's/EXPORT_SYMBOL(\([^)]*\));/	\1;/'
echo 'local:  *;'
echo '};'

