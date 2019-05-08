#!/usr/bin/env bash

PHP='/usr/bin/env php'
RETURN=0

# check PHP files
for FILE in $(find config-templates hooks lib www -name "*.php"); do
    $PHP -l "$FILE" > /dev/null 2>&1
    if ! $PHP -l "$FILE" > /dev/null 2>&1
    then
        echo "Syntax check failed for ${FILE}"
	RETURN=$((RETURN + 1))
    fi
done

exit "$RETURN"
