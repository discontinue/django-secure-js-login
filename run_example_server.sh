#!/bin/bash

ADDR=127.0.0.1:8000
#ADDR=0.0.0.0:8000

CMD=runserver
#echo -n "Use 'runserver_plus' [y/n]: "
#read -n 1 usage
#if [ "${usage}" == "y" ]; then
#    CMD=runserver_plus
#else
#    CMD=runserver
#fi

cd example_project

TEST_DB=example_project_db.sqlite3 # must be the same as in settings.py !

echo
(
    if [ -f ${TEST_DB} ]; then
        # remove old
        rm example_project_db.sqlite3
    fi
    set -x
    ./manage.py migrate
    echo "from django.contrib.auth.models import User; User.objects.create_superuser('test', 'test@test.com', '12345678')" | ./manage.py shell
)

while true
do
(
    set -x
    ./manage.py ${CMD} ${ADDR} --insecure
    sleep 2
)
done