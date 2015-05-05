#!/bin/bash

ETH=$(dmesg | grep -Eo 'eth[[:digit:]]+' | tail -n1)
#IP=$(ifconfig ${ETH} | head -n2 | tail -n1 | cut -d: -f2 | cut -d" " -f1)
IP=127.0.0.1

echo -n "Use 'runserver_plus' [y/n]: "
read -n 1 usage
if [ "${usage}" == "y" ]; then
    CMD=runserver_plus
else
    CMD=runserver
fi

cd example_project

echo
(
    set -x
    rm db.sqlite3
    ./manage.py migrate
    echo "from django.contrib.auth.models import User; User.objects.create_superuser('test', 'test@test.com', '12345678')" | ./manage.py shell
)

while true
do
(
    set -x
    ./manage.py ${CMD} ${IP}:8000
    sleep 2
)
done