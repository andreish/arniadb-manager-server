#!/bin/bash
make clean
mkdir -p log

arn_js stop
arn_auto stop

valgrind  --leak-check=full --log-file=./log/cmserver_auto.valgrind.log arn_auto start
valgrind  --leak-check=full --log-file=./log/cmserver_js.valgrind.log arn_js start

arn_cmserver stop
sleep 3
valgrind  --leak-check=full --log-file=./log/cmserver_cmserver.valgrind.log arn_cmserver start

sed -i -e '/invalid file descriptor .* in syscall close/d' -e '/to select an alternative log fd/d' ./log/cmserver_*.valgrind.log*

arniadb deletedb anotherdb   #remove legacy test database
arniadb deletedb alatestdb #remove legacy test database
arniadb deletedb copydb #remove legacy test database
arniadb deletedb destinationdb #remove legacy test database

make test 

arn_js stop     #must stop before 'make lcov'
arn_auto stop   #must stop before 'make lcov'
sleep 5
make lcov

arniadb deletedb anotherdb   #remove legacy test database
arniadb deletedb copydb #remove legacy test database
arniadb deletedb destinationdb #remove legacy test database
arniadb deletedb alatestdb #remove legacy test database


