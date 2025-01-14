#!/bin/bash

if [ -z $JAVA_HOME ]
then
        echo "WE NEED JAVA_HOME";exit 1;
fi

yum install ant

#build libevent
wget http://cloud.github.com/downloads/libevent/libevent/libevent-2.0.18-stable.tar.gz
tar zxvf libevent-2.0.18-stable.tar.gz
cd libevent-2.0.18-stable
./configure;make;make install

cd ..

#build jsoncpp
wget http://nchc.dl.sourceforge.net/project/jsoncpp/jsoncpp/0.5.0/jsoncpp-src-0.5.0.tar.gz
tar zxvf jsoncpp-src-0.5.0.tar.gz
cd jsoncpp-src-0.5.0
g++ -o src/lib_json/json_reader.o -c -Wall -Iinclude src/lib_json/json_reader.cpp
g++ -o src/lib_json/json_value.o -c -Wall -Iinclude src/lib_json/json_value.cpp
g++ -o src/lib_json/json_writer.o -c -Wall -Iinclude src/lib_json/json_writer.cpp
ar rc src/lib_json/libjson.a src/lib_json/json_reader.o src/lib_json/json_value.o src/lib_json/json_writer.o
ranlib src/lib_json/libjson.a
cp -r include/json /usr/local/include
cp src/lib_json/libjson.a /usr/local/lib

cd ..

#build arniadb
wget ftp://ftp.arniadb.org/ARNIADB_Engine/8.4.1/Linux/ARNIADB-8.4.1.2032.src.tar.gz
tar xzvf ARNIADB-8.4.1.2032.src.tar.gz

cd arniadb-8.4.1.2032
./configure --enable-64bit --enable-debug
make
make install

#configure arniadb env

cat >> .arniadb.sh << EOF
#!/bin/bash
ARNIADB=/root/arniadb
ARNIADB_DATABASES=/root/arniadb/databases
ARNIADB_LANG=en_US
ld_lib_path=`printenv LD_LIBRARY_PATH`
if [ "$ld_lib_path" = "" ]
then
LD_LIBRARY_PATH=$ARNIADB/lib
else
LD_LIBRARY_PATH=$ARNIADB/lib:$LD_LIBRARY_PATH
fi
SHLIB_PATH=$LD_LIBRARY_PATH
LIBPATH=$LD_LIBRARY_PATH
PATH=$ARNIADB/bin:$ARNIADB/arniadbmanager:$PATH
export ARNIADB
export ARNIADB_DATABASES
export ARNIADB_LANG
export LD_LIBRARY_PATH
export SHLIB_PATH
export LIBPATH
export PATH
EOF
chmod +x .arniadb.sh
./.arniadb.sh

mkdir $ARNIADB_DATABASES

