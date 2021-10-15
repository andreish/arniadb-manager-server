ARNIADB=/home/hudson/workspace/jobs/ARNIADB-CM-Common-8.4.1/deploy
ARNIADB_DATABASES=$ARNIADB/databases
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
