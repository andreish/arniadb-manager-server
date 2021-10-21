# ARNIADB Manager Server System

ARNIADB Manager Server(CMS) is a part of ARNIADB Tools.

CMS provides both HTTP or Socket interfaces for ARNIADB Manager
to managing ARNIADB system, and also provides monitoring information about ARNIADB system.

## MAJOR REFERENCES

- ARNIADB Official Site: http://www.arniadb.org and http://www.arniadb.com

## DOWNLOADS and FILE REPOSITORIES
CMS is distributed within ARNIADB distribution which can be found here:

- http://www.arniadb.org/downloads
- http://ftp.arniadb.org

## HOW TO BUILD/INSTALL CMS

### build and install on Linux

Unzip the package of ARNIADB and you can find the source code of CMS here: arniadb-{version}/arniadbmanager/server.

1. Move to the directory where the source is stored.

	```
	cd $HOME/arniadbmanager/server
	```

2. Execute autogen.sh.

	```
	./autogen.sh
	```

3. Execute the configure script.

	```
	./configure --prefix=$ARNIADB
	```

	- `--prefix=$ARNIADB` : It specifies a directory to be installed.
    - `--enable-debug` : Used to enable debug mode.
	- `--enable-64bit` : Used to build in a 64-bit environment since supporting 64-bit from ARNIADB 2008 R2.0 or higher.

4. Build by using make.

	```
	make
	```

5. Install by using make install.

	```
	make install
	```

### build and install on windows

If you want to build CMS on windows, VS2008 must be installed.

1. Open a commander "cmd.exe" and Move to the directory where the source is stored.

	```
	cd %ARNIADB-SRC%/arniadbmanager/server
	```

2. Execute the build batche file

	```
	cmd /c build.bat --prefix=%ARNIADB% --with-arniadb-dir=%ARNIADB%
	```

	- `--prefix=%ARNIADB%` : It specifies a directory to be installed.
	- `--enable-64bit` : Used to build in a 64-bit environment since supporting 64-bit from ARNIADB 2008 R2.0 or higher.
	- `--with-arniadb-dir=%ARNIADB%` : Option specifies the directory ARNIADB is installed.

3. Building with VS2008 requires to set new environment variables, as follow:
arniadb_includedir = %ARNIADB%\include
arniadb_libdir = %ARNIADB%\lib
Also arniadb_lib64dir must be set to %ARNIADB%\lib or arniadb_lib64dir replaced with arniadb_libdir in .vcproj file.
The alternative is to modify paths in .vcproj files, instead of adding new environment variables.


## PROGRAMMING APIs

- [CMS APIs](docs/api/README.md)


## GETTING HELP

If You encounter any difficulties with getting started, or just have some
questions, or find bugs, or have some suggestions, we kindly ask you to 
post your thoughts on our subreddit at https://www.reddit.com/r/ARNIADB/.

Sincerely,
Your CMS Development Team.
