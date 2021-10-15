@echo off

if "%1" == "" goto PRINT_USAGE

set arniadb_dir=%ARNIADB%
set platform=Win32
set mode=release

:LOOP_BEGIN

if "%1" == "" goto LOOP_END

if "%1" == "--help" goto PRINT_USAGE
if "%1" == "--prefix" set prefix=%2& shift & shift & goto LOOP_BEGIN
if "%1" == "--with-arniadb-dir" set arniadb_dir=%2& shift & shift & goto LOOP_BEGIN
if "%1" == "--with-arniadb-libdir" set arniadb_libdir=%2& shift & shift & goto LOOP_BEGIN
if "%1" == "--with-arniadb-includedir" set arniadb_includedir=%2& shift & shift & goto LOOP_BEGIN
if "%1" == "--enable-64bit" set platform=x64& shift & goto LOOP_BEGIN
if "%1" == "--enable-debug" set mode=debug& shift & goto LOOP_BEGIN

shift
:LOOP_END

if "%arniadb_libdir%" == "" (
	set arniadb_libdir=%arniadb_dir%\lib
)

if "%arniadb_includedir%" == "" (
	set arniadb_includedir=%arniadb_dir%\include
)

if "%arniadb_libdir%" == "\lib" (
	echo "Please specify --with-arniadb-libdir option"
	exit /B 1
)

if "%arniadb_includedir%" == "\include" (
	echo "Please specify --with-arniadb-includedir option"
	exit /B 1
)

if "%prefix%" == "" (
	echo "Please specify --prefix option"
	exit /B 1
)

echo ARNIADB include path is %arniadb_libdir%
echo ARNIADB lib path is %arniadb_includedir%
echo OUTPUT path is %prefix%

echo Platform type is "%platform%"
echo Debug mode is "%mode%"

if not exist %prefix% (
	mkdir %prefix%
)

call build_server.bat
set exitcode=!errorlevel!

if "!exitcode!" == "0" (
	echo build successful
) else (
	echo build failed
	exit /b !exitcode!
)

set platform_token=%platform%
if "%platform%" == "Win32" set platform_token=x86

if "%mode%" == "debug" set is_debug=true

set target_server=pack_server

exit /b

:PRINT_USAGE
@echo Usage: build [OPTION]
@echo Build whole ARNIADB Manager project
@echo.
@echo   --prefix=DIR                  build result output directory (required)
@echo   --with-arniadb-dir=DIR         directory have two sub directory (optional)
@echo                                 'include', 'lib'. default to %%ARNIADB%%
@echo   --with-arniadb-libdir=DIR      directory have arniadb lib files (optional)
@echo                                 default to with_arniadb_dir\lib
@echo   --with-arniadb-includedir=DIR  directory have arniadb include files (optional)
@echo                                 default to with_arniadb_dir\include
@echo   --enable-64bit                build 64bit applications
@echo   --enable-debug                build debug version applications
@echo.
@echo   --help                        display this help and exit
@echo.
@echo   Examples:
@echo     build --prefix=c:\out\x64 --with-arniadb-dir=%%ARNIADB%%
