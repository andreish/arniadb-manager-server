
#
# Copyright (C) 2008 Search Solution Corporation. All rights reserved by Search Solution. 
#
#   This program is free software; you can redistribute it and/or modify 
#   it under the terms of the GNU General Public License as published by 
#   the Free Software Foundation; either version 2 of the License, or 
#   (at your option) any later version. 
#
#  This program is distributed in the hope that it will be useful, 
#  but WITHOUT ANY WARRANTY; without even the implied warranty of 
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
#  GNU General Public License for more details. 
#
#  You should have received a copy of the GNU General Public License 
#  along with this program; if not, write to the Free Software 
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#


SUBDIRS = conf

SRC = $(top_srcdir)/src
DBMT_DIR = $(SRC)

INCLUDES = @SRC_INC@
DEFS += @SYS_DEFS@ @VERSION_DEFS@ @COMMON_DEFS@
LIBS += @SYS_LIBS@

bin_PROGRAMS = am_admin arn_manager

am_admin_SOURCES = \
	$(DBMT_DIR)/am_text_encryption.c \
	$(DBMT_DIR)/am_config.cpp \
	$(DBMT_DIR)/am_server_util.cpp \
	$(DBMT_DIR)/am_user.cpp \
	$(DBMT_DIR)/am_cmd.cpp \
	$(DBMT_DIR)/am_cmd_util.cpp \
	$(DBMT_DIR)/am_connect_info.cpp \
	$(DBMT_DIR)/am_cmd_task.cpp
am_admin_CFLAGS = -D_FILE_OFFSET_BITS=64
am_admin_LDFLAGS =  @CMDEP_LIB@ -D_FILE_OFFSET_BITS=64

arn_manager_SOURCES = \
        $(DBMT_DIR)/am_server_util.cpp \
        $(DBMT_DIR)/am_autojob.cpp \
        $(DBMT_DIR)/am_text_encryption.c \
        $(DBMT_DIR)/am_config.cpp \
        $(DBMT_DIR)/am_job_task.cpp \
        $(DBMT_DIR)/am_cmd_exec.cpp \
        $(DBMT_DIR)/am_connect_info.cpp \
        $(DBMT_DIR)/am_auto_task.cpp \
        $(DBMT_DIR)/am_httpd.cpp \
        $(DBMT_DIR)/am_mon_stat.cpp \
        $(DBMT_DIR)/am_user.cpp \
        $(DBMT_DIR)/am_http_server.cpp \
        $(DBMT_DIR)/am_server_extend_interface.cpp \
        $(DBMT_DIR)/am_server_interface.cpp \
        $(DBMT_DIR)/am_cci_interface.cpp \
		$(DBMT_DIR)/am_server_autoupdate.cpp
arn_manager_CPPFLAGS = $(AM_CFLAGS) -DFSERVER_SLAVE -DJSON_SUPPORT -DEVENT__HAVE_OPENSSL -D_FILE_OFFSET_BITS=64 @EXTERNAL_INC@
arn_manager_LDFLAGS = -larniadbcs @AMSTAT_LIB@ @CMDEP_LIB@ @EXTERNAL_LIB@ -lrt -lcascci
