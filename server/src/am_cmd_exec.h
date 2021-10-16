/*
 * Copyright (C) 2008 Search Solution Corporation. All rights reserved by Search Solution.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */


/*
 * am_cmd_exec.h -
 */

#ifndef _AM_COMMAND_EXECUTE_H_
#define _AM_COMMAND_EXECUTE_H_

#include <time.h>

#include "am_dep.h"

#if defined(WINDOWS)
#define DBMT_EXE_EXT        ".exe"
#else
#define DBMT_EXE_EXT        ""
#endif

#define cmd_servstat_result_free(RESULT)        cmd_result_free(RESULT)
#define cmd_asql_result_free(RESULT)            cmd_result_free(RESULT)

#define ERR_MSG_SIZE    1024
#define COLUMN_VALUE_MAX_SIZE 32
#define DATABASE_DESCRIPTION_NUM_LINES 3
#define FILES_DESCRIPTION_NUM_LINES 4
#define BUFFER_MAX_LEN 128

#if !defined (DO_NOT_USE_ARNIADBENV)
#define ARNIADB_ERROR_LOG_DIR            "log/server"
#define ARNIADB_BROKER_LOG_DIR           "log/broker"
#else
#define ARNIADB_ERROR_LOG_DIR            ARNIADB_LOGDIR "/server"
#define ARNIADB_BROKER_LOG_DIR           ARNIADB_LOGDIR"/broker"
#endif

#define ARNIADB_DATABASE_TXT             "databases.txt"
#define ARNIADB_ARNIADB_CONF              "arniadb.conf"
#define ARNIADB_DBMT_CONF                "cm.conf"
#define ARNIADB_BROKER_CONF              "arniadb_broker.conf"
#define ARNIADB_HA_CONF                  "arniadb_ha.conf"
#define ARNIADB_UNLOAD_EXT_INDEX         "_indexes"
#define ARNIADB_UNLOAD_EXT_TRIGGER       "_trigger"
#define ARNIADB_UNLOAD_EXT_OBJ           "_objects"
#define ARNIADB_UNLOAD_EXT_SCHEMA        "_schema"
#define ARNIADB_SERVER_LOCK_EXT          "_lgat__lock"
#define ARNIADB_ACT_LOG_EXT              "_lgat"
#define ARNIADB_ARC_LOG_EXT              "_lgar"
#define ARNIADB_BACKUP_INFO_EXT          "_bkvinf"
#define ARNIADB_ARC_LOG_EXT_LEN          strlen(ARNIADB_ARC_LOG_EXT)

#define ARNIADB_CMD_NAME_LEN    128

#if !defined (DO_NOT_USE_ARNIADBENV)
#if defined(WINDOWS)
#define ARNIADB_DIR_BIN          "bin\\"
#else
#define ARNIADB_DIR_BIN          "bin/"
#endif
#endif

#include <vector>
#include "am_autojob.h"

typedef enum
{
  ARNIADB_MODE_CS = 0,
  ARNIADB_MODE_SA = 1
} T_ARNIADB_MODE;

struct SpaceDbVolumeInfoOldFormat
{
  int volid;
  int total_size;
  int free_size;
  int data_size;
  int index_size;
  char purpose[COLUMN_VALUE_MAX_SIZE];
  char location[PATH_MAX];
  char vol_name[PATH_MAX];
  time_t date;
};

struct SpaceDbVolumeInfoNewFormat
{
  int volid;
  int used_size;
  int free_size;
  int total_size;
  char type[COLUMN_VALUE_MAX_SIZE];
  char purpose[COLUMN_VALUE_MAX_SIZE];
  char volume_name[PATH_MAX];
  time_t date;
};

struct DatabaseSpaceDescription
{
  char type[COLUMN_VALUE_MAX_SIZE];
  char purpose[COLUMN_VALUE_MAX_SIZE];
  int volume_count;
  int used_size;
  int free_size;
  int total_size;
};

struct FileSpaceDescription
{
  char data_type[COLUMN_VALUE_MAX_SIZE];
  int file_count;
  int used_size;
  int file_table_size;
  int reserved_size;
  int total_size;
};

class GeneralSpacedbResult
{
  protected:
    int page_size;
    int log_page_size;
    char err_msg[ERR_MSG_SIZE];
  public:
    GeneralSpacedbResult()
    {
      page_size = 0;
      log_page_size = 0;
      err_msg[0] = '\0';
    }
    GeneralSpacedbResult (int page_size, int log_page_size)
    {
      this->page_size = page_size;
      this->log_page_size = log_page_size;
      err_msg[0] = '\0';
    }
    int get_page_size()
    {
      return page_size;
    }
    int get_log_page_size()
    {
      return log_page_size;
    }
    void set_page_size (int page_size)
    {
      this->page_size = page_size;
    }
    void set_log_page_size (int log_page_size)
    {
      this->log_page_size = log_page_size;
    }
    const char *get_err_msg()
    {
      return err_msg;
    }
    void set_err_msg (char *str)
    {
      strncpy (err_msg, str, ERR_MSG_SIZE);
    }
    bool has_error()
    {
      return err_msg[0] != '\0';
    }
    virtual void create_result (nvplist *res) = 0;
    virtual int get_cnt_tpage() = 0;
    virtual void get_total_and_free_page (const char *type, double &free_page, double &total_page) = 0;
    virtual time_t get_my_time (char *dbloca) = 0;
    virtual void auto_add_volume (autoaddvoldb_node *current, int db_mode, char *dbname) = 0;
    virtual void read_spacedb_output (FILE *fp) = 0;
    virtual ~GeneralSpacedbResult() {}
};

class SpaceDbResultNewFormat : public GeneralSpacedbResult
{
  public:
    SpaceDbResultNewFormat() {}
    void add_volume (char *);
    int get_cnt_tpage();
    void get_total_and_free_page (const char *type, double &free_page, double &total_page)
    {
      for (unsigned int i = 0; i < volumes.size(); i++)
        {
          if (strcmp (volumes[i].purpose, type) == 0)
            {
              total_page += volumes[i].total_size;
              free_page += volumes[i].free_size;
            }
        }
    }
    time_t get_my_time (char *dbloca);
    void auto_add_volume (autoaddvoldb_node *current, int db_mode, char *dbname);
    void read_spacedb_output (FILE *fp);
    void create_result (nvplist *res);

    DatabaseSpaceDescription databaseSpaceDescriptions[DATABASE_DESCRIPTION_NUM_LINES];
    FileSpaceDescription fileSpaceDescriptions[FILES_DESCRIPTION_NUM_LINES];
  private:
    std::vector<SpaceDbVolumeInfoNewFormat> volumes;
};

class SpaceDbResultOldFormat : public GeneralSpacedbResult
{
  public:
    SpaceDbResultOldFormat() {}
    int get_volume_info (char *, SpaceDbVolumeInfoOldFormat &);
    int add_volume (char *str_buf)
    {
      SpaceDbVolumeInfoOldFormat volume;
      int rc = get_volume_info (str_buf, volume);
      if (rc == TRUE)
        {
          volumes.push_back (volume);
        }
      return rc;
    }

    int add_temporary_volume (char *str_buf)
    {
      SpaceDbVolumeInfoOldFormat volume;
      int rc = get_volume_info (str_buf, volume);
      if (rc == TRUE)
        {
          temporary_volumes.push_back (volume);
        }
      return rc;
    }

    void create_result (nvplist *);
    void get_total_and_free_page (const char *type, double &free_page, double &total_page)
    {
      for (unsigned int i = 0; i < volumes.size(); i++)
        {
          if (strcmp (volumes[i].purpose, type) == 0)
            {
              total_page += volumes[i].total_size;
              free_page += volumes[i].free_size;
            }
        }
    }
    int get_cnt_tpage();
    time_t get_my_time (char *dbloca);
    void auto_add_volume (autoaddvoldb_node *current, int db_mode, char *dbname);
    void read_spacedb_output (FILE *);
  private:
    std::vector<SpaceDbVolumeInfoOldFormat> volumes;
    std::vector<SpaceDbVolumeInfoOldFormat> temporary_volumes;
};

typedef T_CMD_RESULT T_ASQL_RESULT;

GeneralSpacedbResult *cmd_spacedb (const char *dbname, T_ARNIADB_MODE mode);
T_ASQL_RESULT *cmd_asql (char *dbname, char *uid, char *passwd,
                         T_ARNIADB_MODE mode, char *infile, char *command, char *error_continue);
int cmd_start_server (char *dbname, char *err_buf, int err_buf_size);
int cmd_stop_server (char *dbname, char *err_buf, int err_buf_size);
void cmd_start_master (void);
char *arniadb_cmd_name (char *buf);
int read_error_file (const char *err_file, char *err_buf, int err_buf_size);
int read_error_file2 (char *err_file, char *err_buf, int err_buf_size, int *err_code);
int read_asql_error_file (char *err_file, char *err_buf, int err_buf_size);

#endif                /* _AM_COMMAND_EXECUTE_H_ */
