# backupvolinfo

The backupvolinfo interface will get databases backup volume information.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "backupvolinfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "alatestdb",
  "level": "0",
  "pathname": "$ARNIADB_DATABASES/alatestdb/backup/alatestdb_backup_lv0"
}
```
