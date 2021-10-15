# startinfo

Get databases' information in arniadb.

## Request Json Syntax


| **Key** | **Description** |
| --- | --- |

| task | task name |
| token | token string encrypted. |


## Request Sample

```
{
  "task":"startinfo",
  "token":"4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
}
```

## Response Json Syntax


| **Key** | **Description** |
| --- | --- |

| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dblist | the whole databases in the arniadb, including its name and path.  |
| activelist | get the databaes' name in active status. |


## Response Sample

```
{
   "__EXEC_TIME" : "72 ms",
   "activelist" : 
      {
         "active" : [
            {
               "dbname" : "testdb"
            }
      }
   ],
   "dblist" : 
      {
         "dbs" : [
            {
               "dbdir" : "/home/huangqiyu/arniadb_8.4.3/databases/testdb3",
               "dbname" : "testdb3"
            },
            {
               "dbdir" : "/home/huangqiyu/arniadb_8.4.3/databases/testdb2",
               "dbname" : "testdb2"
            },
            {
               "dbdir" : "/home/huangqiyu/arniadb_8.4.3/databases/testdb",
               "dbname" : "testdb"
            }
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "startinfo"
}
```
