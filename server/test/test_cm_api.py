import httplib,urllib
import json
import struct
import requests

cmsip="localhost"
port=8001
url="/cm_api"

cminfo = "{\'task\":\"login\",\
\"id\":\"admin\",\
\"password\":\"admin\",\
\"clientver\":\"10.2\"\}"

json_cmi_payload = str(json.dumps(cminfo))
print json_cmi_payload

r = requests.post("https://localhost:8001/cm_api", data = json_cmi_payload, verify = False)
print r.text

















def exec_task(ip, port, url, body):
    conn = httplib.HTTPConnection(ip, port)
    conn.request("POST", url, body)
    resp = conn.getresponse().read()
    conn.close()
    data=json.loads(resp.decode())
    print (resp.decode())
    return data

def do_task(task):
    json_cmi["task"] = task
    response = exec_task(cmsip, port, url, str(json.dumps(json_cmi)))
    return response

do_task("sql")

# import sql
do_task("importdb")
# export sql
do_task("exportdb")

json_cmi["class"] = ["code"]
# export csv
json_cmi["export_type"] = 1
json_cmi["export_path"] = "task_test_sql/db.csv"
do_task("exportdb")
#import csv
json_cmi["import_type"] = 1
json_cmi["import_path"] = "task_test_sql/db.csv"
do_task("importdb")

do_task("oid_get")
do_task("oid_put")
json_cmi["oids"] = ["@540|1|0"]
do_task("oid_del")