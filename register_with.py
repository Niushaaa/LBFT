import json
import requests

url = "http://127.0.0.1:7000/register_with"
data = {"node_address": "http://127.0.0.1:8000", "req_chain": 1}
headers = {'Content-Type': "application/json"}
requests.post(url,
              data=json.dumps(data),
              headers=headers)

url = "http://127.0.0.1:7001/register_with"
data = {"node_address": "http://127.0.0.1:8000", "req_chain": 1}
headers = {'Content-Type': "application/json"}
requests.post(url,
              data=json.dumps(data),
              headers=headers)

url = "http://127.0.0.1:7000/register_with"
data = {"node_address": "http://127.0.0.1:7001", "req_chain": 0}
headers = {'Content-Type': "application/json"}
requests.post(url,
              data=json.dumps(data),
              headers=headers)