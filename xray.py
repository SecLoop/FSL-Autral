import requests
import pandas as pd
import os

base_url = 'http://127.0.0.1:8080'
data = pd.read_csv('/Users/bianzhenkun/Desktop/new_result_S1.csv')
urls = data['route']
for url in urls:
    os.system('cd ~/Desktop & ./xray_darwin_amd64 webscan --url {url} --json-output {url}.json')

res = os.system('cd /Users/bianzhenkun/Desktop & ./xray_darwin_amd64 webscan --url http://127.0.0.1:8080/codeinject?filepath=1  --json-output report5.json')
