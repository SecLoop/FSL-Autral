# -*- coding: utf-8 -
import os
import subprocess
import traceback
import tempfile

path = "/Users/lousix/Desktop/Java-ICS/"
database_path = "/Users/lousix/sec/CodeQL/CodeQLpy/out/database/"

files= os.listdir(path)
s = []
for file in files:
    if "base1.jar" in file:
        s.append(file)


def subprocess_popen(statement):
    p = subprocess.Popen(statement,stdout=subprocess.PIPE, shell=True)  # 执行shell语句并定义输出格式
    resout = []
    reserr = []
    out, err = p.communicate()
    return out, err

for file in s:
    dir = file.replace(".jar","")

    print("\nCommand1:")
    print(f"python3 main.py -t {path + file} --compiled")
    resout, reserr = subprocess_popen(f"python3 main.py -t {path + file} --compiled")

    print("\n\n\nCommand2:")
    print (f'codeql database create out/database/{dir} --language=java --command="/bin/bash -c /Users/lousix/sec/CodeQL/CodeQLpy/out/decode/run.sh" --overwrite')
    resout, reserr = subprocess_popen(f'codeql database create out/database/{dir} --language=java --command="/bin/bash -c /Users/lousix/sec/CodeQL/CodeQLpy/out/decode/run.sh" --overwrite')

    print("\n\n\nCommand3:")
    print(f"python3 main.py -d { database_path + dir}")
    resout = subprocess_popen(f"python3 main.py -d { database_path + dir}")