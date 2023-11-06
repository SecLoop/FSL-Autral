#! -*- coding:utf-8 -*-
import os
import re
import json
from difflib import SequenceMatcher
from itertools import combinations


# FINDINGS_DIR = "/Users/lousix/sec/CodeQL/JavaProject/Hello-Java-Sec-bak/src/test/resources/com/best/fuzz/FuzzTemplateInputs/fuzzTemplateTest"

# BASE_DIR = "/Users/lousix/sec/CodeQL/JavaProject/Hello-Java-Sec-bak"
# FUZZ_DIR = ""
# SEED_DIR = "/Users/lousix/sec/CodeQL/JavaProject/Hello-Java-Sec-bak/seed-init"
# FUZZ_PATH = "com.best.fuzz.FuzzTemplate"


BASE_DIR = "/Users/lousix/Desktop/华为杯/提交/code/WebGoat-fuzz"
FINDINGS_DIR = f"{BASE_DIR}/src/test/resources/org/owasp/webgoat/fuzz/FuzzTemplateInputs/fuzzTemplateTest/"
# FUZZ_FILE = "/Users/lousix/Desktop/华为杯/提交/code/WebGoat-fuzz/src/test/java/org/owasp/webgoat/fuzz/FuzzTemplate.java"
SEED_DIR = f"{BASE_DIR}/seed-init"
FUZZ_PATH = "org.owasp.webgoat.fuzz.FuzzTemplate"

separate_words = [rb"\xdc.",rb"\x5c."]

def set_seed():
    print(f"rm -r {BASE_DIR}/seed/ && cp -r {BASE_DIR}/seed-init/ {BASE_DIR}/seed/")
    os.system(f"rm -r {BASE_DIR}/seed/; cp -r {BASE_DIR}/seed-init/ {BASE_DIR}/seed/")

def fuzz_single_route(data):
    with open(BASE_DIR + "/data.json", "wb") as f:
        f.write(json.dumps(data, indent=4).encode())
    print(f"cd {BASE_DIR} && cifuzz run {FUZZ_PATH}")
    # os.system(f"cd {BASE_DIR}&& cifuzz ")
    os.system(f"cd {BASE_DIR}&& cifuzz run {FUZZ_PATH}")

def clean():
    print(f"cd {BASE_DIR} && rm -r .cifuzz-build/ .cifuzz-corpus/ .cifuzz-findings/ target/ && rm -r {FINDINGS_DIR}")
    os.system(f"cd {BASE_DIR} && rm -r .cifuzz-build/ .cifuzz-corpus/ .cifuzz-findings/ target/ && rm -r {FINDINGS_DIR}")

def get_corpus(filepath):
    corpus = []
    file_list = os.listdir(filepath)

    # 遍历文件列表，筛选出文件
    for file_name in file_list:
        if not os.path.isfile(os.path.join(filepath, file_name)):
            continue
        with open(os.path.join(filepath, file_name), 'rb') as f:
            corpus.append(f.read())
    return corpus

def seperate_corpus(corpus_list):   
    corpus_list_new = []
    for corpus in corpus_list:
        for word in separate_words:
            corpus = re.sub(word, b'[sepword]', corpus)
        corpus_list_new.append(corpus.split(b'[sepword]'))
    return corpus_list_new

def find_similar(target):
    vote_feature = {}
    combinations_list = list(combinations(target, 2))
    for item in combinations_list:
        matcher = SequenceMatcher(None, item[0], item[1])
        for match in matcher.get_matching_blocks():
            if match.size == 0:
                continue
            key = item[0][match.a:match.a+match.size]
            
            if key in vote_feature.keys():
                vote_feature[key] += 1
            else:
                vote_feature[key] = 1
    return vote_feature

def check_corpus_valid(corpus, feature):
    for item in feature:
        if item not in corpus:
            return False
    return True

def find_valid_corpus(target, feature):
    corpus = ""
    for corpus_target in target:
        if check_corpus_valid(corpus_target, feature):
            corpus = corpus_target
    
    feature = sorted(feature, key=len)
    for item in feature:
        # print(item)
        corpus = corpus.replace(item, b"{{keywords:*"+item+b"*}}")
    return corpus

def set_param_fuzz_value(data, num, payload):
    pathParams = data['pathParams']
    getParams = data['getParams']
    postParams = data['postParams']

    if num < len(pathParams):
        data["pathParams"][num]["value"] = payload
    elif num - len(pathParams) < len(getParams):
        data["getParams"][num - len(pathParams)]["value"] = payload
    else:
        print(num - len(pathParams) - len(getParams))
        data["postParams"][num - len(pathParams) - len(getParams)]["value"] = payload
    return data

def find_all_subsequence(corpus_list, data):
    corpus_sep = seperate_corpus(corpus_list)
    print(corpus_sep)
    min_len = min(min(len(temp) for temp in corpus_sep), len(data['getParams']) + len(data['postParams']) + len(data['pathParams']))

    feature = []
    target = []
    for i in range(min_len):
        target = []
        for n in range(len(corpus_sep)):
            if corpus_sep[n][i] != "":
                target.append(corpus_sep[n][i])

        if len(target) <= 1:
            data = set_param_fuzz_value(data, i, target[0])
        else:
            vote_feature = find_similar(target)
            print(vote_feature)
            highest_vote = max(vote_feature.values())
            feature = [key for key, value in vote_feature.items() if value == highest_vote]
            payload_demo = find_valid_corpus(target, feature)
            data = set_param_fuzz_value(data, i, payload_demo)

    return data


        
def gen_fuzz_poc(data):
    print(data)
    url = data['routeName'].encode()
    pathParams = data['pathParams']
    getParams = data['getParams']
    postParams = data['postParams']
    httpHeaders = data['headers']

    for path in pathParams:
        url = url.replace(b"{"+path.encode()+b"}", path['value'])
    
    if len(getParams) > 0:
        url += b"?"
    for param in getParams:
        if "value" in param.keys():
            url += param['name'].encode() + b"=" + param['value'] + b"&"
        else:
            postData += param['name'].encode() + b"=&"
    if len(getParams) > 0:
        url = url[:-1]

    headers = b""
    for key in httpHeaders.keys():
        headers += key.encode() + b": " + httpHeaders[key].encode() + b"\n"

    postData = b""
    for param in postParams:
        if "value" in param.keys():
            postData += param['name'].encode() + b"=" + param['value'] + b"&"
        else:
            postData += param['name'].encode() + b"=&"
    if len(postParams) > 0:
        postData = postData[:-1]

    return b"""%b %b HTTP/1.1
Host:
%b
%b""" % (data['method'].encode(), url, headers, postData)
    

if __name__ == "__main__":

    with open("data.json", "r") as file:
        data = json.load(file)
    
    clean()
    set_seed()
    count = 0
    for item in data:
        if item['sinks'] == {}:
            continue
        fuzz_single_route(item)
        corpus_list = get_corpus(FINDINGS_DIR)
        output = {}
        output["routeName"] = item["routeName"]
        output["sinks"] = item["sinks"]
        print("====================")
        print(output)
        # corpus_list = [b'22229222222>\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000\'"\x08\n\r\t\\%_222222222222322105222\n']

        print(corpus_list)
        print("====================")
        if corpus_list == []:
            continue
        # if len(item['getParams']) + len(item['postParams']) + len(item['pathParams']) > 1:
        reuslt_fuzz = find_all_subsequence(corpus_list, item)
        # else:
            # reuslt_fuzz = set_param_fuzz_value()
        content = gen_fuzz_poc(reuslt_fuzz)
        with open(f"templates/poc_{count}.txt" , 'wb') as f:
            f.write(content)
        clean()
        set_seed()
        count += 1


