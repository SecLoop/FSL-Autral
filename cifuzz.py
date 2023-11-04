#! -*- coding:utf-8 -*-
import os
import re
import json


# FINDINGS_DIR = "/Users/lousix/sec/CodeQL/JavaProject/Hello-Java-Sec-bak/src/test/resources/com/best/fuzz/FuzzTemplateInputs/fuzzTemplateTest"

# BASE_DIR = "/Users/lousix/sec/CodeQL/JavaProject/Hello-Java-Sec-bak"
# FUZZ_DIR = ""
# SEED_DIR = "/Users/lousix/sec/CodeQL/JavaProject/Hello-Java-Sec-bak/seed-init"
# FUZZ_PATH = "com.best.fuzz.FuzzTemplate"


BASE_DIR = "/Users/lousix/Desktop/华为杯/提交/code/WebGoat-fuzz"
FINDINGS_DIR = f"{BASE_DIR}/src/test/resources/org/owasp/webgoat/fuzz/FuzzTemplateInputs/fuzzTemplateTest/"
FUZZ_FILE = "/Users/lousix/Desktop/华为杯/提交/code/WebGoat-fuzz/src/test/java/org/owasp/webgoat/fuzz/FuzzTemplate.java"
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

def find_all_subsequence(strs):
    
    pass

if __name__ == "__main__":

    with open("test.json", "r") as file:
        data = json.load(file)
    
    clean()
    set_seed()
    for item in data:
        if item['sinks'] == {}:
            continue
        # fuzz_single_route(item)
        # corpus_list = get_corpus(FINDINGS_DIR)
        output = {}
        output["routeName"] = item["routeName"]
        output["sinks"] = item["sinks"]
        # output["corpus"] = corpus_list
        print(output)
        corpus_list = [b"Larry\\\x89['\\\x89[\xf2\xf2", b"Larry\\\x89['\x12\r", b"Larry\\;\x89@'\x00\x00\x00\x18\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff{\\,\xb1\xf2\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", b"Larry\\\x89@'[", b"Larry\\\x89['\xf2\xf2"]
        print(corpus_list)
        # print(b"\n".join(seperate_corpus(corpus_list)))

        if len(data['getParams']) + len(data['postParams']) + len(data['pathParams']) > 1:
            aaa = seperate_corpus(corpus_list)
        
            for w in aaa:
                print(w)
        # with open("result_fuzz.json", "ab+") as f:
        #     f.write(json.dumps(output, indent=4).encode())
        #     f.write(b"\n")
        #     f.write(b",".join(corpus_list))
        #     f.write(b"\n\n")
        # print(output)
        clean()
        set_seed()













    # parts = re.split(r'\x5c.', input_string)
    # print(parts)

    # fuzz_single_route(data)

    

    # corpus_list = get_corpus(FINDINGS_DIR)
    # corpus_list = ["Larry\x5c\xaawww\x5c\xaahtml","Larry\x5c\xcawww\x5c\xachtml"]
    # corpus_list = seperate_corpus(corpus_list)
    # print(corpus_list)

    # param_corpus = []
    # for i in range(len())

    # if len(corpus_list) <= 1:
    #     print(corpus_list)
    #     # return corpus_list
    # else:
    #     match_seq = find_all_subsequence(corpus_list)
    #     print(match_seq)









#  data = """{
#   "routeName": "/RCE/ProcessBuilder/vul",
#   "filePath": "",
#   "className": "ProcessBuilderVul",
#   "method": "POST",
#   "getParams": [],
#   "postParams": [{
#     "name": "filepath",
#     "pos": "POST",
#     "classType": "String",
#     "property": []
#   }],
#   "pathParams": [],
#   "headers": {
#     "Cookies": "",
#     "Content-Type": "application/x-www-form-urlencoded"
#   },
#   "sinks": {
#     "classType": "String",
#     "name": "filepath",
#     "pos": "POST",
#     "property": [],
#     "vulnType": "ExecTainted"
#   },
#   "yaml": ""
# }
# """


# from fuzzywuzzy import fuzz

# str1 = "apple"
# str2 = "apples"

# similarity_ratio = fuzz.ratio(str1, str2)
# print("字符串相似度:", similarity_ratio)

# from difflib import SequenceMatcher

# # str1 = "abcdefgjjjacdrrr"
# # str2 = "abdefghoooacdppp"
# str1 = "\n\n"
# str2 = "\njazze"
# matcher = SequenceMatcher(None, str1, str2)
# match = matcher.find_longest_match(0, len(str1), 0, len(str2))
# print(match)
# common_part = str1[match.a:match.a + match.size]
# print("相同部分:", common_part)
# # strings = ["fdddsabcdef", "rtewabcde", "gfdgeabcdf"]

# print(list(matcher.get_matching_blocks()))

# if __name__ == "__main__":
#     # print(get_corpus(BASE_DIR))
#     strings = ["fdddsabcdef", "rtewabcde", "gfdgeabcdf"]
#     # strings = [b'\r\r\n', b'\n\n', b'\njazze']
#     result = longest_common_subsequence(strings)
#     print("最长公共子串:", result)