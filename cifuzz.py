import os
import re
import json


FINDINGS_DIR = "/Users/lousix/sec/CodeQL/JavaProject/Hello-Java-Sec-bak/src/test/resources/com/best/fuzz/FuzzTemplateInputs/fuzzTemplateTest"

BASE_DIR = "/Users/lousix/sec/CodeQL/JavaProject/Hello-Java-Sec-bak"
FUZZ_DIR = ""
SEED_DIR = "/Users/lousix/sec/CodeQL/JavaProject/Hello-Java-Sec-bak/seed-init"
FUZZ_PATH = "com.best.fuzz.FuzzTemplate"
separate_words = [r"\xdc.",r"\x5c."]

def set_seed():
    os.system(f"cd {BASE_DIR} && rm -r seed/ && cp -r seed-init/ seed/")


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
            corpus = re.sub(word, '[sepword]', corpus)
        corpus_list_new.append(corpus.split('[sepword]'))
    return corpus_list_new


def find_all_subsequence(strs):
    
    pass

if __name__ == "__main__":

    with open("data.json", "r") as file:
        data = json.load(file)
    
    print(len(data))
    for item in data:
        fuzz_single_route(item)
        corpus_list = get_corpus(FINDINGS_DIR)
        output = {}
        output["routeName"] = item["routeName"]
        output["sinks"] = item["sinks"]
        # output["corpus"] = corpus_list
        print(output)
        print(corpus_list)
        with open("result_fuzz.json", "ab+") as f:
            f.write(json.dumps(output, indent=4).encode())
            f.write(b"\n")
            # for item in corpus_list:
            #     f.write(item)
            #     f.write(b",")
            f.write(b",".join(corpus_list))
            f.write(b"\n\n")
        print(output)
        clean()



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