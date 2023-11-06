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

separate_words = [r"\xdc.",r"\x5c."]

FUZZ_TEMPALATE = """package org.owasp.webgoat.fuzz;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.fuzz.entity.Param;
import org.owasp.webgoat.fuzz.entity.Route;
import org.owasp.webgoat.lessons.challenges.challenge5.Challenge5;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.http.MediaType;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


public class FuzzTemplate extends LessonTest {
    @BeforeEach
    public void setup() throws Exception {
        when(webSession.getCurrentLesson()).thenReturn(new Challenge5());
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    }

    @FuzzTest
    public void fuzzTemplateTest(FuzzedDataProvider data) throws Exception {
    
            HttpHeaders headers = new HttpHeaders();
            MultiValueMap<String,String> parameters = new LinkedMultiValueMap<>();
            String fuzzTargetUrl;

            %s
            fuzzTargetUrl = "%s";
            HttpMethod method = HttpMethod.valueOf("%s".toUpperCase());

            %s

            %s
            
            mockMvc.perform(request(method, fuzzTargetUrl)
                         .params(parameters).headers(headers)
            ).andExpect(status().isOk());
    }
}
"""

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
            corpus = re.sub(word, '[sepword]', corpus)
        corpus_list_new.append(corpus.split('[sepword]'))
    return corpus_list_new

def gen_assign(data):
    assign_content = ""
    pathParams = data['pathParams']
    getParams = data['getParams']
    postParams = data['postParams']

    for params in [pathParams,getParams,postParams]:
        for param in params:
            if param['property'] == []:
                assign_content += f"String {param['name']} = data.consumeAsciiString(30);\n"
            else:
                for property in param['property']:
                    assign_content += f"String {property} = data.consumeAsciiString(30);\n"
    
    return assign_content

def gen_fuzz_url(routeName, pathParams):
    url = routeName
    for path in pathParams:
        url = url.replace("{"+path+"}", f"\"+{path}+\"")
    return url

def gen_fuzz_headers(header_data):
    header_content = ""
    for header in header_data.keys():
        if header == "Cookie" or header == "Cookies":
            continue
        header_content += f"headers.add(\"{header}\",\"{header_data[header]}\");\n"
    return header_content

def gen_fuzz_params(param_data):
    param_content = ""
    for param in param_data:
        if param['property'] == []:
            param_content += f"parameters.add(\"{param['name']}\",{param['name']});\n"
        else:
            for property in param['property']:
                param_content += f"parameters.add(\"{property}\",{property});\n"
    # print(param_content)
    return param_content

def update_fuzz_url(url, param_data):
    if param_data==[]:
        print(url)
        return url
    url += "?"
    for param in param_data:
        if param['property'] == []:
            url += f'{param["name"]}=" + {param["name"]} + "&'
        else:
            for property in param['property']:
                url += f'{property}=" + {property} + "&'
    # print("\""  + url[:-1] + "\"")
    return url[:-1]

def gen_fuzz_engine(data):
    url = gen_fuzz_url(data['routeName'], data['pathParams'])
    method = data['method'].upper()
    assign = gen_assign(data)
    params = ""
    if method == "GET":
        params = gen_fuzz_params(data['getParams'])
    elif method == "POST":
        params = gen_fuzz_params(data['postParams'])
        url = update_fuzz_url(url, data['getParams'])

    headers = gen_fuzz_headers(data['headers'])

    return assign, url, method, headers, params

def gen_fuzz_content(data):
    assign, url, method, headers, params = gen_fuzz_engine(data)
    # print(assign)
    # print(url)
    # print(method)
    # print(headers)
    # print(params)
    with open(FUZZ_FILE, "w") as f:
        f.write(FUZZ_TEMPALATE % (assign, url, method, headers, params))

    


def find_all_subsequence(strs):
    
    pass

if __name__ == "__main__":

    with open("test.json", "r") as file:
        data = json.load(file)
    
    clean()
    set_seed()

    print(len(data))
    for item in data:
        if item['sinks'] == {}:
            continue
        print("=======================")
        print(gen_fuzz_content(item))
        print("=======================")
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