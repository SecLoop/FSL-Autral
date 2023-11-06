import pandas as pd
import json
import copy
import os
import yaml
import glob
from jinja2 import Template
import time
import base64
from cifuzz import *

current_directory = os.getcwd()
# csv_path = current_directory + '/out/result/mytest/SpringController/result_micro_service_seclab.csv'
csv_path = current_directory + '/out/result/mytest/SpringController/result_Hello-Java-Sec-1.11.csv'
# csv_path = current_directory + '/out/result/mytest/SpringController/result_webgoat.csv'
base_url = current_directory + '/out'
cifuzz_path = current_directory + '/out/fuzz.json'
res_path = current_directory + '/out/data4.json'
xray_path = '/Users/bianzhenkun/Desktop/'
xray_plus_path = '/Users/bianzhenkun/Downloads/xray_1.9.3_darwin_amd64/'
xray_config_path = '/Users/bianzhenkun/Desktop/xray_config/'
base_website_url = 'http://localhost:8080'
init_cookie = ''
folder_path = '/Users/bianzhenkun/Downloads/Hello-Java-Sec-1.11'
yaml_path = current_directory + '/poc/Templates/output.yaml'
extract_element_path = base_url+'/result/mytest/ExtractElement/result_Hello-Java-Sec-1.11.csv'
url_params = []
body_params = []
sub_path = []
cookie_params = []
other_params = []
json_list = []
my_class_params = {}
cifuzz_list = []
poc_dict = {}
name_num = 0
name_num1 = 0

def initEnv():
    initCookie()
    return initData()

# 初始化数据
def initData():
    data = pd.read_csv(csv_path)
    title = ['controller','method','route','content-type','request_method','param','source-type','annotation','param_method']
    data.columns = title
    return formatData(data)

def initCookie():
    yaml_files = glob.glob(xray_config_path+'*.yaml')
    for file in yaml_files:
        modifyConfigYaml(file,['http','headers','Cookie'],init_cookie)

# 原始csv中所有数据前面都加了个空格，所以要格式化一下
def formatData(data):
    data = data.applymap(lambda x: x.strip() if isinstance(x, str) else x)
    return data

"""

以下为最初设想，采用的分类讨论，但是考虑多种因素，最终使用dfs遍历所有情况，只进行粗略的剪枝操作
具体操作如下：
对于同一个route，将该接口方法
每次遍历到叶子结点，就将

=============================
原设想（并未实现）：
classifiedParams方法是对某一条route进行的处理
考虑到判断GET和POST只有以下方法：
    1. GetMapping/PostMapping，可以绝对的判断方法
    2. RequestMapping，需要去提取注解的参数method
    3. 如果RequestMapping注解没有给出参数method，那么需要看HttpServlet的getMathod方法的返回值，但是对于Java Sec Code，全部用的这个，由于我们无法获得getMethod的返回值，所以GET和POST都要发
分类讨论：
    1. 对于@PathVariable和@PathParam，他们两个无所谓GET还是POST，都是url上的参数，直接加到url_param里
    2. 对于@RequestParam，无法区分是GET还是POST
        2.1 如果出现了GetMapping，就一定在url里
        2.2 如果出现了PostMapping，那就url和body里递归，但是只需要发POST包
        2.3 如果出现了RequestMapping，那么url和body里递归
    3. 对于ReuqestBody，可以确定在body里，而且可以确定是POST
    4. 对于没有注解的情况，就是HttpServlet情况了，需要判断最后一列param_method，如果是getParameter(...)，仍然无法确定是在url还是body里，需要递归，而且GET和POST都要发
    
    position==0代表在GET，默认为0，为1则代表在body里
"""
def classifiedParams(data,route,index):
    data = data.reset_index(drop=True)
    # 到达叶子结点
    if index==len(data):
        generateJson(route,data)
        prepareForCIFuzz(route)
        return 
    if data['source-type'][index] == 'MultipartFile':
        # 文件上传，当正常参数处理，后期打特定payload，这个地方需要王正和的payload，文件上传漏洞验证xray如果跑不出来，那么就到最后一步，最后一步打payload
        # 更新，遇到这种情况，直接打一个文件上去，然后第三阶段poc判断的时候，直接访问这个特定文件，
        addBodyParam(data['source-type'][index])
        classifiedParams(data,route,index+1)
        deleteBodyParam()
    elif data['annotation'][index] == 'CookieValue':
        addCookie(data['param'][index])
        classifiedParams(data,route,index+1)
        deleteCookie()
    elif data['annotation'][index] == 'PathVariable' or data['annotation'][index] == 'PathParam':
        temp_route = route + '/' if route[-1]!= '/' else '' + data['param'][index] + '/'
        addPathVaribale(temp_route)
        classifiedParams(data,temp_route,index+1)
        deletePathVariable()
    else:
        if data['request_method'][index] == 'GetMapping':
            addUrlParam(data['param'][index])
            classifiedParams(data,route,index+1)
            deleteUrlParam()
        elif str(data['param_method'][index]).startswith('getHeader'):
            addHeaders(data['param'][index])
            classifiedParams(data,route,index+1)
            deleteHeaders()
        elif data['annotation'][index] == 'RequestBody':
            # 这里选择的方法是将需要解析的类名的解析结果进行存储，在生成json的时候进行解析
            if data['source-type'][index] != 'String':
                # print(base_url+'/result/mytest/ExtractElement/result_Hello-Java-Sec.csv')
                class_data = pd.read_csv(extract_element_path)
                class_params = class_data[class_data['cls'] == data['source-type'][index]]['cls']
                for value in class_params:
                    addBodyParam(value)
                classifiedParams(data,route,index+1)
                for value in class_params:
                    deleteBodyParam()
                # my_class_params[data['source-type'][index]] = class_params
                # addUrlParam(data['source-type'][index])
                # classifiedParams(data,route,index+1)
                # deleteUrlParam()
            else:
                # requestbody string类型需要添加
                addBodyParam('POST_Data') #用这个占位，打payload的时候，直接换json的格式
                classifiedParams(data,route,index+1)
                deleteBodyParam()
                
        elif str(data['param_method'][index]).startswith('getParameter') and data['param'][index] == 'this.callback':
            addUrlParam('callback_')
            classifiedParams(data,route,index+1)
            deleteUrlParam()
        else:
            temp_param_data = data['param'][index]
            # 方便检测先干掉url里的参数
            addUrlParam(temp_param_data)
            classifiedParams(data,route,index+1)
            deleteUrlParam()
            addBodyParam(temp_param_data)
            classifiedParams(data,route,index+1)
            deleteBodyParam()
        
def addCookie(value):
    cookie_params.append(value.strip("\""))
    
def deleteCookie():
    cookie_params.pop()
    
def addPathVaribale(value):
    sub_path.append(value.strip("\""))
    
def deletePathVariable():
    sub_path.pop()
    
def addUrlParam(value):
    url_params.append(value.strip("\""))
    
def deleteUrlParam():
    url_params.pop()
    
def addBodyParam(value):
    body_params.append(value.strip("\""))
    
def deleteBodyParam():
    body_params.pop()
    
def addHeaders(value):
    other_params.append(value.strip("\""))
    
def deleteHeaders():
    other_params.pop()
    
def groupData(data):
    grouped_data = data.groupby('route')
    for route, group in grouped_data:
        group['content-type'] = group['content-type'].apply(process_content_type)
        print(group)
        if len(group[group['content-type']=='application/json']) >0:
            group['content-type'] = 'application/json'
        unique_group = group.drop_duplicates()
        # print(unique_group)
        classifiedParams(unique_group,route,0)
        
def process_content_type(content_type):
    if pd.isna(content_type) or content_type in ['', '""', '{...}']:
        return 'application/x-www-form-urlencoded'
    else:
        return content_type

def generateJson(route,data):
    if data['request_method'][0] == 'GetMapping':
        method = 'GET'
    elif data['request_method'][0] == 'PostMapping' or data['annotation'][0] == 'RequestBody':
        method = 'POST'
    else:
        method = 'GET' if len(body_params)==0 else 'POST'
    
    # 获得params
    params = []
    get_params = []
    post_params = []
    path_params = []
    for i in url_params:
        get_params.append({'name':i,'pos':'GET','classType':data['source-type'][0],'property':[]})
    for i in body_params:
        post_params.append({'name':i,'pos':'POST','classType':data['source-type'][0],'property':[]})
    for i in sub_path:
        path_params.append({'name':i,'pos':'Path','classType':data['source-type'][0],'property':[]})
        
    get_params = rmDuplicates(get_params)
    post_params = rmDuplicates(post_params)
    path_params = rmDuplicates(path_params)
    
    # 获得headers
    headers = {}
    headers['Cookies'] = '=;'.join(cookie_params)
    # print('type:'+str(data['content-type'][0]))
    headers['Content-Type'] = data['content-type'][0] if not pd.isna(data['content-type'][0]) else 'application/x-www-form-urlencoded'
    for i in other_params:
        headers[i] = ''
    params = [dict(t) for t in {tuple(sorted(d.items())) for d in params}]
    
    #生成sinks
    sinks = []
    sink_data = pd.read_csv('/Users/bianzhenkun/Downloads/newsink2.csv')
    sinks = sink_data[(sink_data['c'] == data['controller'][0]) & (sink_data['m'] == data['method'][0])][['source', 'col4']].values.tolist()
    sinks = list(map(list, set(map(tuple, sinks))))
    
    if len(sinks) ==0 :
        res = {'routeName':route,'filePath':'','className':data['controller'][0],'method': method, 'getParams':get_params, 'postParams':post_params,'pathParams':path_params, 'headers':headers, 'sinks':{}, 'yaml':''}
        json_list.append(res)
    print('----------')
    # print(sinks)
    for sink in sinks:
        param_name,param_type = [s.strip() for s in sink[0].split(":")]
        sink_temp = {}
        sink_temp['classType'] = param_type
        sink_temp['name'] = param_name
        if param_name in url_params:
            sink_temp['pos'] = 'GET' 
        elif param_name in body_params:
            sink_temp['pos'] = 'POST'
        elif param_name in sub_path:
            sink_temp['pos'] = 'Path'
        sink_temp['property'] = []
        sink_temp['vulnType'] = sink[1]
        
        # res = {'routeName':route,'filePath':'','className':data['controller'][0],'method': method, 'params':params, 'headers':headers, 'sinks':sink_temp, 'yaml':''}
        res = {'routeName':route,'filePath':'','className':data['controller'][0],'method': method, 'getParams':get_params, 'postParams':post_params,'pathParams':path_params, 'headers':headers, 'sinks':sink_temp, 'yaml':''}
        json_list.append(res)
        
def prepareForCIFuzz(route):
    headers = {}
    headers['Cookies'] = '=;'.join(cookie_params)
    for i in other_params:
        headers[i] = ''
    # 这里有浅拷贝问题
    res = {'route':route,'url_params':copy.deepcopy(url_params),'body_params':copy.deepcopy(body_params),'headers':headers,'sub_path':sub_path}
    cifuzz_list.append(res)
    
def saveJsonData():
    with open(cifuzz_path, 'w') as file:
        json.dump(cifuzz_list, file)
    with open(res_path, 'w') as file:
        json.dump(json_list, file)
        
    
def modifyConfigYaml(config_path,key,value):
    with open(config_path,'r') as f:
        config_data = yaml.safe_load(f.read()) 
    with open(config_path,'w') as f:
        updateValue(config_data, key, value)
        yaml.safe_dump(config_data,f)

# 递归函数，根据路径修改字典的值
def updateValue(data, path, new_value):
    if len(path) == 1:
        data[path[0]] = new_value
    else:
        updateValue(data[path[0]], path[1:], new_value)

# 发送给xray跑
def send2Xray(url,request_method,body,config):
    global name_num1
    command = f'cd {xray_path} && ./xray_darwin_amd64 --config xray_config/{config} webscan --url {url}'
    if request_method == 'POST':
        command += ' --data {}'.format(body if len(body)>0 else '\"\"')
    print('=================command1:'+command+'=================')
    with open(current_directory + '/commands2.txt','a+') as f:
        f.write(command+'\n')
    os.system(command + ' --html-output' + f' /Users/bianzhenkun/Desktop/L3ttuc3WS/CodeQLWS/codeqlpy-plus/out/fuzz_result/1105_fuzz_result_'+str(name_num1)+'.html')
    name_num1 += 1 
    # 每次运行完命令，都需要将环境还原
    # os.system(f'cd {xray_config_path} && cp ./bak.yaml ./config_get.yaml && cp ./bak.yaml ./config_post.yaml && cp ./bak.yaml ./config_request.yaml')

def send2XrayPlus(url,request_method,body):
    global name_num1
    command = f'cd {xray_plus_path} && ./xray_darwin_amd64 webscan --plugins phantasm,jsonp,struts,shiro,fastjson --url {url}'
    if request_method == 'POST':
        command += ' --data {}'.format(body if len(body)>0 else '\"\"')
    with open(current_directory + '/commands2.txt','a+') as f:
        f.write(command+'\n')
    print('=================command2:'+command+'=================')
    os.system(command + ' --html-output' + f' /Users/bianzhenkun/Desktop/L3ttuc3WS/CodeQLWS/codeqlpy-plus/out/fuzz_result/1105_plus_fuzz_result_'+str(name_num1)+'.html')
    name_num1 += 1 
    # 每次运行完命令，都需要将环境还原
    # os.system(f'cd {xray_config_path} && cp ./bak.yaml ./config_get.yaml && cp ./bak.yaml ./config_post.yaml && cp ./bak.yaml ./config_request.yaml')

# 开始xray fuzz
def xrayFuzz():
    with open(res_path,"r") as f:
        data = json.load(f)
    # 探索框架漏洞
    send2Xray(base_website_url,'GET','','config_get.yaml')
    for item in data:
        route = base_website_url + item['routeName'] + '?'
        body = ''
        config_path = f"config_{str(item['method']).lower()}.yaml"
        # for key in item['headers']:
        #     modifyConfigYaml(xray_config_path+config_path,['http','headers',item['headers'][key]],'test')
        for i in item['getParams']:
            route += i['name'] + '=&'
        while route.endswith('?') or route.endswith('&'):
            route = route[:-1]
        for i in item['postParams']:
            body += i['name'] + '=&'
        send2Xray(route,item['method'],body[:-1],config_path)
        send2XrayPlus(route,item['method'],body[:-1])
        
def initPocDict():
    with open('/Users/bianzhenkun/Desktop/poc.txt') as f:
        pocs = f.readlines()
    for line in pocs:
        poc_data = line.split('—')
        poc_dict[poc_data[0]] = [poc_data[1],poc_data[2]]
    # print(poc_dict)

    
def xrayFuzzWithPocs():
    with open(res_path,"r") as f:
        data = json.load(f)
    # print(data)
    for item in data:
        config_path = f"config_{str(item['method']).lower()}.yaml"
        route = base_website_url + item['routeName'] + '?'
        if len(item['sinks'])==0:
            continue
        sink_param = item['sinks']['name']
        # 我们需要先生成yaml，然后根据sink的参数名字，将其值进行payload的遍历，对于每次生成的yaml，放到xray里跑
        # 1. 生成基础yaml
        # 1.1 获取模板
        if item['method'] == 'GET':
            with open('/Users/bianzhenkun/Desktop/L3ttuc3WS/CodeQLWS/codeqlpy-plus/poc/Templates/Get.yaml') as file:
                template_content = file.read()
            template = Template(template_content)
        else:
            with open('/Users/bianzhenkun/Desktop/L3ttuc3WS/CodeQLWS/codeqlpy-plus/poc/Templates/Post.yaml') as file:
                template_content = file.read()
            template = Template(template_content)
        # 1.2 获取模板数据，根据方法获取模板，并渲染基础数据
        # 1.3 遍历sink，生成paylaod，由于我们本身就在便利，每个item只有一个sink，所以这里就不需要遍历了,考虑后这里可以放在生成path和body的时候，一边生成一边查找是不是sink的参数名，如果是的话，就标记{payload}
        yaml_data = {}
        path = item['routeName']
        body = ''
        # for i in str(item['pathParams']):
        #     path += '/' + i
        if len(item['getParams']) >0:
            path += '?'
            for i in item['getParams']:
                if i['name'] == sink_param:
                    path += i['name'] + '=p4yl04d&'
                else:
                    path += i['name'] + '=&'
        for i in item['postParams']:
            if i['name'] == sink_param:
                body += i['name'] + '=p4yl04d&'
            else:
                body += i['name'] + '=&'
        for key in item['headers']:
            yaml_data[key.replace('-','')] = item['headers'][key]
        yaml_data['path'] = path[:-1] if len(item['getParams'])>0 else path
        if item['method'] == 'POST':
            yaml_data['body'] = body[:-1]
        rendered_yaml = template.render(yaml_data)
        with open(yaml_path, 'w') as file:
            file.write(rendered_yaml)

        # 1.4 遍历poc，生成最终带poc和expression的yaml文件，把yaml发送到xray进行攻击
        for payload in poc_dict:
            # 每次将保存有替换标记的yaml写到文件内
            with open(yaml_path, 'w') as file:
                file.write(rendered_yaml)
            # 字符串形式读取，全局替换payload
            with open(yaml_path,'r') as f:
                yaml_data_temp = f.read()
            with open(yaml_path,'w') as f2:
                yaml_data_temp = yaml_data_temp.replace('p4yl04d',payload)
                yaml_data_temp = yaml_data_temp.replace('3xpr3ss10n',poc_dict[payload][0])
                yaml_data_temp = yaml_data_temp.replace('p0cN4m3',poc_dict[payload][1])
                f2.write(yaml_data_temp)
                print('done')
            sendYaml2Xray(base_website_url,item['method'],body[:-1],config_path,yaml_path)

def sendYaml2Xray(url,request_method,body,config,poc):
    global name_num
    command = f'cd {xray_path} && ./xray_darwin_amd64 --config {xray_config_path+config} webscan --url {url}'
    if request_method == 'POST':
        command += ' --data {}'.format(body if len(body)>0 else '\"\"')
    command += f' --poc {poc}'
    os.system(command + ' --html-output ' + ' /Users/bianzhenkun/Desktop/L3ttuc3WS/CodeQLWS/codeqlpy-plus/out/fuzz_result2/fuzz2_result_'+str(name_num)+'.html')
    name_num += 1
    # 每次运行完命令，都需要将环境还原
    # os.system(f'cd {xray_config_path} && cp ./bak.yaml ./config_get.yaml && cp ./bak.yaml ./config_post.yaml && cp ./bak.yaml ./config_request.yaml')


    
def mergeSinkCsvs():
    merged_csv_path = "/Users/bianzhenkun/Downloads/newsink.csv"
    main_folder = "/Users/bianzhenkun/Downloads/Hello-Java-Sec-1.11"
    merged_data = pd.DataFrame()

    # 遍历每个文件夹
    for folder in os.scandir(main_folder):
        if folder.is_dir():
            if folder.is_dir() and folder.name in ["SpringController", "ExtractElement"]:
                continue
            folder_path = folder.path
            for file in os.listdir(folder_path):
                file_path = os.path.join(folder_path, file)
                if file.endswith(".csv"):
                    df = pd.read_csv(file_path)
                    # 这里先去除后缀，但是需要人工标注漏洞类型
                    df.iloc[:, 4] = df.iloc[:, 4].str[:-3]
                    selected_columns = df.iloc[:, :5]
                    merged_data = pd.concat([merged_data, selected_columns], ignore_index=True)
    merged_data.to_csv(merged_csv_path, index=False)
    print("合并完成！")
    
def rmDuplicates(params):
    unique_params = []
    seen_params = set()
    for param in params:
        param_without_property = {k: v for k, v in param.items() if k != 'property'}
        param_tuple = tuple(param_without_property.items())
        if param_tuple not in seen_params:
            unique_params.append(param)
            seen_params.add(param_tuple)   
    return unique_params 


# 接入cifuzz
def cifuzz(data):    
    clean()
    set_seed()
    count = 0
    for item in data:
        if item['sinks'] == {}:
            continue
        fuzz_single_route(item)
        corpus_list = get_corpus(FINDINGS_DIR)
        # output = {}
        # output["routeName"] = item["routeName"]
        # output["sinks"] = item["sinks"]
        if corpus_list == []:
            continue
        reuslt_fuzz = find_all_subsequence(corpus_list, item)
        content = gen_fuzz_poc(reuslt_fuzz)
        # write a poc file
        with open(f"templates/poc_{count}.txt" , 'wb') as f:
            f.write(content)
        clean()
        set_seed()
        count += 1


if __name__ == '__main__':
    # 1. 初始化环境
    params_data = initEnv()
    mergeSinkCsvs()
    # # 2. 对codeql的结果进行处理，生成data.json
    groupData(params_data)
    saveJsonData()
    # # 3. Fuzz Stage1，xray黑盒测试
    xrayFuzz()
    # # 4. Fuzz Stage2，加载poc list，根据sink，自动化生成针对性的xray yaml，发送到xray测试
    initPocDict()
    xrayFuzzWithPocs()
    cifuzz()
    
    
    