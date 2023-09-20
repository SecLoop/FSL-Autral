import pandas as pd
import os
import yaml
import glob
import re

database_path = '/Users/bianzhenkun/Desktop/L3ttuc3WS/CodeQLWS/CodeQLpy/out/database/java-sec-code/'
base_url = 'http://127.0.0.1:8080/WebGoat'
xray_path = '/Users/lousix/sec/info/xray/'
xray_config_path = '/Users/lousix/sec/info/xray/xray_config/'
# 这里的cookie用于测试存储型xss
cookie = 'JSESSIONID=3by2cwrK-NJmj77t8EFYxr1JKcRIa9eh98-1X2zi'
csv_path = '/Users/lousix/sec/CodeQL/codeqlpy-plus/out/result/mytest/SpringController/result_webgoat.csv'
params_csv_path = '/Users/lousix/sec/CodeQL/codeqlpy-plus/out/result/mytest/ExtractElement/result_webgoat.csv'
java_type_list = ['int','double','float','long','long long','Integer','Double','Float','Long','Map','HashMap','List','Set']

base_route = "/WebGoat"
vuln_source = "/Users/lousix/sec/CodeQL/codeqlpy-plus/out/result/mytest/OWASP/result_webgoat.csv"
project_dir ="/Users/lousix/sec/CodeQL/codeqlpy-plus/"
payloads = ["' or 1=1 --", "file:///etc/passwd"]


# 对于数据进行初始化，对于所有涉及到的xray配置文件进行Cookie赋值
def initEnv(data_source):
    initCookie()
    # 初次需要放开这个构建数据库与Excel数据文件
    # initCSV(database_path)
    return initData(data_source)
    
def initCookie():
    yaml_files = glob.glob(xray_config_path+'*.yaml')
    for file in yaml_files:
        print(file)
        modifyConfigYaml(file,['http','headers','Cookie'],cookie)
     
# 构建数据库，并运行所有需要的ql文件，保存在csv中   
def initCSV(database_path):
    os.system(f'cd /Users/bianzhenkun/Desktop/L3ttuc3WS/CodeQLWS/codeqlpy-plus && python3 main.py -d {database_path}')

# 初始化数据
def initData(data_source):
    data = pd.read_csv(data_source)
    # 添加了一列，表示提取该参数的方法，param_method
    title = ['controller','method','route','content-type','request_method','param','source-type','annotation','param_method']
    data.columns = title
    return formatData(data)
    
# 原始csv中所有数据前面都加了个空格
def formatData(data):
    data = data.applymap(lambda x: x.strip() if isinstance(x, str) else x)
    return data

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

# data为GET方法某个url的所有数据行，DataFrame类型
def singleGetMethodCase(data, route, source):
    print(route)
    # url = base_url + route
    path = base_route + route
    url_params = ''
    
    # 如果没有任何注解，代表单纯的GET请求，直接将参数拼接
    if data.iloc[0]['annotation'] == 'no AnAnnotation':
        for index, row in data.iterrows():
            if source == row['param']:
                param = row['param'] if row['param'][0] != '"' else row['param'][1:-1]
                url_params = url_params + param + '={{payload_input}}&'
            else:
                param = row['param'] if row['param'][0] != '"' else row['param'][1:-1]
                url_params = url_params + param + '=&'
    # 若有注解，分情况处理
    else:
        for index, row in data.iterrows():
            if row['annotation'] == 'RequestParam':
                if source == row['param']:
                    param = row['param'] if row['param'][0] != '"' else row['param'][1:-1]
                    url_params = url_params + param + '={{payload_input}}&'
                else:
                    param = row['param'] if row['param'][0] != '"' else row['param'][1:-1]
                    url_params = url_params + param + '=&'
            if row['annotation'] == 'CookieValue':
                # print('cookie!')
                # 这里不知道怎么解决yaml文件里的cookie注入，先写一个固定的
                modifyConfigYaml(xray_config_path+'config_get.yaml',['http','headers','Cookie'],row['param'] + '=123;')
    path = path + '?' + url_params[:-1]
    return PoC2GetYaml(path, xray_config_path+'config_get.yaml')
    
# 处理所有GET方法的结果，传入所有方法为GET方法的data集
def getMethodCase(data,  source):
    grouped_data = data.groupby('route')
    for route, group in grouped_data:
        singleGetMethodCase(group, route, source) 


# V2版本按照参数添加到url上还是body中进行分类，对于添加到body里的，就只发送POST，否则POST和GET都打一遍
# 同样的，传入的参数data还是route路由下所有的行
# 由于涉及到url和body的多次组合，故采用两个列表
def singalRequestAndPostV2(data,route, source):
    # url = base_url + route
    path = base_route + route
    # print(url)
    url_params = ''
    request_body = ''
    has_get = True
    
    # url+' '+request_body
    post_list = []
    # url
    get_list = []
    
    for index, row in data.iterrows():
        # 提取当前参数
        param = row['param'] if row['param'][0] != '"' else row['param'][1:-1]
        # 赋值Conten-Type
        modifyConfigYaml(xray_config_path+'config_request.yaml',['http','headers','Content-Type'],row['content-type'])
        
        # case 1:添加cookie的，目前写死固定值 
        if row['annotation'] == 'CookieValue':
            modifyConfigYaml(xray_config_path+'config_request.yaml',['http','headers','Cookie'],param + '=123;')
        # case 2:没有注解，这种情况比较复杂
        elif row['annotation'] == 'no AnAnnotation':
            # case 2.1: getParameter的话，post和get都可能，而且url和body里的参数都可以用getParameter读取
            # if row['param_method'].startWith('getParameter'):
            #     pass
            # case 2.2: getHeader的话，就是获取的header的东西，我们只需要改yaml文件就行
            if str(row['param_method']).startswith('getHeader'):
                # 这里header_value先默认getHeader获取的是Host，之后添加list动态更改
                header_value = '127.0.0.1'
                modifyConfigYaml(xray_config_path+'config_request.yaml',['http','headers',param],header_value)
            # case 2.3: no get，发现情况也比较复杂，get和post都可以，故与case 2.1合并
            # elif row['param_method'] == 'no get':
            # 合并后就是get的放到get_list中，post的放到post_list中
            # 由于是针对某个url的操作，我们这里其实是对param的组合，分别为
                # 1. get的直接就把参数放到get上
                # 2. post的把post放到post上
                # 3. 然后组合，注意某一个参数只有一个位置，不能url和body同时出现同一个参数的
                # 4. 以上是生成post的请求的过程，对于get请求，直接把所有参数写到url里就行
            else:
                if source != param:
                    url_params = url_params + param + '=&'
                    request_body = request_body + param + '=&'
                else:
                    url_params = url_params + param + '={{payload_input}}&'
                    request_body = request_body + param + '={{payload_input}}&'
                # get_list.append(url+'/?'+url_params[:-1])
                # post_list.append(request_body[:-1]) 
        # case 3: 有注解，并且是@RequestBody，那么就一定是POST，我们需要做的就是不发送GET请求
        elif row['annotation'] == 'RequestBody':
            has_get = False
            if source != param:
                request_body = request_body + param + '=&'
            else:
                request_body = request_body + param + '={{payload_input}}&'
            post_list = [x+param+'=&' for x in post_list]
        # case 4: 有注解，并且为@RequestParam，不能确定是post还是get
        elif row['annotation'] == 'RequestParam':
            # url_params = url_params + param + '=&'
            # get_list = [x+param+'=&' for x in get_list]
            if source != param:
                url_params = url_params + param + '=&'
                # print(url_params)
                request_body = request_body + param + '=&'
            else:
                url_params = url_params + param + '={{payload_input}}&'
                # print(url_params)
                request_body = request_body + param + '={{payload_input}}&'
            # get_list.append(url+'/?'+url_params[:-1])
            # post_list.append(request_body[:-1]) 
        else:
            print('还没有考虑到的情况！！！')
        

        # get_list.append(url+'/?'+url_params[:-1])
        # post_list.append(request_body[:-1]) 
        # print(post_list)
        # print(get_list)
        # 组合发送，这里为了简单省事，直接全组合，毕竟实际参数也不多，后期需要优化组合
        # 发送POST请求
        # if len(post_list) > 0:
        #     for i in get_list:
        #         for j in post_list:
        #             send2Xray(i,'POST',j,xray_config_path+'config_request.yaml')
        # # 发送GET请求，没有请求体
        # if has_get:
        #     for i in get_list:
        #         send2Xray(i,'GET',None,xray_config_path+'config_request.yaml')
        # print(url_params)

        # if url_params != "":
        #     PoC2GetYaml(path + "?" + url_params[:-1], xray_config_path+'config_request.yaml')

        if request_body != "":
            headers = {
                "Content-Type": row['content-type']
            }
            PoC2PostYaml(path, xray_config_path+'config_request.yaml', headers, request_body[:-1])

        # print(request_body)

            
def requestAndPostMethodCaseV2(data, source):
    grouped_data = data.groupby('route')
    for route, group in grouped_data:
        singalRequestAndPostV2(group, route, source)

def PoC2GetYaml(path, config):
    for payload in payloads:
        poc_filename = genGetYaml(path, payload)
        command = f"cd {xray_path} && ./xray_darwin_arm64 --config {config} webscan --url {base_url} --poc {project_dir + poc_filename}"
        send2Xray(command)


def PoC2PostYaml(path, config, headers, body):
    for payload in payloads:
        poc_filename = genPostYaml(path, body, payload, headers)
        command = f"cd {xray_path} && ./xray_darwin_arm64 --config {config} webscan --url {base_url} --poc {project_dir + poc_filename}"
        send2Xray(command)

# 统一发送到xray黑盒验证
# def send2Xray(path,request_method,body,config):
def send2Xray(command):
    print(command)
    result = os.system(command)
    # 每次运行完命令，都需要将环境还原
    os.system(f'cd {xray_config_path} && cp ./bak.yaml ./config_get.yaml && cp ./bak.yaml ./config_post.yaml && cp ./bak.yaml ./config_request.yaml')

# 将数据分类处理
def doClassification(data, source):
    grouped_data = data.groupby('request_method')
    for request_method, group in grouped_data:
        print(request_method)
        if request_method == 'GetMapping':
            getMethodCase(group, source)
        else:
            requestAndPostMethodCaseV2(group, source)


def checkRes():
    file_path = '/Users/bianzhenkun/Desktop/log.out'
    with open(file_path,'r') as f:
        data = f.readlines()
        data = ''.join(data)
    pattern = r'Target\s+"([^"]+)"'
    matches = re.findall(pattern, data)
    if matches:
        print("Target:", matches)
    else:
        print("Target not found")


def initVuln(vuln_source):
    data = pd.read_csv(vuln_source)
    title = ['controller','method','source','sink','vulnType','param1','param2','param3','param4']
    data.columns = title
    return formatData(data)


def getVulnRoute(controller, method, data):
    data_group = data.groupby("controller")
    for controller_g, index_controller in data_group:
        if controller_g == controller :
            data_method = index_controller.groupby("method")
            for method_g, index_method in data_method:
                if method_g == method:
                    return index_method
    return None

def genGetYaml(path, payload):
    filename = "poc/Get.yaml"
    yamlGet = f"""name: poc-yaml-example-com
transport: http
rules:
    r1:
        request:
            cache: true
            method: GET
            path: {path}
            follow_redirects: true
        expression: |
            response.status==200
expression:
    r1()
detail:
    author: Lousix
    links:
        - https://docs.xray.cool/
""".replace("{{payload_input}}", payload)
    with open(filename, "w") as file:
        file.write(yamlGet)
    return filename


def genPostYaml(path, body, payload, headers):
    filename = "poc/Post.yaml"
    headers_yaml = ""
    for key in headers.keys():
        headers_yaml += f"\n                {key}: {headers[key]}"
    yamlPost = f"""name: poc-yaml-example-com
transport: http
rules:
    r1:
        request:
            cache: true
            method: POST
            headers:{headers_yaml}
            path: {path}
            body: {body}
            follow_redirects: true
        expression: |
            response.status==200
expression:
    r1()
detail:
    author: Lousix123
    links:
        - https://docs.xray.cool/
""".replace("{{payload_input}}", payload)
    with open(filename, "w") as file:
        file.write(yamlPost)
    return filename


if __name__ == '__main__':
    # count = 0

    data = initEnv(csv_path)
    vuln_data = initVuln(vuln_source)

    for index, row in vuln_data.iterrows():
        data_route = getVulnRoute(row['controller'],row['method'], data)
        if data_route is None:
            # print("13243243432" + row['source'])
            continue
        # count+=1
        # print(row)
        # print(row['source'])
        source =  row['source'].split(":")[0].strip()
        # print(source)
        doClassification(data_route, source)
        print("===============================")


    # print(count)
    # checkRes()