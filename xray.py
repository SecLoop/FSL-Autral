import pandas as pd
import os
import yaml
import glob

base_url = 'http://127.0.0.1:8080'
xray_path = '/Users/bianzhenkun/Desktop/'
cookie = ''
csv_path = '/Users/bianzhenkun/Desktop/L3ttuc3WS/CodeQLWS/codeqlpy-plus/out/result/mytest/SpringController/result_java-sec-code.csv'

# 对于数据进行初始化，对于所有涉及到的xray配置文件进行Cookie赋值
def initEnv(data_source):
    initCookie()
    return initData(data_source)
    
def initCookie():
    yaml_files = glob.glob(xray_path+'*.yaml')
    for file in yaml_files:
        modifyConfigYaml(file,['http','header','Cookie'],cookie,0)

# 初始化数据
def initData(data_source):
    data = pd.read_csv(data_source)
    # 添加了一列，表示提取该参数的方法，param-method
    title = ['controller','method','route','content-type','request-method','param','source-type','annotation','param-method']
    data.columns = title
    return formatData(data)
    
# 原始csv中所有数据前面都加了个空格
def formatData(data):
    data = data.applymap(lambda x: x.strip() if isinstance(x, str) else x)
    return data

# type 0代表仅修改，1代表继续添加，2代表删除，key为修改参数的层级[layer1,layer2,...,layer n]的格式，value表示值
def modifyConfigYaml(config_path,key,value,type):
    with open(config_path) as f:
        config_data = yaml.safe_load(f)
        for layer in key:    
            update_value(config_data, key, value)
        
# 递归函数，根据路径修改字典的值
def update_value(data, path, new_value):
    if len(path) == 1:
        data[path[0]] = new_value
    else:
        update_value(data[path[0]], path[1:], new_value)

# data为GET方法某个url的所有数据行，DataFrame类型
def singleGetMethodCase(data,route):
    url = base_url + route
    url_params = ''
    # 如果没有任何注解，代表单纯的GET请求，直接将参数拼接
    if data.iloc[0]['annotation'] == 'no AnAnnotation':
        for index, row in data.iterrows():
            param = row['param'] if row['param'][0] != '"' else row['param'][1:-1]
            url_params = url_params + param + '=&'
    # 若有注解，分情况处理
    else:
        for index, row in data.iterrows():
            if row['annotation'] == 'RequestParam':
                param = row['param'] if row['param'][0] != '"' else row['param'][1:-1]
                url_params = url_params + param + '=&'
            if row['annotation'] == 'CookieValue':
                # print('cookie!')
                # 这里不知道怎么解决yaml文件里的cookie注入，先写一个固定的
                modifyConfigYaml(xray_path+'config_get.yaml',['http','header','Cookie'],row['param'] + '=123;',1)
    url = url + '/?' + url_params[:-1]
    return send2Xray(url,'GET',None)
    
# 处理所有GET方法的结果，传入所有方法为GET方法的data集
def getMethodCase(data):
    grouped_data = data.groupby('route')
    for route, group in grouped_data:
        singleGetMethodCase(group,route)
    
# data为POST方法某个url的所有数据行，DataFrame类型
def singlePostMethodCase(data,route):
    url = base_url + route
    url_params = ''
    req_body = ''
    
    # 这里和Get反过来，Get可以通过第一行是否有直接判断出怎么做，但是Post可能后面会有，而且完全没有的情况下单独分析性价比不高，到头来还要重新分析一次带有annotation的
    for index, row in data.iterrows():
        # 情况1: 这条数据是no AnAnnotation，需要修改Cntent-Type，一般为文件上传，xray测不，这里就添加一下header然后pass了
        if row['annotation'] == 'no AnAnnotation':
            modifyConfigYaml(xray_path+'config_post.yaml',['http','header','Content-Type'],'multipart/form-data; boundary=xxx',1)

    #感觉Post的有点晕，起床再说
            
            
# data为request方法某个url的所有数据行，DataFrame类型
# 需要补充的列：
#   1. param-method：提取参数的时候是什么方法，比如getParameter('param1')来提param1，这里就写getParameter
#   2. request-method：在@RequestMapping中的method，比如method = {RequestMethod.POST, RequestMethod.GET}，代表支持POST和GET，没有写就代表POST、GET、INPUT等所有方法都支持（在想这个要不要加，可以直接全部打一遍）
def singalRequest(data,route):
    url = base_url + route
    url_params = ''
    contain_get = True
    request_body = ''
    
    # 我们输入的是这个url对应的所有数据行，我们没法通过一行直接判断是GET还是POST，我们默认认为是GET，当出现requestbody的时候，就将request_method改为POST
    for index, row in data.iterrows():
        param = row['param'] if row['param'][0] != '"' else row['param'][1:-1]
        # case 1: 当没有注释的时候，就是函数内部或者形参上提取
        if row['annotation'] == 'no AnAnnotation':
            # case 1.1: 提取的参数方法是getParameter，直接拼到url路径里
            if row['param-method'] == 'getParameter':
                url_params = url_params + param + '=&' 
            # case 1.2: 提取的参数方法是getHeader，就将header写入yaml文件，但是yaml文件里这个不清楚怎么跑xray，故先写一个定值
            elif row['param-method'] == 'getHeader':
                modifyConfigYaml(xray_path+'config_request.yaml',['http','header',param],'127.0.0.1',1)
            # case 1.3: 提取的方法是无，那么这个url可能在url里也有可能在body里，都要打一遍
            elif row['param-method'] == '':
                request_body = url_params + param + '=&' 
                url_params = url_params + param + '=&' 
        # case 2: 注释为CookieValue时，修改header的cookie
        elif row['annotation'] == 'CookieValue':
            modifyConfigYaml(xray_path+'config_get.yaml',['http','headers','Cookie'],param + '=123;',1)
        # case 3: 注释为RequestBody时，需要判断是否有参数，有参数的话需要判断是否为某个类，如果是某个类，需要将这个类解析为这个类的内容
        elif row['annotation'] == 'RequestBody':
            contain_get = False
            # 处理直接post json格式的内容，这里只进行header添加
            if row['content-type'] == 'application/json':
                modifyConfigYaml(xray_path+'config_request.yaml',['http','headers','Content-Type'],' application/json',1)
            else:
                # 这里需要判断当前请求参数是否在需要解析的类中，具体没有想好怎么实现，索性先用True代替
                if True:
                    pass
        # case4: RequestParam情况
        elif row['annotation'] == 'RequestParam':
            request_body = url_params + param + '=&' 
            url_params = url_params + param + '=&' 
                
        url = url + '/?' + url_params[:-1]    
        send2Xray(url,'GET',None)
        if len(request_body) > 0:
            send2Xray(url,'POST',request_body[:-1])
    
         
def requestMethodCase(data):
    grouped_data = data.groupby('route')
    for route, group in grouped_data:
        singalRequest(group, route)

# 统一发送到xray黑盒验证
def send2Xray(url,request_method,body):
    command = f'cd {xray_path} && ./xray_darwin_amd64 webscan --url {url}'
    print(command)
    if request_method == 'POST':
        command += ' --data {}'.format(body)
    result = os.system(command)
    # 每次运行完命令，都需要将环境还原
    os.system(f'cd {xray_path} && cp ./bak.yaml ./config_get.yaml && cp ./bak.yaml ./config_post.yaml && cp ./bak.yaml ./config_request.yaml')
    return result


if __name__ == '__main__':
    data = initEnv(csv_path)
    getMethodCase(data)
    


