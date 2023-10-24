import pandas as pd
import json

csv_path = 'out/result/mytest/SpringController/result_java-sec-code.csv'
base_url = '~/L3ttuc3WS/CodeQLWS/codeqlpy-plus/out/'
cifuzz_path = 'fuzz.json'
res_path = 'data.json'
url_params = []
body_params = []
sub_path = []
cookie_params = []
other_params = []
json_list = []
my_class_params = {}
cifuzz_list = []

# 初始化数据
def initData():
    data = pd.read_csv(csv_path)
    title = ['controller','method','route','content-type','request_method','param','source-type','annotation','param_method']
    data.columns = title
    return formatData(data)

# 原始csv中所有数据前面都加了个空格
def formatData(data):
    data = data.applymap(lambda x: x.strip() if isinstance(x, str) else x)
    return data

"""
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
    if index==len(data):
        generateJson(route,data)
        prepareForCIFuzz(route)
        # print(data)
        # print(url_params)
        # print(body_params)
        # print(other_params)
        # print(sub_path)
        # print(cookie_params)
        # print('------------')
        return 
    if data['annotation'][index] == 'CookieValue':
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
        elif data['param_method'][index].startswith('getHeader'):
            addHeaders(data['param'][index])
            classifiedParams(data,route,index+1)
            deleteHeaders()
        elif data['annotation'][index] == 'RequestBody':
            # 这里选择的方法是将需要解析的类名的解析结果进行存储，在生成json的时候进行解析
            if data['source-type'][index] != 'String':
                class_data = pd.read_csv(base_url+'result/mytest/ExtractElement/result_java-sec-code.csv')
                class_params = class_data[class_data['cls'] == data['source-type'][index]]
                my_class_params[data['source-type'][index]] = class_params
                
                addUrlParam(data['source-type'][index])
                classifiedParams(data,route,index+1)
                deleteUrlParam()
                
        elif data['param_method'][index].startswith('getParameter') and data['param'][index] == 'this.callback':
            addUrlParam('callback_')
            classifiedParams(data,route,index+1)
            deleteUrlParam()
        else:
            temp_param_data = data['param'][index]
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
        classifiedParams(group,route,0)
        
def generateJson(route,data):
    #获得方法
    if data['request_method'][0] == 'GetMapping':
        method = 'GET'
    elif data['request_method'][0] == 'PostMapping':
        method = 'POST'
    else:
        method = 'GET' if len(body_params)==0 else 'POST'
        
    # 获得params
    params = []
    for i in url_params:
        params.append({'name':i,'pos':'GET','classType':data['source-type'][0],'property':''})
    for i in body_params:
        # 拆分类到属性，但是目前未测试
        # if i in my_class_params['Cls'].values:
        #     params = my_class_params[my_class_params['Cls']==i]['Field']
        #     for index, row in params.iterrows():
                
        #         params.append({'name':row['Cls'],'pos':'POST','classType':row['Col2'],'property':''})
        # else:
        #     params.append({'name':i,'pos':'POST','classType':data['source-type'][0],'property':''})
        params.append({'name':i,'pos':'POST','classType':data['source-type'][0],'property':''})
    
    # 获得headers
    headers = {}
    headers['Cookies'] = '=;'.join(cookie_params)
    for i in other_params:
        headers[i] = ''
    
    res = {'routeName':route,'filePath':'','className':data['controller'][0],'method': method, 'params':params, 'headers':headers, 'sinks':[], 'yaml':''}
    json_list.append(res)
        
def prepareForCIFuzz(route):
    headers = {}
    headers['Cookies'] = '=;'.join(cookie_params)
    for i in other_params:
        headers[i] = ''
    
    res = {'route':route,'url_params':url_params,'boday_params':body_params,'headers':headers,'sub_path':sub_path}

    cifuzz_list.append(res)
    
def saveJsonData():
    with open(cifuzz_path, 'w') as file:
        json.dump(cifuzz_list, file)
    with open(res_path, 'w') as file:
        json.dump(json_list, file)
    

if __name__ == '__main__':
    params_data = initData()
    groupData(params_data)
    saveJsonData()
    # json_string = json.dumps(json_list)
    # print(json_string)
    # json_string2 = json.dumps(cifuzz_list)
    # print(json_string2)