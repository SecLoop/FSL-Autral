import pandas as pd

route = 'aaaaa'
url_params = ['aaa','vvv']
# data = [['apple', 10], ['banana', 15], ['orange', 12]]

# 创建DataFrame对象
df = pd.DataFrame([route,url_params], columns=['route','param'])
# df = pd.DataFrame(data, columns=['fruits', 'quantity'])
print(df)


# 将DataFrame保存为CSV文件
df.to_csv('/Users/bianzhenkun/Desktop/未命名文件夹 3/L3ttuc3WS/CodeQLWS/QLinspector/ql/data.csv', index=False)