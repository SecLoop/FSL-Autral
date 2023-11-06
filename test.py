# target_string = "AskdEjyzIe_j{_s}"

# def reverse_operations(s):
#     result = bytearray(s, 'utf-8')
#     v12 = bytearray(16)
#     v12[:len(result)] = result

#     v3 = 0
#     v13 = v16 = 0
#     v14 = v19 = 0
#     v15 = v22 = 0
#     v17 = v20 = 0
#     v18 = v23 = 0
#     v21 = v24 = 0

#     while v3 != 16:
#         v10 = v12[v3]
#         if (v10 - 65) <= 0x19:
#             v9 = v3 + v10
#             if v9 > 90:
#                 v9 -= 26
#             v12[v3] = v9
#         elif (v10 - 97) <= 0x19:
#             v9 = v3 + v10
#             if v9 > 122:
#                 v9 -= 26
#             v12[v3] = v9
#         v3 += 1

#     if v12.decode() == target_string:
#         print("Input found:", v12.decode())
#     else:
#         print("Input not found.")

# reverse_operations(target_string)


from PIL import Image

# 打开图像文件
image = Image.open('/Users/bianzhenkun/Desktop/111.jpg')

# 修改图像宽度
new_width = 800  # 新的宽度
width_percent = (new_width / float(image.size[0]))
new_height = int(float(image.size[1]) * float(width_percent))
new_image = image.resize((new_width, new_height), Image.ANTIALIAS)

# 保存修改后的图像
new_image.save('output.jpg')