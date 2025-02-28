#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import os
import json
from abc import abstractmethod
import utils.color_print as color_print

from utils.functions import *
from utils.log    import log


class Scan():

    def __init__(self, ):
        self.result_path = "out/result/"

    # 获取插件对应的描述信息
    @staticmethod
    def getInfo(plugin_name):
        pass

    # 获取插件对应的ql查询语句
    @staticmethod
    def getQuery(plugin_name):
        try:
            if not plugin_name.endswith(".ql"):
                plugin_name += ".ql"
            return readFile(plugin_name)
        except Exception as e:
            log.error("Plugin Error, do not use chinese words.")

    # 获取目录下的插件列表
    @staticmethod
    def getPluginList(dirpath):
        ret = []
        for filename in dirFiles(dirpath):
            if filename.endswith(".ql"):
                ret.append(filename[:-3])
        return ret

    # 保存扫描结果
    def saveResult(self, results, filename, pluginname):

        directory = os.path.dirname(filename)

        # 检查目录是否存在，如果不存在则递归创建目录
        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(filename + ".csv", 'w') as w:
            w.write("")
        if len(results) <= 1:
            return

        with open(filename + ".csv", mode='w', newline='') as file:
            writer = csv.writer(file)

            for row in results:
                writer.writerow(row)


        # for i in range(len(results)):
        #     if i == 0:
        #         continue
        #     result = results[i]
        #     with open(filename + ".csv", 'a') as w:
        #         w.write(("\t ".join(result) + '\n'))

    def saveSink(self, result, filename, pluginname):
        with open(filename + ".json", 'w') as w:
            w.write(result)

    # 初始化保存结果的文件
    def initResult(self, filename):
        title = "Source, SourceFunction, SourcePath, Sink, SinkFunction, SinkPath, Remark, Plugin\n"
        with open(os.path.join(self.result_path ,filename), 'a') as w:
            w.write(title)


    # 必须实现的抽象方法，用来执行对应类型的插件扫描
    @abstractmethod
    def run():
        pass

