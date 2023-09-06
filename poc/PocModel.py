# -*- coding: utf-8 -*-
import os

class PocModel:
    def __init__(self, ):
        self.method = "GET"
        self.path = ""
        self.content_type = "application/x-www-form-urlcoded"
        self.cookie = ""
        self.header = {
            "User-Agent": "",
        }

    def yaml_gen(self, ):
        module = """
        """ % ()
        self.output(module)

    def output(self, content, filename, path):
        open(os.path.join(path, filename), "w").write(content)

    
    



