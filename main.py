#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import argparse 
import utils.color_print as color_print

from utils.check        import *
from scan.JavaScan      import JavaScan
from compiler.database  import createDB


print('''Welcome to 
_______________.___. _________            .___     ________  .____     
\______   \__  |   | \_   ___ \  ____   __| _/____ \_____  \ |    |    
 |     ___//   |   | /    \  \/ /  _ \ / __ |/ __ \ /  / \  \|    |    
 |    |    \____   | \     \___(  <_> ) /_/ \  ___//   \_/.  \    |___ 
 |____|    / ______|  \______  /\____/\____ |\___  >_____\ \_/_______ \
           \/                \/            \/    \/       \__>       \/
''')


if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument('-d', '--database', type=str, help='CodeQL database dir of target project')
    args.add_argument('-t', '--target', type=str, help='Target CodeSource')
    args.add_argument('-r', '--root', type=str, help='Target webroot path')
    args.add_argument('-c', '--compiled', action="store_true", help='Target CodeSource is compiled')
    args.add_argument('-s', '--skip', action="store_true", help='Skip checking environment')
    args.add_argument('-v', '--version', type=int, default=8, help='Target Source Code JDK version')
    args.add_argument('-j', '--jar', type=str, default="", help='Additional jar path, eg: oa1.jar,oa2.jar')

    parse_args = args.parse_args()

    if not parse_args.database and not parse_args.target:
        args.print_help()
        sys.exit()

    # 跳过环境检测，第一次不建议跳过，后续跳过节省时间
    if not parse_args.skip:
        if not checkEnv():
            color_print.error("Environment Error")
            sys.exit()

    # 直接基于数据库进行扫描
    if parse_args.database:
        if not checkDB(parse_args.database):
            color_print.error("Database Error")
            sys.exit()

        if not checkQL(parse_args.database):
            color_print.error("qlpath error,check it at config/config.ini or close the Visual Studio Code.")
            sys.exit()

        color_print.info("Environment Check Success, start to scan database.")

        JavaScan().run(parse_args.database)
    else:
        # 通过源代码进行扫描
        if " " in parse_args.target.strip():
            color_print.error("Target path does not allow blank space")
            sys.exit()

        if not parse_args.root:
            parse_args.root = parse_args.target
        target_type = checkTarget(parse_args.target)
        if not target_type:
            color_print.error("Target Error")
            sys.exit()
        color_print.info("Environment Check Success, start to init database.")
        version = parse_args.version
        if version not in [6,7,8,11, ]:
            version = 8
        # 通过源码创建数据库
        createDB(parse_args.target, parse_args.compiled, version, parse_args.jar, parse_args.root)





