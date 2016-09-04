# -*- coding: utf-8 -*-

import idautils
import idc
from idaapi import PluginForm
import operator
import csv
import sys
import os
import json
import subprocess
import platform


def demangle_exe_path():
    sysstr = platform.system()
    if(sysstr =="Darwin"):
        return '/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-demangle'
    if(sysstr =="Windows"):
        directory=os.path.split(os.path.realpath(__file__))[0]
        return directory + '/swift-demangle.exe'

    raise "Only support macOS and Windows"



def demangle(func_list):
    proc = subprocess.Popen(demangle_exe_path(),stdout=subprocess.PIPE,stdin=subprocess.PIPE)
    proc.stdin.write('\n'.join(func_list))
    proc.stdin.close()
    out = proc.stdout.read()
    proc.wait()
    result = out.split('\n')
    return result

AllFunc = []
AllFuncName = []
for func in idautils.Functions():
    name = GetFunctionName(func)

    AllFunc += [func]
    if name [:1] == "_":
        name = name[1:]
    AllFuncName += [name]

demangleList = demangle(AllFuncName)


# To show some special character(like '.' , '@' , '(' , ')') in ida function window,
# demangle swift function name must be wrap in "-[demangle name]" or "+[demangle name]"
def wrapSwiftInOCMethod(funcName):
    funcName = funcName.strip()
    if funcName.startswith('-[') or funcName.startswith('+['):
        return funcName
    if funcName.startswith('static '):
        return  "+[ " + funcName + ' ]'
    return  "-[ " + funcName + ' ]'



for i in xrange(len(AllFunc)):
    addr = AllFunc[i]
    old_name = AllFuncName[i]
    full_name = demangleList[i]
    new_name = full_name
    if "->" in new_name:
        new_name = full_name.split("->")[0]
    # new_name = new_name.replace("@objc ", "_")
    if new_name != old_name:
        new_name = wrapSwiftInOCMethod(new_name);
        MakeNameEx(addr, new_name, SN_NOCHECK|SN_NOWARN)
        SetFunctionCmt(addr, "%s \n%s" % (old_name, full_name), 1)



