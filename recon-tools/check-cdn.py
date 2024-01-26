#!/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import random
import argparse
import dns.resolver
from itertools import combinations
from qqwry import QQwry
import asyncio
import aiodns
import multiprocessing
from multiprocessing import Manager
import itertools


# 获取当前文件的绝对路径
Base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 处理文件的类
class FileHandler:
    # 确保文件夹存在
    @staticmethod
    def ensure_dir_exists(dir_path):
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)
    # 读取文件
    @staticmethod
    def load_file(file_path) -> list[str]:
        if os.path.isfile(file_path) and os.path.splitext(file_path)[1] == '.txt':
            with open(file_path, "r") as f:
                contents = [line.rstrip("\n") for line in f]
            return contents
        else:
            print(f"Fail to open file: {file_path}")
            return []
    # 写入文件
    @staticmethod
    def output_to_file(file_path, data):
        with open(file_path, "w") as f:
            for _ in data:
                f.write(_ + "\n")

# 处理IP的类
class NetHandler(object):
    # 检查IP是否在同一网段
    @staticmethod
    def check_same_subnet(ip01:str, ip02:str):
        if not isinstance(ip01, str) or not isinstance(ip02, str):
            ip01 = str(ip01)
            ip02 = str(ip02)

        def ip_to_int(ip):
            parts = ip.split('.')
            ip_int = 0
            for part in parts:
                ip_int = ip_int << 8 | int(part)
            return ip_int

        subnet_mask = ip_to_int("255.255.255.0")

        return (ip_to_int(ip01) & subnet_mask) == (ip_to_int(ip02) & subnet_mask)
    
    # 查询IP所在地
    @staticmethod
    def find_ip_location(ips_list: list[str]) -> list[str]:
        ip_local_list = []
        q = QQwry()
        q.load_file(os.path.join(Base_dir, "data", "qqwry_lastest.dat"))
        if q.is_loaded():
            for ip in ips_list:
                ip_local_list.append(q.lookup(ip)[0][0:3])
        return ip_local_list
    
    # 处理IP，如果IP在同一网段，则归为同一网段，否则不处理
    # 不需要，只需以255.255.255.0作为子网掩码，将所有ip的化为 x.x.x.0形式，去重即可
    @staticmethod
    def handle_ips(ips_list: list[str]) -> list[str]:
        ip_network_segment_list = ['.'.join(ip.split('.')[:3]) + '.0' for ip in ips_list]
        return set(ip_network_segment_list)

# DNS解析类
class DNSResolver(object):

    def __init__(self):
        self.loop = asyncio.get_event_loop()

    async def perform_dns_query(self, hostname, resolver):
        try:
            result = await resolver.query(hostname, 'A')
            ips = [ip.host for ip in result]
            return ips
        except aiodns.error.DNSError as e:
            return []
        
    async def perform_dns_query_cname(self, hostname, resolver):
        try:
            result = await resolver.query(hostname, "CNAME")
            return result.cname
        except (asyncio.TimeoutError, aiodns.error.DNSError) as e:
            return "cname_no_data'"
        
    async def resolve_with_multiple_servers(self, hostname, resolver_list):
        tasks = []
        for resolver_addr in resolver_list:
            resolver = aiodns.DNSResolver(nameservers=[resolver_addr])
            task = asyncio.ensure_future(self.perform_dns_query(hostname, resolver))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        return results

        

# 检查CDN的类
class Check_CDN(object):

    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.validResolversList = []
        self.vailcdncnames = []
        self.noCdnDomains = []
        self.useCdnDomains = []
        self.__reversfile_path = os.path.join(self.base_dir, "data", "resolvers.txt")
        self.__cnamefile_path = os.path.join(self.base_dir, "data", "cdn_cname.txt")
        self.__load_data()

    def __load_data(self):
        self.validResolversList = FileHandler.load_file(self.__reversfile_path)
        self.vailcdncnames =  FileHandler.load_file(self.__cnamefile_path)
        
    def output_to_files(self):
        output_dir = os.path.join(os.getcwd(), "output")
        FileHandler.ensure_dir_exists(output_dir)
        FileHandler.output_to_file(os.path.join(output_dir, "useCdnDomains.txt"), self.useCdnDomains)
        FileHandler.output_to_file(os.path.join(output_dir, "noCdnDomains.txt"), self.noCdnDomains)



    def resolve_domain(self, domain, resolvers_list, dnsresolver):

        result =  dnsresolver.loop.run_until_complete(dnsresolver.resolve_with_multiple_servers(domain, resolvers_list))
        return list(itertools.chain.from_iterable(result))
    


    def check_domain(self, domain:str, usecdndomain_list:list, nocdndomain_list:list):
        
        print(f"Processing {domain} in process {os.getpid()}")

        if not isinstance(domain, str): domain = str(domain)

        dnsresolver = DNSResolver()
        try:
            answers1 =  dnsresolver.loop.run_until_complete(dnsresolver.perform_dns_query_cname(domain, aiodns.DNSResolver()))
            if answers1 != "cname_no_data'":
                answers2 = dnsresolver.loop.run_until_complete(dnsresolver.perform_dns_query_cname(answers1, aiodns.DNSResolver()))

                # if set(['.'.join(answer.split('.')[-2:]) for answer in (answers1,answers2) ]).issubset(self.vailcdncnames):
                if (('.'.join(answers1.split('.')[-2:])) in self.vailcdncnames) or (('.'.join(answers2.split('.')[-2:])) in self.vailcdncnames):
                    print(f"[+]此域名存在 CNAME 记录 >> {domain}")
                    print(f"[+]此域名的 CNAME 为已知 CDN 域名  存在 CDN >> {domain}")
                    self.useCdnDomains.append(domain)
                else:
                    print(f"[-]此域名的 CNAME 为未知 CDN 域名 >> {domain}")

                    # 从DNS服务器列表中随机选取30个解析器
                    resolver_list = random.sample(self.validResolversList, 30)

                    # 从30个解析器中解析域名
                    result =  dnsresolver.loop.run_until_complete(dnsresolver.resolve_with_multiple_servers(domain, resolver_list))
                    ips_list = list(set(itertools.chain.from_iterable(result)))
                    

                    # 检查上述解析的IP是否在同一网段，是则归为同一网段，写入ip_result_list
                    ip_network_segment_list = NetHandler.handle_ips(ips_list)


                    # 对上述的ip进行查询所在地
                    # 如果上述的IP超过3个网段，且IP所在地超过3个，则判断为CDN
                    if (len(set(ip_network_segment_list)) > 3) and (len(set(NetHandler.find_ip_location(ips_list))) > 3):
                        print(f"[+]此域名存在 CDN >> {domain}")
                        self.useCdnDomains.append(domain)
                    else:
                        print(f"[+]此域名不存在 CDN >> {domain}")
                        self.noCdnDomains.append(domain)
            else:
                # 无响应，则不存在CNAME记录，则判断为无CDN
                print(f"[+]此域名无 CNAME 记录 >> {domain}")
                # ipadds = [ip.to_text() for ip in resolver.resolve(domain, 'A')]
                self.noCdnDomains.append(domain)

        except Exception as e:
            print(e)

        finally:
            usecdndomain_list.extend(self.useCdnDomains)
            nocdndomain_list.extend(self.noCdnDomains)



def handle_domain(domain):
    domains = domain.split(",")
    handle_check(domains)

def handle_domain_file(domain_file):
    domains = FileHandler.load_file(domain_file)
    handle_check(domains)

def handle_default():
    print("please check the command")
    sys.exit()

def handle_check(domains):
    checker = Check_CDN()
    with Manager() as manager:
        usecdndomain_list = manager.list()
        nocdndomain_list = manager.list() 
        pool = multiprocessing.Pool(processes=4)
        for domain in domains:
            pool.apply_async(checker.check_domain, (domain,usecdndomain_list,nocdndomain_list))
        pool.close()
        pool.join()

        print(f"[+]使用cdn域名:{usecdndomain_list}\n"+f"[+]未使用cdn域名:{nocdndomain_list}")
        if  not os.path.exists(os.path.join(os.getcwd(), "output")): os.mkdir("output")
        FileHandler.output_to_file(os.path.join(os.getcwd(), "output", "useCdnDomains.txt"),usecdndomain_list)
        FileHandler.output_to_file(os.path.join(os.getcwd(), "output", "nocdndomains.txt"),nocdndomain_list)
        print(f"[+]Result Output ./output")

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog = "CDN Checker",
        description = "Check whether the domain name has CDN acceleration",
        usage = "python check_CDN.py -d [domian] | -df [domain_file]",
    )
    parser.add_argument("-d", "--domain", help="domain name just like: domain1,domian2", type=str)
    parser.add_argument("-df", "--domain-file", help="domain name file", type=str)
    args = parser.parse_args()

    handlers = {
            'domain': handle_domain,
            'domain_file': handle_domain_file,
    }
    for arg, value in vars(args).items():
        if value:
            handler = handlers.get(arg, handle_default)
            break
    handler(value)
        