from threads import Threads
from flask import request
from result import error
import time

class ratelimit:
    def __init__(self):
        self.ipList = {}
        self.limit = 200
        # self.limit = 3
        
        self.banned_ips_file = './banned_ips.txt'
        self.bypass_ips_file = './bypass_ips.txt'
        self.bypass_ips = []
        self.banned_ips = []
        
        self.exceeded = 'rate_limit_exceeded'
        
        self.threads = Threads()
        self.threads.append(self.update_ipList)()
    
    def load_banned_ips(self):
        # Format 127.0.0.1,127.0.0.1,...
        with open(self.banned_ips_file, 'r') as file:
            self.banned_ips = file.read().split(',')
        with open(self.bypass_ips_file, 'r') as file:
            self.bypass_ips = file.read().split(',')
    
    def save_banned_ips(self):
        with open(self.banned_ips_file, 'w') as file:
            file.write(','.join(self.banned_ips))
        with open(self.bypass_ips_file, 'w') as file:
            file.write(','.join(self.bypass_ips))
    
    def ban_ip(self, ip):
        if ip in self.bypass_ips:
            return
        
        self.banned_ips.append(ip)
        self.save_banned_ips()
    
    def unban_ip(self, ip):
        self.banned_ips.remove(ip)
        self.save_banned_ips()
    
    def bypass_ip(self, ip):
        self.bypass_ips.append(ip)
        self.save_banned_ips()
    
    def unbypass_ip(self, ip):
        self.bypass_ips.remove(ip)
        self.save_banned_ips()
    
    def update_ipList(self):
        while True:
            time.sleep(60)
            for ip in self.ipList:
                if self.ipList[ip] > self.limit * 2:
                    return self.ban_ip(ip)
                self.ipList[ip] = 0
    
    def check_ip(self, ip):
        if ip in self.bypass_ips:
            return True
        
        if ip not in self.ipList:
            self.ipList[ip] = 1
        else:
            self.ipList[ip] += 1
            
        if self.ipList[ip] >= self.limit+1:
            return False
        return True
    
    def request(self, callback):
        ip = request.remote_addr
        
        if not self.check_ip(ip):
            return error(self.exceeded, 429)
    
        if ip in self.banned_ips:
            return error('ip_banned', 403)
        
        return callback()