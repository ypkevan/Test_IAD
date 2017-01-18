#!/usr/bin/python
#-*- coding: latin-1 -*-
from subprocess import Popen, PIPE
from scapy.all import *
from httplib2 import Http
import urllib, json, re
import sys

def print_ok(s):
    print  "\x1b[1;32;40m"+ s +"\x1b[0m"

def print_nok(s):
    print  "\x1b[1;31;40m"+ s +"\x1b[0m"



def get_summary(url):
    http= Http()
    try:
        resp, content=http.request(
            uri=url,
            method='GET',
            headers={'User-Agent':'Testing/5.0','Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','Accept-Language':'en-US,en;q=0.5'},
            body=urllib.urlencode({}),
            )
    except :
        print_nok("Failed to connect to "+ url +".")
        return 0
    return json.loads(content.decode("utf-8"))

def print_all_services(url):
    
    res=get_summary(url)
    if (res==0):
        return 0
    print str(res[0]['internet']['state']) + " : Internet status"
    print str(res[0]['voip'][0]['status']) + " : Void status"
    print str(res[0]['services']['firewall']['enable']) + " Firewall enable"
    print str(res[0]['services']['dyndns']['enable']) + " DYNDNS enable"
    print str(res[0]['services']['dhcp']['enable']) + " DHCP enable"
    print str(res[0]['services']['nat']['enable']) + " NAT enable"
    print str(res[0]['services']['upnp']['igd']['enable']) + " UPNP enable"
    print str(res[0]['services']['proxywol']['enable']) + " PROXYWOL enable"
    print str(res[0]['wan']['ip']['stats']['rx']['occupation']) + " WAN uplink occupation"
    print str(res[0]['wan']['ip']['stats']['tx']['occupation']) + " WAN downlink occupation"

def service_info(ip):
    fail=0
    url="http://"+ ip +"/api/v1/summary"
    res=get_summary(url)
    if (res==0):
        return -1
    if (str(res[0]['internet']['state'])=="2"):
        print_ok("[+] Internet is OK")
    else :
        print_nok("[+] The Internet connection seems to be down. (state != 2)")
        fail=1
    if ( str(res[0]['voip'][0]['status'])=="Up"):
        print_ok("[+] VOIP is OK")
    else :
        print_nok("[+] The VOIP seems to be down (status != Up))")
        fail=1
    if ( res[0]['wan']['ip']['stats']['tx']['occupation']>0 or res[0]['wan']['ip']['stats']['rx']['occupation']>0):
        print_ok("[+] The WAN link is up")
    else :
        print_nok("[+] The wan link seems to be down (line occupation is 0 )")
        fail=1
    try:
        if sr1(IP(dst="8.8.8.8")/ICMP(),verbose=0, timeout=3).summary().find('echo-reply')==-1:
            print "[+] Check firewall rules recieved"
            fail=1
        else :
            print_ok('[+] Ping to 8.8.8.8 works')
    except:
        print_nok("[+] No PING reply from google (8.8.8.8)")
        fail=1
    return fail

#service_info("10.0.0.1")

