#!/usr/bin/python
#-*- coding: latin-1 -*-

# Change the configuration of the IP address of th IAD
# Try to make it not to respect ranges
import httplib2 , urllib, time
import iad_ihm
import json
import scanner, verify_services, iad_ihm


#This file is to ensure firewalls tests
# it includes 1 
# 

IP="192.168.1.254"
PASSWORD=""  # IHM
def add_block_all(ip,passwd):
    """
     Add a rule that blocks everything and check if services are ok
    """
    global IP
    global PASSWORD
    connection=iad_ihm.ihm_connection()
    connection.TARGET_IP=ip
    connection.BASE_URL="http://"+ip
    if connection.ihm_login(password=passwd)==-1:
        return -1
    if connection.ihm_init_cookie() is None:
        print "Could not connect: Check password and network connection"
        return -1
    connection.ihm_init_tokens()
    param_dic={'action': 'Drop','description':'Block Everything','dstip':'','dstipnot':'0','dstports':'','enable':'1','ipprotocol':'IPv4','protocols':'udp','srcip':'','srcipnot':'0','srcports':''}
    url=connection.BASE_URL+'/api/v1/firewall/rules?btoken='+connection.ihm_init_tokens()
    connection.headers['Content-Type']= 'application/x-www-form-urlencoded'
    http=httplib2.Http()
    resp,cont = http.request(url,'POST',headers=connection.headers,body=urllib.urlencode(param_dic))
    if resp.status==200 or resp.status==201:
        print "[+]The firewall rule is applied"
        if verify_services.service_info(ip)==0:
            return True
        else :
            return False
    elif resp.status==400:
        print "[+] Bad request. code " + str(resp.status)
        return False
    else :
        print "[-] Could not create the rule, code=" + str(resp.status) 
    return -1


def fw_scan_ports():
    """
     This test is to see if the device resists to port scanning
    """
    global IP
    scanner.scan_ports(ip=IP)
    try:
        with open("openports.txt") as f:
            for line in f:
                print line
    except:
        print "Could not find openports.txt. Make nmap is installed"
        return -1
    scanner.clean_all()
    verify_services.service_info(IP)

def fw_check_ports():
    """
    This method reports if a list of important ports ( normally closed by default) is opened
    """
    global IP
    port_list={"22","51005","51022"}
    #scan_ports  takes string a port list seperated by comma
    scanner.scan_ports(ip=IP,port_list="22,51005,51022,26,666")
    scanner.check_open_ports(port_list=port_list)
    scanner.clean_all()
    


