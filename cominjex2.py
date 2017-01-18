#!/usr/bin/python
#-*- coding: latin-1 -*-

import json,ast
import urllib
import httplib2
import sys
import iad_ihm

class Fuzzer:
    http=None
    TARGET_IP=None
    BASE_URL=None
    connection=None
    PASSWORD=None

    headers= None

    def __init__(self,ip,passwd):
	    self.http = httplib2.Http()
	    self.PASSWORD=passwd
	    self.connection=iad_ihm.ihm_connection()
	    self.connection.TARGET_IP=ip
	    self.connection.BASE_URL="http://"+ self.connection.TARGET_IP
	    resp=self.connection.ihm_login(password=self.PASSWORD)
	    if resp==1:  # implies connection successful
	        self.connection.ihm_init_cookie()
		self.headers=self.connection.headers
	    else:
		exit()
	    
	   
    

    def fuzz_firewall(self):
	  
	    dic={'action': 'Accept','description':'XSS','dstip':'8.8.8.8/8','dstipnot':'0','dstports':'58','enable':'1','ipprotocol':'IPv4','protocols':'tcp','srcip':'10.0.0.35','srcipnot':'0','srcports':'30'}
	    self.fuzz_post(path="/api/v1/firewall/rules",param_dic=dic,banner="Fuzzing Firewall rules")


    def fuzz_lan_addr(self):
	  
	    dic={'ipaddress':'10.0.0.1','validate':'1'}
	    self.fuzz_put(path='/api/v1/lan',param_dic=dic,banner="Fuzzing LAN ADDRESS")

    def fuzz_dhcp_config(self):
	    dic={'enable':'1','leasetime':'86580','maxaddress':'10.0.0.100','minaddress': '10.0.0.1'}
	    self.fuzz_post(path='/api/v1/dhcp',param_dic=dic,banner="Fuzzing DHCP configuration")

    def fuzz_dhcp_options(self):
	    print "Fuzzing DHCP options"
	    global headers
	    dic={'enable':'1','name':'6','value':'4.4.4.4'}
	    initial=dic
	    lan_url=self.connection.BASE_URL+'/api/v1/options/'
	    # Trying to inject the url
	    with open("all_unix_attacks.txt") as f:
		for x in f:
		    dic=initial
		    lan_url= self.connection.BASE_URL + '/api/v1/options/' + x
		    resp, cont= self.http.request(lan_url,'PUT',headers=self.connection.headers,body=urllib.urlencode(dic))
	    # Now trying to inject the parameters
	    lan_url= self.connection.BASE_URL+ '/api/v1/options/1'
	    for key,value in dic.iteritems():
		with open("all_unix_attacks.txt") as f:
		    for x in f:
		        dic=initial
		        dic[key]=x
		        resp,cont=self.http.request(lan_url,'PUT',headers=self.connection.headers,body=urllib.urlencode(dic))
		        if (resp.status==200):
		            print "[+]  Sucess response code 200 => Sucess"
		        elif (resp.status==400):
		            #print "[+]  Response code 400 => BAD request"
		            pass
		        elif (resp.status==401):
		            print "Trying to get a new token"
		            init_tokens()
		        elif (resp.status==404):
	                    pass
		        else:
		            print resp.status
		            print cont

    def fuzz_dhcp_clients(self):
	    dic={'enable':'1','device':'10.0.0.35','ipaddress':'10.0.0.56','macaddress':'34:62:00:00:56:40','hostname':'MIX-GTC'}
	    self.fuzz_post(path="/api/v1/dhcp/clients",param_dic=dic,banner="Fuzzing DHCP Client")

    def fuzz_dhcp_delete(self):
	    self.fuzz_delete_and_get(path="/api/v1/dhcp/clients/",method='DELETE',banner="Fuzzing DHCP Deletion")

    def fuzz_dns(self):
	    dic={'enable':'1','server':'dtdns','record':'A','host':'www.rrkrk.com','username':'blabla','password':'blablabla','device':'34:62:00:00:56:40'}
	    self.fuzz_post(path="/api/v1/dyndns",param_dic=dic,banner="Fuzzing DNS form")
    def fuzz_dns_delete(self):
	    self.fuzz_delete_and_get(path="/api/v1/dyndns/",method='DELETE',banner="Fuzzing DNS Deletion")


    def fuzz_delete_and_get(self,method='DELETE',path=None, banner=None):
	    global headers
	    print banner
	    count=0
	    url= self.connection.BASE_URL+ path
	    # Trying to inject the url
	    with open("all_unix_attacks.txt") as f:
		for x in f:
		    url = self.connection.BASE_URL+ path + x
		    resp, cont= self.http.request(url,method,headers=self.connection.headers)
		    if resp.status==200 or resp.status==201:
		        print "[+] Response code sucess:"
		        print "INJECTING:"+x
		        count +=1
		    elif resp.status==400:
		        #print "[-] Response code 400. BAD request"
		        pass
		    elif resp.status==401:
		        print "[-] Trying to get new token"
		        self.connection.ihm_init_tokens()
		    elif (resp.status==404):
	                pass
		    else :
		        print resp
		        print cont
		        print "INJECTING:"+ x
	    print str(count) + " were sucessful"

    def fuzz_put(self,path=None,param_dic=None, banner=None):
	    print banner
	    global headers
	    url=self.connection.BASE_URL+path
	    initial=param_dic
	    count=0
	    for key,value in param_dic.iteritems():
		with open("all_unix_attacks.txt") as f:
		    for line in f:
		        param_dic=initial
		        param_dic[key]=line
		        resp,cont=self.http.request(url,'PUT',headers=self.connection.headers,body=urllib.urlencode(param_dic))
		        if (resp.status==200):
		            print "[+]  Sucess response code 200 => Sucess"
		            print "INJECTING in "+key +":"+ line
		            count+=1
		        elif (resp.status==400):
		            #print "[+]  Response code 400 => BAD request"
		            pass
		        elif resp.status == 401:
		            self.connection.ihm_init_tokens()
		        elif (resp.status==404):
	                    pass
		        else:
		            print resp.status
		            print cont
		            print "INJECTING:" + line
	    print str(count) + " Sucessful response"

    def fuzz_post(self,path=None,param_dic=None,banner=None):
	    global headers
	    print banner
	    initial=param_dic
	    self.connection.headers['Content-Type']='application/x-www-form-urlencoded'
	    url = self.connection.BASE_URL + path +'?btoken=' + self.connection.ihm_init_tokens()
	    count=0
	    for key, value in param_dic.iteritems():
		with open("all_unix_attacks.txt") as f:
		    for line in f:
		        param_dic=initial
		        param_dic[key]=line
		        #print param_dic
		        resp,cont=self.http.request(url,'POST',headers=self.connection.headers,body=urllib.urlencode(param_dic))
		        if (resp.status==201):
		            print "[+]  Sucess response code 201 => CREATED"
		            print "INJECTING in "+ key +":"+line
		            count +=1
		        elif (resp.status==400):
		            #print "[+]  Response code 400 BAD request"
		            pass
		        elif (resp.status==401):
		            print "Trying to get new token"
		            url=self.BASE_URL+ path +'?btoken='+self.connection.ihm_init_tokens()
		        elif (resp.status==404):
	                    pass
	                else:
		            print resp.status
		            print cont
		            print "INJECTING:" + line
	    print str(count) + "  of successful commands"
	    del self.connection.headers['Content-Type']

	##########
	#  Port redirection
	########

    def fuzz_upnp(self):
	    dic={'enable':'0'}
	    self.fuzz_put(path="/api/v1/upnp/ldg",param_dic=dic,banner="Fuzzing upnp")
	    
    def fuzz_dmz(self):
	    dic={'enable':'1','device':'00:11:22:33:44:55','ipddress':'10.0.0.95','dnsprotect':'0'}
	    self.fuzz_put(path="/api/v1/nat/dmz",param_dic=dic,banner="Fuzzing DMZ")

    def fuzz_nat_put(self):
	    dic={'enable':'0'}
	    self.fuzz_put(path="/api/v1/nat/rules",param_dic=dic,banner="Fuzzing NAT rules")

    def fuzz_nat_dmz(self):
	    dic={'enable':'0'}
	    self.fuzz_put(path="/api/v1/nat/dmz",param_dic=dic,banner="Fuzzing NAT DMZ")

    def fuzz_nat_delete(self):
	    self.fuzz_delete_and_get(method="DELETE",path="/api/v1/nat/rules/",banner="Fuzzing NAT rules delete")

    def fuzz_nat_post(self):
	    dic={"enable":"1","description":"bbla","protocol":"tcp","external_port":"90","ipaddress":"1","internal_port":"33","ipremote":"10.0.0.23","ipprotocol":"IPv4"}
	    self.fuzz_post(path="/api/v1/nat/rules",param_dic=dic,banner="Fuzzing NAT POST")

	
	#Parental control
	########

    def fuzz_parental_enable(self):
	    dic={'enable':'0'}
	    self.fuzz_put(path="/api/v1/parentalcontrol",param_dic=dic,banner="Fuzzing Parental enable")

    def fuzz_parental_scheduler(self):
	    dic={"enable":"0","start":"Friday 11:00","end":"Friday 12:00"}
	    self.fuzz_post(path="/api/v1/parentalcontrol/scheduler",param_dic=dic,banner="Fuzzing Parental Scheduler")


	
	#########
	#Notification
	######

    def fuzz_notification(self):
	    dic={'login':'aaa','password':'bbb'}
	    self.fuzz_put(path="/api/v1/profile/account",param_dic=dic,banner="Fuzzing Notification Login")

	########
	# WIFI
	######

    def fuzz_wifi(self):
	    dic={"passphrase":"1234567890","security":"WPA/WPA2","radio":"11bgn","channel":"0","encryption":"AES","hidden":"0","ssid":"Bbix-00F55670","ht40":"0"}
	    self.fuzz_put(path="/api/v1/wireless/24",param_dic=dic,banner="Fuzzing wifi configuration")
	
	# Reinilialiser le parac_dic avant chaque modification
	# Enlever toute sorte de redundance 
    def launch_attacks(self):
	    self.fuzz_firewall()
	    self.fuzz_lan_addr()
	    self.fuzz_dhcp_options()
	    self.fuzz_dhcp_config
	    self.fuzz_dhcp_clients()
	    self.fuzz_dhcp_delete()
	    self.fuzz_dns()
	    self.fuzz_dns_delete()
	    self.fuzz_upnp()
	    self.fuzz_dmz()
	    self.fuzz_nat_put()
	    self.fuzz_nat_dmz()
	    self.fuzz_nat_delete()
	    self.fuzz_nat_post()
	    self.fuzz_parental_enable()
	    self.fuzz_parental_scheduler()
	    self.fuzz_notification()
	    self.fuzz_wifi()


fu=Fuzzer("192.168.1.254","aaBBcc22!!")
fu.launch_attacks()
	    

