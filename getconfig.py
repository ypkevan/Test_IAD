#!/usr/bin/python
#-*- coding: latin-1 -*-


# Change the configuration of the IP address of th IAD
# Try to make it not to respect ranges
import iad_ihm
import json,ast,urllib,httplib2
import copy


class IadConfiguration:
    IP=""
    connection=None
    connected=None

    def __init__(self,ip,passwd):
        self.IP=ip
        self.connection=iad_ihm.ihm_connection();
        self.connection.TARGET_IP= ip
        self.connection.BASE_URL= "http://"+ip
        if self.connection.ihm_login(password=passwd)==1:
            self.connected=1
            self.connection.ihm_init_cookie()
            print "Connected to Device"
        else:
            print "Could not connect"
        
        if self.connected==1:
            self.connection.ihm_init_tokens()
            self.get_wan_ip()
            self.get_bssid()
            print ""
        
        
    
    def get_wan_ip(self):
        """
        This method is used to get the wan ip address of the IAD from the API only when logged in
        """
        if self.connected==None:
            print "Not connected"
            exit()
        http=httplib2.Http()
        url=self.connection.BASE_URL+"/api/v1/wan/ip"
        resp, cont = http.request(url,'GET',headers=self.connection.headers)
        content=json.loads(cont.decode("utf-8"))
        return str(content[0]['wan']['ip']['address'])
       # print cont[0]['ip']['address']

    def get_bssid(self):
        """
        This method is used to get the ssid of the IAD from the API
        """
        if self.connected==None:
            print "Not connected"
            exit()
        http=httplib2.Http()
        url=self.connection.BASE_URL+"/api/v1/wireless"
        resp, cont = http.request(url,'GET',headers=self.connection.headers)
        content=json.loads(cont.decode("utf-8"))
        return str(content[0]['wireless']['ssid']['24']['bssid']),str(content[0]['wireless']['ssid']['24']['id'])
        #print content[0]['wireless']['ssid']['24']['id']

        
#conf=IadConfiguration('192.168.1.254','aaBBcc22!!')

