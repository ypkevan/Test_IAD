#!/usr/bin/python
#-*- coding: latin-1 -*-

# Ths module contains methods to communicate with the IAD IHM

# ihm_login()
# ihm_init_tokens() but also inits cookies
# ihm_init_cookies()
# ihm_logout

import json,ast,urllib,httplib2

class ihm_connection: 
    http = httplib2.Http()
    TARGET_IP="10.0.0.1"
    BASE_URL='http://'+TARGET_IP
    verbose=True

    headers= {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:50.0) Gecko/20100101 Firefox/50.0',\
        'Accept': '*/*',\
        'Accept-Language': 'en-US,en;q=0.5',\
        'Accept-Encoding': 'gzip, deflate',\
        #'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',\
        'X-Requested-With': 'XmlHttpRequest',\
        'Cookie': '_pk_id.2.1876=cda07167fe3de36c.1480691546.2.1480697482.1480695033.',\
        'Connection': 'keep-alive'}
    


    def ihm_login(self,password=''):
        global headers
        url = self.BASE_URL+'/api/v1/login'
        body = {'remember': '0', 'password': password}

        self.headers['Content-Type']='application/x-www-form-urlencoded; charset=UTF-8'
        response, content = self.http.request(url, 'POST', headers=self.headers, body=urllib.urlencode(body))
        try:
            if response.status==401:
                if self.verbose:
                    print "FAILED: Wrong password"
                    return None
                else :
                    return None
            elif response.status==429:
                print "Anti Bruteforce mechanism is enabled. Too many attempts"
                return 429
            elif response.status==200:

                self.headers['Cookie']=response['set-cookie']
            
        except :
            if self.verbose:
                print "FAILED TO LOG IN:No set cookie found in response"
            del self.headers['Content-Type']
            return -1
        
        del self.headers['Content-Type']
        return 1
    

    def ihm_init_tokens(self):
        """
         This method initilises the tokens and cookie of the global headers used in all methods
         It returns the btoken
        """
        global headers;
        #Must first initialise the cookies
        #ihm_init_cookie()

        url = self.BASE_URL +'/api/v1/device/token'
        response, content = self.http.request(url, 'GET', headers=self.headers)
        #print "Trying to get the token"
        #print response

        if 'application/json' in response['content-type'] and response.status==200:
            list_res= json.loads(content.decode("utf-8"))

            #converting for unicode u'<json>  dictionary to normal
            # This small hack removes all the u' in the dictionary
            dic= ast.literal_eval(json.dumps(list_res[0]))
            #print dic
            oldcookie=self.headers['Cookie']
            self.headers['Cookie']=oldcookie+"; btoken="+ str(dic['device']['token']) + "; btoken_expires="+ str(dic['device']['expires'])
            return str(dic['device']['token'])
        else:
            print "FAILED TO OBTAIN A NEW TOKEN"
            print "response status: "+ str(response.status) + "/api/v1/device/token"
            return None

    def ihm_init_cookie(self):
        """
         This method initilises the cookie  of the global headers used in all methods
        """
        global headers;
        response, content = self.http.request(self.BASE_URL+"/api/v1/login", 'PUT', headers=self.headers)

        try:
            self.headers['Cookie']=response['set-cookie']
            return response['set-cookie']
        except:
            if self.verbose:
                print "FAILED TO GET A NEW COOKIE"
                return None

    def ihm_logout(self):
        """
         This method is used to logout from the IHM. It simply resets the cookies    """
        global headers
        del self.headers["Cookie"]

#connection=ihm_connection()
#print connection.headers
#connection.ihm_login()
#print connection.headers
