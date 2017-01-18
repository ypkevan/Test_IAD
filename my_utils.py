#!/usr/bin/python
#-*- coding: latin-1 -*-
import socket
import re
def print_success(s):
    print "\x1b[0;32;40m"+ s +"\x1b[0m"+ "\n"

def print_warning(s):
    print "\x1b[0;33;40m"+ s +"\x1b[0m" + "\n"

def print_failure(s):
    print "\x1b[0;31;40m"+ s  +"\x1b[0m" + "\n"

def print_attack(s):
    print "\x1b[0;30;43m"+ s +"\x1b[0m" + "\n"

def print_summary(s):
    print "\x1b[1;34;40m"+ s +"\x1b[0m" 

def is_valid_ipv4_address(address):
    """
    This method is used to test if an address is a valid IPv4 address.
    It returns true if the address is valid and false otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET,address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
            return False
    return True

def is_valid_ipv6_address(address):
    """
    This method is used to verify if an address given as parameter is a valid IPv6 address. 
    It returns true if the address is valid and false otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET6,address)
    except socket.error:
        return False
    return True

def is_valid_port(port):
    """
    This method  is used to verify if a port is valid. 
    It return true if the port is valid and false otherwise
    """
    try:
        var = int(port)
        is_number= True
    except ValueError:
        is_number= False
        return False
    if (var>0 and var<=65535 and is_number):
        return True
    else :
        return False

def is_valid_mac(pat):
    allowed = re.compile(r"""
                         (
                             ^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$
                         )
                         """,
                         re.VERBOSE|re.IGNORECASE)

    if allowed.match(pat) is None:
        return False
    else:
        return True
