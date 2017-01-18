#!/usr/bin/python
#-*- coding: latin-1 -*-


###############
# This file is used test if the WIFI security requirements are met 
# 1- WPS PIN has to good anti bruteforce mechanism (Reaver)
# 2- Test if WPS PIN is opened on  (Reaver)
##############
from subprocess import Popen,PIPE


def wps_pin_state(ssid):
    """
    This method is used to test if the to test if the pin is enable or dissacble on the device.
    This method used "reaver -i mon0 -b ssid". Wash is part of the reaver suite.
    It takes the SSID as parameter
    It returns True if pin state is OPENED
               False if it is CLOSED
    """
    try:
        SSID=ssid
        process= Popen(['if sudo reaver -i mon0 -b ',SSID,' -T .5 -vv | grep -q "Failed to associate"; then CLOSED_WPS=1 ; echo "WPS is disabled on device";fi'])
        if process.wait()==0:
            return True
        else :
            return False
    except:
        print "Could not check if WPS is enables or Not"
        return -1    


def brute_force_wps_pin(ssid):
    """
    This method is used to bruteforce the wps pin. It assumes the WPS PIN CODE is enabled ton the device an that the interface is on monitor mode (mon0)
    """
    SSID=ssid
    process= subprocess.Popen(['if sudo reaver -i mon0 -b ',SSID,' -T .5 -vv'],stderr=subprocess.PIPE,stdin=subprocess.PIPE)
    process.communicate()
    process.wait()


