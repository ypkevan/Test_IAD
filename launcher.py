#!/usr/bin/python-1 
#-*- coding: latin -*-

""" This module is the launcher of direct tests. It includes tests that can produce results immediately. 
 It does not include bruteforce , cookies and token randomness check ( bruteforce.py , recurrence.py)
 This module produces a report in HTML format(report.html).

FLOODING (DOSer.py)
--------
-> SYN FLOODING A PORT
-> SYN FLOODING ALL PORT 
-> TCP FLOODING A PORT **** useless
-> UDP FLOODING A PORT
-> ICMP FLOODING 
-> SSL RENEGOCIATION DOS
-> MAXIMUM NUMBER OF TCP CONNECTIONS ****
-> TearDrop
4-> PING OF DEATH
-> SIP INVITE FLOODING
-> SIP REGISTER FLOOD 


FIREWALL (scanner.py) file makes use of scanner.py
--------
-> CHECK REGISTANCE TO SCAN LAN
-> CHECK RESISTANCE TO SCAN WAN
-> CHECK SSH LAN 
-> CHECK SPECIAL PORTS 
-> BLOCK ALL VERIFY SERVICES

IP MISCONFIGURATION (config_ip.py)
-------------------
-> CHANGE IP TO UNALLOWED ONE
-> CHECK IF FIREWALL RULES REMAINS AFTER IP MODIFICATION

WIFI (wifi.py)
----
-> CHECK WPS PIN CODE IS DISABLED
-> TRY WPS PIN BRUTE FORCE

PORT MAPPING PROTOCOLS (upnp.py)
----------------------
-> UPNP FLOODING
-> NAT-PMP FLOODING
-> UPNP INJECTION
-> UPNP BUFFER OVERFLOW

IHM (cominjex.py)
----------
-> CSRF ON ALL PAGES
-> COMMAND INJECTION ON ALL PAGES
-> XSS ON ALL PAGES
-> SQL INJECTION ON ALL PAGES
-> *** wifi clé wpa source page
"""
# Take lan_ip,wan_ip,ihm_password,port_used for flooding
import my_utils,wifi,getconfig
import os
import flooder,scanner,config_ip,firewall,reporting,upnp,bruteforce
print "\t#######################################"
print "\t## IAD SECURITY TESTING TOOL ##########"
print "\t## # # # # # # # # # # # # # ##########"
print "\t#######################################"

enable_dos=True
enable_scan=True
enable_conf_ip=True
enable_wifi=False
enable_port_map=False
enable_inject=True
enable_bruteforce_ihm=False
enable_bruteforce_ssh=False
def menu(dos=" ",scan=" ",conf_ip=" ",wi=" ",port_map=" ",inject=" ",brute_ihm=" ",brute_ssh=" "):
    global enable_dos,enable_scan,enable_conf_ip,enable_wifi,enable_port_map,enable_inject,enable_bruteforce_ihm,enable_bruteforce_ssh
    if enable_dos:
        dos="*"
    if enable_scan:
        scan="*"
    if enable_conf_ip:
        conf_ip="*"
    if enable_wifi:
        wi="*"
    if enable_port_map:
        port_map="*"
    if enable_inject:
        inject="*"
    if enable_bruteforce_ihm:
        brute_ihm="*"
    if enable_bruteforce_ssh:
        brute_ssh="*"
    os.system("clear")
    print "====================================="
    print "Menu----"
    print "====================================="
    print "1.["+str(dos)+"] \tFlooding tests"
    print "2.["+str(scan)+"] \tFirewall and scanning tests"
    print "3.["+str(conf_ip)+"] \tIP configurations tests "
    print "4.["+str(wi)+"] \tWifi WPS PIN tests"
    print "5.["+str(port_map)+"] \tUPNP and NATPMP  tests (including flooding)"
    print "6.["+str(inject)+"] \tIHM injections and Fuzzing"
    print "7.["+str(brute_ihm)+"]\tBruteforce IHM login"
    print "8.["+str(brute_ssh)+"]\tBruteforce SSH login"
    print "\n"
    tmp=raw_input("Enter the NUMBER of the tests you want to enable or 'C' to Continue:")
    if tmp is "1":
        enable_dos^=True  # XOR operation used to toggle the value from true to false
        menu()
    elif tmp is "2":
        enable_scan^=True
        menu()
    elif tmp is "3":
        enable_conf_ip^=True
        menu()
    elif tmp is "4":
        enable_wifi^=True
        menu()
    elif tmp is "5":
        enable_port_map^=True
        menu()
    elif tmp is "6":
        enable_inject^=True
        menu()
    elif tmp is "7":
        enable_bruteforce_ihm^=True
        menu()
    elif tmp is "8":
        enable_bruteforce_ssh^=True
        menu()
    elif tmp is "C":
        pass
    else :
        menu()
# Calling Menu
menu()

tmp=raw_input("Enter the IP address of the LAN interface[192.168.1.254]:")
if my_utils.is_valid_ipv4_address(tmp):
    IP_LAN=tmp
else:
    my_utils.print_warning("USING DEFAULT IP 192.168.1.254 ")
    IP_LAN="192.168.1.254"

tmp=None
tmp=raw_input("Enter IHM password:")
PASSWORD=tmp

configs=getconfig.IadConfiguration(IP_LAN,PASSWORD)
if configs.connected!=1:
    exit()
tmp=raw_input("Enter the IP address of the WAN interface ["+configs.get_wan_ip()+"]:")
if my_utils.is_valid_ipv4_address(tmp):
    IP_WAN=tmp
else:
    IP_WAN=configs.get_wan_ip()
    my_utils.print_warning("Taking WAN IP address from Device"+ IP_WAN)
    

tmp=raw_input("Enter the PORT to be used for flooding [443]:")
if my_utils.is_valid_port(tmp):
    PORT=tmp
else:
    my_utils.print_warning("Usiing Port Number 443")
    PORT="443"

tmp=raw_input("Enter the duration of each attack [30 seconds]:")
try :
    tmp=int(tmp)
    if tmp.is_integer():
        DUREE=tmp
        print DUREE
        exit()
except :
    my_utils.print_warning("Using the default duration of 30 secondes")
    DUREE=3
#Taking password list file
if enable_bruteforce_ihm or enable_bruteforce_ihm:
   tmp=None
   tmp=raw_input("Enter the name and path to WORDLIST or PASSWORD list to be used for bruteforce: ")
   try:
       with open(tmp,"r") as f:
           pass
       f.close()
   except:
       my_utils.print_failure("Sorry but the file cannot be found")
       exit()
   PASSLIST=tmp
   
   #Taking user list for ssh bruteforce
   if enable_bruteforce_ssh:
       tmp=None
       tmp=raw_input("Enter the name and path to USER LIST to be used for SSH  bruteforce: ")
       try:
           with open(tmp,"r") as f:
              pass
           f.close()
       except:
           my_utils.print_failure("Sorry but the file cannot be found")
           exit()
       USERLIST=tmp
      
   
if enable_wifi:
    my_utils.print_warning("=== WARNING ===")
    my_utils.print_warning( "1. Make sure you have a Wireless NIC enabled on mon0")
    my_utils.print_warning("Use this command to enable it  [$ sudo airmon-ng start  [**wireless interface**]     ]")
    ssid,essid=configs.get_bssid()
    tmp=raw_input(" BSSID of the Wifi access point is ["+essid+"]" )
    SSID=ssid
    # print "The SSID is NOT valid"


my_utils.print_summary("Configuration is finished.")
tmp=raw_input("Press 'Return' to launch the tests")
os.system("clear")
# Creating the reporting object
report = reporting.Reporter()


# Create a flooder object

if enable_dos:
    Flood=flooder.Flooder(DUREE)
    # launching attacks and taking results
    ######################################

    SYN_FLOOD_PORT= Flood.syn_flood(IP_LAN,PORT)
    SYN_FLOOD_ALL_PORT= Flood.syn_flood_thread(IP_LAN)
    UDP_FLOOD_PORT= Flood.udp_flood(IP_LAN,PORT)
    ICMP_FLOOD= Flood.icmp_flood(IP_LAN)
    SSL_DOS= Flood.ssl_dos(IP_LAN,PORT)
    IHM_DOS= Flood.ihm_dos(IP_LAN)
    TEARDROP= Flood.teardrop_attack(IP_LAN,PORT)
    PING_OF_DEATH= Flood.pingofdeath(IP_LAN)
    SIP_INVITE= Flood.sip_invite_flood(IP_LAN)
    SIP_REGISTER= Flood.sip_register_flood(IP_LAN)

    #reporting
    report.create_record("SYN Flooding a port","DOS",SYN_FLOOD_PORT)
    report.create_record("SYN FLOODING all port ","DOS",SYN_FLOOD_ALL_PORT)
    report.create_record("UDP Flooding  ","DOS",UDP_FLOOD_PORT)
    report.create_record("ICMP Flooding","DOS",ICMP_FLOOD)
    report.create_record("SSL renegociation DOS ","DOS",SSL_DOS)
    report.create_record("IHM sessions DOS ","DOS",IHM_DOS)
    report.create_record("Tear Drop ","DOS",TEARDROP)
    report.create_record("Ping of Death","DOS",PING_OF_DEATH)
    report.create_record("Sip Invite flooding","DOS",SIP_INVITE)
    report.create_record("Sip register flooding","DOS",SIP_REGISTER)



if enable_scan:
    # Launching firewall tests
    ##########################
    RESIST_LAN_SCAN=scanner.scan_ports(ip_scan=IP_LAN,ip_api=IP_LAN,port_list="1-100")
    ports_to_check_on_lan=["22","51022","51005"]
    ports_to_check_on_wan=["22","51022","51005","80","443"]
    CHECK_SSH_LAN=scanner.check_open_ports(port_list=["22"])
    CHECK_LAN_PORT=scanner.check_open_ports(port_list=ports_to_check_on_lan)

    RESIST_WAN_SCAN=scanner.scan_ports(ip_api=IP_LAN,ip_scan=IP_WAN,port_list="1-100")
    CHECK_WAN_PORT=scanner.check_open_ports(port_list=ports_to_check_on_wan)
    scanner.clean_all()

    #create a rule that block everything and verify services
    BLOCK_ALL=firewall.add_block_all(IP_LAN,PASSWORD)

    #reporting
    report.create_record("Resistance to port scanning","SCAN",RESIST_LAN_SCAN)
    report.create_record("Check that SSH is off by default on LAN","SCAN",CHECK_SSH_LAN)
    report.create_record("Check that some ports are not opened on LAN","SCAN",CHECK_LAN_PORT)
    report.create_record("Resistance to WAN scanning","SCAN",RESIST_WAN_SCAN)
    report.create_record("Check if NOT ports(80,443,22,...) are openned on WAN","SCAN",CHECK_WAN_PORT)
    report.create_record("Verify if service work even after Blocking all traffic","FIREWALL",BLOCK_ALL)


if enable_conf_ip:
    # Lauching IP misconfiguration Tests
    ####################################

    # Try to change IP to unallowed one
    conf=config_ip.IpMisconfiguration(IP_LAN,PASSWORD)
    tmp=conf.change_ip("8.8.8.8") # Forbiden ip
    if tmp==False:   # => unable to change the address
        FORBIDDEN_IP=True 
    elif tmp==True:    # => address was changed sucessfully
        FORBIDDEN_IP=False
    CHECK_RULE_AFTER_IP_CHANGE=conf.test_rule_and_ip()
    if CHECK_RULE_AFTER_IP_CHANGE==True:
        conf.reset_ip()
    conf.reset_firewall_rules()
    #reporting
    report.create_record("Verify if possible to use UNALLOWED IP","IP CONFIG",FORBIDDEN_IP)
    report.create_record("Verify if firewall rule applies to interface and NOT IP","IP CONFIG",CHECK_RULE_AFTER_IP_CHANGE)



# Have to remove icmp block to 8.8.8.8   *****
# Have to remove firewall to block everything    *****

if enable_port_map:
    # Launching port mapping protocols tests
    ########################################

    UPNP_FLOOD=upnp.flood_msearch(IP_LAN,DUREE)
    NATPMP_FLOOD=upnp.flood_natpmp(IP_LAN,DUREE)
    UPNP_FUZZING=upnp.fuzz_upnp(IP_LAN)
    UPNP_OVERFLOW=upnp.upnp_overflow(IP_LAN)

    #reporting 
    report.create_record("UPnP MSearch flooding attack","UPNP",UPNP_FLOOD)
    report.create_record("NATPMP flooding attack","NATPMP",NATPMP_FLOOD)
    report.create_record("Fuzzing UPnP XML parameters","UPnP",UPNP_FUZZING)
    report.create_record("UPnP buffer overflow attack","UPnP",UPNP_OVERFLOW)

if enable_wifi:
    # Wifi Security test
    ###################

    WPS_PIN_STATE=wifi.wps_pin_state(SSID)
    report.create_record("Testing if WPS_PIN is disabled","WIFI",WPS_PIN_STATE)

if enable_inject:
    # Injection
    ########################################

    os.system("python command-injection/cominjex.py "+IP_LAN+" '"+PASSWORD+"'")
    report.create_record("CSRF on all pages","INJECTIONS",None)
    report.create_record("OS command injections on all pages","INJECTIONS",None)
    report.create_record("XSS injection","INJECTIONS",None)
    report.create_record("SQL injection","INJECTIONS",None)

if enable_bruteforce_ihm:
   # Bruteforce HTTP login
   #######################
    IHM_BRUTEFORCE=bruteforce.bruteforce_ihm_login(IP_LAN,wordlist=PASSLIST)
    report.create_record("IHM Anti bruteforce  mechanism is enabled","BRUTEFORCE",IHM_BRUTEFORCE)

    
if enable_bruteforce_ssh:
   # Bruteforce SSH login
   #######################
    SSH_BRUTEFORCE=bruteforce.bruteforce_ssh_login(target=IP_LAN,user_list=USERLIST,pass_list=PASSLIST,port=22)
    report.create_record("SSH Bruteforcing","BRUTEFORCE",SSH_BRUTEFORCE)
# Reporting generation
my_utils.print_summary("Generating report (report.html) ....")
report.generate_report()
