#!/usr/bin/python3

def global_variables():
    """Declaring Global Variables"""

    sys.path.insert(1, './py-venv/lib/python3.6/site-packages')
    sys.path.insert(1, './py-venv/lib64/python3.6/site-packages')
    sys.tracebacklimit = 0
    os.system("clear")

"""Importing Python Modules"""
import sys
import os
global_variables()
import ntplib
import distro
import dns.resolver
import dns.message
import dns.query
import subprocess
import socket
import SSSDConfig
from datetime import datetime, timezone
from subprocess import PIPE, run

def print_line_start():
    """Print Lines For Better Formatting"""
    print("\n      --------------------------------------------------")

def print_line_end():
    """Print Lines For Better Formatting"""
    print("      --------------------------------------------------")

def ad_server_address_list(ad_domain):
    """Generate AD Server IPAddress List"""

    try:
        getaddrinfo_data = socket.getaddrinfo(ad_domain, 389, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        print ("Name service failure For Domain: " +ad_domain+ "\nExiting....!")
        sys.exit(1)

    ad_server_ipaddr_list = []
    for info in getaddrinfo_data:
        ipaddr = info[4][0]
        if ipaddr not in ad_server_ipaddr_list:
            ad_server_ipaddr_list.append(ipaddr)

    return ad_server_ipaddr_list

def kerberos_ticket_check():
    """Check If Kerberos Ticket is Present"""

    if subprocess.call(['klist', '-s']) != 0:
        print("IMPORTANT:\n\n"
              "   Valid Kerberos Ticket Is Not Present!\n\n"
              "   The Script Requires Valid Kerberos Ticket of 'admin' or equivalent user.\n\n"
              "   Run Command '# kinit <username>' And Execute The Script Again.\n\n"
              "   Exiting...")
        sys.exit(1)

def get_dns_resolvers():
    """Provide DNS Server IPAddress From /etc/resolv.conf File"""

    resolvers = []
    try:
        with open("/etc/resolv.conf", encoding='utf-8') as resolvconf:
            for line in resolvconf.readlines():
                line = line.split('#', 1)[0].rstrip()
        if 'nameserver' in line:
            resolvers.append(line.split()[1])
        return resolvers[0] if len(resolvers) > 0 else "127.0.0.1"
    except Exception as err:
        return "127.0.0.1"

def ad_server_A_records(ad_domain):
    """Display AD Servers A records"""
    
    print("")
    print_line_end()

    nserver = get_dns_resolvers()
    dns_request = dns.message.make_query(ad_domain, dns.rdatatype.ANY)
    dns_response = dns.query.tcp(dns_request, nserver)
    command_output = str(dns_response.answer[0])
    command_output = command_output.splitlines()
    
    for info in command_output:
            print("      "+info)
    
    print_line_end()

def ad_server_ping_reachability(ad_server_ipaddr):
    """To Check Ping Reachability To AD Server"""

    print("")
    for ad_server in ad_server_ipaddr:
        status = os.system("ping -c 2 " + ad_server + ">/dev/null 2>&1")
        if status == 0:
            print("      "+ad_server+": Reachable")
        else:
            print("      "+ad_server+" Unreachable.")
            print("Check Network Connectivity or Firewall. ")

def ipa_server_ipv6_loopback():
    """Check If IPV6 Is Enabled In IPA Server"""

    status = os.system("ping6 -c 2 ::1 >/dev/null 2>&1")
    if status == 0:
        print("ipv6 loopback enabled")
    else:
        print("ipv6 loopback Unreachable. Check if ipv6 stack is "
              "enabled. Exiting...")

def ad_server_port_reachability(ad_domain):
    """Check AD Servers Port Reachability From IPA"""

    tcp_ad_port_list = ['53', '88', '135', '138', '139', '389', '445', '3268']
    udp_ad_port_list = ['53', '88', '138', '139', '389', '445']
    ad_port_protocol = [[ tcp_ad_port_list, 'Tcp', socket.SOCK_STREAM], [ udp_ad_port_list, 'Udp', socket.SOCK_DGRAM]]

    print_line_start()
    for (port_array_name, protocol, socket_type) in ad_port_protocol:

        print("\n      "+protocol+" Ports:")
        for service_port in port_array_name:
            print("")
            try:
                getaddrinfo_data = socket.getaddrinfo( ad_domain, service_port, 0, socket_type)
            except socket.gaierror:
                print ("Name service failure For Domain: " +ad_domain+ " on port " +service_port+ "\nExiting....!")

            for info in getaddrinfo_data:
                socket_args = info[0:3]
                address = info[4]
                s = socket.socket(*socket_args)

                try:
                    s.connect(address)
                except socket.error:
                    print("         Unreachable "+protocol+" Port:", info[4][0]+":", service_port, ". Check firewall.")
                else:
                    print("         Reachable "+protocol+" Port:", info[4][0]+":", service_port)
    print_line_end()
    

def ad_server_timesync(ad_server_ipaddr):
    """Check If IPA and AD server Time Is Within 300 Seconds"""

    print("")
    for ad_server in ad_server_ipaddr:
        c = ntplib.NTPClient()
        try:
            response = c.request(ad_server, version=3)
            print("      AD Server: "+ad_server+" : ", round(response.offset, 2), "seconds")

            if round(response.offset, 2) > 300:
                print("\n   Time diff is more than 300 seconds. Sync Time with AD")

        except ntplib.NTPException:
            print("      AD Server: "+ad_server+" : No response received")

def ad_domain_validity_check(ad_domain):
    """Check AD Domain Is Not Single Level Domainname"""
    
    sub_str ="."
    if (ad_domain.find(sub_str) == -1):
        print("Invalid Domainname. IPA does not support single level AD domainname")
    else:
        print("Valid AD Domainname ("+ad_domain+")")

def ipa_ad_trust_local_config_check():
    """Check SMB and WINBIND Services Post "ipa-adtrust-install" command"""

    service_list = ['smb', 'winbind']

    for service in service_list:
        status = os.system("systemctl status " + service +  " >/dev/null 2>&1")

        if status == 0:
            print("\n      "+service+" Service: running")
        else:
            print("      "+service+" Service: Not running. Try running"
                  " '# ipa-adtrust-install' command again")

def ipa_dnssec_check():
    """Check If DNSSEC is enabled"""

    print(" ")
    if distro.major_version() == '7':
        named_conf_file = "/etc/named.conf"
        status_flag = 1
    elif distro.major_version() == '8' or distro.major_version() == '9':
        named_conf_file = "/etc/named/ipa-options-ext.conf"
        status_flag = 0
   
    with open(named_conf_file, encoding='utf-8') as namedconf:
        for line in namedconf.readlines():
            line = line.split('/*', 1)[0].rstrip()
            line = line.split('*', 1)[0].rstrip()
            line = line.split('//', 1)[0].rstrip()
            line = line.split('#', 1)[0].rstrip()
            
            if line.find('dnssec-enable') == status_flag or \
                line.find('dnssec-validation') == status_flag:

                dnssec_vars = line.strip()
                print("      "+dnssec_vars)

def ipa_dns_forwarder_check(ad_domain):
    """Check If DNS Fowarder For AD Domain Is Configured."""
    
    command = "ipa dnsforwardzone-show " + ad_domain
    status = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

    print_line_start()
    if status.returncode == 0:
        command_output = status.stdout.splitlines()
        for counter in range(len(status.stdout.splitlines())):
            print("    "+command_output[counter])
    else:
	    print("\n      "+status.stderr)
    print_line_end()

def ipa_trustconfig_show():
    """Check If Local Trust Is Configured."""

    command = "ipa trustconfig-show"
    status = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

    print_line_start()
    if status.returncode == 0:
        command_output = status.stdout.splitlines()
        for counter in range(len(status.stdout.splitlines())):
            print("    "+command_output[counter])
    else:
	    print("\n      "+status.stderr)
    print_line_end()

def ipa_trust_find():
    """Check If IPA Trust with AD Domain Is Configured."""

    command = "ipa trust-find"
    status = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

    print_line_start()
    if status.returncode == 0:
        command_output = status.stdout.splitlines()
        for counter in range(len(status.stdout.splitlines())):
            print("      "+command_output[counter])
    else:
	    print("\n      "+status.stderr)
    print_line_end()

def ipa_trust_idrange():
    """Display ID Range."""

    command = "ipa idrange-find"
    status = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

    print_line_start()
    if status.returncode == 0:
        command_output = status.stdout.splitlines()
        for counter in range(len(status.stdout.splitlines())):
            print("      "+command_output[counter])
    else:
	    print("\n      "+status.stderr)
    print_line_end()
    
def ad_domain_dns_records_check(ad_domain):
    """Check DNS Records For AD Domain"""


    dns_ipa_request_array = [['ldap', '_tcp'], ['ldap','_tcp.dc._msdcs'],
                            ['kerberos','_udp'], ['kerberos','_udp.dc._msdcs']]

    dns_ad_request_array =  [['ldap', '_tcp'], ['ldap','_tcp.dc._msdcs'],
                            ['kerberos','_tcp'], ['kerberos','_udp'],
                            ['kerberos','_tcp.dc._msdcs']]
   
    print("\n       a. IPA DNS SRV Record:")
    
    sssdconfig = SSSDConfig.SSSDConfig()
    sssdconfig.import_config()
    ipa_domain = sssdconfig.list_active_domains()
    ipa_domain = ipa_domain[0]

    for (service, protocol) in dns_ipa_request_array:
        try:
            srv_records = (dns.resolver.resolve("_"+service+"."+protocol+"."+ipa_domain, 'SRV'))
            print(" ")
            print("          * _"+service+"."+protocol+"."+ipa_domain+" : Resolved")
            print(" ")
            for srv_result  in srv_records:
                print("           ", end =" ")
                print(srv_result)
        except dns.resolver.NXDOMAIN:
            print(" ")
            print("          * _"+service+"."+protocol+"."+ipa_domain+" : Failed")



    print("\n       b. AD DNS SRV Record:")
    for (service, protocol) in dns_ad_request_array:
        try:
            srv_records = (dns.resolver.resolve("_"+service+"."+protocol+"."+ad_domain, 'SRV'))
            print(" ")
            print("          * _"+service+"."+protocol+"."+ad_domain+" : Resolved")
            print(" ")
            for srv_result  in srv_records:
                print("           ", end =" ")
                print(srv_result)
        except dns.resolver.NXDOMAIN:
            print(" ")
            print("          * _"+service+"."+protocol+"."+ad_domain+" : Failed")
    print("")


def ipa_ad_trust_keytab_file_check(ad_domain):
    """Check If IPA - AD Trust Keytab File Is Present And Working"""
        
    fstatus = 0

    if (((ad_domain.strip())[-1]) == '.' ):
        str = ad_domain.split('.')
        ad_domain = '.'.join(str[0:-1])
    trust_keytab_fname = "/var/lib/sss/keytabs/"+ad_domain+".keytab"
    fstatus = os.path.isfile(trust_keytab_fname)
    print("\n       a. IPA - AD Trust Keytab File Check:")
    if fstatus == True:
        print("\n          File \""+trust_keytab_fname+"\" Exists.")
        fstatus = 1
    else:
        print("\n          File \""+trust_keytab_fname+"\" Does Not Exist.")

    if fstatus == 1:

        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
        ipa_domain = sssdconfig.list_active_domains()
        ipa_domain = ipa_domain[0]
        ipa_netbios = (((ipa_domain.split('.'))[0]).upper())

        ipa_ad_trust_principal = ("\'" +ipa_netbios.upper()+ "$@" +ad_domain.upper()+ "\'")
        kstatus = os.system("kinit -k "+ ipa_ad_trust_principal + " -t " +trust_keytab_fname+ " >/dev/null 2>&1")


        print("\n       b. IPA - AD Trust Kinit Check:")
        if kstatus == 0:
            print("\n          Kinit Based On IPA - AD Trust Prinipal "+ ipa_ad_trust_principal +" is successful")
        else:
            print("\n          Kinit Based On IPA - AD Trust Prinipal "+ ipa_ad_trust_principal +" is a failure")
 
def exit_script():
    """Exit The Script"""

    print("Exiting...")
    sys.exit(0)

def ipa_ad_trust_pre_check():
    """Master Function To Perform Pre IPA - AD Trust Check"""

    print("   AD Domain Name:", end =" ")
    ad_domain = input()

    ad_server_ipaddr = ad_server_address_list(ad_domain) 

    print("\n   Initiating Checks:")
    
    print("\n   1. AD Server: A Records")
    ad_server_A_records(ad_domain)

    print("\n   2. Checking AD Server Ping Reachability:")
    ad_server_ping_reachability(ad_server_ipaddr)

    print("\n   3. Checking AD Server Port Reachability:")
    ad_server_port_reachability(ad_domain)
    
    print("\n   4. IPA Server Ipv6 enabled:", end = " ")
    ipa_server_ipv6_loopback()
    
    print("\n   5. Timesync Difference To AD Server:")
    ad_server_timesync(ad_server_ipaddr)
    
    print("\n   6. AD Domainname check:", end = " ")
    ad_domain_validity_check(ad_domain)
    
    print("\n   7. Local configuration for IPA - AD Trust:")
    ipa_ad_trust_local_config_check()
    
    print("\n   8. DNSSec Check:")
    ipa_dnssec_check()
    
    print("\n   9. IPA DNS Forwarder Check:", end = " ")
    ipa_dns_forwarder_check(ad_domain)
    
    print("\n   10. AD Domain DNS Validation:")
    ad_domain_dns_records_check(ad_domain)
    print("")

def ipa_ad_trust_post_check():
    """Master Fuction To Perform Post IPA - AD Trust Check"""
    
    print("   AD Domain Name:", end =" ")
    ad_domain = input()

    ad_server_ipaddr = ad_server_address_list(ad_domain) 

    print("\n   Initiating Checks:")
    
    print("\n   1. AD Server: A Records")
    ad_server_A_records(ad_domain)
    
    print("\n   2. Checking AD Server Ping Reachability:")
    ad_server_ping_reachability(ad_server_ipaddr)

    print("\n   3. Checking AD Server Port Reachability:")
    ad_server_port_reachability(ad_domain)
    
    print("\n   4. Timesync Difference To AD Server:")
    ad_server_timesync(ad_server_ipaddr)
    
    print("\n   5. Local configuration for IPA - AD Trust:")
    ipa_ad_trust_local_config_check()
    
    print("\n   6. DNSSec Check:")
    ipa_dnssec_check()
    
    print("\n   7. IPA DNS Forwarder Check:", end = " ")
    ipa_dns_forwarder_check(ad_domain)
    
    print("\n   8. IPA Local Trust Config Check:", end = " ")
    ipa_trustconfig_show()
    
    print("\n   9. IPA AD Trust Config:", end = " ")
    ipa_trust_find()
    
    print("\n   10. IPA - AD Trust IDRange Check:", end = " ")
    ipa_trust_idrange()
    
    print("\n   11. AD Domain DNS Validation:")
    ad_domain_dns_records_check(ad_domain)
    
    print("\n   12. AD Trust Keytab File Check:")
    ipa_ad_trust_keytab_file_check(ad_domain)
    print("")


def menu():
    """Function Display Menu Options"""

    print("=======================================================")
    print("IPA - AD Trust Healthcheck Script")
    print("=======================================================\n")
    print("1. Pre IPA - AD Trust Check")
    print("2. Post IPA - AD Trust Check")
    print("3. Exit.")
    print("=======================================================\n")
    print("Enter Option:", end =" ")

if __name__ == "__main__":

    kerberos_ticket_check()
    
    menu()
    choice = input()

    if choice == "1":
        
        print("\nPerforming Pre IPA - AD Trust Checks\n")
        ipa_ad_trust_pre_check()

    elif choice == "2":

        print("\nPerforming Post IPA - AD Trust Checks\n")
        ipa_ad_trust_post_check()

    elif choice == "3":
        exit_script()

    else:
        print("\nWrong Options Selected!! Try again\n")
        exit_script()
