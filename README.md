# IPA - AD Trust Health Check Script

This repository contains a howto and the required artifacts to use 
IPA - AD Trust Health Check Script in following servers.

* Red Hat Enterprise Linux 7
* Red Hat Enterprise Linux 8

## Motivation

Active Directory is one of the most common backends for user identities and 
many environments including Linux rely on Active Directory for user management. 
Red Hat Identity Management supports configuring a cross-forest trust between 
an IdM domain and an Active Directory domain.

Both IPA and Active Directory manage a variety of core services:

* Kerberos
* DNS
* LDAP
* Certificate Services

To transparently integrate these two diverse environments, all core services must 
interact seamlessly with one another. In IPA - AD trust setup, those services can 
be broken into two major points of interaction: 

* Kerberos realm
* DNS domain 

Successful working of IPA - AD Trust environment depends on multiple factors. 
The objective of this Python  script is to perform a checklist to validate the 
factors leading to a successful creation of IPA - AD Trust and also, a post-Trust setup.

## User experience

IPA - AD Trust creation or its operations may experience issues because of any of the 
following common factors:

* Firewall
* Time Sync
* DNS
* Kerberos

To successfully troubleshoot any issue, the Administrator should be aware 
of all the possible checks to be performed Pre and Post IPA - AD Trust 
creation.

## Script Features

The script will perform the following checks Pre and Post Trust creation.

1. Pre IPA - AD Trust creation checks:

	* Checking AD Server Ping Reachability
	* Checking AD Server Port Reachability
	* IPA Server Ipv6 enabled
	* Timesync Difference to AD Server
	* AD Domain Name check
	* Local configuration for IPA - AD Trust
	* IPA DNS Forwarder Check
	* AD Domain DNS Validation

2. Post IPA - AD Trust creation checks:

	* Checking AD Server Ping Reachability
	* Checking AD Server Port Reachability
	* Timesync Difference to AD Server
	* Local configuration for IPA - AD Trust
	* DNSSec Check
	* IPA DNS Forwarder Check
	* IPA Local Trust Config Check
	* IPA AD Trust Config
	* IPA AD Trust ID Range
	* AD Domain DNS Validation
	* IPA - AD Trust Keytab File Check

## Setting up the environment

This section describes the detailed steps that are required to run the script.
You will need an IPA server up and running and you need to have some basic prerequisite steps performed.

### 1. Prerequisites

* [Prerequisites for Installing a Server](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/linux_domain_identity_authentication_and_policy_guide/installing-ipa)

* [Preparing the IdM Server for Trust](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/trust-during#trust-set-up-idm)

* [Configuring Forward Zones](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html-single/linux_domain_identity_authentication_and_policy_guide/index#conf-forward-zones)


### 2. Configure Virtual Python Environment For The Script

This python script runs on [venu](https://docs.python.org/3/tutorial/venv.html) 
virtual environment to avoid interfering with the existing modules.

<span style="color:blue"> Note:</span> The script performs only read
operations and does NOT make any changes in the system. 

Steps to configure the Python `venu` virtual environment are listed below.

1. Download the script in the IPA server

	```
	# git clone https://github.com/DeepakDas7/ipa-ad-trust-healthcheck
	```

2. Configure the Python Virtual Environment

	```
	# cd ipa-ad-trust-healthcheck
	# python3 -m venv py-venv
	# source py-venv/bin/activate
	# python -m pip install -r requirements.txt
	# python -m pip list
	```

3. Run the script as below

	```
	# kinit admin
	# ./ipa-ad-trust-healthcheck.py
	```

4. Below Menu will be displayed

	```
	IPA - AD Trust Healthcheck Script
	======================================
	1. Pre IPA - AD Trust Check
	2. Post IPA - AD Trust Check
	3. Exit.
	======================================
	Enter Option:
	```

## Future work
In no particular order and without going too deep into details:

* Support for Red Hat Enterprise Linux 9
* Support for multi IPA - AD Trust scenario. 

## Disclaimers

* The script is an individual effort and is NOT in any way supported by any organization.
* The script performs read only operation and can be used at User's discretion.
