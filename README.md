# Security Operation Assessment Using Snort & Pfsense Firewall

**By Ahmed Pinger**

## Table Of Contents
1. [Introduction](#introduction)
2. [Project Implementation Plan](#project-implementation-plan)
    - [Analysis & Design](#analysis--design)
    - [Development](#development)
    - [Testing](#testing)
    - [Documentation](#documentation)
3. [Scope Of Work](#scope-of-work)
4. [Project Flow](#project-flow)
    - [Setting Up Topology Diagram](#setting-up-topology-diagram)
    - [Setup VMware](#setup-vmware)
    - [Setting Up Virtual Switches](#setting-up-virtual-switches)
5. [Development](#development-1)
    - [Setup and Configure Web Server](#1-setup-and-configure-web-server)
    - [Setup an Attacker Machine](#2-setup-an-attacker-machine)
    - [Setup Normal User Machine](#3-setup-normal-user-machine)
    - [Install and Configure Pfsense Firewall](#4-install-and-configure-pfsense-firewall)
    - [Setup Snort as an IDS/IPS](#5-setup-snort-as-an-idsips)
6. [Testing](#testing-1)
    - [Testing whether Snort can detect a Brute Force attack or not](#1-testing-whether-snort-can-detect-a-brute-force-attack-or-not)
    - [Testing whether Snort can detect an LFI attack or not](#2-testing-whether-snort-can-detect-an-lfi-attack-or-not)
7. [Acronyms](#acronyms)

   
## Introduction

Securing web applications is a critical aspect of enterprise security, with a rising trend in cyber-attacks targeting web applications. This project focuses on providing solutions to protect web pages requiring passwords against Brute Force Attacks and securing a specific WordPress website with vulnerable plugins. The mitigation involves detecting and countering attacks using Snort IDS/IPS on a PFSense Firewall. The project follows a methodology encompassing analysis, design, development, testing, and documentation.

## Project Implementation Plan

### Analysis & Design
1. Draft Environment Setup
2. Install Needed ISOs

### Development
1. Setup and Configure Web Server
2. Setup an Attacker Machine
3. Install and Configure the Pfsense Firewall
4. Setup Snort as an IDS/IPS
5. Configure Snort to Defend Against Brute Force Attack and LFI attack

### Testing
1. Performing HTTP-Basic Authentication Brute Force Attack
2. Performing Local File Inclusion Attack
3. Check Alerts on Firewall/IPS

### Documentation
1. PPT
2. Gantt Chart
3. Proposal

## Scope Of Work

| Sr. No. | Tasks                                       |
|---------|---------------------------------------------|
| 1.      | Setup Virtual Switches                      |
| 2.      | Setup Web Server                            |
| 3.      | Setup Attacker Machine                      |
| 4.      | Setup Normal User Machine                   |
| 5.      | Install Pfsense and Do Basic Configuration  |
| 6.      | Install Snort                               |
| 7.      | Apply Rules on Snort                        |
| 8.      | Test                                        |
| 9.      | Documentation                               |

## Project Flow

To set up the entire environment, the first step involves designing the topology using MS Visio. Afterwards, VMware Workstation Pro is installed to implement the topology.

### Setting Up Topology Diagram:

<img src="https://lh7-us.googleusercontent.com/YF83BAlpvMgO4F_dK1ec16DWkC8RFd-JG9K9Hzyg0bur4Q3qTW8cnztkuQDc319UPFDLSmIhcmxtdKo_ZaiNlAMg_6vL1YWUUCNxmqnNEEX2v4SmAEeC-FyQMyFZ-KJKAjeKEntLjLihx3g9LXpeF1HgFt5G7Dxl3xiEtfJmjJqauZkMcRRgMrIKI9ZGQeKakm0xmd5-Mg" style="width:6.5in;height:3.59722in" />

The topology consists of virtual switches, including VMnet8, VMnet11, and VMnet12, each assigned to specific interfaces. 

### Setup VMware:

1. Install VMware Workstation
2. Download and install ISO files
3. Set up virtual machines

### Setting Up Virtual Switches:

1. Create VMnet8 and set it up to Bridge Network with DHCP enabled
2. Create VMnet11 and set it up to Host-only mode with IP address 192.168.40.0
3. Create VMnet12 and set it up to Host-only mode with IP address 192.168.50.0

## Development

## Development

### 1. Setup and Configure Web Server

Install LAMP and WordPress, apply HTTP-Basic authentication on admin directories, and make admin directories password-protected.

```bash
# Installing LAMP
sudo apt install apache2 apache2-utils
sudo service apache2 start
sudo service apache2 enable

sudo apt install mariadb

sudo apt install php
sudo apt install phpmyadmin

# Installing WordPress
sudo apt install php-curl php-gd php-mbstring php-xml php-xmlrpc php-soap php-intl php-zip

wget https://wordpress.org/latest.tar.gz
tar -zxvf latest.tar.gz
sudo mv wordpress /var/www/html/
```
# Configuring Apache
sudo nano /etc/apache2/sites-available/000-default.conf

# Add the following within the <VirtualHost> section:
<Directory "/var/www/html/admin">
  AuthType Basic
  AuthName "admin area"
  AuthUserFile /etc/nginx/.htpasswd
  Require valid-user
</Directory>

<Directory "/var/www/html/wordpress/wp-admin">
  AuthType Basic
  AuthName "admin area"
  AuthUserFile /etc/nginx/.htpasswd
  Require valid-user
</Directory>

# Restart Apache
sudo service apache2 restart

# Configuring MariaDB
sudo mysql_secure_installation

# Create a MariaDB database and user for WordPress
sudo mysql -u root -p
CREATE DATABASE wordpress;
GRANT ALL PRIVILEGES ON wordpress.* TO 'wordpressuser'@'localhost' IDENTIFIED BY 'password';
FLUSH PRIVILEGES;
EXIT;

# Access the WordPress installation page
http://localhost/wordpress

# Make Admin Directories Password Protected
sudo apt install nginx
sudo htpasswd -c /etc/nginx/.htpasswd USERNAME
sudo nano /etc/apache2/sites-available/000-default.conf

# Add the following within the <Directory> sections for admin areas:
AuthType Basic
AuthName "Restricted Access"
AuthUserFile /etc/nginx/.htpasswd
Require valid-user

<img src="https://lh7-us.googleusercontent.com/4eT7T9Esl0pOPNxtx9j_cAKhlCyPYduPVwmUxnpwjAN2BoWCgeQrLLpYGPvWRk6rxn1InyxTYMbcsgVGrtluj8QzUUJZh3jrRFKG6gK-0xLREUPeD4B_T75P99hmQ_NKXEspXi7uu5URwgRBOMWPKaT1LI_yJXF6yKssH9Cpe8YG9gvPxysQkJUKmsreJ7T_Gxqao9grCQ" style="width:6.5in;height:3.59722in" />

# Restart Apache
sudo service apache2 restart

### 2. Setup an Attacker Machine

No additional configuration is needed; leverage default Kali Linux tools for penetration testing.

### 3. Setup Normal User Machine

No additional configuration is needed; leverage a default user machine for testing.

### 4. Install and Configure Pfsense Firewall

Assign interfaces, configure WAN, LAN, and DMZ interfaces, assign IP addresses, and install Pfsense on VMware.

### 5. Setup Snort as an IDS/IPS

Install Snort on Pfsense through the web portal, configure interfaces, and add custom rules for Brute Force and LFI attacks.

```plaintext
#### Installing Snort on Pfsense:

1. Open the Pfsense web portal.
2. Navigate to **System > Package Manager > Available Packages.**
3. Search for "snort" and click **Install**.

#### Configuring Snort Interfaces:

1. In the Pfsense web portal, go to **Services > Snort.**
2. Configure the WAN, LAN, and DMZ interfaces.
3. Set appropriate IP addresses, networks, and rules for each interface.

#### Adding Custom Rules:

Create custom Snort rules to detect and mitigate specific attacks. For example:

- **Brute Force Attack Rule:**
  ```plaintext
  alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SERVER-WEBAPP Site Editor WordPress plugin local file access attempt"; flow:to_server,established; content:"/ajax_shortcode_pattern.php?"; fast_pattern:only; http_uri; content:"ajax_path="; nocase; http_uri; metadata:policy max-detect-ips drop, service http; reference:cve,2018-7422; classtype:web-application-attack; sid:47424; rev:1;)

- **LFI Attack Rule:**
  ```plaintext
  alert tcp any any -> 192.168.40.200 80 (msg:"HTTP AUTH brute force attack"; content:"535 Authentication failed."; nocase; classtype:attempted-user; threshold:type threshold, track by_src, count 2, seconds 60; sid:1000500; rev:6;)
```
## Testing

### 1. Testing whether Snort can detect a Brute Force attack or not.

Use Nmap to perform a Brute Force attack on the web server; check Snort alerts on Pfsense.

- **Nmap Command:**
  ```plaintext
  nmap -p80 --script http-brute --script-args 'http-brute.hostname=192.168.40.200,http-brute.method=POST,http-brute.p ath=/admin/,userdb=/usr/share/nmap/nselib/data/usernames.lst,passdb=/us r/share/nmap/nselib/data/passwords.lst' -v 192.168.40.200 -n

### 2. Testing whether Snort can detect an LFI attack or not.

Launch an LFI attack on the web server; check Snort alerts on Pfsense.

- **Payload:**
  ```plaintext
  http://192.168.40.200/wordpress/wp-content/plugins/site-editor /editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_ path=/etc/passwd


## Acronyms

- IPS: Intrusion Prevention System
- HTTP: HyperText Transfer Protocol
- LFI: Local File Inclusion
- XSS: Cross-Site Scripting
- IDS: Intrusion Detection System
- DHCP: Dynamic Host Configuration Protocol
- IP: Internet Protocol
- LAMP: Linux, Apache, MySQL, PHP
- URL: Universal Resource Locator

