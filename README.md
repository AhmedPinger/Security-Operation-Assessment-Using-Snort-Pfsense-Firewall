# Security Operation Assessment Using Snort & Pfsense Firewall

**By Ahmed Pinger**

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

### 1. Setup and Configure Web Server

Install LAMP and WordPress, apply HTTP-Basic authentication on admin directories, and make admin directories password-protected.

### 2. Setup an Attacker Machine

No additional configuration needed; leverage default Kali Linux tools for penetration testing.

### 3. Setup Normal User Machine

No additional configuration needed; leverage a default user machine for testing.

### 4. Install and Configure Pfsense Firewall

Assign interfaces, configure WAN, LAN, and DMZ interfaces, assign IP addresses, and install Pfsense on VMware.

### 5. Setup Snort as an IDS/IPS

Install Snort on Pfsense through the web portal, configure interfaces, and add custom rules for Brute Force and LFI attacks.

## Testing

### 1. Testing whether Snort can detect a Brute Force attack or not.

Use Nmap to perform a Brute Force attack on the web server; check Snort alerts on Pfsense.

### 2. Testing whether Snort can detect an LFI attack or not.

Launch an LFI attack on the web server; check Snort alerts on Pfsense.

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

