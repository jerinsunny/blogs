---
layout: postinterceptingtls
title: Intercepting IoT TLS Traffic
date:   2024-12-12 07:40:59 +0530
tags: jekyll update
author: Jerin Sunny
published: false
---

This is the second part of the blog series on security research of Sonoff IoT Devices. In the previous blog, we detailed how to extract the firmware, modify it, and boot the modified firmware. This blog explores how we bypassed SSL pinning on the device to perform a man-in-the-middle attack, enabling us to intercept the device's traffic. Additionally, we also analyze the complete communication between the IoT device, cloud, and the app.

# Introduction

As explained in the previous blog, Sonoff devices communicate with the cloud to transfer device telemetry and perform various smart operations. In this blog, we will focus on analyzing the communication between the IoT device and the cloud. Our main goal is to identify all the API endpoints it connects to and find any security tokens or keys used for device authentication with the cloud. This will enable us to clone the device.

There are two approaches to accomplish our goals. The first method is to reverse engineer the entire firmware we extracted. The second method is to perform a MITM (Man-In-The-Middle) attack to intercept the device's communication with the cloud and inspect the online traffic that goes in and out of it. 

We opted for the second approach because if successful , it would provide a more complete understanding of the real time communication between the device and the cloud. 

# MITM Attack 

Picture of MITM 


First step is to route the traffic from the IoT device to the cloud through the laptop, which will allow us to do a preliminary analysis on the communication.

Windows has a pretty nifty feature of mobile hotspot , which allows devices to connect to internet through the laptop. We connect the Sonoff device to the laptop hotspot and route the traffic through the laptop. 

### Cloud communication analysis

 Using wireshark we can sniff of the hostpot adapter to view the traffic. The laptop assigns a an IP to the device which can be seen in the hotspot settings. Using the IP assigned to the device, we can filter out the traffic particular to the device.


Figure of wirehark log 

As shown in above wireshark log, the device first sends a DNS query to resolve the IP address for the domain name as-dispd.coolki.cc .

After the IP is resolved the device uses this IP address to connect to the web server.  After that the device initiates a TLS/SSL connection to the web server. 
>TLS/SSL communication ensures secure data transmission by encrypting the data and verifying the identity of the communicating parties.

Since the device uses TLS communication, unless there is a flaw in the TLS protocol implementation, the device communication to and from the cloud is encrypted and unreadable. 



We use burp suite as proxy to intercept TLS ..

as You can see the device rejects the connection. for this very reason TLS is used to identify the server and encrypt the communication.

we have a  cert in firmware we extract it 



we extract the cert for wireishark to seee if this is the iceret which it use to validate the server (explin tls somewhere above saying y cert is used to verifyt the dervere, how  TLS is used to verify the communicating server )





# Methodology

We will proceed with the second method, which, if successful, will provide us with in-depth information about how the device communicates and the API endpoints it uses.

# Conclusion

As we have already shown in the previous blog, there is no secure boot or firmware integrity check. Therefore, we will proceed with the second method.



