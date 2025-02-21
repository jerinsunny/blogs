---
layout: postsonofffirmex
date:   2024-11-05 07:40:59 +0530
tags: jekyll update
published: true
---


<!-- In today's interconnected world, smart home devices have become ubiquitous, but they also introduce unique security challenges. In this first part of our blog series, we'll take an in-depth look at the security research conducted on `Sonoff Smart Home IoT devices`. This initial post will explore the basics of the device, discuss the methodology used for assessing its security, and lay the groundwork for understanding potential vulnerabilities. In the second part, we'll dive deeper into the findings and explore how we exploited them, as well as their impact. -->


In today’s interconnected world, smart home devices have become ubiquitous, but they also introduce unique security challenges. This blog series delves into the vulnerabilities identified during our security research on `Sonoff Smart Home IoT devices`, which earned CVE-2024-7205 and CVE-2024-7206.

In this first part, we explore the basics of the device, discuss the methodology used for assessing its security posture, explain the process of extracting firmware from the device and overcoming integrity checks to successfully boot modified firmware. This lays the foundation for understanding how firmware manipulations can expose critical security flaws.

In the second part of the series, we will build on these findings and demonstrate how they can be exploited to reveal further security weaknesses.

<!-- In the second part of the series, we’ll shift our attention to bypassing SSL pinning on the device, exploring how this vulnerability can be exploited and its potential impact on the overall security of the device. -->

# Introduction

Sonoff has a wide range of smart home products, including smart switches, lights, gateways, sensors, etc.. The aim of our security research was to uncover vulnerabilities in Sonoff Wifi Devices. The target device selected for this security research was the **[Sonoff ZigBee Bridge (ZB Bridge)](https://sonoff.tech/product/gateway-and-sensors/zbbridge/)** as it worked on Wi-Fi. The Sonoff ZigBee Bridge connects to various sensors over ZigBee, accumulates the data and sends it to the cloud. The eWelink app is used to interact with the devices and access data over the cloud. 
The **[eWelink App]()** is used to pair the device over Bluetooth. The app provides other features, such as device sharing with a secondary user, where the secondary user can also interact with the device. `The paid version allows the primary user to restrict access to the secondary user.`

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/sonoff_overview.webp" width="60%" > 
<figcaption>Sonoff ZB Bridge Overview </figcaption>
</figure>


# Target Reconnaissance

As part of the initial recon, to gain more information about the hardware, we began with a physical teardown.
Opening the device gave us our first look at its internal hardware, and allowed us to analyse the PCB and its components. 

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/teardown.webp" width="70%" > 
<figcaption>Hadware Teardown </figcaption>
</figure>

The main components of interest to us are the following :
``` text
* CC2652 MCU 
* ESP32 D0WD-V3
* SPI Flash(ZB25VQ32)
* Debug Port
```

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/pcb.webp" width="45%" > 
<figcaption>Component Identification </figcaption>
</figure>


The CC-based MCU is used for ZigBee communication, while the EPS32 based MCU serves as the brain of the device, managing all other smart home functionalities and the Wifi connectivity. 


# Firmware Extraction

Analyzing the firmware of an IoT device is a crucial step in security research, as it can reveal potential vulnerabilities, hardcoded secrets, and APIs that could be exploited. There are several methods to extract firmware such as Memory Chip Extraction, Firmware Update File, Debug Port.

## Debug port analysis

We decided to investigate the debug port on the target device to determine if the firmware could be extracted through it. Analyzing the PCB markings, it appeared to be a UART debug port. On connecting it with a USB to serial converter we get boot logs as shown in the figure below

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/hardware_setup.webp" width="60%" > 
<figcaption>UART connection to PC
 </figcaption>
</figure>


<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/boot_logs.webp" width="60%" > 
<figcaption>Boot logs
 </figcaption>
</figure>

### Boot Mode

On referring to the [ESP32 Datasheet](https://www.espressif.com/sites/default/files/documentation/esp32_datasheet_en.pdf), we understand that the the chip allows configuring its boot parameters through Strapping pins, GPIO0 is one of the strapping pins which controls the boot mode. This pin is also present on the debug port. 
There are namely two boot modes and the logic levels of the pins for the appropriate boot mode is mentioned in the datasheet, shown below.

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/boot_mode.webp" width="35%" > 
<figcaption>ESP32 Boot Mode 
 </figcaption>
</figure>

SPI Boot Mode is default boot mode in which the device boots, we switched the boot mode and observed the boot logs

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/download_boot_mode.webp" width="70%" > 
<figcaption>ESP32 Boot Mode 
 </figcaption>
</figure>

Esptool is a python based utility to  communicate with the ROM bootloader in Espressif SoCs. 
Esptool provides various capabilities such as :

* Read, write, erase, and verify binary data stored in flash. 
* Read chip features and other related data such as MAC address or flash chip ID. 
* Prepare binary executable images ready for flashing.


### ESP32 Partition Table
We can extract the full flash contents using Esptool. However, let's dive deep down into how external flash memory is mapped and used in  most of the Espressif SoCs. A single ESP32's flash can contain multiple apps, as well as many different kinds of data (calibration data, filesystems, parameter storage, etc). For this reason a Partition Table is maintained within the flash.

First we'll extract the partition table from the target device. The partition table can then be analysed using [gen_esp32part.py](https://github.com/espressif/esp-idf/blob/46acfdce/components/partition_table/gen_esp32part.py)

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/partition_table.webp" width="70%" > 
<figcaption>Partition Table 
 </figcaption>
</figure>

The partition table entries include a name (label), type (app, data, or something else), subtype and the offset where the partition is loaded, as shown in figure above. The type field indicates the data type stored in each partition. 

Each of these partitions can be extracted separately and analyzed individually.

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/nvs.webp" width="70%" > 
<figcaption>Partition Table 
 </figcaption>
</figure>

Our analysis of these partitions revealed the following:
```
* The Application firmware is stored in in ota_0 and ota_1 partition. 
* The NVS partition contains the SSID and password of the Wi-Fi APs.
* The Version partition contains the version information.
* The Otadata, phy_init have other supporting data required for the device to function.
```

{% include admonition.html type="warning" title="Vulnerability" body="CWE-1191: On-Chip Debug and Test Interface With Improper Access Control" %}

# Firmware Modification

<!-- Now that we have successfully extracted the firmware, it's time to dive into the analysis.  -->

The partition of interest is the application firmware i.e ota_0 and ota_1 , which contains the core app code specific to this smart home device. This is where we expect to find the logic that controls the device's features, communication protocols, and potentially, any hardcoded credentials or configurations.


However, before we start dissecting the application firmware, it is crucial to determine whether we can modify the firmware and flash it back to the device. This step helps us verify if the device employs any firmware integrity checks, such as digital signatures or checksums, which are designed to prevent unauthorized firmware modifications.

## Secure boot

Espressif SoCs feature a Secure Boot mechanism designed to ensure that only trusted firmware is executed on the device. These SoCs utilize eFuses to store system parameters and enable various security features. The ESP32 Technical Reference Manual provides details on the eFuses and the specific fuses responsible for each feature. We use the `espefuse.py` tool to inspect the device's eFuse settings.

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/secure_boot.webp" width="90%" > 
<figcaption>ESP32 Secure Boot eFuse Values 
 </figcaption>
</figure>
 
The secure boot feature was found to be disabled on the target device as shown in the figure above.

We modified the  application firmware by making a small controlled change and flashing it back to the target device. However, after flashing the modified firmware, the device failed to boot.

### ESP32 Application Image Format

ESP32 has a application image format that includes a footer with a single byte checksum and SHA256 hash. ESP32 uses this checksum and hash to verify the application partition.  We can use esptool to check if the checksum and hash is valid for the modified file.

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/mod_invalid.webp" width="90%" >
<figcaption>Checksum and hash for modified App Image
 </figcaption>
</figure>


Unless the checksum and hash is valid, the bootloader will panic on startup, and fail to run the modified app partition . Since secure boot is not enabled, this checksum and hash do not provide a strong security guarantee. So we can locate the checksum and hash and modify it.

<figure style="text-align:center;">
<img src="../../../assets/sonoff/images/mod_valid.webp" width="90%" >
<figcaption>Replaced checksum and has for modified App Image
 </figcaption>
</figure>

Once the checksum and hash are replaced with valid values, we can flash the modified firmware back to the target device using esptool. This allowed us to successfully boot the modified firmware on the device. 

{% include admonition.html type="warning" title="Vulnerability" body="CWE-1326: Missing Immutable Root of Trust in Hardware" %}


# Conclusion
This blog post describes the findings obtained during the preliminary security research conducted on Sonoff Smart Home IoT device. The summary of the key findings are described below:
* Firmware extraction was successfully performed through UART debug port.
* We examined the partition table of the device's flash memory to understand how the application image and other critical data are organized and stored.
* Modified firmware was flashed back to the device bypassing the integrity checks.



* * *
### This research was carried out by [`Jerin Sunny`](https://www.linkedin.com/in/jerin-sunny/){:target="_blank"} and [`Shakir Zari`](https://www.linkedin.com/in/shakir-zari/){:target="_blank"} and published on behalf of the .

* * *


