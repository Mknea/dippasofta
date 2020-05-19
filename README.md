# README

This repository contains the software implementation of my thesis:

### Methods and supporting software for industrial control system and instrumentation security testing.

---
# The software

The software is a proof of concept on using publicly available open-source security testing modules in conjunction with Robot Framework test suite for ICS network security testing. As the networks contain numerous different protocols and technologies, a choice was made to focus on testing a common PLC, **Siemens S7-1200**.

The software is composed of:
* [The Robot Framework test suite](./ICSSecTestSuite.robot)
* Scanner modules:
  * [PROFINET scanner](./ProfinetScanner.py)
  * [S7CommPlus scanner](./S7CommPlusScanner.py)
* Exploit module:
  * [S7-1200 manipulator](./S7-1200manipulator.py)

The test suite is used to control the modules and chain their execution and outputs. Alternately, the modules are individually operable through command-prompt (e. g. `$ sudo python profinetscanner.py -i enp0s3`)

---
# Operation

## PROFINET scanner
Sends out PROFINET-DCP 'identify all' message through the given network interface, to which all Siemens devices within the subnetwork respond with their identification data:
 	
| mac address       | type of station | name of station | vendor id         | device id      | device role         | ip address      | subnet mask   | standard gateway    |
|---|---|---|---|---|---|---|---|---|
| e0:dc:a0:XX:XX:XX | S7-1200         | plcxb1      | 002a (SIEMENS AG) | 010d (S7-1200) | 02 (IO-Controller ) | 192.168.250.129 | 255.255.255.0 | 192.168.250.130  |

## S7CommPlus scanner

Initiates connection with S7CommPlus protocol to given IP address. S7-1200 and -1500 models utilise this protocol and should respond. Before encryption comes to play in subsequent messages, device ID and firmware are obtained from first response and the connection is terminated.

| Target IP       | Hardware ID          | Firmware version |
|:----------------|----------------------|:----------------:|
| 192.168.250.129 | 6ES7 211-1AE40-0XB0  | V4.2.2           |

## S7-1200 manipulator

Used to demonstrate the possibility of reading the state of device inputs, outputs and merkers (internal flag variables), and writing to outputs and merkers. Module utilises basic S7Comm protocol which S7-300 and -400 devices use as default, S7-1200 devices use unless disabled, and S7-1500 devices can be configured to use.

## The Robot Framework test suite

Test cases are built to contain the desired set of actions. Keywords within the test suite interract with the modules and handle parsing etc.

Desired test cases can be run straight from command-prompt with:
```
$ sudo robot -t SiemensScanTestCase ICSsectestsuite.robot
```
And with given values:
```
$ sudo robot --variable EthIface:enp0s5 ICSsectestsuite.robot
```
