# ripscan

## Description

Ripscan is a basic TCP/UDP Port scanner, made for educational purpose only (mine and yours).<br>
It's my attempt at reproducing [really basic] nmap functionalities and getting my foot into
the realm of <br>cybersecurity tools, used for Pentesting, Bug Bounty and/or CTFs.

## Usage

- Get Help: <br>
  &emsp;`./ripscan.py -h`<br><br>
- Launch a TCP scan on localhost from port 1 to 5000 : <br>
  &emsp;`./ripscan.py localhost 1,5000 tcp`<br><br>
- Launch a UDP scan on 127.0.0.1 from port 433 to 455 : <br>
  &emsp;`./ripscan.py 127.0.0.1 433,455 udp`<br><br>
- Launch a TCP/UDP scan on localhost on port 53 : <br>
  &emsp;`./ripscan.py localhost 53 all`<br> or <br>&emsp;`./ripscan.py localhost 53`<br><br>

## Examples

![Example 1](img/scanH.png) <br><br>
![Example 1](img/scanS.png) <br><br>
Here I basically started 2 netcat listener on port 4433 and 4444 and a HTTP server from python's SimpleHTTPServer module.<br>
Our netcat listenners are giving us no addtional info on the open ports.<br>
However, the HTTP server responded with a broken HTML with error code 400, which is enough to know that port 4201 is probably running a web server.<br>
![Example 2](img/scanE.png) <br>

## Functionalities

This scanner only supports scans on a single host for the moment,
but will eventually permits batch scanning.

You can provide a Hostname, which will be resolved into an IPV4 Address, if it is valid<br>
or simply provide a valid IPV4 Address.<br><br>
While scanning, ripscan will try to gather information on the default service running on a specific port
and will send probes to retrieve a service banner, if any is available.

Since ripscan allocates the chosen port range across multiple processes, it is unlikely going to test ports in consecutive order,<br>which might help avoiding port scan filtering.
