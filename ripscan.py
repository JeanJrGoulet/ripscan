#!/usr/bin/python3.9

# ------------------------------------------------**DISCLAIMER**----------------------------------------------------#
# Scanning device that you don't own is illegal and you could end up having some serious legal problems.            #
#                                                                                                                   #
# I am not responsible for any misuse you made out of this tool and/or any damage that you may cause.               #
#                                                                                                                   #
# This is for educational purpose and should only be used against your own devices, or other devices that           #
# you have been authorized by the owner to perform those kind of action on them.                                    #
#-------------------------------------------------------------------------------------------------------------------#


#-------------------------------------------------------------------------------------------------------------------#
# Name          : ripscan.py                                                                                        #
#                                                                                                                   #
# Version       : 1.0.0                                                                                             #
#                                                                                                                   #
# Description   : This script is a basic TCP/UDP Port scanner, made for educational purpose only (mine and yours).  #
#                 It's my attempt at reproducing [really basic] nmap functionalities and getting my foot into       #
#                 the realm of cybersecurity tools, used for Pentesting, Bug Bounty and/or CTFs.                    # 
#                                                                                                                   #
#                 ripscan will scan from a specific port range by using this command format:                        #
#                       ex: ./ripscan.py 127.0.0.1 1,1000 all                                                       #
#                                                                                                                   #
#                 With this command, ripscan will perform a scan on both TCP and UDP ports from 1 to 1000.          #
#                                                                                                                   #
#                 Depending on the Scan protocol chosen, different methods will be used to reach the host.          #
#                 Ripscan will try to gather basic information on the running services like the service banner      #
#                 and the default service running.                                                                  #
#                                                                                                                   #
#-------------------------------------------------------------------------------------------------------------------#

from multiprocessing import Value, Queue, Process
import binascii
import datetime
import time
import socket
import sys



RHOST = "127.0.0.1"                     # Address of the target machine to perform the scan on -> will be overwritten by sys.argv[1].
PORT_RANGE = '1,10000'                  # Range of Ports to perfom the scan on -> will be overwritten by sys.arv[2].
SCAN_PROTOCOL = []                      # List of protocol to perform scans with -> will be overwritten by sys.argv[3].

ACTIVE_PROCESSES = []                   # List of active process.
MAX_PROCESSES = 20                      # Constant holding the max number of processes to create

SOCK_TIMEOUT = 1                        # If a connection cannot be established within that time, the scan_sock will timeout.
                                        # The lower SOCK_TIMEOUT is, the faster the program will scan.
                                        # However, lowering the SOCK_TIMEOUT too much might give a less accurate scan.

UDP_PROBES = {
    #ask DNS server for google.com
    'dns_pack' :    "FF F0 "\
                    "01 00 00 01 00 00 00 00 00 00 " \
                    "06 67 6F 6F 67 6C 65 03 63 6F 6D 00 00 01 00 01",
}



def showUsage():
    print("""
    \n
    For more info about the program and commands, run:\n\n       ./ripscan.py -h\n\n
    Usage: ./ripscan.py [RHOST] [PORT_RANGE] [PROTOCOL]
           ./ripscan.py 127.0.0.1 1,1000 all
           ./ripscan.py 127.0.0.1 1,1000 tcp
    \n
    """)

def showHelp():
    print("""
    \n
     Actions:   |             Description
    ---------------------------------------------------------------------------------------
     RHOST      |      Hostname or IP Address of the remote host (target machine).
                |
     PORT_RANGE |      The range of port to perform the scan on example: [ 1, 5001 ]
                |      will scan port 1 to 5001 (5000 ports).
                |
     PROTOCOL   |      Specify the protocol of the scan. 
                |        Ex: tcp / udp / all.
                |
                |      Note: If you don't supply any protocol, 
                |           the scan will be perform a TCP/UDP scan
    ---------------------------------------------------------------------------------------
    \n
    """)

# Will try to resolve the Hostname or IP address
# if the hostname or ip can be resolve, the ip address associated with it will be returned
def resolveHostAddr(host):
    frag_host = host.strip('.').split('.')
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        for frag in frag_host:
            if not frag.isnumeric():
                print("Cannot resolve Hostname : {0}".format(host))
                return None
        print("Cannot resolve IP Address: {0}".format(host))
        return None

def getSvcBanner(host, port):
    svc_banner= b''
    banner_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        banner_sock.settimeout(1)
        banner_sock.connect((host, port))
        banner_sock.send(b'whoareyou\r\n')
        
        svc_banner = banner_sock.recv(128)
    except:
        pass
    banner_sock.close()
    return svc_banner.decode().strip("\r\n").replace('\r\n', ' ').replace('\n', ' ')

def outputResults(scan_time, q_open_ports):
    # TODO: Fix Time, second(s) and minutes can still be displayed in decimal ex: 7.75 seconds or 7.75 minutes is possible
    rounded_time = round(scan_time)
    time_unit = 'second(s)'
    ports_svc_list = []

    if rounded_time > 60 :
        scan_time = scan_time/60
        time_unit= 'minute(s)'
    
    # Unpack the Queue and build the ports/services list with its data.
    for i in range(0, q_open_ports.qsize()):
        ports_svc_list.append(q_open_ports.get(i))

    ports_svc_list.sort()

    print("[Done] Scan took {1} {2} - Found {0} open port(s)\n".format( len(ports_svc_list), round(scan_time, 2), time_unit))
    print("  Ports \t State\t\t\tService\t\tVersion\n")

    for port_svc in ports_svc_list:
        print('  {0}/{4}\t {1}\t\t{2}\t\t{3}'.format( port_svc[0], port_svc[1], port_svc[2], port_svc[3], port_svc[4]))

def scanTCPPorts(port, n_ports_scanned, q_open_ports):
    global RHOST
    global SOCK_TIMEOUT

    is_open = False
    scan_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        scan_sock.settimeout(SOCK_TIMEOUT)
        scan_sock.connect((RHOST, port))
        try: 
            known_svc = socket.getservbyport(port, 'tcp')
        except:
            known_svc = 'unknown'
        is_open = True
    except:
        pass
    finally:
        scan_sock.close()
        if is_open == True:
            q_open_ports.put((port, 'open\t', known_svc, getSvcBanner(RHOST, port), 'tcp'))

        time.sleep(0.5)

        # Here we need to use the lock provided with the CTYPE variable to lock
        # the variable during the mutation process.
        # This will prevent other processes from mutating it at the same time.
        with n_ports_scanned.get_lock():                                    
            n_ports_scanned.value += 1

# TODO: The UDP can isn't really accurate yet, I need to figure this out eventually
def scanUDPPorts(port, n_ports_scanned, q_open_ports):
    global RHOST
    global SOCK_TIMEOUT
    global UDP_PROBES

    scan_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    scan_sock.settimeout(3)

    message = b'whoareyou\r\n'

    if port == 53:
        message = binascii.unhexlify(UDP_PROBES['dns_pack'].replace(" ", "").replace("\n", ""))
    try:
        try:
            known_svc = socket.getservbyport(port, 'udp')
        except:
            known_svc = 'unknowm'
            pass

        # UDP is connectionless, therefore we can send message without being connected to it.
        scan_sock.sendto(message, (RHOST, port))

        # Will mostly timeout or error here since , since Firewall may drop or filter packets.       
        message, address = scan_sock.recvfrom(1024)

        if message.decode() != '':
            q_open_ports.put((port, 'open', known_svc, message.decode().strip('\r\n').replace('\r\n', ' ').replace('\n',' '), 'udp'))

    except socket.timeout:
        q_open_ports.put((port, 'open|filtered', known_svc, '', 'udp'))
        pass
    except socket.error as sock_err:
        if sock_err.errno == socket.errno.ECONNREFUSED:
            pass

    finally:
        scan_sock.close()
        time.sleep(0.5)

        # Locking variable to prevent other processes from mutating it at the same time.
        with n_ports_scanned.get_lock():
            n_ports_scanned.value += 1

def scanPorts(min, max, n_ports_scanned, q_open_ports, scan_protocol):
    # Iterate through the protocols that we have chosen from SCAN_PROTOCOL list
    for protocol in scan_protocol:
        for port in range (min, max):
            if protocol == 'tcp':
                scanTCPPorts(port, n_ports_scanned, q_open_ports)
            elif protocol == 'udp':
                scanUDPPorts(port, n_ports_scanned, q_open_ports)

def printProgress(n_ports, n_ports_scanned, scan_protocol):
    counter = 0
    anim_char = ['-', '\\', '|', '/']
    total_ports = n_ports * 2 if len(scan_protocol) > 1 else n_ports
    while n_ports_scanned.value < total_ports:
        time.sleep(0.06)
        counter = 0 if counter == 4 else counter
        print("\t[{2}] Scan Progress: {0}/{1}".format( n_ports_scanned.value, total_ports, anim_char[counter]), end ="\r")
        counter += 1

def initArgs():
    global SCAN_PROTOCOL
    global RHOST
    global PORT_RANGE

    for arg_index in range (0, len(sys.argv)):      
        if arg_index == 1:
            if sys.argv[arg_index] == '-h' or sys.argv[arg_index] == '-H':
                showUsage()
                showHelp()
                exit()
            else:
                RHOST = sys.argv[arg_index]
        elif arg_index == 2:
            PORT_RANGE = sys.argv[arg_index]
        elif arg_index == 3:
            if (sys.argv[arg_index]).lower() == 'all':
                SCAN_PROTOCOL.append('tcp')
                SCAN_PROTOCOL.append('udp')
            elif (sys.argv[arg_index]).lower() == 'tcp' or (sys.argv[arg_index]).lower() == 'udp':
                SCAN_PROTOCOL.append(sys.argv[arg_index])

    if len(sys.argv) < 3:
        showUsage()
        exit()

    if len(SCAN_PROTOCOL) == 0:
        SCAN_PROTOCOL.append('tcp')
        SCAN_PROTOCOL.append('udp')

def main():
    global SCAN_PROTOCOL
    global RHOST
    global PORT_RANGE
    global MAX_PROCESSES

    # Initializing program arguments.
    initArgs()

    # Storing our Port range in the p_range list.
    p_range = PORT_RANGE.split(',')

    if len(p_range) > 2 or len(p_range) < 1:
        print("\n [ERROR] - Invalid Port range supplied", file=sys.stderr)
        showUsage()
        return

    if p_range[0].isnumeric():
        try:
            p_range[1].isnumeric()     
        except:
            print("\n [WARNING] - Only the first value in range will be scanned because max value is missing")
            p_range = [p_range[0]]
            pass
    else:
        print("\n [ERROR] - Port must be a numeric value", file=sys.stderr)
        showUsage()
        return

    offset= 0

    # The number of ports to scan is determined by the difference between 
    # the Highest Value supplied in p_range and the Lowest Value supplied in p_range.
    if len(p_range) == 1:
        n_ports = 1
    else:
        n_ports = (int(p_range[1]) + 1 ) - int(p_range[0])

    n_process = n_ports if n_ports < MAX_PROCESSES else MAX_PROCESSES

    # Determining how many ports each process will scan.
    n_ports_process = round(n_ports/n_process)

    # Storing remainder in case of odd numbering
    n_ports_remainder = n_ports % n_process

    # Since traditional variable won't share their state across different processes,
    # we need to rely on some solutions from the multiprocessing library.
    n_ports_scanned = Value('i', 0)                                                     # Creates a CTYPE variable that will share the same memory space on all processes.
    q_open_ports = Queue()                                                              # Queues are shareable across all processes. 
   
    scan_mode = ''

    for protocol in SCAN_PROTOCOL:
        scan_mode += protocol.upper() + '/'

    scan_mode= scan_mode.strip('/')
    RHOST = resolveHostAddr(RHOST)

    if RHOST != None: 
        print("\n* Starting {1} Port Scan on {0} *\n".format(RHOST, scan_mode))
        start = time.time()

        try:
            # Starting the Progress process, that will be use to output the progress of the scan to stdout.
            prog_proc = Process(target=printProgress, args=(n_ports, n_ports_scanned, SCAN_PROTOCOL))
            prog_proc.start()

            ACTIVE_PROCESSES.append(prog_proc)

            # Spawning an army of snakes
            for x in range (0, n_process):

                # If we are in the last iteration we will add the n_ports_remainder
                # to the last process workload, since the above division may give a odd number as a result.
                if x == n_process-1:
                    n_ports_process += n_ports_remainder

                # Starting a Scan process within a certain range determined by the [lowest port to scan] + [offset]
                # and the [highest port to scan] + [offset].
                if len(p_range) > 1:
                    scan_proc = Process(target=scanPorts, args=(int(p_range[0]) + offset, n_ports_process + offset + int(p_range[0]), n_ports_scanned, q_open_ports, SCAN_PROTOCOL))
                else:
                    scan_proc = Process(target=scanPorts, args=(int(p_range[0]), int(p_range[0]) + 1, n_ports_scanned, q_open_ports, SCAN_PROTOCOL))
                scan_proc.start()

                ACTIVE_PROCESSES.append(scan_proc)

                # Increment the offset by the number of port scanned by the process.
                offset += n_ports_process

            prog_proc.join()
            end = time.time()
            scan_time = end - start
            outputResults(scan_time, q_open_ports)

        # Triggered when system receives SIGINT.
        except KeyboardInterrupt:
            try:
                for p in ACTIVE_PROCESSES:
                    p.terminate()
            except:
                pass
            exit()

if __name__ == '__main__':
    main()
