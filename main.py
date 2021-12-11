from struct import *
from socket import *
from utils  import *

eth_protocols = {'ip_protocol' : 8}

ip_protocols  = {'tcp_protocol'  : 6,
                 'icmp_protocol' : 1,
                 'udp_protocol'  : 17}

# Create a socket descriptor object that will receive any type of packet. 
# For details please see the function definition in utils.py
sd = socket_universal()

for _ in range(5):
    print 'WAITING FOR PACKET...'

    # Receive up to 65565 bytes of data from any available source
    # as a tuple of the form (packet_contents, source_socket_info)
    packet, \
    source  \
    = sd.recvfrom(65565)

    print 'PACKET RECEIVED : '

    # Parse the destination and source MAC addresses and the protocol from the ethernet header.
    # For details please see the function definition in utils.py
    dest_mac,    \
    src_mac,     \
    eth_protocol \
    = parse_ethernet_header(packet)

    print '\tETHERNET HEADER :                     \n', \
          '\t\tDestination MAC :', dest_mac,      '\n', \
          '\t\tSource MAC :     ', src_mac,       '\n', \
          '\t\tEth. Protocol :  ', eth_protocol


        # Parse IP packets
        if eth_protocol == eth_protocols['ip_protocol']:
            # Parse all available information from the IP header of the packet.
            # For details please see the function definition in utils.py
            version,         \
            ihl,             \
            type_of_service, \
            total_len,       \
            identification,  \
            ip_flags,        \
            offset,          \
            ttl,             \
            ip_protocol,     \
            ip_checksum,     \
            src_ip_addr,     \
            dest_ip_addr     \
            = parse_ip_header(packet)

            print '\tIP HEADER :                                 \n', \
                  '\t\tVersion :            ', version,         '\n', \
                  '\t\tIP Header Length :   ', ihl,             '\n', \
                  '\t\tType of Service :    ', type_of_service, '\n', \
                  '\t\tTotal Length :       ', total_len,       '\n', \
                  '\t\tIdentification :     ', identification,  '\n', \
                  '\t\tFlags :              ', ip_flags,        '\n', \
                  '\t\tOffset :             ', offset,          '\n', \
                  '\t\tTime to Live :       ', ttl ,            '\n', \
                  '\t\tIP Protocol :        ', ip_protocol,     '\n', \
                  '\t\tChecksum :           ', ip_checksum,     '\n', \
                  '\t\tSource Address :     ', src_ip_addr,     '\n', \
                  '\t\tDestination Address :', dest_ip_addr

            # Parse TCP packets 
            if ip_protocol == ip_protocols['tcp_protocol']:
                # Parse all available information from the TCP header of the packet.
                # For details please see the function definition in utils.py
                src_port,     \
                dest_port,    \
                seq_num,      \
                ack_num,      \
                data_offs,    \
                tcp_flags,    \
                window,       \
                tcp_checksum, \
                urg_ptr,      \
                data          \
                = parse_tcp_header(packet, ihl)

                print '\tTCP HEADER:                            \n', \
                      '\t\tSource Port :      ', src_port,     '\n', \
                      '\t\tDest Port :        ', dest_port,    '\n', \
                      '\t\tSequence Number :  ', seq_num,      '\n', \
                      '\t\tAcknowledgement :  ', ack_num,      '\n', \
                      '\t\tTCP header length :', data_offs,    '\n', \
                      '\t\tFlags :            ', tcp_flags,    '\n', \
                      '\t\tWindow :           ', window,       '\n', \
                      '\t\tChecksum :         ', tcp_checksum, '\n', \
                      '\t\tUrgen Pointer :    ', urg_ptr,      '\n', \
                      '\t\tData :             ', data 

            # Parse ICMP packets          
        elif ip_protocol == ip_protocols['icmp_protocol']:
            # Parse all available information from the ICMP header of the packet.
            # For details please see the function definition in utils.py
            icmp_type,     \
            code,          \
            icmp_checksum, \
            data           \
            = dataparse_icmp_header(packet, ihl)

                    print '\tIMCP HEADER :                  \n', \
                          '\t\tType :    ', icmp_type,     '\n', \
                          '\t\tCode :    ', code,          '\n', \
                          '\t\tChecksum :', icmp_checksum, '\n', \
                          '\t\tData :    ', data

        # Parse UDP packets
        elif ip_protocol == ip_protocols['udp_protocols']:
            src_port,     \
            dest_port,    \
            length,       \
            udp_checksum, \
            data          \
            = parse_udp_header(packet, ihl)

            print '\tUDP HEADER :                     \n', \
                  '\t\tSource Port :', src_port,     '\n', \
                  '\t\tDest Port :  ', dest_port,    '\n', \
                  '\t\tLength :     ', length,       '\n', \
                  '\t\tChecksum :   ', udp_checksum, '\n', \
                  '\t\tData :       ', data

        else:
            print '\tNOT A TCP, ICMP OR UDP PACKAGE. SKIPPING...' 


        print '\tEND OF PACKET.\n'
