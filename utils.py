def socket_safe(*args):
    # Sets up a socket using the specified args, taking care of any exceptions
    # and returning the socket descriptor object
    try:
        sd = socket.socket(*args)
    except error, msg:
        print ('Error', msg[0], 'creating socket:', msg[0])
        sys.exit()
    return sd


def socket_universal():
    # Uses the socket_safe function to set up a socket object that will capture
    # any incoming or outgoing (including TCP, UDP and ICMP)
    # 0x0003 is ETH_P_ALL
    return socket_safe(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))