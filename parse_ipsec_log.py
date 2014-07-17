import sys

# define relevant text strings in logfile to get that line
LOG_TEXTS=["ISAKMP-SA established", "login succeeded","authenticated","IPsec-SA established", "deleted", "purged"]
is_debug=False
#is_debug=True

class Connection:
    def __init__(self, username, ip, date_logged_in, date_logged_out, isakmp_spi, ipsec_spi):
        self.username=username
        self.ip = ip
        self.date_logged_in=date_logged_in
        self.date_logged_out=date_logged_out
        self.isakmp_spi=isakmp_spi
        self.ipsec_spi=ipsec_spi

def main():
    user_file = sys.argv[1]
    logfile = open_file(user_file)
    filtered_lines = filter_logfile(logfile) 
    connections = get_connections(filtered_lines)
    prettify_and_print(connections)

def open_file(user_file):
    """ validate user inputed file """
    try:
        logfile = open (user_file, 'r')
    except IOError:
        raise
    return logfile

def filter_logfile(logfile):
    """ get only the lines about connects and disconnects """
    filtered_lines = []
    for logline in logfile.readlines():
        for logtext in LOG_TEXTS:
            if logtext in logline: 
                #debugging(logline)
                filtered_lines.append(logline)
                break
    return filtered_lines

def get_connections(filtered_lines):
    """ parse log file and create connection objects with usernames and connection times """
    is_ISAKMP = False
    has_connected = False
    open_connections = []
    closed_connections = []
    new_connection = Connection(None, None, None, None, None, None)
    for logline in filtered_lines:
        if ("ISAKMP-SA established" in logline):
            new_connection = Connection(None, None, None, None, None, None)
            # could be a client connection
            is_ISAKMP = True
            has_connected = False
            new_connection.ip=get_isakmp_ip(logline)
            new_connection.date_logged_in=get_date(logline)
            new_connection.isakmp_spi=get_isakmp_spi(logline)
        elif ("login succeeded" in logline) or ("authenticated" in logline):
            debugging(logline)
            username=get_username(logline)
            if is_ISAKMP:
                new_connection.username=username
                #connections = []
                #connections.append(new_connection)
                #prettify_and_print(connections)
            else:
                new_connection = Connection(username, None, None, None, None, None)
            is_ISAKMP = False
            has_connected=True
        elif ("IPsec-SA established" in logline):
            is_ISAKMP = False
            if has_connected:
                new_connection.ipsec_spi=get_ipsec_spi(logline)
                new_connection.ip=get_ipsec_ip(logline)
                if not new_connection.date_logged_in:
                    new_connection.date_logged_in=get_date(logline)
                    new_connection.isakmp_spi = None
            has_connected = False
        elif ("deleted" in logline) or ("purged" in logline):
            is_ISAKMP = False
            has_connected = False
            if new_connection.username and (new_connection.isakmp_spi or new_connection.ipsec_spi):
                open_connections.append(new_connection)
            if open_connections:
                for connection in open_connections:
                    closed_connection = get_closed_connection(connection, logline)
                    new_connection = Connection(None, None, None, None, None, None)
                    if closed_connection.date_logged_out and closed_connection.username:
                        closed_connections.append(closed_connection)
                        open_connections.remove(closed_connection)
                        break;
        else:
            has_connected = False
            is_ISAKMP = False
    all_connections = []
    all_connections = add_connections(all_connections, open_connections)
    all_connections = add_connections(all_connections, closed_connections)
    debugging("open connections")
    #prettify_and_print(open_connections)
    debugging("closed connections")
    #prettify_and_print(closed_connections)
    return all_connections

def get_closed_connection(connection, logline):
    """ Compare both spi's to know if this connection closes """
    logout_date=get_date(logline)
    ipsec_spi = None
    debugging("*****\nisa: " + str(connection.isakmp_spi))
    debugging("username: " + str(connection.username))
    debugging("log: " + logline + "*****")
    if (str(connection.isakmp_spi) in logline) or (str(connection.ipsec_spi) in logline):
        debugging("isa: "+ str(connection.isakmp_spi)+" // ipsec: "+ str(connection.ipsec_spi) + " // "+ logline)
        connection.date_logged_out = logout_date
    return connection

def add_connections(destination_connections, source_connections):
    for connection in source_connections:
        destination_connections.append(connection)
    return destination_connections

def get_isakmp_ip(logline):
    ip_ini = str.find(logline, "]-", 0, len(logline))
    ip_ini = ip_ini + 2 
    ip_end = str.find(logline, "[", ip_ini, len(logline))
    ip = logline[ip_ini:ip_end]
    return ip

def get_ipsec_ip(logline):
    ip_ini = str.find(logline, ">", 0, len(logline))
    ip_ini = ip_ini + 1 
    ip_end = str.find(logline, "[", ip_ini, len(logline))
    ip = logline[ip_ini:ip_end]
    return ip

def get_date(logline):
    date = logline[0:16]
    return date

def get_isakmp_spi(logline):
    spi_ini = str.find(logline, "spi", 0, len(logline))
    spi_ini = spi_ini + 4 
    spi_end = len(logline)-1
    isakmp_spi = logline[spi_ini:spi_end]
    return isakmp_spi

def get_username(logline):
    user_ini = str.find(logline, "user", 0, len(logline))
    user_ini = user_ini + 6 
    if ("authenticated" in logline):
        user_end = str.find(logline, "'", user_ini, len(logline))
    else:# "succeeded"
        user_end = str.find(logline, "\"", user_ini, len(logline))
    username = logline[user_ini:user_end]
    return username

def get_ipsec_spi(logline):
    spi_ini = str.find(logline, "spi=", 0, len(logline))
    spi_ini = spi_ini + 4 
    spi_end = str.find(logline, "(", spi_ini, len(logline))
    ipsec_spi = logline[spi_ini:spi_end]
    return ipsec_spi


def prettify_and_print(connections):
    """ print connections made by users """
    for connection in connections:
        print "----------\n", connection.username, "\n", connection.ip, "\n", connection.date_logged_in, "\n", connection.date_logged_out

def debugging(message):
    if is_debug:
        print message

if __name__ == "__main__":
    main()
