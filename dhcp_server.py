from socket import *
import sys
import sqlite3
import binascii
import time


def db_create():  # creates table if not exsists
    query('''CREATE TABLE if not exists "dhcplist" (
	"id"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	"mac"	TEXT UNIQUE,
	"ip"	TEXT UNIQUE,
	"up_time" timestamp,
	"start_time" timestamp);''')


def query(sql):
    with sqlite3.connect("dhcplist.sqlite") as conn:
        cur = conn.execute(sql)
        conn.commit()
    return cur.fetchall()


def newmac(mac_add):
    res = query('select id,ip,start_time from dhcplist order by ip;'.format(mac_add))
    if res:
        iplist = []
        for i in res:
            iplist.append(int(i[1].split(".5.", 3)[1]))
        iplist.sort()
        i = 0
        d = 0
        while i <= (len(iplist)):
            if d == 0:
                d = 2
            else:
                try:
                    if d == (iplist[i]):
                        d += 1
                        i += 1
                    else:
                        i = i + 1
                        break
                except IndexError:
                    i += 1
                    pass
        query('insert into dhcplist (mac,ip,start_time,up_time) values ("{}","{}{}",{},"{}");'.format(mac_add, addr, str(d), time.time(), time.asctime(time.localtime(time.time()))))
        return "{}{}".format(addr, str(d))
    else:
        query('insert into dhcplist (mac,ip,start_time,up_time) values ("{}","{}2",{},"{}");'.format(mac_add, addr, time.time(), time.asctime(time.localtime(time.time()))))
        return "{}2".format(addr)


def check_db(mac_add):
    res = query('select id,ip,start_time from dhcplist where mac like "{}";'.format(mac_add))
    if res:
        query('update dhcplist set start_time = {} where mac like "{}" ;'.format(time.time(), mac_add))
        return res[0][1]
    else:
        return newmac(mac_add)


def update_leases():
    query('delete from dhcplist where ({}-start_time) > {};'.format(time.time(), leasesecs_time))


def send_message(newmessage, address):
    try:
        newmessage = binascii.unhexlify(newmessage)
        socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        socket.sendto(newmessage, (address, 68))
        print("message sent", address, ":68")
    except OSError:
        print("error sending message")
        pass


def check_message(message):
    discoverflag = binascii.hexlify(message[240:243]).decode()  # discover 01 offer 03
    if discoverflag == "350101":
        print("catched discover packet from mac address:", mac_add(message[28:34]))
        newip = check_db(mac_add(message[28:34]))
        offer = makepacket(message[28:34], newip, message[4:8], "offer")
        print("generating offer message to :", mac_add(message[28:34]))
        send_message(offer, "255.255.255.255")
    elif discoverflag == "350102":
        print("catched offer packet:")
    elif discoverflag == "350103":
        print("catched request packet:")
        newip = check_db(mac_add(message[28:34]))
        ack = makepacket(message[28:34], newip, message[4:8], "ack")
        print("generating ack massage:")
        send_message(ack, "255.255.255.255")
    # show_table()


def mac_add(add):
    mac = binascii.hexlify(add).decode()
    mac = (mac[0:2] + '-' + mac[2:4] + '-' + mac[4:6] + '-' + mac[6:8] + '-' + mac[8:10] + '-' + mac[10:12])
    return mac.upper()


def makepacket(macaddress, address, tid, type):
    message1 = "02".encode()  # bootreply
    message1 += "01".encode()  # ethernet
    message1 += "06".encode()  # hardware length
    message1 += "00".encode()  # hops
    message1 += binascii.hexlify(tid)  # transactionid
    message1 += "0000".encode()  # seconds elpased
    message1 += "0000".encode()  # boot flags
    message1 += "00000000".encode()  # client ip address
    ip = address

    print("offered ip:", ip)
    message1 += binascii.hexlify(inet_aton(ip))  # offered ip address
    message1 += binascii.hexlify(inet_aton(ip))  # server ip address
    ip1 = "0.0.0.0"
    message1 += binascii.hexlify(inet_aton(ip1))  # relay ip address
    message1 += binascii.hexlify(macaddress)  # client mac address
    message1 += "00000000000000000000".encode()  # mac padding
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "00000000000000000000000000000000".encode()  # boot file
    message1 += "63825363".encode()  # magic cookie
    if type == "offer":
        message1 += "350102".encode()  # offer flag
    elif type == "ack":
        message1 += "350105".encode()  # offer flag
    message1 += "0104ffffff00".encode()  # calss c
    message1 += "0304".encode()  # router ip address option
    ip = routerip
    message1 += binascii.hexlify(inet_aton(ip))  # router ip address
    message1 += "0604".encode()  # domain option
    message1 += binascii.hexlify(inet_aton(ip))  # router ip address
    message1 += "3604".encode()  # dhcp server ip
    ip = routerip
    message1 += binascii.hexlify(inet_aton(ip))  # dhcp server
    lease = "{:06x}".format(leasesecs_time)
    if len(lease) == 4:
        message1 += ("33040000{}".format(lease)).encode()  # lease time
    elif len(lease) == 5:
        message1 += ("3304000{}".format(lease)).encode()  # lease time
    elif len(lease) == 6:
        message1 += ("330400{}".format(lease)).encode()  # lease time
    elif len(lease) == 7:
        message1 += ("33040{}".format(lease)).encode()  # lease time
    elif len(lease) == 8:
        message1 += ("3304{}".format(lease)).encode()  # lease time
    message1 += "ff".encode()  # end flag
    message1 += "00000000000000".encode()  # padding
    a = binascii.hexlify(message1).decode()
    return message1


def show_table():
    con = sqlite3.connect('dhcplist.sqlite')
    cursorObj = con.cursor()
    cursorObj.execute('SELECT mac, ip, up_time FROM dhcplist')
    rows = cursorObj.fetchall()
    formatted_row = '{:<17} | {:<13}| {:<25}|'
    print("\nOffers-list:")
    print(formatted_row.format("MAC-Address", "IP-Address", "Up-Time"))
    print("------------------------------------------------------------")
    for Row in rows:
        print(formatted_row.format(*Row))
    print("\n")


def listening_loop():
    update_leases()  # delete expired ip addresses
    message, address = socket.recvfrom(1024)  # receiving packets
    check_message(message)
    return address, "68".encode(), show_table()


if __name__ == "__main__":
    db_create()  # creates the database if not exists
    addr = "192.168.5."  # set the dhcp offer addresses
    routerip = "1".format(addr)  # router ip
    leasesecs_time = 300 # (5 minutes) insert here the lease time
    socket = socket(AF_INET, SOCK_DGRAM)
    try:
        socket.bind(("", 67))
        print("DHCP SERVER - Listening to port 67")
    except OSError:
        print("port 67 taken! close another program and run this program again")
        time.sleep(10)
        sys.exit(1)
    routerip = addr + routerip
    netmaskip = addr + "0"
    print("Netmask is: ", netmaskip)
    print("Router IP is: ", routerip)
    update_leases()
    show_table()
    while True:
        listening_loop()
