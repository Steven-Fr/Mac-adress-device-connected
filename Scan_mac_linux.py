import networkscan
from getmac import get_mac_address as gma
import socket
import netifaces
from netifaces import interfaces, ifaddresses, AF_INET
import tkinter as tk
import tkinter.ttk as ttk
from threading import Thread
import sys
import time
from queue import Queue
import subprocess

running = True

def read_mac(threadname):
    global running

    #lettura ip salvati nel pc ivp4
    list_ip = []
    #list_ip.append('192.168.11.0/24')

    for iface in netifaces.interfaces():
        iface_details = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in iface_details:
            for ip_interfaces in iface_details[netifaces.AF_INET]:
                for key, ip_add in ip_interfaces.items():
                    if key == 'addr' and ip_add != '127.0.0.1':
                        ipfind = ip_add
                        ipfind = '.'.join(ipfind.split('.')[:-1]) + '.0'
                        ipfind = (ipfind + '/24')
                        list_ip.append(ipfind)

    list_machine = []
    for l in list_ip:
        my_network = l

        my_scan = networkscan.Networkscan(my_network)

        my_scan.run()

        for i in my_scan.list_of_hosts_found:
            try:
                tipo = gma(ip=i, network_request=True)
                print(i)
                tipo2 = tipo[:-9]
                nbtscan = subprocess.check_output(["nbtscan","-e", i]).decode("utf8")
                if nbtscan == '':
                    name = "None"
                else:
                    name = nbtscan.split('\t')[1].strip()
                if tipo2 == '20:87:56':
                    mach_siem =('Machine: Siemens' + '\tip: ' + i + '\tMAC: ' + gma(ip=i, network_request=True) + '\tName: ' + name)
                    list_machine.append(mach_siem)
                elif tipo2 == '00:a0:cd' :
                    mach_heid = ('Machine: Heidenhain' + '\tip: ' + i + '\tMAC: ' + gma(ip=i, network_request=True) + '\tName: ' + name)
                    list_machine.append(mach_heid)
                else:
                    pass
            except:
                pass
    #salvo la lista in un file
    f = open("scan_mac.txt", "w")
    for element in list_machine:
        f.write(element + "\n")
    running = False

def popup(pippo):
    global running
    count = 0
    window = tk.Tk(className='mytk')
    window.title('Dronex')
    window.geometry('220x70+400+300')
    label = tk.Label(window, text= "Wait searching in progress...")

    label.grid(row=0,column=0, padx = 5, pady = 5)

    while True:
        time.sleep(0.05)
        count = count  +1
        process_bar = ttk.Progressbar(window, orient="horizontal", length=200, mode="indeterminate")
        process_bar.grid(row=1,column=0, padx = 6, pady = 5)
        process_bar['value'] = count
        window.update()
        if count > 200:
            count = 0
        if running == False:
            break

thread1 = Thread( target=read_mac, args=("Thread-1",) )
thread2 = Thread( target=popup, args=("Thread-2",) )
thread1.start()
thread2.start()
thread1.join()
thread2.join()

