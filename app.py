
from flask import Flask, render_template, request, redirect, url_for
from scapy.all import rdpcap,Ether,IP,TCP,ARP
import os
from collections import Counter


app=Flask(__name__)
UPLOAD_FOLDER='uploads'
app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER

def analyze_pcap(pcapng_file):
    mac_addresses=set()
    ip_addresses=set()
    port_control={}

    arp_cache={}
    arp_anomalies=set()
    ip_counter=Counter()
    ip_mac_map={}

    packets=rdpcap(pcapng_file)

    for packet in packets:
        if packet.haslayer(Ether):
            mac_addresses.add(packet[Ether].src)
            mac_addresses.add(packet[Ether].dst)

        if packet.haslayer(IP):
            ip_src=packet[IP].src
            ip_dst=packet[IP].dst
            ip_addresses.add(ip_src)
            ip_addresses.add(ip_dst)
            ip_counter[ip_src]+=1

            if packet.haslayer(Ether):
                ip_mac_map[ip_src]=packet[Ether].src
                ip_mac_map[ip_dst]=packet[Ether].dst

        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip=packet[IP].src
            dst=packet[IP].dst
            ip_addresses.add(packet[IP].src)
            ip_addresses.add(packet[IP].dst)
            port=packet[TCP].dport
                
            if ip not in port_control:
                port_control[ip]={'targets':{},'total_ports':0}

            if dst not in port_control[ip]['targets']:
                port_control[ip]['targets'][dst]=set()
            port_control[ip]['targets'][dst].add(port)
            port_control[ip]['total_ports']+=1

               
        
        if packet.haslayer(ARP):
            if packet[ARP].op==2:
                sender_ip=packet[ARP].psrc
                sender_mac=packet[ARP].hwsrc

                if sender_ip in arp_cache and arp_cache[sender_ip]!=sender_mac:
                    anomaly_detail=f"ARP Zehirlenmesı Potansıyleı: IP {sender_ip} daha önce MAC {arp_cache[sender_ip]} ile ilişkilendirilirken, şimdi MAC {sender_mac} ile görüldü. (Paket Numarası: {packets.index(packet) + 1})"
                    arp_anomalies.add(anomaly_detail)
                else:
                    arp_cache[sender_ip]=sender_mac

    return{
        "macs":sorted(mac_addresses),
        "ips":sorted(ip_addresses),
        "ip_mac_map":ip_mac_map,
        "port_scans":{k: v for k, v in port_control.items() if any(len(p)>10 for p in v['targets'].values())},
        "arp_anomalies":list(arp_anomalies),
        "heavy_traffic":{ip: count for ip,count in ip_counter.items() if count>1000}
    }


@app.route('/',methods=['GET','POST'])
def index():
    if request.method=='POST':
        file=request.files['pcapng']
        if file:
            path=os.path.join(app.config['UPLOAD_FOLDER'],file.filename)
            file.save(path)
            results=analyze_pcap(path)
            return render_template('index.html',results=results)
    return render_template('index.html')

if __name__=='__main__':
    os.makedirs(UPLOAD_FOLDER,exist_ok=True)
    app.run(debug=True)