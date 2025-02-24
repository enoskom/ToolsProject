import socket
import ssl
import requests
from tkinter import font
import tkinter as tk
import netifaces
import subprocess
import ipaddress
import threading
import whois

# Ana pencereyi oluşturma
root = tk.Tk()
root.title("IP & Web Insights")  
root.geometry("1000x930")  
root.config(bg="black")  

# Ekran kenarlıklarını kalın yapmak için
root.tk_setPalette(background="black") 
root.configure(highlightthickness=5, highlightbackground="green")

# ASCII Art ENOSKOM
ENOSKOM_ASCII = """ 
 _____ _   _  ___  ____  _  _____  __  __ 
| ____| \ | |/ _ \/ ___|| |/ / _ \|  \/  |
|  _| |  \| | | | \___ \| ' / | | | |\/| |
| |___| |\  | |_| |___) | . \ |_| | |  | |
|_____|_| \_|\___/|____/|_|\_\___/|_|  |_|
"""

# ASCII Art ENOSKOM1
ENOSKOM1_ASCII = """ 
 _____ _   _  ___  ____  _  _____  __  __ 
| ____| \ | |/ _ \/ ___|| |/ / _ \|  \/  |
|  _| |  \| | | | \___ \| ' / | | | |\/| |
| |___| |\  | |_| |___) | . \ |_| | |  | |
|_____|_| \_|\___/|____/|_|\_\___/|_|  |_|
"""

# ASCII Art yazısını Tkinter'e yerleştirme
ascii_font = font.Font(family="Courier", size=18, weight="bold")
ascii_label = tk.Label(root, text=ENOSKOM_ASCII, font=ascii_font, fg="#00FF00", bg="black", justify="center")
ascii_label.pack(pady=12) 

# IP & Web Insights hakkında açıklama yazısı
info_text = """
IP & Web Insights, internet üzerindeki 
IP adreslerini ve web trafiğini analiz 
etmek için geliştirilmiş bir uygulamadır.
"""

# Bilgi yazısını "Telegraph" benzeri bir font ile yerleştirme
info_font = font.Font(family="Courier", size=12, weight="normal")  
info_label = tk.Label(root, text=info_text, font=info_font, fg="white", bg="black", justify="center")
info_label.pack(pady=1) 

# Yükleniyor animasyonunu göstermek için etiket
loading_label = tk.Label(root, text="", font=("Courier", 14, "bold "), fg="green", bg="black")
loading_label.pack(pady=30)

# Yükleniyor animasyonu
def start_action():
    print(" Başla butonuna tıklandı !")
    
    # Başla butonuna basıldığında yükleniyor animasyonunu başlatma
    loading_label.config(text="Yükleniyor .") 
    animate_loading_text()

    # 2.5 saniye sonra mevcut sayfanın üzerine ENOSKOM1 ASCII sanatını gösterme
    root.after(2500, show_enoskom1)

# Yükleniyor animasyonu metni
def animate_loading_text(i=0):
    dots = "." * (i % 4)  
    loading_label.config(text="Yükleniyor" + dots)
    i += 1
    root.after(200, animate_loading_text, i)  

# Yükleniyor animasyonunu sonlandırma ve ENOSKOM1'yi gösterme
def show_enoskom1():
    # Mevcut tüm bileşenleri kaldırma
    for widget in root.winfo_children():
        widget.pack_forget()

    # ENOSKOM1 ASCII sanatını ekleme
    ascii_font = font.Font(family="Courier", size=4, weight="bold") 
    Enoskom1_label = tk.Label(root, text=ENOSKOM1_ASCII, font=ascii_font, fg="#00FF00", bg="black", justify="center")
    Enoskom1_label.pack(anchor="nw", padx=0.1, pady=0.1)

    # HUNTING TIME!!! yazısını ekleme
    label = tk.Label(root, text="HUNTING TIME!!!", font=("Creepster", 23, "bold"), bg="black", fg="#00FF00", relief="raised", bd=5, padx=20, pady=20, highlightthickness=2, highlightbackground="#00FF00", highlightcolor="#00FF00")
    label.pack(pady=20)

    # Hover açıklamaları için label
    hover_label = tk.Label(root, text="", font=("Helvetica", 12), fg="gray", bg="black")
    hover_label.pack(pady=5)

    # Metin girdi kutusu
    entry = tk.Entry(root, width=40, font=("Helvetica", 15), bg="white", fg="black", bd=3)
    entry.pack(pady=5)

    # Port tarayıcı fonksiyonu
    def port_scan():
        ip_address = entry.get().strip()  
        if not ip_address:  
            result_text.config(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Lütfen bir IP adresi girin.")
            result_text.config(state=tk.DISABLED)
            return

        open_ports = []
        port_range = range(1, 1025)  

        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"{ip_address} için açık portlar:\n")

        for port in port_range:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip_address, port)) == 0: 
                    open_ports.append(port)
                    result_text.insert(tk.END, f"Açık Port: {port}\n")

        if not open_ports:
            result_text.insert(tk.END, "Açık port bulunamadı.")
        
        result_text.config(state=tk.DISABLED)

    # Butonlar için işlem yapma
    def get_public_ip():
        public_ip = requests.get('https://api.ipify.org').text
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Public IP: {public_ip}")
        result_text.config(state=tk.DISABLED)

    def get_private_ip():
        interfaces = netifaces.interfaces()
        private_ip = None  
        for interface in interfaces:
            try:
                # IPv4 adresini alma
                ip_info = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                for addr in ip_info:
                    ip = addr['addr']
                    if not ip.startswith('127. '):  #
                        private_ip = ip
                        break  
            except (KeyError, IndexError):
                continue  

        # Sonuç metnini güncelleme
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        if private_ip:
            result_text.insert(tk.END, f"Private IP: {private_ip}")
        else:
            result_text.insert(tk.END, "Private IP bulunamadı.")
        result_text.config(state=tk.DISABLED)

    def get_ip_location():
        ip_address = entry.get().strip()  
        if not ip_address:  
            public_ip = requests.get('https://api.ipify.org').text
            ip_address = public_ip  

        try:
            # ip info.io API'si ile IP location bilgilerini alma
            response = requests.get(f"https://ipinfo.io/{ip_address}/json")
            data = response.json()

            # IP'nin bilgilerini alma
            country = data.get("country", "Bilinmiyor")
            city = data.get("city", "Bilinmiyor")
            region = data.get("region", "Bilinmiyor")
            loc = data.get("loc", "Bilinmiyor").split(",") 
            latitude = loc[0] if len(loc) > 0 else "Bilinmiyor"
            longitude = loc[1] if len(loc) > 1 else "Bilinmiyor"
            isp = data.get("org", "Bilinmiyor")  
            timezone = data.get("timezone", "Bilinmiyor")

            # Bağlantı türü ve anonimleşme durumu
            is_anonymous = "Hayır"
            if "VPN" in isp or "Proxy" in isp:
                is_anonymous = "Evet"

            # Sonuç metnini formatlı bir şekilde oluşturma
            result = (
                f"Ülke: {country}\nŞehir: {city}\nBölge: {region}\nEnlem: {latitude}\n"
                f"Boylam: {longitude}\nISP: {isp}\nZaman Dilimi: {timezone}\n"
                f"Anonimleşme Durumu: {is_anonymous}"
            )
        except Exception as e:
            result = "IP Location alınamadı. Hata: " + str(e)
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
        result_text.config(state=tk.DISABLED)

    def scan_local_network():
        private_ip = None
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            try:
                ip_info = netifaces.ifaddresses(interface)[netifaces.AF_INET]
                for addr in ip_info:
                    ip = addr['addr']
                    if not ip.startswith('127.'):
                        private_ip = ip
                        break
            except (KeyError, IndexError):
                continue

        if private_ip:
            # IP adresini al ve ağ maskesini belirleme
            subnet = ipaddress.ip_network(private_ip + '/24', strict=False)

            # Aktif IP'leri bulmak için ping atma
            active_ips = []
            def ping_ip(ip):
                try:
                    output = subprocess.check_output(['ping', '-c', '1', str(ip)], stderr=subprocess.STDOUT)
                    active_ips.append(str(ip))
                except subprocess.CalledProcessError:
                    pass

            threads = []
            for ip in subnet.hosts():
                thread = threading.Thread(target=ping_ip, args=(ip,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            result_text.config(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            if active_ips:
                result_text.insert(tk.END, "Ağdaki Aktif Cihazlar:\n" + "\n".join(active_ips))
            else:
                result_text.insert(tk.END, "Ağda aktif cihaz bulunamadı.")
            result_text.config(state=tk.DISABLED)

    def ip_resolve():
        hostname = entry.get().strip()
        if hostname:
            try:
                ip_address = socket.gethostbyname(hostname)
                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"{hostname} için IP adresi: {ip_address}")
                result_text.config(state=tk.DISABLED)
            except socket.gaierror:
                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"{hostname} için IP adresi bulunamadı.")
                result_text.config(state=tk.DISABLED)
        else:
            result_text.config(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Lütfen bir hostname girin.")
            result_text.config(state=tk.DISABLED)

    def dns_resolve():
        ip_address = entry.get().strip()
        if ip_address:
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"{ip_address} için hostname: {hostname}")
                result_text.config(state=tk.DISABLED)
            except socket.herror:
                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"{ip_address} için hostname bulunamadı.")
                result_text.config(state=tk.DISABLED)
        else:
            result_text.config(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Lütfen bir IP adresi girin.")
            result_text.config(state=tk.DISABLED)

    def dns_all():
        hostname = entry.get().strip()
        if hostname:
            try:
                addresses = socket.getaddrinfo(hostname, None)  
                unique_ips = set() 

                for addr in addresses:
                    ip = addr[4][0] 
                    unique_ips.add(ip) 

                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"{hostname} için IP adresleri:\n" + "\n".join(unique_ips))
                result_text.config(state=tk.DISABLED)
            except socket.gaierror:
                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"{hostname} için IP adresleri bulunamadı.")
                result_text.config(state=tk.DISABLED)
        else:
            result_text.config(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Lütfen bir hostname girin.")
            result_text.config(state=tk.DISABLED)

    def whois_query():
        domain = entry.get().strip()
        if domain:
            try:
                w = whois.whois(domain)
                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"{domain} için WHOIS bilgileri:\n")
                for key, value in w.items():
                    result_text.insert(tk.END, f"{key}: {value}\n")
                result_text.config(state=tk.DISABLED)
            except Exception as e:
                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"WHOIS sorgusu yapılamadı. Hata: {str(e)}")
                result_text.config(state=tk.DISABLED)
        else:
            result_text.config(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Lütfen bir alan adı girin.")
            result_text.config(state=tk.DISABLED)

    def ssl_check():
        domain = entry.get().strip()
        if domain:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        result_text.config(state=tk.NORMAL)
                        result_text.delete(1.0, tk.END)
                        result_text.insert(tk.END, f"{domain} için SSL Sertifikası:\n")
                        for key, value in cert.items():
                            result_text.insert(tk.END, f"{key}: {value}\n")
                        result_text.config(state=tk.DISABLED)
            except Exception as e:
                result_text.config(state=tk.NORMAL)
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"SSL kontrolü yapılamadı. Hata: {str(e)}")
                result_text.config(state=tk.DISABLED)
        else:
            result_text.config(state=tk.NORMAL)
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Lütfen bir alan adı girin.")
            result_text.config(state=tk.DISABLED)

    # Butonlar için bir Frame oluşturma
    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)

    # IP butonları
    public_ip_button = tk.Button(button_frame, text="PUBLIC", font=("Helvetica", 15), bg="green", fg="white", width=9, command=get_public_ip)
    public_ip_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")  

    ip_resolve_button = tk.Button(button_frame, text="FIND IP", font=("Helvetica", 15), bg="green", fg="white", width=9, command=ip_resolve)
    ip_resolve_button.grid(row=0, column=1, padx=5, pady=5, sticky="w")  

    dns_resolve_button = tk.Button(button_frame, text="FIND DNS ", font=("Helvetica", 15), bg="green", fg="white", width=9, command=dns_resolve)
    dns_resolve_button.grid(row=0, column=2, padx=5, pady=5, sticky="w")  

    dns_all_button = tk.Button(button_frame, text="DNS ALL", font=("Helvetica", 15), bg="green", fg="white", width=9, command=dns_all)
    dns_all_button.grid(row=1, column=1, padx=5, pady=5, sticky="w") 

    whois_button = tk.Button(button_frame, text="WHOIS", font=("Helvetica", 15), bg="green", fg="white", width=9, command=whois_query)
    whois_button.grid(row=1, column=2, padx=5, pady=5, sticky="w")

    ssl_button = tk.Button(button_frame, text="SSL", font=("Helvetica", 15), bg="green", fg="white", width=9, command=ssl_check)
    ssl_button.grid(row=2, column=1, padx=5, pady=5, sticky="w") 

    private_ip_button = tk.Button(button_frame, text="PRIVATE", font=("Helvetica", 15), bg="green", fg="white", width=9, command=get_private_ip)
    private_ip_button.grid(row=1, column=0, padx=5, pady=5, sticky="w")

    ip_location_button = tk.Button(button_frame, text="IP GEO", font=("Helvetica", 15), bg="green", fg="white", width=9, command=get_ip_location)
    ip_location_button.grid(row=2, column=0, padx=5, pady=5, sticky="w")

    local_ips_button = tk.Button(button_frame, text="LOCAL", font=("Helvetica", 15), bg="green", fg="white", width=9, command=scan_local_network)
    local_ips_button.grid(row=3, column=0, padx=5, pady=5, sticky="w") 

    port_scan_button = tk.Button(button_frame, text="PORTSCAN", font=("Helvetica", 15), bg="green", fg="white", width=9, command=port_scan)
    port_scan_button.grid(row=2, column=2, padx=5, pady=5, sticky="w")

    # TEMİZLE butonu
    clear_button = tk.Button(button_frame, text="TEMİZLE", font=("Helvetica", 15), bg="blue", fg="white", width=9, command=lambda: result_text.config(state=tk.NORMAL) or result_text.delete(1.0, tk.END) or result_text.config(state=tk.DISABLED))
    clear_button.grid(row=3, column=2, padx=5, pady=5, sticky="w")

    # Hover efekti eklemek
    def on_hover(event):
        event.widget.config(bg="red", fg="white")
        if event.widget == public_ip_button:
            hover_label.config(text="Public IP'nizi alır.")
        elif event.widget == private_ip_button:
            hover_label.config(text ="Private IP'nizi alır.")
        elif event.widget == ip_location_button:
            hover_label.config(text="IP'nin lokasyon bilgisini gösterir. Örn:192.168.1.1")
        elif event.widget == local_ips_button:
            hover_label.config(text="Yerel ağdaki aktif cihazları tarar.")
        elif event.widget == ip_resolve_button:
            hover_label.config(text="Hostname için IP adresi çözer. Örn: example.com")
        elif event.widget == dns_resolve_button:
            hover_label.config(text="IP adresi için hostname çözer. Örn: 192.168.1.1")
        elif event.widget == dns_all_button:
            hover_label.config(text="Web sitesinin tüm IP adreslerini bulur. Örn: www.example.com")
        elif event.widget == whois_button:
            hover_label.config(text="Alan adı için WHOIS sorgusu yapar. Örn: www.example.com")
        elif event.widget == ssl_button:
            hover_label.config(text="Alan adı için SSL sertifikasını kontrol eder. Örn: www.example.com")
        elif event.widget == port_scan_button:
            hover_label.config(text="Belirtilen IP adresindeki açık portları tarar(1-1024). Örn: 192.168.1.1")

    def on_leave(event):
        event.widget.config(bg="green", fg="white")
        hover_label.config(text="")  

    # Hover event'lerini butonlara ekleme
    public_ip_button.bind("<Enter>", on_hover)
    public_ip_button.bind("<Leave>", on_leave)

    private_ip_button.bind("<Enter>", on_hover)
    private_ip_button.bind("<Leave>", on_leave)

    ip_location_button.bind("<Enter>", on_hover)
    ip_location_button.bind("<Leave>", on_leave)

    local_ips_button.bind("<Enter>", on_hover)
    local_ips_button.bind("<Leave>", on_leave)

    ip_resolve_button.bind("<Enter>", on_hover)
    ip_resolve_button.bind("<Leave>", on_leave)

    dns_resolve_button.bind("<Enter>", on_hover)
    dns_resolve_button.bind("<Leave>", on_leave)

    dns_all_button.bind("<Enter>", on_hover)
    dns_all_button.bind("<Leave>", on_leave)

    whois_button.bind("<Enter>", on_hover)
    whois_button.bind("<Leave>", on_leave)

    ssl_button.bind("<Enter>", on_hover)
    ssl_button.bind("<Leave>", on_leave)

    port_scan_button.bind("<Enter>", on_hover)
    port_scan_button.bind("<Leave>", on_leave)

    # Sonuç metni için metin kutusu
    result_text = tk.Text(root, height=9, width=60, font=("Courier New", 12), fg="#FF0000", bg="#ffffff")
    result_text.pack(pady=5)

    # Yazma modunu sadece okuma
    result_text.config(state=tk.DISABLED)

    # ÇIKIŞ butonu
    close_button_result = tk.Button(root, text="ÇIKIŞ", font=("Helvetica", 10), bg="blue", fg="white", command=root.quit)
    close_button_result.pack(pady=5)

# Başla butonu
start_button = tk.Button(root, text="Başla", font=("Helvetica", 20), bg="green", fg="white", command=start_action)
start_button.pack(pady=10) 

# Kapat butonu
close_button = tk.Button(root, text="Kapat", font=("Helvetica", 10), bg="red", fg="white", command=root.quit)
close_button.pack(pady=5)  

# Sürüm bilgisi
version_text = "Version: 1.0.0" 

# Sürüm bilgisini sağ alt köşeye yerleştirme
version_label = tk.Label(root, text=version_text, font=("Helvetica", 8 ), fg="gray", bg="black", anchor="se")
version_label.place(relx=1.0, rely=1.0, x=-10, y=-10, anchor="se")

# Pencereyi ekranın ortasında tutmak için fonksiyon
def center_window():
    window_width = 1000
    window_height = 930
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")

# Uygulama açıldığında pencereyi ortala
center_window()

# Tkinter uygulamasını çalıştırma
root.mainloop()