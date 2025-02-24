# ToolsProject
IP &amp; Web Insights

IP & Web Insights, IP adresleri, ağ taraması ve web trafiği analizine yönelik kapsamlı bir araçtır. Bu araç, IP adreslerinin yerini tespit etmenin, ağınızdaki açık portları kontrol etmenin ve web siteleri hakkında bilgi edinmenin basit bir yolunu sunar. Ayrıca, IP adresinin konumunu, DNS bilgilerini ve SSL sertifikasını sorgulamak gibi daha ileri düzey analizler de sağlar.
Özellikler

    Public ve Private IP adreslerini almak
    Yerel ağdaki aktif cihazları taramak
    IP adresi üzerinden lokasyon bilgisi almak
    Port taraması yapmak
    IP adresi ile hostname çözme ve tersi (hostname ile IP çözme)
    DNS sorguları ve tüm IP adreslerini bulma
    WHOIS sorgusu yapma
    SSL sertifikası kontrolü

Gereksinimler

    Python 3.7+
    Aşağıdaki Python kütüphaneleri:
        requests
        netifaces
        subprocess
        socket
        whois
        tkinter

Kurulum
1. Python Yüklemesi

Öncelikle Python 3.x sürümünü buradan indirip yükleyin.
2. Gerekli Bağımlılıkları Yükleyin

Aşağıdaki komutları kullanarak gerekli Python kütüphanelerini yükleyebilirsiniz:

pip install requests
pip install netifaces
pip install whois

3. Uygulamayı Çalıştırma

Projenin bulunduğu dizinde terminali açarak aşağıdaki komutu çalıştırabilirsiniz:

python app.py

Bu, GUI arayüzünü açacaktır ve artık IP & Web Insights aracını kullanmaya başlayabilirsiniz.
Kullanım

IP & Web Insights uygulamasının sunduğu bazı ana işlevler şunlardır:
1. Public IP: Public IP'nizi almak için "PUBLIC" butonuna tıklayın.
2. Private IP: Yerel ağınızdaki private IP adresini görmek için "PRIVATE" butonuna tıklayın.
3. IP Lokasyonu: IP'nin coğrafi lokasyon bilgilerini almak için "IP GEO" butonunu kullanabilirsiniz.
4. Port Scan: Belirli bir IP adresindeki açık portları taramak için "PORTSCAN" butonuna tıklayın.
5. Yerel Ağ Tarama: Yerel ağınızdaki aktif cihazları taramak için "LOCAL" butonuna tıklayın.
6. DNS ve IP Çözme:

    Bir domain ismi girerek IP adresini öğrenmek için "FIND IP" butonuna basın.
    Bir IP adresini girerek, o IP'nin bağlı olduğu hostname’i öğrenmek için "FIND DNS" butonuna basın.

7. DNS All: Bir domainin tüm IP adreslerini listelemek için "DNS ALL" butonuna basın.
8. WHOIS: Alan adı için WHOIS bilgilerini almak için "WHOIS" butonuna tıklayın.
9. SSL Sertifikası: Bir domainin SSL sertifikasını kontrol etmek için "SSL" butonuna tıklayın.
Katkı Sağlama

Eğer projeye katkı sağlamak isterseniz, lütfen şu adımları izleyin:

    Bu depoyu çatallayın (fork).
    Değişikliklerinizi yeni bir dalda yapın (git checkout -b feature-xyz).
    Yaptığınız değişiklikleri commit edin (git commit -am 'Add new feature').
    Dalınızı remote depoya push edin (git push origin feature-xyz).
    Bir pull request açın.
