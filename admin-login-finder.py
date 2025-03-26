#!/usr/bin/env python3
import urllib.request
import urllib.error
import argparse
import concurrent.futures
import colorama
from colorama import Fore, Style
import sys
import time
from urllib.parse import urlparse

colorama.init(autoreset=True)

class AdminFinder:
    def __init__(self, url, threads=10, timeout=3, wordlist=None, user_agents_file=None):
        self.url = self._format_url(url)
        self.threads = threads
        self.timeout = timeout
        self.found = []
        self.total = 0
        self.checked = 0
        self.wordlist = wordlist
        self.user_agents_file = user_agents_file
        self.user_agents = self._load_user_agents()

    def _format_url(self, url):
        """URL'yi doğru formata getirir"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # URL sonunda / yoksa ekle
        if not url.endswith('/'):
            url += '/'
            
        return url
    
    def _get_paths(self):
        """Admin paneli yollarını döndürür"""
        if self.wordlist:
            try:
                with open(self.wordlist, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{Fore.RED}Hata: {self.wordlist} dosyası bulunamadı.")
                sys.exit(1)
        else:
            # Geliştirilmiş ve genişletilmiş admin yolları listesi
            return [
                # Genel admin panelleri
                'admin/', 'admin/login', 'admin/login.php', 'wp-admin/', 'login.php', 
                'administrator/', 'admin/account.php', 'adminpanel/', 'cpanel/', 
                'login/', 'wp-login.php', 'administrator/index.php', 'admin/index.php',
                'panel/', 'admin1/', 'admin2/', 'admin.php', 'admin.html',
                'adminLogin/', 'admin_area/', 'panel-administracion/', 'instadmin/',
                'memberadmin/', 'administratorlogin/', 'adm/', 'account.asp', 
                'admin/account.asp', 'admin/index.asp', 'admin/login.asp', 'admin/admin.asp',
                
                # CMS'e özel yollar
                # WordPress
                'wp-admin/', 'wp-login.php', 'wordpress/wp-admin/', 'wp/wp-admin/',
                'wp-admin/admin.php', 'wp-admin/index.php', 'wp-admin/login.php',
                
                # Joomla
                'administrator/', 'administrator/index.php', 'administrator/login.php',
                'joomla/administrator/', 'joomla/administrator/index.php',
                
                # Drupal
                'user/login', 'admin/user/login', 'user', 'user/admin', 'admin/user',
                
                # Magento
                'admin/', 'magento/admin/', 'admin/index.php', 'admin/dashboard/',
                
                # PrestaShop
                'adminpanel/', 'admin123/', 'admin-panel/', 'prestashop/admin/',
                
                # OpenCart
                'admin/', 'opencart/admin/', 'administration/',
                
                # Diğer web tabanlı paneller
                'phpmyadmin/', 'phpmyadmin/index.php', 'phpMyAdmin/', 'phpMyAdmin/index.php',
                'webmail/', 'mail/', 'cpanel/', 'cp/', 'webmin/', 'plesk/',
                'clients/', 'client/', 'portal/', 'members/', 'member/',
                'control/', 'controlpanel/', 'my-account/', 'myaccount/',
                
                # Sunucu yönetim panelleri
                'whm/', 'myadmin/', 'server/', 'server-status/', 'server-info/',
                'status/', 'info/', 'cpanel/', 'whm-server-status/', 'plesk-stat/',
                'webmin/', 'virtualmin/', 'usermin/', 'cloudmin/',
                
                # Dosya yöneticileri
                'filemanager/', 'file-manager/', 'fm/', 'files/', 'file/',
                'uploads/', 'upload/', 'manager/', 'manage/', 'mgr/',
                
                # Popüler uygulamalar
                'roundcube/', 'roundcube/index.php', 'webmail/roundcube/',
                'horde/', 'squirrelmail/', 'phpinfo.php', 'apc.php', 'info.php',
                
                # Arayüz girişleri
                'signin/', 'sign-in/', 'sign_in/', 'sign-in.php', 'login.asp',
                'login.html', 'login.htm', 'login/', 'logon/', 'logon.php',
                'logon.asp', 'logon.html', 'signin.php', 'signin.html', 'signin.asp',
                
                # Türkçe ve diğer diller
                'giris/', 'giris.php', 'yonetim/', 'yonetim.php', 'kontrol/',
                'kontrol.php', 'panel/', 'panel.php', 'paneladmin/', 'adminpanel/',
                'uye/', 'uye/giris', 'uye/giris.php', 'kullanici/', 'kullanici/giris',
                
                # E-ticaret sistemleri
                'sysadmin/', 'sysadm/', 'sys/', 'control/admin/', 'control/login/',
                'shop/admin/', 'shop/admin/login', 'shopping/admin/', 'sale/admin/',
                'store/admin/', 'store/login/', 'ecommerce/admin/',
                
                # Diğer yaygın yollar
                'backend/', 'back-end/', 'back/', 'config/', 'configuration/',
                'settings/', 'setting/', 'setup/', 'configure/', 'dashboard/',
                'dash/', 'moderator/', 'mod/', 'webmaster/', 'mods/', 'supervisor/',
                'support/', 'staff/', 'cp/', 'cms/', 'cms/login', 'cms/admin/',
                'cms/admin/login', 'console/', 'console/login', 'console/admin/',
                'adm/admloginuser.php', 'adm.php', 'affiliate.php', 'adm_auth.php',
                'memberadmin.php', 'administratorlogin.php', 'bb-admin/',
                'bb-admin/login.php', 'bb-admin/admin.php', 'bb-admin/admin.html',
                'administrator/account.php', 'relogin.php', 'relogin.html',
                'check.php', 'relogin.htm', 'blog/wp-login.php', 'user.php',
                'user.html', 'admin/user.php', 'admin/user.html', 'yonetici.php',
                'yonetici.html', 'yonet.php', 'yonet.html', 'moderator.php',
                'moderator.html', 'ADMIN/', 'panel-administracion/login.php',
                'pages/admin/', 'admincp/', 'admincp.php', 'admin/controlpanel.php',
                'adminpanel.html', 'webadmin.php', 'webadmin/index.php',
                'webadmin/login.php', 'user/admin.php', 'admin/admin_login.php',
                'admin_login.php', 'panel-administracion/login.php', 'adminLogin.php',
                'home.php', 'admin.php', 'admin/home.php', 'cp.php', 'cp.html',
                'ADMIN/login.php', 'ADMIN/login.html', 'adminitem/', 'adminitems/',
                'administrator/', 'administrator/login.html', 'administrator.html',
                'siteadmin.php', 'siteadmin.html', 'adminsite/', 'kpanel/',
                'vorod/', 'vorod.php', 'vorud/', 'vorud.php', 'adminpanel/',
                'PSUser/', 'secure/', 'webmaster/', 'webmaster/login.php',
                'autologin/', 'userlogin/', 'admin_area/', 'cmsadmin/'
            ]
    
    def _load_user_agents(self):
        """User agent listesini yükler"""
        default_agents = [
            # Windows Tarayıcıları
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
            "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
            # Mac Tarayıcıları
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0",
            # Mobil Tarayıcılar
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
            "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
            # Linux Tarayıcıları
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36"
        ]
        
        # paste.txt dosyasından ek user agent'ları ekle (varsa)
        try:
            if hasattr(self, 'user_agents_file') and self.user_agents_file:
                with open(self.user_agents_file, 'r') as f:
                    custom_agents = [line.strip() for line in f if line.strip()]
                    return default_agents + custom_agents
        except Exception:
            pass
            
        return default_agents
            
    def check_url(self, path):
        """Belirtilen yolu kontrol eder, geliştirilmiş tespit yöntemleriyle"""
        full_url = self.url + path
        try:
            import random
            request = urllib.request.Request(full_url)
            # Rastgele bir User-Agent seç
            user_agent = random.choice(self.user_agents)
            request.add_header('User-Agent', user_agent)
            request.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
            request.add_header('Accept-Language', 'en-US,en;q=0.5')
            
            # Referrer ekleyerek daha gerçekçi görünüm sağla
            request.add_header('Referer', self.url)
            
            # Cookie desteği ekle
            request.add_header('Cookie', 'session=test')
            
            response = urllib.request.urlopen(request, timeout=self.timeout)
            
            # Yanıt kodunu kontrol et
            status_code = response.getcode()
            
            # Yanıt içeriğini al (ilk 1024 byte)
            content = response.read(1024).decode('utf-8', errors='ignore')
            
            # Panel tespit belirteçleri
            admin_indicators = [
                'username', 'password', 'admin', 'login', 'sign in', 'signin',
                'usuario', 'contraseña', 'giriş', 'Вход', 'hasło',
                'dashboard', 'cpanel', 'control panel', 'yönetim', 'giris',
                'admin area', 'admin panel', 'administration', 'login form',
                'authentication', 'auth', 'authorize', 'member'
            ]
            
            # Admin başlık belirteçleri
            title_indicators = [
                '<title>admin</title>', '<title>login</title>', 
                '<title>panel</title>', '<title>cpanel</title>',
                '<title>control panel</title>', '<title>dashboard</title>',
                '<title>administrator</title>', '<title>backoffice</title>',
                '<title>yönetim</title>', '<title>yonetim</title>',
                '<title>giriş</title>', '<title>giris</title>'
            ]
            
            # İçerik türü kontrolü
            content_lower = content.lower()
            
            # Başarılı durum kodları (200, 201, 202...)
            if 200 <= status_code < 300:
                # İçerik kontrolü - belirteçler var mı?
                if any(indicator in content_lower for indicator in admin_indicators) or \
                any(indicator.lower() in content_lower for indicator in title_indicators):
                    self.found.append((full_url, "KESİN"))
                    print(f"{Fore.GREEN}[+] KESİN BULUNDU: {full_url} ({status_code}) - Admin panel içeriği tespit edildi!")
                else:
                    # <form> etiketi var mı?
                    if '<form' in content_lower and ('pass' in content_lower or 'user' in content_lower):
                        self.found.append((full_url, "MUHTEMEL"))
                        print(f"{Fore.BLUE}[+] MUHTEMEL BULUNDU: {full_url} ({status_code}) - Login form içeriyor")
                    else:
                        self.found.append((full_url, "ZAYIF"))
                        print(f"{Fore.CYAN}[+] MUHTEMEL PANEL: {full_url} ({status_code})")
            
            # Yönlendirme yanıtları
            elif status_code in [301, 302, 303, 307, 308]:
                redirect_url = response.headers.get('Location', '')
                if 'login' in redirect_url or 'admin' in redirect_url:
                    self.found.append((full_url, "YÖNLENDİRME"))
                    print(f"{Fore.YELLOW}[+] YÖNLENDİRME BULUNDU: {full_url} → {redirect_url}")
                
        except urllib.error.HTTPError as e:
            # 401 ve 403 kodları da ilginç olabilir (erişim engellendi ama sayfa var)
            if e.code in [401, 403]:
                self.found.append((full_url, "ERİŞİM ENGELLİ"))
                print(f"{Fore.YELLOW}[!] ERİŞİM ENGELLİ: {full_url} ({e.code}) - Giriş gerekebilir!")
                
                # Sayfanın varlığını doğrulamak için ek kontrol
                try:
                    # HEAD isteği gönder
                    head_request = urllib.request.Request(full_url, method='HEAD')
                    head_request.add_header('User-Agent', random.choice(self.user_agents))
                    urllib.request.urlopen(head_request, timeout=self.timeout)
                    print(f"{Fore.YELLOW}[!] Sayfa MEVCUT ancak erişim engellendi: {full_url}")
                except:
                    pass
            pass
        except Exception as e:
            # Bağlantı hataları için özel kontrol
            if isinstance(e, urllib.error.URLError) and "Connection refused" in str(e):
                # Firewall veya koruma olabilir - bu aslında iyi bir işaret
                print(f"{Fore.MAGENTA}[!] BAĞLANTI REDDEDİLDİ: {full_url} - Firewall olabilir!")
            pass
        finally:
            self.checked += 1
            # İlerleme göstergesini kaldırdık
    
    def start_scan(self):
        """Taramayı başlatır - ilerleme göstergesi olmadan"""
        paths = self._get_paths()
        self.total = len(paths)
        
        print(f"{Fore.BLUE}[*] Hedef: {self.url}")
        print(f"{Fore.BLUE}[*] {self.total} potansiyel admin paneli kontrol ediliyor...")
        print(f"{Fore.BLUE}[*] {self.threads} thread kullanılıyor")
        start_time = time.time()
        
        # Thread havuzuyla kontrolleri paralel yap
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_url, paths)
        
        # Tarama süresini kaydet
        self.scan_duration = time.time() - start_time
        
        print(f"\n{Fore.BLUE}[*] Tarama tamamlandı. Süre: {self.scan_duration:.2f} saniye")
        
        # Sonuçları göster
        if self.found:
            print("\n" + "="*60)
            print(f"{Fore.GREEN}[+] BULUNAN PANEL SONUÇLARI:")
            print("="*60)
            
            # Güven seviyesine göre sırala
            confidence_levels = {"KESİN": 1, "ERİŞİM ENGELLİ": 2, "YÖNLENDİRME": 3, "MUHTEMEL": 4, "ZAYIF": 5}
            self.found.sort(key=lambda x: confidence_levels.get(x[1], 999))
            
            # Duplikatları kaldır - aynı URL'den birden fazla varsa en güvenilir olanını tut
            unique_urls = {}
            for url, confidence in self.found:
                # URL zaten listedeyse ve mevcut güven düzeyi daha yüksekse, değiştirme
                if url in unique_urls and confidence_levels.get(unique_urls[url], 999) <= confidence_levels.get(confidence, 999):
                    continue
                unique_urls[url] = confidence
            
            # Benzersiz sonuçları güven düzeyine göre sıralayarak göster
            sorted_results = sorted(unique_urls.items(), key=lambda x: confidence_levels.get(x[1], 999))
            
            for url, confidence in sorted_results:
                if confidence == "KESİN":
                    print(f"{Fore.GREEN}[+++] {confidence}: {url}")
                elif confidence == "ERİŞİM ENGELLİ":
                    print(f"{Fore.YELLOW}[++] {confidence}: {url}")
                elif confidence == "YÖNLENDİRME" or confidence == "MUHTEMEL":
                    print(f"{Fore.BLUE}[++] {confidence}: {url}")
                else:
                    print(f"{Fore.CYAN}[+] {confidence}: {url}")
            
            print("\n" + "="*60)
            print(f"{Fore.GREEN}Toplam bulunan: {len(sorted_results)}")
            
            # Sonuçları JSON formatında dosyaya kaydet (duplikatları kaldırılmış haliyle)
            self.found = sorted_results
            self._save_results()
        else:
            print(f"\n{Fore.YELLOW}[!] Hiç admin paneli bulunamadı.")

    def _save_results(self):
        """Bulunan panelleri JSON formatında dosyaya kaydeder"""
        import json
        from datetime import datetime
        
        # JSON formatında dosya adı
        filename = f"admin_panels_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            # JSON verisi oluştur
            results_data = {
                "target": self.url,
                "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "total_found": len(self.found),
                "scan_duration_seconds": self.scan_duration,
                "results": []
            }
            
            # Bulunan her panel için detaylı bilgi ekle
            for url, confidence in self.found:
                results_data["results"].append({
                    "url": url,
                    "confidence": confidence,
                    "discovery_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
            
            # JSON dosyasına yaz
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, ensure_ascii=False, indent=4)
            
            print(f"{Fore.GREEN}[+] Sonuçlar '{filename}' JSON dosyasına kaydedildi.")
        except Exception as e:
            print(f"{Fore.RED}[!] Sonuçlar kaydedilirken hata: {str(e)}")
            
        # Ek olarak klasik metin dosyası formatında da kaydet
        txt_filename = f"admin_panels_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(txt_filename, 'w') as f:
                f.write(f"Hedef: {self.url}\n")
                f.write(f"Tarama Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Bulunan Panel Sayısı: {len(self.found)}\n")
                f.write("="*60 + "\n\n")
                
                for url, confidence in self.found:
                    f.write(f"{confidence}: {url}\n")
            
            print(f"{Fore.GREEN}[+] Sonuçlar ayrıca '{txt_filename}' dosyasına da kaydedildi.")
        except Exception:
            pass  # Metin dosyası oluşturulamazsa sessizce devam et

def main():
    parser = argparse.ArgumentParser(description='Admin Panel Bulucu')
    parser.add_argument('url', help='Taranacak web sitesi URL\'si')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Kullanılacak thread sayısı (varsayılan: 10)')
    parser.add_argument('-o', '--timeout', type=int, default=3, help='İstek zaman aşımı (varsayılan: 3 saniye)')
    parser.add_argument('-w', '--wordlist', help='Özel wordlist dosyası')
    parser.add_argument('-u', '--user-agents', help='Özel user-agent dosyası')
    
    args = parser.parse_args()
    
    print(Fore.RED + """
    ╔═══════════════════════════════════════════╗
    ║          ADMIN PANEL BULUCU               ║
    ║         Geliştirilmiş Versiyon            ║
    ╚═══════════════════════════════════════════╝
    """)
    
    try:
        finder = AdminFinder(args.url, args.threads, args.timeout, args.wordlist, args.user_agents)
        finder.start_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Kullanıcı tarafından durduruldu.")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Hata: {str(e)}")

if __name__ == "__main__":
    main()