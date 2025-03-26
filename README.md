# Admin Panel Bulucu

Bu proje web sitelerinde admin panel URL'lerini bulmak için geliştirilmiş bir araçtır.

## Versiyonlar

### V1 (Orijinal)
Temel admin panel arama işlevi

### V2 (Geliştirilmiş)
- Çoklu iş parçacığı desteği ile hızlandırılmış tarama
- Özelleştirilebilir wordlist desteği
- Gelişmiş User-Agent rotasyonu
- HTTP durum kodları analizi
- İlerleme göstergesi
- Zaman aşımı kontrolü
- Özelleştirilebilir parametreler

## Kullanım

### V2 Kullanımı:
```bash
python admin-login-finder-v2.py hedef-site.com -t 10 -o 3 -w wordlist.txt -u user-agents.txt