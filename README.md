# 🚀 Promil's Eye 2.0 - TCP Port Scanner with CVE Integration 🔍

**Promil's Eye 2.0**, Python ve Tkinter ile geliştirilmiş GUI tabanlı güçlü bir **TCP port tarayıcı**dır.  
Hedef IP ve port aralığını hızlıca tarar, açık portları tespit eder, banner bilgisi alır ve servislerin potansiyel **CVE (Common Vulnerabilities and Exposures)** zafiyetlerini **NVD (National Vulnerability Database)** veritabanından kontrol eder.

---

## ⚙️ Özellikler

- 🔥 **Hızlı TCP port taraması:** Maksimum 200 iş parçacığı ile paralel tarama  
- 📡 **Banner grabbing:** Portlardan dönen servis bilgilerini alma  
- 🛡️ **CVE entegrasyonu:** Banner içeriğine göre ilgili güvenlik açıklarını listeleme  
- 🌐 **Otomatik CVE verisi indirimi:** Yıllık NVD JSON dosyasını indirir ve işler  
- 📊 **Sonuç gösterimi:** GUI üzerinden canlı çıktı ve tarama sonrası CSV kaydı  
- 🎮 **Matrix animasyonu:** Taramalar sırasında görsel efekt  

---
🎯 Kullanım
Programı çalıştırın:

bash
Kopyala
Düzenle
python promils_eye.py
Hedef IP adresini girin.

Tarama yapılacak port aralığını belirtin (örn. 1-1024).

Start TCP Scan butonuna tıklayın.

Açık portlar, banner bilgisi ve varsa CVE listesi canlı olarak çıktı alanında gösterilecektir.

Taramadan sonra sonuçlar scan_results.csv dosyasına kaydedilir.

⚠️ Dikkat!
Yasal izin olmadan başkalarının sistemlerini taramak yasadışıdır.

Çok yüksek iş parçacığı sayısı, sistem ve ağınıza zarar verebilir veya yavaşlatabilir.

Bu program eğitim ve kişisel kullanım amaçlıdır.
---
## 🚀 Kurulum

Python 3.x yüklü olduğundan emin olun.  
Gerekli Python paketi: requests

Aşağıdaki komutu terminal veya CMD'de çalıştırarak yükleyin:

bash
pip install requests
