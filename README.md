![Picture tool](https://github.com/wannazid/XWan/blob/main/img.jpg)
![Version](https://img.shields.io/badge/XWan%20v1.0-blue)
# XWan
Address brute-forcing for quota injection via VMess, Trojan, and VLESS. Command-line based utilizing Xray core v25.10.15.
## Kelebihan
- Aman karena tidak akan meyimpan log akun anda karena tool ini open source
- Multi protocol support seperti VMess,Trojan dan VLESS
- Dapat melalukan cek secara bersamaan
- Tool bekerja secara cepat dan dapat membantu anda mencari address yang cocok
- Konfigurasi fleksibel untuk Websocket/TCP, TLS/Non TLS
## Akurat
Tool ini memiliki keakuratan 90% jadi sangat membantu anda untuk mencari alamat web/ip yang cocok untuk melakukan injeksi sesuai dengan kuota yang anda gunakan. Gunakan saat tidak ada kuota reguler dan hanya ada kuota yang mau di injeksi.
## Kekurangan
Karena tool ini berbasis CLI dan dijalankan untuk android dengan termux maka ada beberapa cacat bawaan
- Tidak dapat membuat VPN Interface
- Tidak dapat override DNS system
- Tidak dapat capture semua traffic 
#### Mengapa akuratnya tidak 100%
- Tool ini belum bisa bypass DNS menggunakan DoH (DNS Over HTTPS) ataupun DoT (DNS Over TLS)
- Belum bisa melakukan Fake DNS
## Cara Install
Tool ini khusus untuk android dengan arsitektur (arm64) dan saran saya menggunakan termux.
- Masuk termux dan masukan command berikut secara berurutan:
```
termux-setup-storage
```
```
pkg update && pkg upgrade
```
```
pkg install wget
```
```
pkg install python && pkg install git && pkg install python-pip
```
```
pip install colorama
```
```
git clone https://github.com/wannazid/XWan
```
```
cd XWan
```
```
chmod +x install.sh
```
```
./install.sh
```
- Jika ada pertanyaan replace. Ketik y lalu enter.
```
nano list.txt
```
- Masukan alamat web/ip secara berurutan dan setelah itu CTRL+X dan CTRL+Y dan ENTER
```
python xwan.py
```
- Selamat menggunakan toolsnya >_<
## Perhatian 
- Akun jangan bertabrakan, gunakan akun yang tidak dalam kondisi untuk injeksi
- Pastikan akun stabil dan tidak dalam masalah
- Jangan ada kuota reguler, hanya ada kuota yang mau di cek bug nya
- Untuk pengecekan agar lebih pasti ulangi tool lebih dari 1
## Laporan 
Jika ada error pada tool ini bisa langsung lapor langsung lewat telegram
- [Hubungi saya](https://t.me/otaksenku)
# Syarat dan Ketentuan Layanan
Pengguna yang memanfaatkan alat ini setuju untuk mematuhi semua hukum yang berlaku dan melepas tanggung jawab pengembang dari klaim apa pun yang muncul akibat penggunaannya.
