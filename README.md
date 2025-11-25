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
Tool ini memiliki keakuratan 90% jadi sangat membantu anda untuk mencari alamat web/ip yang cocok untuk melakukan injeksi sesuai dengan kuota yang anda gunakan.
## Kekurangan
Karena tool ini berbasis CLI dan dijalankan untuk android dengan termux maka ada beberapa cacat bawaan
- Tidak dapat membuat VPN Interface
- Tidak dapat override DNS system
#### Mengapa akuratnya tidak 100%
- Tool ini belum bisa bypass DNS menggunakan DoH (DNS Over HTTPS) ataupun DoT (DNS Over TLS)
- Belum bisa melakukan Fake DNS
## Cara Install
Tool ini khusus untuk android dan saran saya menggunakan termux.
- Masuk termux dan masukan command berikut secara berurutan:
```
pkg update && pkg upgrade
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
cd Xwan
```
```
python xwan.py
```
