#!/usr/bin/env python3
#xwan v.1.0 use xray core v25.10.15
import subprocess
import time
import json
import os
import urllib.parse
import base64
from colorama import Fore, Style, init
init()
os.system("clear")

def parse_vmess_trojan_url(url):
    
    if url.startswith('trojan://'):
        return parse_trojan_url(url)
    elif url.startswith('vmess://'):
        return parse_vmess_url(url)
    elif url.startswith('vless://'):
        return parse_vless_url(url)
    else:
        raise ValueError(f"{Fore.RED}Protocol tidak didukung: {url}{Style.RESET_ALL}")

def parse_trojan_url(url):
    parsed = urllib.parse.urlparse(url)
    password = parsed.username or parsed.netloc.split('@')[0]
    server_info = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    address = server_info.split(':')[0]
    port = int(server_info.split(':')[1]) if ':' in server_info else 443
    
    query_params = urllib.parse.parse_qs(parsed.query)
    
    security = "tls"
    if 'security' in query_params:
        security = query_params['security'][0]
    elif port == 80 or 'allowInsecure' in query_params:
        security = "none"
    
    config = {
        "protocol": "trojan",
        "address": address,
        "port": port,
        "password": password,
        "security": security,
        "network": query_params.get('type', ['tcp'])[0],
        "path": query_params.get('path', ['/'])[0],
        "host": query_params.get('host', [address])[0],
        "sni": query_params.get('sni', query_params.get('host', [address])[0])[0],
        "fp": query_params.get('fp', ['chrome'])[0],
        "alpn": query_params.get('alpn', ['h2,http/1.1'])[0].split(',')[0]
    }
    
    return config

def parse_vmess_url(url):
    encoded_data = url[8:]
    padding = 4 - len(encoded_data) % 4
    if padding != 4:
        encoded_data += '=' * padding
    decoded_data = base64.b64decode(encoded_data).decode('utf-8')
    vmess_config = json.loads(decoded_data)
    
    security = "none"
    if vmess_config.get('tls') == 'tls':
        security = "tls"
    
    config = {
        "protocol": "vmess",
        "address": vmess_config['add'],
        "port": int(vmess_config['port']),
        "id": vmess_config['id'],
        "security": security,
        "network": vmess_config.get('net', 'tcp'),
        "path": vmess_config.get('path', '/'),
        "host": vmess_config.get('host', vmess_config['add']),
        "sni": vmess_config.get('sni', vmess_config.get('host', vmess_config['add'])),
        "fp": vmess_config.get('fp', 'chrome'),
        "type": vmess_config.get('type', 'none')
    }
    
    return config

def parse_vless_url(url):
    parsed = urllib.parse.urlparse(url)
    uuid = parsed.username
    server_info = parsed.netloc.split('@')[1] if '@' in parsed.netloc else parsed.netloc
    address = server_info.split(':')[0]
    port = int(server_info.split(':')[1]) if ':' in server_info else 443
    
    query_params = urllib.parse.parse_qs(parsed.query)
    
    security = query_params.get('security', ['none'])[0]
    if security == 'none' and (port == 80 or 'encryption' in query_params):
        security = "none"
    
    config = {
        "protocol": "vless",
        "address": address,
        "port": port,
        "id": uuid,
        "security": security,
        "network": query_params.get('type', ['tcp'])[0],
        "path": query_params.get('path', ['/'])[0],
        "host": query_params.get('host', [address])[0],
        "sni": query_params.get('sni', query_params.get('host', [address])[0])[0],
        "fp": query_params.get('fp', ['chrome'])[0],
        "flow": query_params.get('flow', [''])[0]
    }
    
    return config

def create_xray_config(server_config, target_address=None):
    if target_address:
        actual_address = target_address
    else:
        actual_address = server_config['address']
    
    base_config = {
        "inbounds": [{
            "port": 10808,
            "protocol": "socks",
            "listen": "127.0.0.1",
            "settings": {"auth": "noauth", "udp": True}
        }]
    }
    
    stream_settings = {
        "network": server_config['network']
    }
    
    if server_config['security'] == 'tls':
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {
            "serverName": server_config['sni'],
            "allowInsecure": False,
            "fingerprint": server_config['fp']
        }
        if server_config.get('alpn'):
            stream_settings["tlsSettings"]["alpn"] = [server_config['alpn']]
    else:
        stream_settings["security"] = "none"
    
    if server_config['network'] == 'ws':
        stream_settings["wsSettings"] = {
            "path": server_config['path'],
            "headers": {"Host": server_config['host']}
        }
    
    if server_config['protocol'] == 'trojan':
        base_config["outbounds"] = [{
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": actual_address,
                    "port": server_config['port'],
                    "password": server_config['password']
                }]
            },
            "streamSettings": stream_settings
        }]
    
    elif server_config['protocol'] == 'vmess':
        base_config["outbounds"] = [{
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": actual_address,
                    "port": server_config['port'],
                    "users": [{
                        "id": server_config['id'],
                        "security": server_config.get('security', 'auto')
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    
    elif server_config['protocol'] == 'vless':
        base_config["outbounds"] = [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": actual_address,
                    "port": server_config['port'],
                    "users": [{
                        "id": server_config['id'],
                        "flow": server_config.get('flow', ''),
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    
    return base_config

def test_xray_connection(config_file):
    try:
        xray_proc = subprocess.Popen(
            ["xray", "run", "-config", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(3)
        
        if xray_proc.poll() is None:
            xray_proc.terminate()
            xray_proc.wait()
            return True
        else:
            stdout, stderr = xray_proc.communicate()
            print(f"{Fore.RED}[!] Xray Error: {stderr}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[!] Error menjalankan Xray: {e}{Style.RESET_ALL}")
        return False

def load_addresses_from_file(filename):
    addresses = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    addresses.append(line)
        return addresses
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File {filename} tidak ditemukan!{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[!] Error membaca file: {e}{Style.RESET_ALL}")
        return []

def test_address(target_address, server_config):
    try:
        xray_config = create_xray_config(server_config, target_address)
        
        config_file = f"test-{target_address.replace('.', '-').replace('/', '-')}.json"
        with open(config_file, "w") as f:
            json.dump(xray_config, f, indent=2)
        
        xray_proc = subprocess.Popen(
            ["core/xray", "run", "-config", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        time.sleep(5)
        
        try:
            result = subprocess.run(
                ["curl", "-s", "--socks5", "127.0.0.1:10808", 
                 "-o", "/dev/null", "-w", "%{http_code}", 
                 "http://httpbin.org/ip"],
                capture_output=True, text=True, timeout=10
            )
            
            success = result.stdout == "200"
            
        except:
            success = False
        
        xray_proc.terminate()
        xray_proc.wait()
        
        try:
            os.remove(config_file)
        except:
            pass
        
        return success
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error testing {target_address}: {e}{Style.RESET_ALL}")
        return False
        
banner = f"""
__   ___    _             
\ \ / / |  | |            
 \ V /| |  | | __ _ _ __  
 /   \| |/\| |/ _` | '_ \ 
/ /^\ \  /\  / (_| | | | |
\/   \/\/  \/ \__,_|_| |_|
{Fore.YELLOW}Xray-core v25.10.15{Style.RESET_ALL}  {Fore.GREEN}v.1.0{Style.RESET_ALL}

Github : github.com/wannazid
Blog : www.malastech.my.id                          
"""        
print(banner)
main_account_url = input(f"{Fore.YELLOW}[*] Masukkan URL akun (vmess/trojan/vless): {Style.RESET_ALL}").strip()

if not main_account_url:
    print(f"{Fore.RED}[!] URL akun tidak boleh kosong!{Style.RESET_ALL}")
    exit(1)

print(f"{Fore.YELLOW}[!] Menguji koneksi akun utama...{Style.RESET_ALL}")
try:
    main_config = parse_vmess_trojan_url(main_account_url)
    xray_config = create_xray_config(main_config)
    
    config_file = "main-config.json"
    with open(config_file, "w") as f:
        json.dump(xray_config, f, indent=2)
    
    if test_xray_connection(config_file):
        print(f"{Fore.GREEN}[!] XRAY BERHASIL TERHUBUNG!{Style.RESET_ALL}")
        print(f"- Protocol: {main_config['protocol'].upper()}")
        print(f"- Server: {main_config['address']}:{main_config['port']}")
        print(f"- Network: {main_config['network']}")
        print(f"- Security: {main_config.get('security', 'none')}")
        print(f"- Path: {main_config['path']}")
        print(f"- Host: {main_config['host']}")
    else:
        print(f"{Fore.RED}[!] GAGAL terhubung dengan Xray!{Style.RESET_ALL}")
        print("   Periksa konfigurasi akun Anda.")
        exit(1)
        
except Exception as e:
    print(f"{Fore.RED}[!] Error dengan akun utama: {e}{Style.RESET_ALL}")
    exit(1)

try:
    os.remove(config_file)
except:
    pass

filename = input(f"{Fore.YELLOW}[*] List address untuk di-scan (txt): {Style.RESET_ALL}").strip()

addresses = load_addresses_from_file(filename)

if not addresses:
    print(f"{Fore.RED}[!] Tidak ada address yang bisa di-test!{Style.RESET_ALL}")
    exit(1)

print(f"{Fore.YELLOW}[!] Security: {main_config.get('security', 'none')}")
print(f"[!] Memulai scan...\n{Style.RESET_ALL}")

success_count = 0

for i, target in enumerate(addresses, 1):
    print(f"[#] Testing [{i}/{len(addresses)}]: {target}")
    
    subprocess.run(["pkill", "-f", "xray"], capture_output=True)
    time.sleep(2)
    
    works = test_address(target, main_config)
    
    if works:
        print(f"✅ CONNECTED - {Fore.GREEN}{target}{Style.RESET_ALL}")
        success_count += 1
        with open("Result.txt", "a") as f:
            f.write(target + "\n")
    else:
        print(f"❌ FAILED - {Fore.RED}{target}{Style.RESET_ALL}")
print("\n")
print(f"[!] Hasil tersimpan di: Result.txt{Style.RESET_ALL}")