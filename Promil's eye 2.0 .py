import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
from queue import Queue
import json
import gzip
import requests
import csv
import os
import random

MAX_THREADS = 200
NVD_URL_TEMPLATE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.json.gz"

class PromilsEyeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Promil's Eye 2.0 - TCP Port Scanner with CVE")
        self.root.geometry('800x600')

        # IP
        ttk.Label(root, text="Target IP:").pack(anchor='w', padx=10, pady=(10,0))
        self.ip_entry = ttk.Entry(root, width=40)
        self.ip_entry.pack(anchor='w', padx=10)

        # Port Range
        ttk.Label(root, text="Port Range (start-end):").pack(anchor='w', padx=10, pady=(10,0))
        self.port_entry = ttk.Entry(root, width=40)
        self.port_entry.insert(0, "1-1024")
        self.port_entry.pack(anchor='w', padx=10)

        # Scan Button
        self.scan_button = ttk.Button(root, text="Start TCP Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Output area
        self.output = scrolledtext.ScrolledText(root, width=95, height=25)
        self.output.pack(padx=10, pady=10)

        # Matrix Animation Canvas
        self.canvas = tk.Canvas(root, bg="black", height=60)
        self.canvas.pack(fill='x', side='bottom')
        self.matrix_texts = []
        self.running_matrix = False

        # Queue & Lock
        self.queue = Queue()
        self.lock = threading.Lock()

        # CVE verisini yükle (veya indir)
        self.cve_data = {}
        self.load_cve_database()

    def log(self, msg):
        self.output.insert(tk.END, msg + "\n")
        self.output.see(tk.END)

    def load_cve_database(self):
        year = 2025
        filename = f"nvdcve-2.0-{year}.json.gz"
        json_filename = f"nvdcve-2.0-{year}.json"

        if not os.path.exists(json_filename):
            self.log(f"CVE verisi yok, indiriliyor ({filename})...")
            try:
                url = NVD_URL_TEMPLATE.format(year)
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                with open(filename, 'wb') as f:
                    f.write(r.content)
                with gzip.open(filename, 'rb') as f_in, open(json_filename, 'wb') as f_out:
                    f_out.write(f_in.read())
                os.remove(filename)
                self.log("CVE verisi başarıyla indirildi ve açıldı.")
            except Exception as e:
                self.log(f"CVE verisi indirilemedi: {e}")
                return

        try:
            with open(json_filename, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.cve_data = {}
            for item in data.get('CVE_Items', []):
                desc = item['cve']['description']['description_data'][0]['value'].lower()
                cve_id = item['cve']['CVE_data_meta']['ID']
                for keyword in ['ssh', 'ftp', 'http', 'apache', 'nginx', 'smb', 'smtp', 'mysql']:
                    if keyword in desc:
                        self.cve_data.setdefault(keyword, []).append(cve_id)
            self.log(f"CVE veritabanı hazır. Anahtar kelimeler: {list(self.cve_data.keys())}")
        except Exception as e:
            self.log(f"CVE verisi yüklenirken hata: {e}")

    def get_cves_for_banner(self, banner):
        banner = banner.lower()
        results = []
        for keyword, cves in self.cve_data.items():
            if keyword in banner:
                results.extend(cves)
        return results if results else ["Yok"]

    def tcp_scan(self, ip, port, results_list):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((ip, port))
            banner = "[Yok]"
            try:
                sock.sendall(b"\r\n")
                response = sock.recv(1024).decode(errors='ignore').strip()
                if response:
                    banner = response[:50]
            except:
                pass

            cves = self.get_cves_for_banner(banner)
            cve_display = ", ".join(cves) if cves and cves != ["Yok"] else "Yok"

            with self.lock:
                result_str = f"{ip}:{port} - Açık - Banner: '{banner}' - CVE: {cve_display}"
                self.log(result_str)
                results_list.append((ip, port, "Açık", banner, cve_display))

            sock.close()
        except:
            pass
        finally:
            self.queue.get()
            self.queue.task_done()

    def do_scan(self, ip, start_port, end_port):
        self.output.delete(1.0, tk.END)
        self.log(f"Scanning {ip} ports {start_port}-{end_port} with up to {MAX_THREADS} threads...")
        self.start_matrix_animation()
        results_list = []
        for port in range(start_port, end_port + 1):
            self.queue.put(port)
            while self.queue.qsize() > MAX_THREADS:
                pass
            t = threading.Thread(target=self.tcp_scan, args=(ip, port, results_list))
            t.daemon = True
            t.start()

        self.queue.join()
        self.stop_matrix_animation()
        self.log("Taramalar tamamlandı. Sonuçlar dosyaya kaydediliyor...")

        try:
            with open("scan_results.csv", "w", newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["IP", "Port", "Durum", "Banner", "CVE Listesi"])
                for row in results_list:
                    writer.writerow([row[0], row[1], row[2], row[3], row[4]])
            self.log("Sonuçlar scan_results.csv dosyasına kaydedildi.")
        except Exception as e:
            self.log(f"Sonuç dosyasına yazılırken hata: {e}")

    def start_scan(self):
        ip = self.ip_entry.get().strip()
        port_range = self.port_entry.get().strip()

        if not ip:
            messagebox.showerror("Hata", "IP adresi boş olamaz!")
            return

        try:
            start_port, end_port = map(int, port_range.split('-'))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
        except:
            messagebox.showerror("Hata", "Port aralığı yanlış! Örnek: 1-1024")
            return

        threading.Thread(target=self.do_scan, args=(ip, start_port, end_port), daemon=True).start()

    def start_matrix_animation(self):
        self.running_matrix = True
        self.matrix_texts.clear()
        self.animate_matrix()

    def stop_matrix_animation(self):
        self.running_matrix = False

    def animate_matrix(self):
        if not self.running_matrix:
            self.canvas.delete("all")
            return

        self.canvas.delete("all")
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        cols = width // 20

        for i in range(cols):
            x = i * 20
            y = random.randint(0, height)
            char = random.choice("01")
            color = "#00FF00"
            self.canvas.create_text(x, y, text=char, fill=color, font=("Courier", 16, "bold"))

        self.canvas.after(100, self.animate_matrix)


if __name__ == "__main__":
    root = tk.Tk()
    app = PromilsEyeApp(root)
    root.mainloop()
