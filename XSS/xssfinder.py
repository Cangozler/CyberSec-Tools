import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import ttk
import threading
#TR:Öncellikle bu proğramın tek amacı güvenlik açıklarını bulup bunları düzeltmektir. Amacı dısında kullanım dahilinde sorumluluk kullanıcıya aittir.
#ENG:First of all, the sole purpose of this program is to find security vulnerabilities and fix them. Responsibility for use outside its intended purpose belongs to the user.

class XSSFinderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("XSS Finder Made.By Cgzlr")
        
        self.stop_event = threading.Event()
        self.scan_thread = None
        # Stil tanımlama
        #Style
        self.style = ttk.Style()
        self.style.configure("TButton", foreground="green", background="black", font=("Helvetica", 10), padding=(5, 5))
        
        # URL 
        # Url 
        self.url_label = ttk.Label(root, foreground='Green',background='black',text="URL:")
        self.url_label.grid(row=0, column=0, padx=5, pady=5)

        self.url_entry = ttk.Entry(root, width=40)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)

        # Derinlik Seçimi
        #Level choice
        self.depth_label = ttk.Label(root,foreground='Green',background='black',text="Choose Level:")
        self.depth_label.grid(row=1, column=0, padx=5, pady=5)

        self.depth_combobox = ttk.Combobox(root, values=[1, 2, 3, 4, 5], state="readonly")
        self.depth_combobox.set(2)
        self.depth_combobox.grid(row=1, column=1, padx=5, pady=5)

        # Tarama Sonuçları (tk.Text kullanarak)
        #Scan Results
        self.result_text = tk.Text(root, height=10, width=150,bg='black', fg='green')
        self.result_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        # Tarama Butonu
        # Start Buton
        self.scan_button = ttk.Button(root, text="Start Scan", command=self.on_scan_button_click, style="TButton")
        self.scan_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Durdur Butonu
        #stop button
        self.stop_button = ttk.Button(root, text="Stop Scan", command=self.stop_scan, style="TButton")
        self.stop_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.scan_thread = None
        self.stopped = False

    def on_scan_button_click(self):
        target_url = self.url_entry.get()
        max_depth = int(self.depth_combobox.get())

        self.stopped = False
        self.stop_event.clear()
        # threading.Thread ile xss_scan fonksiyonunu başka bir thread üzerinde çalıştırıyoruz
        # Starting xss_scand func
        self.scan_thread = threading.Thread(target=self.xss_scan, args=(target_url, max_depth))
        self.scan_thread.start()

    def xss_scan(self, target_url, max_depth=2, current_depth=0):
                  
        try:
            
            response = requests.get(target_url)

            if "<script>" in response.text:
                self.update_result(f"Potansiyel XSS Açığı Tespit Edildi: {target_url}\n")
            else:
                self.update_result("XSS Açığı Bulunamadı.\n")

            links = self.get_links(target_url)

            if current_depth < max_depth and not self.stopped:
                for link in links:
                    self.xss_scan(link, max_depth, current_depth + 1)

        except requests.exceptions.RequestException as e:
            self.update_result(f"Hata Oluştu: {e}\n")

    def get_links(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            return links
        except requests.exceptions.RequestException as e:
            print(f"Hata Oluştu: {e}")
            return []

    def update_result(self, text):
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)  # Scrolling to the end of the text #Kaydırma çubuğu ile aşşagıya inme

    def stop_scan(self):
        self.stop_event.set() 
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join()

if __name__ == "__main__":
    root = tk.Tk()
    root.configure(bg="#000000")
    app = XSSFinderApp(root)
    root.mainloop()
