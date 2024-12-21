import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from email.parser import BytesParser
from email.policy import default
from email.utils import parsedate_to_datetime
import ipinfo
import folium
import webbrowser
from bs4 import BeautifulSoup
import re
import os
import json
from datetime import datetime

# Initialize the IPinfo client
access_token = 'Enter Your Token Here'
ipinfo_client = ipinfo.getHandler(access_token)

class EmailTracerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CCC Mail Forensic Analyzer")
        self.geometry("800x600")
        self.iconbitmap('favicon.ico')

        self.style = ttk.Style(self)
        self.style.configure('TButton', font=('Arial', 12), padding=10)

        self.create_widgets()
        self.create_menu()

        self.email_content = None
        self.email_header = None
        self.email_body = None

    def create_widgets(self):
        self.menu_frame = ttk.Frame(self)
        self.menu_frame.pack(side=tk.TOP, fill=tk.X)

        self.upload_button = self.create_animated_button("Upload Email File", self.upload_file)
        self.upload_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.analyze_button = self.create_animated_button("Analyze Email", self.analyze_email)
        self.analyze_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.report_button = self.create_animated_button("Generate Report", self.generate_report)
        self.report_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.trace_button = self.create_animated_button("Trace IP", self.trace_ip)
        self.trace_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.search_label = ttk.Label(self.menu_frame, text="Keyword Search:")
        self.search_label.pack(side=tk.LEFT, padx=5, pady=5)

        self.search_entry = ttk.Entry(self.menu_frame, width=20)
        self.search_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.search_button = ttk.Button(self.menu_frame, text="Search", command=self.search_keyword)
        self.search_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.output_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, height=20)
        self.output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    def create_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Upload Email File", command=self.upload_file)
        file_menu.add_command(label="Analyze Email", command=self.analyze_email)
        file_menu.add_command(label="Generate Report", command=self.generate_report)
        file_menu.add_command(label="Trace IP", command=self.trace_ip)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

    def create_animated_button(self, text, command):
        button = ttk.Button(self.menu_frame, text=text, command=command)
        button.bind("<Enter>", lambda e: self.animate_button(button, '#ffcccc'))
        button.bind("<Leave>", lambda e: self.animate_button(button, '#ff6666'))
        return button

    def animate_button(self, button, color):
        def _animate(step):
            if step <= 10:
                factor = step / 10
                current_color = self._blend_colors('#ff6666', color, factor)
                style_name = f"{current_color}.TButton"
                self.style.configure(style_name, background=current_color)
                button.configure(style=style_name)
                self.after(10, _animate, step + 1)

        _animate(0)

    def _blend_colors(self, start_color, end_color, factor):
        start_color = [int(start_color[i:i+2], 16) for i in (1, 3, 5)]
        end_color = [int(end_color[i:i+2], 16) for i in (1, 3, 5)]
        blended_color = [int(start_color[i] + factor * (end_color[i] - start_color[i])) for i in range(3)]
        return f"#{''.join(f'{c:02x}' for c in blended_color)}"

    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Email files", "*.eml")])
        if file_path:
            with open(file_path, 'rb') as f:
                self.email_content = f.read()
            self.output_area.insert(tk.END, "Email file uploaded successfully.\n")
            messagebox.showinfo("Success", "Email file uploaded successfully.")

    def analyze_email(self):
        if not self.email_content:
            messagebox.showwarning("Warning", "Please upload an email file first.")
            return

        parser = BytesParser(policy=default)
        self.email_header = parser.parsebytes(self.email_content)
        self.email_body = self.email_header.get_body(preferencelist=('html', 'plain'))
        email_text = self.email_body.get_content()
        self.output_area.insert(tk.END, f"Email analyzed successfully.\n{email_text}\n")

        if self.email_body.get_content_type() == 'text/html':
            self.display_email_html(email_text)
        else:
            self.output_area.insert(tk.END, email_text)

        messagebox.showinfo("Success", "Email analyzed successfully.")

    def display_email_html(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        text_content = soup.get_text()
        self.output_area.insert(tk.END, text_content + '\n')

        for img in soup.find_all('img'):
            self.output_area.insert(tk.END, f"Image: {img['src']}\n")

        for link in soup.find_all('a'):
            href = link.get('href')
            if href:
                self.output_area.insert(tk.END, f"Link: {href}\n")

    def generate_report(self):
        if not self.email_header:
            messagebox.showwarning("Warning", "Please analyze an email first.")
            return

        from_address = self.email_header['From']
        to_address = self.email_header['To']
        subject = self.email_header['Subject']
        date = parsedate_to_datetime(self.email_header['Date']).strftime('%Y-%m-%d %H:%M:%S')

        report_html = f"""
        <html>
        <head>
            <title>Email Analysis Report</title>
        </head>
        <body>
            <h1>Email Analysis Report</h1>
            <p><strong>From:</strong> {from_address}</p>
            <p><strong>To:</strong> {to_address}</p>
            <p><strong>Subject:</strong> {subject}</p>
            <p><strong>Date:</strong> {date}</p>
            <h2>Body:</h2>
            <p>{self.email_body.get_content()}</p>
        </body>
        </html>
        """

        report_filename = f"email_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.html"
        with open(report_filename, "w") as f:
            f.write(report_html)

        self.output_area.insert(tk.END, "Report generated successfully.\n")
        webbrowser.open(report_filename)

    def trace_ip(self):
        if not self.email_header:
            messagebox.showwarning("Warning", "Please analyze an email first.")
            return

        received_headers = self.email_header.get_all('Received')
        if not received_headers:
            messagebox.showwarning("Warning", "No 'Received' headers found in the email.")
            return

        last_received_header = received_headers[-1]
        ip_address = self.extract_ip(last_received_header)
        if not ip_address:
            messagebox.showwarning("Warning", "No IP address found in the 'Received' headers.")
            return

        details = ipinfo_client.getDetails(ip_address)
        city = details.city
        country = details.country_name

        self.output_area.insert(tk.END, f"IP Address: {ip_address}\nCity: {city}\nCountry: {country}\n")
        messagebox.showinfo("IP Trace", f"IP Address: {ip_address}\nCity: {city}\nCountry: {country}")

        map_filename = f"ip_trace_map_{datetime.now().strftime('%Y%m%d%H%M%S')}.html"
        map = folium.Map(location=[details.latitude, details.longitude], zoom_start=10)
        folium.Marker([details.latitude, details.longitude], popup=f"{city}, {country}").add_to(map)
        map.save(map_filename)

        webbrowser.open(map_filename)

    def extract_ip(self, received_header):
        match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received_header)
        if match:
            return match.group(1)
        return None

    def search_keyword(self):
        if not self.email_content:
            messagebox.showwarning("Warning", "Please upload and analyze an email first.")
            return

        keyword = self.search_entry.get().strip()
        if not keyword:
            messagebox.showwarning("Warning", "Please enter a keyword to search.")
            return

        parser = BytesParser(policy=default)
        email = parser.parsebytes(self.email_content)

        body = email.get_body(preferencelist=('html', 'plain'))
        if body:
            content = body.get_content()
            if keyword in content:
                self.output_area.tag_configure('highlight', background='yellow')
                start_pos = '1.0'
                while True:
                    start_pos = self.output_area.search(keyword, start_pos, stopindex=tk.END)
                    if not start_pos:
                        break
                    end_pos = f"{start_pos}+{len(keyword)}c"
                    self.output_area.tag_add('highlight', start_pos, end_pos)
                    start_pos = end_pos
            else:
                messagebox.showinfo("Info", f"Keyword '{keyword}' not found in the email.")

    def show_about(self):
        messagebox.showinfo("About", "CCC Mail Forensic Analyzer\n\nProduct Developed by: Cyber Crime Consultant Punjab\n\nWarning: This software is protected by copyright law and international treaties. unauthorized reproduction or distribution of this software tool is punishable under the law. \nCCC Mail Analyzer Version: 1.0 [Licensed Access]")

if __name__ == "__main__":
    app = EmailTracerApp()
    app.mainloop()
