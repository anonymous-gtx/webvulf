import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import dns.resolver
import requests
import time

# Global variable to track running tasks
is_running = False


def append_output(message):
    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, message + "\n")
    output_text.config(state=tk.DISABLED)
    output_text.see(tk.END)


def execute_function():
    global is_running

    if is_running:
        messagebox.showerror("Error", "A task is already running. Please stop it before starting another.")
        return

    option = function_choice.get()
    domain = domain_entry.get().strip()
    wordlist = wordlist_entry.get().strip()

    if not domain:
        messagebox.showerror("Error", "Please enter a domain.")
        return

    is_running = True
    progress_bar.start()

    if option == "DNS Enumeration":
        threading.Thread(target=dns_enum, args=(domain,)).start()
    elif option == "Subdomain Enumeration":
        if not wordlist:
            messagebox.showerror("Error", "Please provide a wordlist.")
            stop_task()
            return
        threading.Thread(target=subdomain_enum, args=(domain, wordlist)).start()
    elif option == "CORS Vulnerability Test":
        threading.Thread(target=test_cors_vulnerability, args=(domain,)).start()


def browse_wordlist():
    file_path = filedialog.askopenfilename(
        title="Select Wordlist File",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        wordlist_entry.delete(0, tk.END)
        wordlist_entry.insert(0, file_path)


def update_ui(*args):
    if function_choice.get() == "Subdomain Enumeration":
        wordlist_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        wordlist_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        browse_button.grid(row=2, column=2, padx=10, pady=10)
    else:
        wordlist_label.grid_forget()
        wordlist_entry.grid_forget()
        browse_button.grid_forget()


def stop_task():
    global is_running
    if is_running:
        is_running = False
        progress_bar.stop()
        append_output("Task stopped by user.")
    else:
        append_output("No task is currently running.")


def dns_enum(domain):
    global is_running
    append_output("Starting DNS Enumeration...")
    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'SOA', 'TXT']

    for record in record_types:
        if not is_running:
            break
        try:
            answers = dns.resolver.resolve(domain, record)
            append_output(f"{record} Records:")
            for answer in answers:
                append_output(answer.to_text())
        except dns.resolver.NoAnswer:
            append_output(f"No {record} record found.")
        except dns.resolver.LifetimeTimeout:
            append_output(f"Timeout while resolving {record} records for {domain}.")
        except dns.resolver.NXDOMAIN:
            append_output(f"{domain} does not exist.")
            break

    progress_bar.stop()
    is_running = False
    append_output("DNS Enumeration completed.")


def subdomain_enum(domain, wordlist):
    global is_running
    append_output("Starting Subdomain Enumeration...")
    try:
        with open(wordlist, 'r') as file:
            subdomains = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        append_output(f"Error: Wordlist '{wordlist}' not found.")
        stop_task()
        return

    valid_subdomains = []
    for sub in subdomains:
        if not is_running:
            break
        try:
            dns.resolver.resolve(f"{sub}.{domain}", "A")
            valid_subdomains.append(f"{sub}.{domain}")
            append_output(f"{sub}.{domain} is valid.")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
            pass

    result = "\n".join(valid_subdomains)
    if result:
        with open('output_file.txt', 'w') as file:
            file.write(result + '\n')
        append_output("Output saved to 'output_file.txt'.")
    else:
        append_output("No valid subdomains found.")

    progress_bar.stop()
    is_running = False
    append_output("Subdomain Enumeration completed.")


def test_cors_vulnerability(domain):
    global is_running
    append_output("Starting CORS Vulnerability Test...")
    headers = {"User-Agent": "CORS-Checker"}
    default_origins = ["https://evil.com", "null"]

    for origin in default_origins:
        if not is_running:
            break
        headers["Origin"] = origin
        urls = [f"http://{domain}", f"https://{domain}"]

        for url in urls:
            if not is_running:
                break
            try:
                response = requests.get(url, headers=headers, timeout=10)
                if "Access-Control-Allow-Origin" in response.headers:
                    allowed_origin = response.headers["Access-Control-Allow-Origin"]
                    if allowed_origin == origin or allowed_origin == "*":
                        append_output(f"[!] Vulnerable! URL: {url} allows Origin: {allowed_origin}")
                    else:
                        append_output(f"[+] Safe! URL: {url} does not allow Origin: {origin}")
                else:
                    append_output(f"[+] No CORS headers found for URL: {url}")
            except requests.RequestException as e:
                append_output(f"[ERROR] Failed to connect to {url}: {e}")

    progress_bar.stop()
    is_running = False
    append_output("CORS Vulnerability Test completed.")


# Create the main window
root = tk.Tk()
root.title("Webvulf - GUI")

# Configure grid weights
root.grid_columnconfigure(1, weight=1)

# Dropdown for function choice
ttk.Label(root, text="Choose a Function:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
function_choice = ttk.Combobox(root, values=["DNS Enumeration", "Subdomain Enumeration", "CORS Vulnerability Test"], state="readonly")
function_choice.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
function_choice.current(0)
function_choice.bind("<<ComboboxSelected>>", update_ui)

# Entry for domain
ttk.Label(root, text="Domain:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
domain_entry = ttk.Entry(root, width=40)
domain_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

# Wordlist UI elements
wordlist_label = ttk.Label(root, text="Wordlist:")
wordlist_entry = ttk.Entry(root)
browse_button = ttk.Button(root, text="Browse", command=browse_wordlist)

# Output section
output_text = tk.Text(root, wrap=tk.WORD, height=15, state=tk.DISABLED)
output_text.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

# Progress bar
progress_bar = ttk.Progressbar(root, mode="indeterminate")
progress_bar.grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

# Buttons
execute_button = ttk.Button(root, text="Execute", command=execute_function)
execute_button.grid(row=5, column=0, pady=10)
stop_button = ttk.Button(root, text="Stop", command=stop_task)
stop_button.grid(row=5, column=1, pady=10)

# Initialize UI state
update_ui()

# Run the main event loop
root.mainloop()
