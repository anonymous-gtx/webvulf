# WebVulf GUI/CLI

A **Web Vulnerability Assessment Tool** with a user-friendly GUI, built using Python and `tkinter`. This application allows users to test for CORS vulnerabilities, perform DNS enumeration, and conduct subdomain enumeration with ease. It also has a CLI version of it.

## Features

- **CORS Vulnerability Testing**  
  Test if a domain is vulnerable to Cross-Origin Resource Sharing (CORS) attacks.  

- **DNS Enumeration**  
  Retrieve DNS records (A, AAAA, MX, CNAME, TXT, etc.) for a given domain.  

- **Subdomain Enumeration**  
  Discover valid subdomains of a domain using a custom wordlist file.

- **Dynamic GUI**  
  A responsive GUI that adjusts to display sizes and includes:  
  - Dropdown options for function selection.  
  - Progress indicator with a loading spinner.  
  - A section to display outputs in real-time.  
  - Stop functionality to interrupt running tasks.

## Prerequisites

Ensure you have the following installed on your system:  
- Python 3.8 or later  
- `dns.resolver` module (part of `dnspython`)  
- `requests` library  

Install dependencies using pip:  
```bash
pip install dnspython requests
```

## Installation

1. Clone the repository:  
   ```bash
   github.com:anonymous-gtx/webvulf.git
   cd WebVulf-GUI
   ```
   
2. Run the Python script:  
   ```bash
   python webvulf_gui.py
   ```

### **Optional: Create an Executable**
To create a standalone executable for Windows:
```bash
pyinstaller --onefile --noconsole webvulf_gui.py
```
The executable will be located in the `dist` folder.

## Usage

1. Launch the application by running the executable or the script.  
2. Select the desired functionality from the dropdown:
   - **CORS Vulnerability Test**: Enter the domain name.  
   - **DNS Enumeration**: Enter the domain name.  
   - **Subdomain Enumeration**: Enter the domain name and browse for a wordlist file.  
3. Click **Execute** to start the selected operation.  
4. Monitor the progress and output in the dedicated sections.  
5. Use the **Stop** button to interrupt the current process.

## Screenshots

**Main Interface**  
*![webvul_input](https://github.com/user-attachments/assets/6df5e9fc-0f2a-4a03-ae8c-622c0112d6b2)
*  

**Output Section**  
*![webvulf_output](https://github.com/user-attachments/assets/5ee4a884-f2aa-4181-a4b7-4f4fad7fee50)
*  

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.  

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.  

## Acknowledgments

- [Tkinter Documentation](https://docs.python.org/3/library/tkinter.html)  
- [dnspython](https://www.dnspython.org/)  
- [Requests Library](https://docs.python-requests.org/)

---
