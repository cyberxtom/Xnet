import socket
import sys
from datetime import datetime
import pyfiglet
import os


red = '\033[91m'
green = '\033[32m'
reset = '\033[0m'
purple = '\033[95m'
blue = '\033[34m'
if os.name == 'nt':    
    lin = os.system('cls')
else:  
    lin = os.system('clear')
def header(text: str = "X NET", font: str = "big") -> str:
    
    ascii_art = pyfiglet.figlet_format(text, font=font)

    
    colors = ["\033[91m", "\033[93m", "\033[92m",
              "\033[96m", "\033[94m", "\033[95m"]
    reset = "\033[0m"

    
    colored_lines = []
    for i, line in enumerate(ascii_art.splitlines()):
        if line.strip():
            color = colors[i % len(colors)]
            colored_lines.append(color + line + reset)
        else:
            colored_lines.append(line)

    
    width = max(len(line) for line in ascii_art.splitlines())
    border = "+" + "-" * (width + 2) + "+"
    framed = [border] + [f"| {line.ljust(width)} |" for line in colored_lines] + [border]

    return "\n".join(framed)
print(header())    

print("\033[92m \n Developed by @XTOM\033[0m")  
if len(sys.argv) == 2:
    target = socket.gethostbyname(sys.argv[1])  # Translate hostname to IPv4
else:
    print(f"{red}[-]Invalid amount of arguments.")
    print("[-]Syntax: python xnet.py <ip>"+reset)
    sys.exit()
def banner():
    print(f"{purple}")
    print("#"*50)
    print(f"\n[*] Target: {target}\n")
    print(f"[*] Scan started at: {str(datetime.now())}\n")
    print("#"*50)
    print(f"{reset}")
banner()
report = open("scan_report.txt", "w")
C_ports = [21,22,23,25,53,67,68,69,80,110,123,137,138,139,143,161,162,179,443,445,514,520,587,631,636,873,990,993,995,1080,1194,1433,1521,1723,2049,2082,2083,2095,2096,3306,3389,5432,5900,5984,6379,6667,6881,8080]
def choose(C_ports,s_port):
    print("\n>Choose the type of scan you want to perform:\n")
    print(f"\t{blue}[1]- Common Ports \n")
    print(f"\t[2]- Specific Port")          
    user = int(input(f"\n[$] Scan type:"))
    if user == 1:
        return C_ports 
    elif user == 2:
        s_port = int(input(f"{blue}[$] Enter the port number: {reset}"))
    else:
       print(f"{red}[-] Invalid option.{reset}")
       sys.exit()
    return [s_port]
s_port = 0
S_ports = choose(C_ports,s_port)





def generate_html_report(open_ports, target):
     rows = ''.join([f'<tr><td>{port} is open port</td></tr>' for port in open_ports])
     html_content = f"""
    
     <html>
     <head>
          <title>Port Scan Results for {target}</title>
          <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ font-family: Arial, sans-serif; background: rgb(21, 24, 20); height: 100%;width: 100%;}}
                h2 {{ color: #7e7e7edc; }}
                div {{ text-align: center; margin: 3vh 20vw;}}
                h1 {{ color: #00d107; background-color: rgb(21, 24, 20); padding: 15px; border-radius: 10px; border-style: none; }}
                table {{ border-collapse: collapse; width: 50%; margin: 20px auto;  box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); border-radius: 20px; overflow: hidden; border-style: none;}}
                th, td,tr {{ border: none; padding: 8px; text-align: center; }}
                th {{ background: #00d107; color: white; }}
                tr{{border-bottom: 1px solid black;}}
                td,tr {{height: 20px; background-color: rgb(85, 85, 85) ;  font-weight: 900; font-family: Impact, Haettenschweiler, 'Arial Narrow Bold', sans-serif; }}
                span {{ border-radius: 20px;overflow: hidden; border-style: none; background: #ffffff; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }}
          </style>
     </head>
     <body>
          <div>
               <h1>Xnet Report</h1>
          <h2>Open Ports for {target}</h2>
     </div><span> 
<table>
                <tr><th><h1>Ports</h1></th></tr>
                {rows}
            
          </table>
     </span>
          
     </body>
     </html>
     
     """
     with open("xnet.html", "w") as html_file:
          html_file.write(html_content)
def scanner(S_port):      

    open_ports = []
    try:
        print(f"{purple}-"*50 +f"{reset}")
        print(f"{green}\n[*] Scanning target {target}{reset}\n")
        for port in S_port:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"{green}[+] Port {port} is open{reset}")
                report.write(f"Port {port} is open\n")
                open_ports.append(port)
            
            s.close()   
        print("\n")
        print(f"{purple}#"*50 +f"{reset}")
        print(f"{green}[+] Scan completed at: {str(datetime.now())}{reset}")
        print(f"{green}[+] Html report generated: xnet.html{reset}")

        print(f"{purple}#"*50 +f"{reset}")
        generate_html_report(open_ports, target)
    except KeyboardInterrupt:
        print(f"\n{red}[-] Exiting program.{reset}")
        sys.exit()
    except socket.gaierror:
        print(f"{red}[-] Hostname could not be resolved.{reset}")
        sys.exit()
    except socket.error:
        print(f"{red}[-] Could not connect to server.{reset}")
        sys.exit()
scanner(S_ports)

report.close()     
