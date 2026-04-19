import socket

target = "127.0.0.1"

for port in range(1, 1024):
    s = socket.socket()
    s.settimeout(0.1)
    
    try:
        s.connect((target, port))
        print(f"Port {port} open")
    except:
        pass
    
    s.close()