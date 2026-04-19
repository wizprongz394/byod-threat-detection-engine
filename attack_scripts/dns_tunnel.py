import socket
import random
import string
import time

def random_domain():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=30)) + ".com"

while True:
    domain = random_domain()
    print("Querying:", domain)
    
    try:
        socket.gethostbyname(domain)
    except:
        pass
    
    time.sleep(1)  # control speed