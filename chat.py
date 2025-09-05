import socket
import threading
import time
from encryption import generate_key, share_key, encrypt_messages, decrypt_messages

LISTEN_PORT = 5003
SESSION_KEY = None

def send_msg(sock):
    global SESSION_KEY
    while True:
        msg = input("> ").encode()
        encrypted = encrypt_messages(SESSION_KEY, msg)
        sock.sendall(len(encrypted).to_bytes(4, 'big') + encrypted)

def receive_msg(sock):
    global SESSION_KEY
    while True:
        length_bytes = sock.recv(4)
        if not length_bytes:
            continue
        length = int.from_bytes(length_bytes, 'big')

        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                print("Connection lost")
                return
            data += chunk

        try:
            plaintext = decrypt_messages(SESSION_KEY, data)
            print(f"Peer: {plaintext.decode()}")
        except Exception:
            print("Message undecrypted")


def listen_for_peer(port):
    global SESSION_KEY
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(1)
    print(f"Listening on port {port}")

    conn, addr = sock.accept()
    print(f"Connection request from {addr}")

    priv, pub = generate_key()
    peer_pub = conn.recv(32)
    conn.sendall(pub)
    SESSION_KEY = share_key(priv, peer_pub)

    return conn




def connect_to_peer(ip, port):
    global SESSION_KEY
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))


    priv, pub = generate_key()
    sock.sendall(pub)                
    peer_pub = sock.recv(32)        
    SESSION_KEY = share_key(priv, peer_pub)

    return sock

if __name__ == "__main__":
    print("Listen for 1")
    print("Connect for 2")
    choice = input("Select(1 or 2): ").strip()
    
    if choice == "1":
        sock = listen_for_peer(LISTEN_PORT)
    elif choice == "2":
        ip = input("Enter ip: ").strip()
        port = int(input("Enter port: ").strip())
        sock = connect_to_peer(ip, port)
    else:
        print("Invalid")
        exit()

    t1 = threading.Thread(target=receive_msg, args=(sock,), daemon=True)
    t2 = threading.Thread(target=send_msg, args=(sock,), daemon=True)
    t1.start()
    t2.start()



    while True:
        time.sleep(1)

