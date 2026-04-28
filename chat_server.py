import selectors
import socket
import sys
import types
import rsa
from cryptography.fernet import Fernet

sel = selectors.DefaultSelector()
clients = {}

def accept_wrapper(sock):
    conn, addr = sock.accept()
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, username=None, outb=b"")
    clients[conn] = data
    sel.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)

def broadcast(sender_sock, message):
    """Invia messaggio a tutti i client tranne il mittente"""
    for client_sock, client_data in clients.items():
        if client_sock != sender_sock:
            client_data.outb += message

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data

    # 1. Genera RSA UNA VOLTA SOLA (per tutto il server)
    if not hasattr(data, 'rsa_pub'):    
      data.rsa_pub, data.rsa_priv = rsa.newkeys(1024)    
      print("🔑 Server RSA pub generata:", data.rsa_pub)
    # 2. INVIA la chiave pubblica RSA al client
    sock.sendall(data.rsa_pub.save_pkcs1())
    print("📤 Inviata RSA pub al client")
    # 3. RICEVI la chiave Fernet CIFRATA dal client
    key_cifrata = sock.recv(1024)
    data.session_key = rsa.decrypt(key_cifrata, data.rsa_priv)
    data.cipher = Fernet(data.session_key)
    print("✅ Ricevuta chiave sessione:", data.session_key)

    if mask & selectors.EVENT_READ:
        try:
            recv_data = sock.recv(1024)
        except ConnectionResetError:
            print(f"{data.username or sock.getpeername()} disconnected abruptly")
            sel.unregister(sock)
            sock.close()
            clients.pop(sock, None)
            return

        if recv_data:
            # Primo messaggio = username
            if data.username is None:
                data.username = recv_data.decode()
                print(f"{data.username} joined the chat from {data.addr}")
                join_msg = f"{data.username} joined the chat\n".encode()
                broadcast(sock, join_msg)
                return

            # Separazione messaggio pubblico e segreto
            if b"|SECRET|" in recv_data:
                public, secret = recv_data.split(b"|SECRET|")
                public = public.decode()
                print(f"{data.username}: {public}")
                try:
                    secret_msg = data.cipher.decrypt(recv_data).decode()
                    print(f"[SERVER SECRET from {data.username}]: {secret_msg}")
                except Exception as e:
                    print(f"[SERVER SECRET from {data.username}]: Could not decrypt message ({e})")

                # Broadcast messaggio pubblico
                broadcast_msg = f"{data.username}: {public}\n".encode()
                broadcast(sock, broadcast_msg)

            else:
                msg = recv_data.decode()
                print(f"{data.username}: {msg}")
                broadcast(sock, f"{data.username}: {msg}\n".encode())

        else:
            print(f"{data.username} left the chat")
            leave_msg = f"{data.username} left the chat\n".encode()
            broadcast(sock, leave_msg)
            sel.unregister(sock)
            sock.close()
            clients.pop(sock, None)

    if mask & selectors.EVENT_WRITE:
        if data.outb:
            try:
                sent = sock.send(data.outb)
                data.outb = data.outb[sent:]
            except ConnectionResetError:
                sel.unregister(sock)
                sock.close()
                clients.pop(sock, None)

# Controllo argomenti
if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <host> <port>")
    sys.exit(1)

host, port = sys.argv[1], int(sys.argv[2])

# Socket di ascolto
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((host, port))
lsock.listen()
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

print(f"Server listening on {(host, port)}")

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)

except KeyboardInterrupt:
    print("\nServer stopped")
finally:
    sel.close()