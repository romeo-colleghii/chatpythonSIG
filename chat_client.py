import socket
import rsa
import datetime
import threading
from cryptography.fernet import Fernet
 
def ricevi_messaggi(sock, cipher):
    """Thread per ricevere e stampare i messaggi dal server"""
    while True:
        try:
            # Ricevi messaggio cifrato dal server
            data_cifrato = sock.recv(4096)
            if not data_cifrato:
                print("\n Connessione chiusa dal server")
                break
            # Decifra il messaggio
            try:
                msg_decifrato = cipher.decrypt(data_cifrato).decode()
                print(f"\n{msg_decifrato}")
                print("Tu: ", end="", flush=True)
            except Exception as e:
                print(f"\n Errore decifratura: {e}")
                print("Tu: ", end="", flush=True)
        except ConnectionResetError:
            print("\n Connessione persa con il server")
            break
        except Exception as e:
            print(f"\n Errore ricezione: {e}")
            break
 
def invia_messaggi(sock, cipher, username):
    """Thread per inviare messaggi al server"""
    while True:
        try:
            msg = input("Tu: ")
            # Se l'utente vuole inviare un messaggio segreto
            if msg.startswith("/secret "):
                # Formato: /secret <messaggio_segreto>
                secret_msg = msg[8:]  # Rimuovi "/secret "
                # Formato: messaggio_pubblico|SECRET|messaggio_segreto
                full_msg = f"{username} ha inviato un messaggio segreto|SECRET|{secret_msg}"
                print(f" Messaggio segreto inviato (solo il server lo vede)")
            else:
                full_msg = msg
            # Aggiungi timestamp
            tempo = datetime.datetime.now()
            full_msg_with_time = f"[{tempo.strftime('%H:%M:%S')}] {username}: {full_msg}"
            # Cifra e invia
            msg_cifrato = cipher.encrypt(full_msg_with_time.encode())
            sock.sendall(msg_cifrato)
        except KeyboardInterrupt:
            print("\n Chiusura chat...")
            break
        except Exception as e:
            print(f" Errore invio: {e}")
            break
 
# 1. Connessione al server
HOST = '192.168.137.1'  # Indirizzo del server
PORT = 8888
 
print(f" Connessione a {HOST}:{PORT}...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
print(" Connesso al server!")
 
# 2. Ricevi la chiave pubblica RSA dal server
print(" Ricezione chiave pubblica RSA...")
pub_pem = sock.recv(4096)  # Aumentato buffer per sicurezza
server_pub = rsa.PublicKey.load_pkcs1(pub_pem)
print(" Ricevuta chiave pubblica dal server")
 
# 3. Genera chiave Fernet e cifrala con RSA
print(" Generazione chiave Fernet...")
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)
key_cifrata = rsa.encrypt(fernet_key, server_pub)
 
# 4. Invia la chiave cifrata
sock.sendall(key_cifrata)
print(" Inviata chiave sessione cifrata al server")
 
# 5. Invia username cifrato
username = input("Inserisci il tuo username: ")
username_cifrato = cipher.encrypt(username.encode())
sock.sendall(username_cifrato)
print(f" Benvenuto {username}! Connesso alla chat sicura")
print(" Comandi speciali:")
print("   /secret <messaggio> - Invia un messaggio visibile solo al server")
print("   Ctrl+C - Esci dalla chat")
print("\n" + "="*50 + "\n")
 
# 6. Avvia thread per ricevere messaggi
thread_ricezione = threading.Thread(target=ricevi_messaggi, args=(sock, cipher), daemon=True)
thread_ricezione.start()
 
# 7. Thread principale per inviare messaggi
try:
    invia_messaggi(sock, cipher, username)
except KeyboardInterrupt:
    print("\n Disconnessione...")
finally:
    sock.close()