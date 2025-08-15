# secure_chat.py
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import socket
import threading
import json
from crypto_module import (
    create_rsa_keys, serialize_pubkey, load_pubkey,
    create_aes_key, get_fernet, rsa_encrypt, rsa_decrypt
)

# ---------------- Global State ----------------
session = {
    "conn": None,
    "addr": None,
    "private_key": None,
    "public_key": None,
    "peer_public_key": None,
    "aes_key": None,
    "fernet": None
}

HOST = ""
PORT = 55555


# ---------------- Networking ----------------
def send_packet(packet):
    """Send a JSON packet to peer."""
    try:
        conn = session["conn"]
        if conn:
            conn.sendall(json.dumps(packet).encode())
    except Exception as e:
        print(f"Send error: {e}")

def recv_loop():
    """Listen for incoming messages."""
    conn = session["conn"]
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            packet = json.loads(data.decode())
            handle_packet(packet)
        except Exception as e:
            print(f"Receive error: {e}")
            break


# ---------------- Packet Handlers ----------------
def handle_packet(packet):
    """Process incoming JSON packets."""
    ptype = packet.get("type")
    pdata = packet.get("data")

    if ptype == "public_key":
        peer_key = load_pubkey(pdata.encode())
        session["peer_public_key"] = peer_key
        add_message("[System] Received peer's public key.")

    elif ptype == "aes_key":
        if session["private_key"]:
            decrypted_key = rsa_decrypt(session["private_key"], bytes.fromhex(pdata))
            session["aes_key"] = decrypted_key
            session["fernet"] = get_fernet(decrypted_key)
            add_message("[System] AES key received and stored.")

    elif ptype == "message":
        msg_text = pdata
        if session["fernet"]:
            try:
                msg_text = session["fernet"].decrypt(bytes.fromhex(pdata)).decode()
            except Exception as e:
                msg_text = "[Decryption failed]"
        add_message(f"Peer: {msg_text}")


# ---------------- GUI Actions ----------------
def add_message(msg):
    chat_area.config(state=tk.NORMAL)
    chat_area.insert(tk.END, msg + "\n")
    chat_area.config(state=tk.DISABLED)
    chat_area.see(tk.END)

def send_message():
    msg = msg_entry.get()
    if not msg:
        return

    # Encrypt if AES key is set
    if session["fernet"]:
        encrypted = session["fernet"].encrypt(msg.encode())
        send_packet({"type": "message", "data": encrypted.hex()})
    else:
        send_packet({"type": "message", "data": msg})

    add_message(f"You: {msg}")
    msg_entry.delete(0, tk.END)

def share_public_key():
    pem_pub = serialize_pubkey(session["public_key"]).decode()
    send_packet({"type": "public_key", "data": pem_pub})
    add_message("[System] Public key sent.")

def share_aes_key():
    if not session["peer_public_key"]:
        messagebox.showwarning("Warning", "You need the peer's public key first!")
        return
    key = create_aes_key()
    encrypted_key = rsa_encrypt(session["peer_public_key"], key)
    send_packet({"type": "aes_key", "data": encrypted_key.hex()})
    session["aes_key"] = key
    session["fernet"] = get_fernet(key)
    add_message("[System] AES key generated and sent.")

def quit_chat():
    root.destroy()
    if session["conn"]:
        session["conn"].close()


# ---------------- Connection Setup ----------------
def start_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    add_message(f"[System] Waiting for a connection on port {PORT}...")
    conn, addr = server_sock.accept()
    session["conn"] = conn
    session["addr"] = addr
    add_message(f"[System] Connected to {addr}")
    threading.Thread(target=recv_loop, daemon=True).start()

def start_client(ip):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((ip, PORT))
    session["conn"] = conn
    session["addr"] = ip
    add_message(f"[System] Connected to server at {ip}")
    threading.Thread(target=recv_loop, daemon=True).start()


# ---------------- Main ----------------
root = tk.Tk()
root.title("Secure Chat")

chat_area = scrolledtext.ScrolledText(root, width=50, height=20, state=tk.DISABLED)
chat_area.grid(row=0, column=0, columnspan=4, padx=5, pady=5)

msg_entry = tk.Entry(root, width=40)
msg_entry.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

send_btn = tk.Button(root, text="Send", command=send_message)
send_btn.grid(row=1, column=3, padx=5, pady=5)

pubkey_btn = tk.Button(root, text="Share Public Key", command=share_public_key)
pubkey_btn.grid(row=2, column=0, padx=5, pady=5)

aes_btn = tk.Button(root, text="Share AES Key", command=share_aes_key)
aes_btn.grid(row=2, column=1, padx=5, pady=5)

quit_btn = tk.Button(root, text="Quit", command=quit_chat)
quit_btn.grid(row=2, column=3, padx=5, pady=5)

# Generate RSA keypair for this session
priv, pub = create_rsa_keys()
session["private_key"] = priv
session["public_key"] = pub

# Ask role
role = simpledialog.askstring("Role", "Enter role: server or client")
if role and role.lower().startswith("s"):
    threading.Thread(target=start_server, daemon=True).start()
else:
    server_ip = simpledialog.askstring("Server IP", "Enter server IP:")
    print(server_ip)
    threading.Thread(target=start_client, args=(server_ip,), daemon=True).start()

root.mainloop()
