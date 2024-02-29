import tkinter as tk
from tkinter import PhotoImage ,scrolledtext, messagebox, Menu
import threading
import socket
import rsa
import re
import json

# Initialize RSA keys
(public_key, private_key) = rsa.newkeys(2048) 

# Server and Client socket setup
server = None
client = None
connected_client_socket = None  

# Setup GUI
root = tk.Tk()
root.title("Secure Chat Application")
root.geometry('360x640')  # fixed size
root.resizable(False, False)  # Disable resizing
root.configure(bg='#ADD8E6')

# Constants
SERVER_PORT = 9999
BUFFER_SIZE = 1024

# GUI Elements Styling
BUTTON_BG = "#00BFFF"
BUTTON_FG = "white"
MESSAGE_BOX_BG = "#F0FFFF"  # background color for message display box
TITLE_BG = "#ADD8E6"
TITLE_FG = "#00008B"

# GUI responsiveness
for i in range(5):
    root.grid_rowconfigure(i, weight=1)
    root.grid_columnconfigure(i, weight=1)

# Validate IP address function
def validate_ip(ip):
    pattern = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return pattern.match(ip)

# Function to accept client connections
def accept_connections(server_socket):
    global public_partner, connected_client_socket
    while True:
        client_socket, client_address = server_socket.accept()
        connected_client_socket = client_socket  # Update to keep track of the connected client
        messagebox.showinfo("Connection Established", f"Connection from {client_address} has been established.")
        display_message("System: Hosting started. Waiting for connections...")
        # Send public key to the connected client
        client_socket.send(json.dumps({'public_key': public_key.save_pkcs1().decode()}).encode('utf-8'))
        start_receiving_thread(client_socket)

# Function to start receiving messages thread
def start_receiving_thread(conn):
    thread = threading.Thread(target=receive_message, args=(conn,))
    thread.daemon = True
    thread.start()

# Function to display messages in the GUI
def display_message(msg):
    message_display.configure(state='normal')
    message_display.insert(tk.END, msg + "\n")
    message_display.configure(state='disabled')
    message_display.see(tk.END)

# Function to receive messages and update GUI
def receive_message(conn):
    global private_key, public_partner
    while True:
        try:
            message = conn.recv(BUFFER_SIZE)
            if message:
                try:
                    # Attempt to decode as JSON first to check for public key exchange
                    decoded_message = message.decode('utf-8')
                    data = json.loads(decoded_message)
                    if 'public_key' in data:
                        public_partner = rsa.PublicKey.load_pkcs1(data['public_key'].encode())
                        display_message("System: Connected successfully.")
                        continue
                except (UnicodeDecodeError, json.JSONDecodeError):
                    # Handle encrypted message
                    decrypted_message = rsa.decrypt(message, private_key).decode('utf-8')
                    display_message(f"Friend: {decrypted_message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Function to host a chat
def host_chat():
    global server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(('', SERVER_PORT))
        server.listen(5)
        display_message("System: Hosting chat on port " + str(SERVER_PORT))
        threading.Thread(target=accept_connections, args=(server,), daemon=True).start()
    except Exception as e:
        messagebox.showerror("Hosting Failed", f"Failed to host chat: {e}")
        if server:
            server.close()

# Function to join a chat
def join_chat():
    global client
    ip = ip_entry.get()
    display_message("You: Entered IP " + ip)
    if not validate_ip(ip):
        messagebox.showerror("Invalid IP", "Please enter a valid IP address.")
        return
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((ip, SERVER_PORT))
        # Send public key to the server
        client.send(json.dumps({'public_key': public_key.save_pkcs1().decode()}).encode('utf-8'))
        display_message("System: Attempting to connect...")
        start_receiving_thread(client)
    except Exception as e:
        messagebox.showerror("Connection Failed", f"Failed to connect to chat: {e}")
        if client:
            client.close()

# Function to send encrypted messages
def send_message(event=None):
    global client, public_partner, connected_client_socket
    message = message_entry.get().strip()
    if message and public_partner:
        try:
            encrypted_message = rsa.encrypt(message.encode('utf-8'), public_partner)
            if client:  # If joined as a client
                client.send(encrypted_message)
            elif connected_client_socket:  # If hosting a chat
                connected_client_socket.send(encrypted_message)
            display_message(f"You: {message}")
            message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Failed", f"Failed to send message: {e}")

# Function to display about information
def display_about():
    messagebox.showinfo("About", "This is a secure chat application using RSA encryption.")

# Function to display help information
def display_help():
    messagebox.showinfo("Help", "It's Simple to use "
                               "You can either host a chat or join an existing one by entering the IP address "
                               "of the host.")

# Function to exit the application
def exit_application():
    if server:
        server.close()
    if client:
        client.close()
    root.quit()

# Add a styled label for the app name
app_name_label = tk.Label(root, text="Secure Chat", font=("Helvetica", 16, "bold"), bg='#FF0000', fg='#FFFFFF')
app_name_label.grid(row=0, column=0, columnspan=5, pady=10)

# Add menu
menu_bar = Menu(root)
root.config(menu=menu_bar)

file_menu = Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Exit", command=exit_application)

help_menu = Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="About", command=display_about)
help_menu.add_command(label="Help", command=display_help)

# GUI Elements with updated styling and custom size
ip_label = tk.Label(root, text="IP Address:", bg='#40FA04')
ip_label.grid(row=1, column=0, pady=5, sticky=tk.E)

ip_entry = tk.Entry(root, width=15)
ip_entry.grid(row=1, column=1, columnspan=2, pady=5)

host_button = tk.Button(root, text="Host Chat", command=host_chat, bg='#FE6000', fg=BUTTON_FG)
host_button.grid(row=1, column=3, pady=5)

join_button = tk.Button(root, text="Join Chat", command=join_chat, bg='#FE6000', fg=BUTTON_FG)
join_button.grid(row=1, column=4, pady=5)

# Custom size for message display
message_display = scrolledtext.ScrolledText(root, height=15, width=50, )  # Adjust height as needed
message_display.grid(row=2, column=0, columnspan=5, pady=5)
message_display.configure(state='disabled')

message_label = tk.Label(root, text="Message:", bg='#40FA04')
message_label.grid(row=3, column=0, pady=5, sticky=tk.E)

message_entry = tk.Entry(root, width=35,)
message_entry.grid(row=3, column=1, columnspan=3, pady=5)
message_entry.bind("<Return>", send_message)

send_button = tk.Button(root, text="Send", command=send_message, bg='#FA0000', fg=BUTTON_FG)
send_button.grid(row=3, column=4, pady=5)

# Starting GUI event loop
root.mainloop()
