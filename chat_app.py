import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import threading
import json
import time
import base64
import os
from PIL import Image, ImageTk
import emoji

class ChatServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.clients = {}  # username -> socket mapping
        self.rooms = {"General": []}  # room -> list of users
        self.room_history = {"General": []}  # room -> message history
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False
        self.lock = threading.Lock()  # For thread safety
        
    def start_server(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            print(f"Server started on {self.host}:{self.port}")
            
            # Start accepting clients
            accept_thread = threading.Thread(target=self.accept_clients)
            accept_thread.daemon = True
            accept_thread.start()
            
            return True
        except Exception as e:
            print(f"Error starting server: {e}")
            return False
    
    def accept_clients(self):
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"New connection from {client_address}")
                
                # Start a thread for each client
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"Error accepting client: {e}")
    
    def handle_client(self, client_socket):
        username = None
        room = "General"
        
        try:
            while self.running:
                data = client_socket.recv(10240).decode('utf-8')
                if not data:
                    break
                    
                try:
                    message = json.loads(data)
                except json.JSONDecodeError:
                    continue
                
                # Process different message types
                if message['type'] == 'login':
                    username = message['username']
                    if username in self.clients:
                        response = {'type': 'error', 'message': 'Username already taken'}
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        continue
                    
                    with self.lock:
                        self.clients[username] = client_socket
                        self.rooms[room].append(username)
                    
                    # Send room history to the new user
                    room_history = self.room_history.get(room, [])[-20:]
                    
                    response = {
                        'type': 'login_success',
                        'message': f'Welcome to ChatSphere, {username}!',
                        'room': room,
                        'users': self.rooms[room],
                        'rooms': list(self.rooms.keys()),
                        'room_history': room_history
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    
                    # Notify other users
                    self.broadcast_message({
                        'type': 'user_joined',
                        'username': username,
                        'message': f'{username} joined the room',
                        'users': self.rooms[room]
                    }, room, exclude=username)
                    
                elif message['type'] == 'message':
                    if username and room:
                        msg_data = {
                            'type': 'message',
                            'username': username,
                            'message': message['message'],
                            'timestamp': time.strftime('%H:%M:%S'),
                            'color': message.get('color', '#000000')
                        }
                        
                        # Store message in history
                        with self.lock:
                            if room not in self.room_history:
                                self.room_history[room] = []
                            self.room_history[room].append(msg_data)
                        
                        self.broadcast_message(msg_data, room, exclude=username)
                
                elif message['type'] == 'private_message':
                    recipient = message['recipient']
                    # FIXED: Only send to the intended recipient
                    if recipient in self.clients:
                        private_msg = {
                            'type': 'private_message',
                            'sender': username,
                            'recipient': recipient,  # Added recipient field
                            'message': message['message'],
                            'timestamp': time.strftime('%H:%M:%S'),
                            'color': message.get('color', '#000000')
                        }
                        try:
                            self.clients[recipient].send(json.dumps(private_msg).encode('utf-8'))
                            # Also send confirmation to sender
                            confirmation = {
                                'type': 'private_message_sent',
                                'recipient': recipient,
                                'message': message['message'],
                                'timestamp': time.strftime('%H:%M:%S')
                            }
                            client_socket.send(json.dumps(confirmation).encode('utf-8'))
                        except:
                            # If recipient is not available
                            error_msg = {
                                'type': 'error',
                                'message': f'Could not send message to {recipient}'
                            }
                            client_socket.send(json.dumps(error_msg).encode('utf-8'))
                
                elif message['type'] == 'create_room':
                    new_room = message['room']
                    if new_room and new_room.strip():  # Check for non-empty room name
                        with self.lock:
                            if new_room not in self.rooms:
                                self.rooms[new_room] = []
                                self.room_history[new_room] = []
                                # Notify all users about the new room
                                for user in self.clients:
                                    try:
                                        self.clients[user].send(json.dumps({
                                            'type': 'new_room',
                                            'room': new_room
                                        }).encode('utf-8'))
                                    except:
                                        continue  # Skip disconnected clients
                
                elif message['type'] == 'join_room':
                    new_room = message['room']
                    if new_room in self.rooms:
                        with self.lock:
                            # Remove from current room
                            if room in self.rooms and username in self.rooms[room]:
                                self.rooms[room].remove(username)
                                self.broadcast_message({
                                    'type': 'user_left',
                                    'username': username,
                                    'message': f'{username} left the room',
                                    'users': self.rooms[room]
                                }, room, exclude=username)
                            
                            # Add to new room
                            room = new_room
                            self.rooms[room].append(username)
                        
                        # Send room history to the user
                        room_history = self.room_history.get(room, [])[-20:]
                        
                        response = {
                            'type': 'room_joined',
                            'room': room,
                            'users': self.rooms[room],
                            'message': f'Joined {room} room',
                            'room_history': room_history
                        }
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        
                        # Notify new room
                        self.broadcast_message({
                            'type': 'user_joined',
                            'username': username,
                            'message': f'{username} joined the room',
                            'users': self.rooms[room]
                        }, room, exclude=username)
                
                elif message['type'] == 'file_share':
                    if username and room:
                        # Limit file size (1MB max)
                        if len(message['filedata']) > 1_000_000:
                            error_msg = {
                                'type': 'error',
                                'message': 'File size exceeds 1MB limit'
                            }
                            client_socket.send(json.dumps(error_msg).encode('utf-8'))
                            continue
                            
                        file_msg = {
                            'type': 'file_share',
                            'username': username,
                            'filename': message['filename'],
                            'filedata': message['filedata'],
                            'timestamp': time.strftime('%H:%M:%S')
                        }
                        self.broadcast_message(file_msg, room)
        
        except Exception as e:
            print(f"Error handling client {username}: {e}")
        finally:
            if username:
                # Clean up user data
                with self.lock:
                    if username in self.clients:
                        del self.clients[username]
                    if room in self.rooms and username in self.rooms[room]:
                        self.rooms[room].remove(username)
                        self.broadcast_message({
                            'type': 'user_left',
                            'username': username,
                            'message': f'{username} left the room',
                            'users': self.rooms[room]
                        }, room, exclude=username)
                try:
                    client_socket.close()
                except:
                    pass
    
    def broadcast_message(self, message, room, exclude=None):
        if room in self.rooms:
            for username in self.rooms[room]:
                if username in self.clients and username != exclude:
                    try:
                        self.clients[username].send(json.dumps(message).encode('utf-8'))
                    except Exception as e:
                        print(f"Error broadcasting to {username}: {e}")
    
    def stop_server(self):
        self.running = False
        try:
            self.server_socket.close()
        except Exception as e:
            print(f"Error stopping server: {e}")
        print("Server stopped")


class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("ChatSphere - Multi-Room Chat Application")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Configure style
        self.setup_styles()
        
        self.socket = None
        self.connected = False
        self.username = None
        self.current_room = "General"
        self.user_colors = {}  # Store colors for each user
        
        self.setup_ui()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        self.bg_color = "#f0f0f0"
        self.sidebar_color = "#2c3e50"
        self.accent_color = "#3498db"
        self.chat_bg = "#ffffff"
        self.my_message_color = "#d4edda"
        self.other_message_color = "#f8f9fa"
        
        style.configure("TFrame", background=self.bg_color)
        style.configure("TLabel", background=self.bg_color, font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("TEntry", font=("Segoe UI", 10))
        
        # Custom styles
        style.configure("Sidebar.TFrame", background=self.sidebar_color)
        style.configure("Sidebar.TLabel", background=self.sidebar_color, foreground="white")
        style.configure("Sidebar.TButton", background="#34495e", foreground="white")
        style.configure("Accent.TButton", background=self.accent_color, foreground="white")
        style.configure("Chat.TFrame", background=self.chat_bg)
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="0")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)
        
        # Sidebar
        sidebar = ttk.Frame(main_frame, width=200, style="Sidebar.TFrame")
        sidebar.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.W))
        sidebar.grid_propagate(False)
        
        # Login frame
        login_frame = ttk.Frame(sidebar, style="Sidebar.TFrame", padding="10")
        login_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(login_frame, text="Username:", style="Sidebar.TLabel").pack(anchor=tk.W)
        self.username_entry = ttk.Entry(login_frame, width=18, font=("Segoe UI", 10))
        self.username_entry.pack(fill=tk.X, pady=(5, 10))
        
        ttk.Label(login_frame, text="Server:", style="Sidebar.TLabel").pack(anchor=tk.W)
        self.server_entry = ttk.Entry(login_frame, width=18, font=("Segoe UI", 10))
        self.server_entry.insert(0, "localhost:5555")
        self.server_entry.pack(fill=tk.X, pady=(5, 0))
        
        self.connect_button = ttk.Button(login_frame, text="Connect", command=self.connect_to_server, style="Accent.TButton")
        self.connect_button.pack(fill=tk.X, pady=(10, 0))
        
        # Rooms frame
        rooms_frame = ttk.Frame(sidebar, style="Sidebar.TFrame", padding="10")
        rooms_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(rooms_frame, text="Rooms", style="Sidebar.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # Room list with scrollbar
        room_list_frame = ttk.Frame(rooms_frame, style="Sidebar.TFrame")
        room_list_frame.pack(fill=tk.X)
        
        self.rooms_listbox = tk.Listbox(room_list_frame, width=20, height=8, bg="#34495e", fg="white", 
                                       selectbackground=self.accent_color, font=("Segoe UI", 10),
                                       relief=tk.FLAT, highlightthickness=0)
        self.rooms_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        room_scrollbar = ttk.Scrollbar(room_list_frame, orient=tk.VERTICAL, command=self.rooms_listbox.yview)
        room_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rooms_listbox.config(yscrollcommand=room_scrollbar.set)
        
        self.rooms_listbox.insert(tk.END, "General")
        
        # Room controls
        room_controls = ttk.Frame(rooms_frame, style="Sidebar.TFrame")
        room_controls.pack(fill=tk.X, pady=(5, 0))
        
        self.room_entry = ttk.Entry(room_controls, font=("Segoe UI", 10))
        self.room_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.create_room_button = ttk.Button(room_controls, text="+", width=3, command=self.create_room, state=tk.DISABLED, style="Sidebar.TButton")
        self.create_room_button.pack(side=tk.RIGHT)
        
        self.join_room_button = ttk.Button(rooms_frame, text="Join Room", command=self.join_room, state=tk.DISABLED, style="Sidebar.TButton")
        self.join_room_button.pack(fill=tk.X, pady=(5, 0))
        
        # Users frame
        users_frame = ttk.Frame(sidebar, style="Sidebar.TFrame", padding="10")
        users_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(users_frame, text="Online Users", style="Sidebar.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        # User list with scrollbar
        user_list_frame = ttk.Frame(users_frame, style="Sidebar.TFrame")
        user_list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.users_listbox = tk.Listbox(user_list_frame, width=20, height=10, bg="#34495e", fg="white", 
                                       selectbackground=self.accent_color, font=("Segoe UI", 10),
                                       relief=tk.FLAT, highlightthickness=0)
        self.users_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        user_scrollbar = ttk.Scrollbar(user_list_frame, orient=tk.VERTICAL, command=self.users_listbox.yview)
        user_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.users_listbox.config(yscrollcommand=user_scrollbar.set)
        
        # Chat area
        chat_frame = ttk.Frame(main_frame, style="Chat.TFrame", padding="10")
        chat_frame.grid(row=0, column=1, sticky=(tk.N, tk.S, tk.W, tk.E))
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)
        
        # Chat display with custom styling
        self.chat_display = scrolledtext.ScrolledText(chat_frame, width=50, height=20, state=tk.DISABLED,
                                                     font=("Segoe UI", 10), wrap=tk.WORD, padx=10, pady=10,
                                                     relief=tk.FLAT, highlightthickness=1,
                                                     highlightbackground="#e0e0e0")
        self.chat_display.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Message entry - using Text widget for multi-line support
        self.message_entry = scrolledtext.ScrolledText(chat_frame, height=3, font=("Segoe UI", 10),
                                                      relief=tk.FLAT, highlightthickness=1,
                                                      highlightbackground="#e0e0e0")
        self.message_entry.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.S), pady=(0, 10))
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<Control-Return>", self.new_line)
        
        self.send_button = ttk.Button(chat_frame, text="Send", command=self.send_message, state=tk.DISABLED, style="Accent.TButton")
        self.send_button.grid(row=1, column=1, sticky=tk.E, pady=(0, 10), padx=(10, 0))
        
        # Private message frame
        pm_frame = ttk.Frame(chat_frame)
        pm_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        ttk.Label(pm_frame, text="Private to:", font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 5))
        self.pm_entry = ttk.Entry(pm_frame, width=15, font=("Segoe UI", 9))
        self.pm_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.pm_button = ttk.Button(pm_frame, text="Send", command=self.send_private_message, state=tk.DISABLED, style="Accent.TButton")
        self.pm_button.pack(side=tk.RIGHT)
        
        # Message formatting toolbar
        toolbar = ttk.Frame(chat_frame)
        toolbar.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Emoji button
        emoji_button = ttk.Button(toolbar, text="😊", width=3, command=self.show_emoji_picker)
        emoji_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Formatting buttons
        bold_button = ttk.Button(toolbar, text="B", width=3, command=lambda: self.format_text("bold"))
        bold_button.pack(side=tk.LEFT, padx=(0, 5))
        
        italic_button = ttk.Button(toolbar, text="I", width=3, command=lambda: self.format_text("italic"))
        italic_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # File attachment button
        file_button = ttk.Button(toolbar, text="📎", width=3, command=self.attach_file)
        file_button.pack(side=tk.LEFT)
        
        # Color selection
        ttk.Label(toolbar, text="Color:").pack(side=tk.LEFT, padx=(20, 5))
        self.color_var = tk.StringVar(value="#000000")
        color_combo = ttk.Combobox(toolbar, textvariable=self.color_var, width=8, state="readonly")
        color_combo['values'] = ('#000000', '#FF0000', '#00AA00', '#0000FF', '#FF00FF', '#FF5500')
        color_combo.pack(side=tk.LEFT)
        
        # Status bar
        status_frame = ttk.Frame(self.root, relief=tk.SUNKEN)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_var = tk.StringVar(value="Not connected")
        status_bar = ttk.Label(status_frame, textvariable=self.status_var, anchor=tk.W, font=("Segoe UI", 9))
        status_bar.pack(side=tk.LEFT, padx=5)
        
        self.room_status_var = tk.StringVar(value="Room: None")
        room_status = ttk.Label(status_frame, textvariable=self.room_status_var, anchor=tk.W, font=("Segoe UI", 9))
        room_status.pack(side=tk.LEFT, padx=5)
        
        self.user_count_var = tk.StringVar(value="Users: 0")
        user_count = ttk.Label(status_frame, textvariable=self.user_count_var, anchor=tk.W, font=("Segoe UI", 9))
        user_count.pack(side=tk.LEFT, padx=5)
        
        # Configure text tags for styling
        self.configure_chat_tags()
        
        # Bind user list selection to PM field
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
    def configure_chat_tags(self):
        self.chat_display.tag_config("timestamp", foreground="gray", font=("Segoe UI", 8))
        self.chat_display.tag_config("system", foreground="blue", font=("Segoe UI", 10))
        self.chat_display.tag_config("username", font=("Segoe UI", 10, "bold"))
        self.chat_display.tag_config("pm_username", foreground="purple", font=("Segoe UI", 10, "bold"))
        self.chat_display.tag_config("pm_message", foreground="purple")
        self.chat_display.tag_config("my_message", background=self.my_message_color, lmargin1=20, lmargin2=20, rmargin=20)
        self.chat_display.tag_config("other_message", background=self.other_message_color, lmargin1=20, lmargin2=20, rmargin=20)
        self.chat_display.tag_config("bold", font=("Segoe UI", 10, "bold"))
        self.chat_display.tag_config("italic", font=("Segoe UI", 10, "italic"))
        self.chat_display.tag_config("file", foreground="blue", underline=1)
        
    def on_user_select(self, event):
        # Auto-fill PM field when user selects from user list
        selection = self.users_listbox.curselection()
        if selection:
            user = self.users_listbox.get(selection[0])
            if user != self.username:  # Don't PM yourself
                self.pm_entry.delete(0, tk.END)
                self.pm_entry.insert(0, user)
        
    def connect_to_server(self):
        if self.connected:
            self.disconnect_from_server()
            return
            
        username = self.username_entry.get().strip()
        server_info = self.server_entry.get().strip()
        
        if not username:
            messagebox.showerror("Error", "Please enter a username")
            return
            
        if not server_info:
            messagebox.showerror("Error", "Please enter server address")
            return
            
        try:
            host, port = server_info.split(":")
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Invalid server format. Use host:port")
            return
            
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True
            
            # Start listening thread
            listen_thread = threading.Thread(target=self.listen_to_server)
            listen_thread.daemon = True
            listen_thread.start()
            
            # Send login message
            login_message = {
                'type': 'login',
                'username': username
            }
            self.socket.send(json.dumps(login_message).encode('utf-8'))
            
            self.username = username
            self.connect_button.config(text="Disconnect")
            self.username_entry.config(state=tk.DISABLED)
            self.server_entry.config(state=tk.DISABLED)
            self.status_var.set(f"Connected to {host}:{port}")
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            if self.socket:
                self.socket.close()
                self.socket = None
                
    def disconnect_from_server(self):
        if self.socket:
            self.socket.close()
            self.socket = None
        self.connected = False
        self.connect_button.config(text="Connect")
        self.username_entry.config(state=tk.NORMAL)
        self.server_entry.config(state=tk.NORMAL)
        self.send_button.config(state=tk.DISABLED)
        self.pm_button.config(state=tk.DISABLED)
        self.create_room_button.config(state=tk.DISABLED)
        self.join_room_button.config(state=tk.DISABLED)
        self.status_var.set("Not connected")
        self.room_status_var.set("Room: None")
        self.user_count_var.set("Users: 0")
        self.add_message_to_chat("System", "Disconnected from server")
        
    def listen_to_server(self):
        while self.connected:
            try:
                data = self.socket.recv(10240).decode('utf-8')
                if not data:
                    break
                    
                message = json.loads(data)
                self.handle_server_message(message)
                
            except Exception as e:
                if self.connected:
                    print(f"Error receiving data: {e}")
                break
                
        self.disconnect_from_server()
        
    def handle_server_message(self, message):
        msg_type = message.get('type')
        
        if msg_type == 'login_success':
            self.add_message_to_chat("System", message['message'])
            self.current_room = message['room']
            self.update_users_list(message['users'])
            self.update_rooms_list(message['rooms'])
            self.send_button.config(state=tk.NORMAL)
            self.pm_button.config(state=tk.NORMAL)
            self.create_room_button.config(state=tk.NORMAL)
            self.join_room_button.config(state=tk.NORMAL)
            self.room_status_var.set(f"Room: {self.current_room}")
            
            # Load room history
            for msg in message.get('room_history', []):
                if msg['username'] == self.username:
                    self.add_message_to_chat(msg['username'], msg['message'], msg['timestamp'], is_me=True, color=msg.get('color', '#000000'))
                else:
                    self.add_message_to_chat(msg['username'], msg['message'], msg['timestamp'], is_me=False, color=msg.get('color', '#000000'))
            
        elif msg_type == 'error':
            messagebox.showerror("Error", message['message'])
            
        elif msg_type == 'message':
            is_me = message['username'] == self.username
            self.add_message_to_chat(message['username'], message['message'], message.get('timestamp'), is_me, message.get('color', '#000000'))
            
        elif msg_type == 'private_message':
            # FIXED: Only display if it's for the current user
            if message.get('recipient') == self.username or message.get('sender') == self.username:
                self.add_private_message_to_chat(
                    message['sender'], message['message'], message.get('timestamp'), message.get('color', '#000000')
                )
            
        elif msg_type == 'private_message_sent':
            # Confirmation that private message was sent
            self.add_private_message_to_chat(
                f"To {message['recipient']}", message['message'], message.get('timestamp'), "#000000"
            )
            
        elif msg_type == 'user_joined':
            self.add_message_to_chat("System", message['message'])
            self.update_users_list(message['users'])
            
        elif msg_type == 'user_left':
            self.add_message_to_chat("System", message['message'])
            self.update_users_list(message['users'])
            
        elif msg_type == 'room_joined':
            self.current_room = message['room']
            self.add_message_to_chat("System", message['message'])
            self.update_users_list(message['users'])
            self.room_status_var.set(f"Room: {self.current_room}")
            
            # Load room history
            for msg in message.get('room_history', []):
                if msg['username'] == self.username:
                    self.add_message_to_chat(msg['username'], msg['message'], msg['timestamp'], is_me=True, color=msg.get('color', '#000000'))
                else:
                    self.add_message_to_chat(msg['username'], msg['message'], msg['timestamp'], is_me=False, color=msg.get('color', '#000000'))
            
        elif msg_type == 'new_room':
            self.rooms_listbox.insert(tk.END, message['room'])
            
        elif msg_type == 'file_share':
            self.display_file_message(message['username'], message['filename'], message['filedata'], message.get('timestamp'))
            
    def send_message(self, event=None):
        if not self.connected:
            return
            
        message = self.message_entry.get("1.0", tk.END).strip()
        if not message:
            return
            
        msg_data = {
            'type': 'message',
            'message': message,
            'color': self.color_var.get()
        }
        
        try:
            self.socket.send(json.dumps(msg_data).encode('utf-8'))
            self.message_entry.delete("1.0", tk.END)
        except Exception as e:
            print(f"Error sending message: {e}")
            self.disconnect_from_server()
            
    def send_private_message(self, event=None):
        if not self.connected:
            return
            
        recipient = self.pm_entry.get().strip()
        message = self.message_entry.get("1.0", tk.END).strip()
        
        if not recipient:
            messagebox.showwarning("Warning", "Please enter a recipient")
            return
            
        if not message:
            messagebox.showwarning("Warning", "Please enter a message")
            return
            
        if recipient == self.username:
            messagebox.showwarning("Warning", "You cannot send a private message to yourself")
            return
            
        msg_data = {
            'type': 'private_message',
            'recipient': recipient,
            'message': message,
            'color': self.color_var.get()
        }
        
        try:
            self.socket.send(json.dumps(msg_data).encode('utf-8'))
            self.pm_entry.delete(0, tk.END)
            self.message_entry.delete("1.0", tk.END)
        except Exception as e:
            print(f"Error sending private message: {e}")
            self.disconnect_from_server()
            
    def create_room(self):
        if not self.connected:
            return
            
        room_name = self.room_entry.get().strip()
        if not room_name:
            messagebox.showerror("Error", "Please enter a room name")
            return
            
        if room_name in self.rooms_listbox.get(0, tk.END):
            messagebox.showerror("Error", "Room already exists")
            return
            
        msg_data = {
            'type': 'create_room',
            'room': room_name
        }
        
        try:
            self.socket.send(json.dumps(msg_data).encode('utf-8'))
            self.room_entry.delete(0, tk.END)
        except Exception as e:
            print(f"Error creating room: {e}")
            self.disconnect_from_server()
            
    def join_room(self):
        if not self.connected:
            return
            
        selection = self.rooms_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a room to join")
            return
            
        room_name = self.rooms_listbox.get(selection[0])
        
        msg_data = {
            'type': 'join_room',
            'room': room_name
        }
        
        try:
            self.socket.send(json.dumps(msg_data).encode('utf-8'))
        except Exception as e:
            print(f"Error joining room: {e}")
            self.disconnect_from_server()
            
    def add_message_to_chat(self, username, message, timestamp=None, is_me=False, color="#000000"):
        self.chat_display.config(state=tk.NORMAL)
        
        if timestamp:
            time_str = f"[{timestamp}] "
        else:
            time_str = f"[{time.strftime('%H:%M:%S')}] "
            
        # Insert timestamp
        self.chat_display.insert(tk.END, time_str, "timestamp")
        
        if username == "System":
            self.chat_display.insert(tk.END, f"{message}\n", "system")
        else:
            # Assign a color for the user if not already assigned
            if username not in self.user_colors:
                colors = ['#FF5500', '#00AA00', '#0000FF', '#FF00FF', '#AA00AA', '#0055FF']
                self.user_colors[username] = colors[len(self.user_colors) % len(colors)]
            
            user_color = self.user_colors[username]
            
            # Insert username with color
            self.chat_display.insert(tk.END, f"{username}: ", ("username", f"color_{username}"))
            self.chat_display.tag_config(f"color_{username}", foreground=user_color)
            
            # Insert message with background based on sender
            message_tag = "my_message" if is_me else "other_message"
            self.chat_display.insert(tk.END, f"{message}\n", (message_tag, f"msg_color_{username}"))
            self.chat_display.tag_config(f"msg_color_{username}", foreground=color)
            
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
        
    def add_private_message_to_chat(self, username, message, timestamp=None, color="#000000"):
        self.chat_display.config(state=tk.NORMAL)
        
        if timestamp:
            time_str = f"[{timestamp}] "
        else:
            time_str = f"[{time.strftime('%H:%M:%S')}] "
            
        self.chat_display.insert(tk.END, time_str, "timestamp")
        self.chat_display.insert(tk.END, f"{username} ", "pm_username")
        self.chat_display.insert(tk.END, f"{message}\n", ("pm_message", f"pm_color_{username}"))
        self.chat_display.tag_config(f"pm_color_{username}", foreground=color)
        
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
        
    def display_file_message(self, username, filename, filedata, timestamp=None):
        self.chat_display.config(state=tk.NORMAL)
        
        if timestamp:
            time_str = f"[{timestamp}] "
        else:
            time_str = f"[{time.strftime('%H:%M:%S')}] "
            
        self.chat_display.insert(tk.END, time_str, "timestamp")
        self.chat_display.insert(tk.END, f"{username} sent a file: ", "username")
        
        # Create a clickable file link
        file_tag = f"file_{filename}_{time.time()}"
        self.chat_display.insert(tk.END, f"{filename}\n", ("file", file_tag))
        self.chat_display.tag_bind(file_tag, "<Button-1>", 
                                  lambda e, data=filedata, name=filename: self.save_file(data, name))
        
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
        
    def save_file(self, filedata, filename):
        """Save a received file"""
        try:
            file_bytes = base64.b64decode(filedata)
            file_path = filedialog.asksaveasfilename(
                initialfile=filename,
                title="Save file",
                filetypes=[("All files", "*.*")]
            )
            if file_path:
                with open(file_path, 'wb') as f:
                    f.write(file_bytes)
                messagebox.showinfo("Success", f"File saved as {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save file: {e}")
        
    def update_users_list(self, users):
        self.users_listbox.delete(0, tk.END)
        for user in sorted(users):
            if user != self.username:  # Don't show yourself in the user list
                self.users_listbox.insert(tk.END, user)
        self.user_count_var.set(f"Users: {len(users)}")
        
    def update_rooms_list(self, rooms):
        self.rooms_listbox.delete(0, tk.END)
        for room in sorted(rooms):
            self.rooms_listbox.insert(tk.END, room)
            
    def format_text(self, format_type):
        """Add formatting to the current message"""
        if format_type == "bold":
            self.insert_text_formatted("**", "**")
        elif format_type == "italic":
            self.insert_text_formatted("*", "*")
            
    def insert_text_formatted(self, start_tag, end_tag):
        """Insert formatting tags around selected text"""
        try:
            if self.message_entry.tag_ranges(tk.SEL):
                start = self.message_entry.index(tk.SEL_FIRST)
                end = self.message_entry.index(tk.SEL_LAST)
                
                selected_text = self.message_entry.get(start, end)
                self.message_entry.delete(start, end)
                self.message_entry.insert(start, f"{start_tag}{selected_text}{end_tag}")
            else:
                
                cursor_pos = self.message_entry.index(tk.INSERT)
                self.message_entry.insert(cursor_pos, f"{start_tag}{end_tag}")
                self.message_entry.mark_set(tk.INSERT, f"{cursor_pos}+{len(start_tag)}c")
        except Exception as e:
            print(f"Error formatting text: {e}")
            
    def show_emoji_picker(self):
        """Show a simple emoji picker"""
        emoji_window = tk.Toplevel(self.root)
        emoji_window.title("Emoji Picker")
        emoji_window.geometry("300x200")
        emoji_window.transient(self.root)
        emoji_window.grab_set()
        
        
        common_emojis = ["😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇", 
                        "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚",
                        "👍", "👎", "❤️", "🔥", "🎉", "🙏", "🤔", "🤯", "😎", "🥳"]
        
        emoji_frame = ttk.Frame(emoji_window)
        emoji_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        row, col = 0, 0
        for e in common_emojis:
            btn = ttk.Button(emoji_frame, text=e, width=3, 
                            command=lambda emoji=e: self.insert_emoji(emoji, emoji_window))
            btn.grid(row=row, column=col, padx=2, pady=2)
            col += 1
            if col > 5:
                col = 0
                row += 1
                
    def insert_emoji(self, emoji_char, window):
        """Insert selected emoji into message field"""
        self.message_entry.insert(tk.INSERT, emoji_char)
        window.destroy()
        
    def attach_file(self):
        """Attach a file to the message"""
        file_path = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[("All files", "*.*")]
        )
        
        if file_path:
            try:
                file_size = os.path.getsize(file_path)
                if file_size > 1_000_000:  # 1MB limit
                    messagebox.showerror("Error", "File size exceeds 1MB limit")
                    return
                    
                with open(file_path, 'rb') as f:
                    file_data = base64.b64encode(f.read()).decode('utf-8')
                    
                filename = os.path.basename(file_path)
                
                msg_data = {
                    'type': 'file_share',
                    'filename': filename,
                    'filedata': file_data
                }
                
                self.socket.send(json.dumps(msg_data).encode('utf-8'))
                
            except Exception as e:
                messagebox.showerror("Error", f"Could not send file: {e}")
                
    def new_line(self, event=None):
        """Insert a new line in the message entry (Ctrl+Enter)"""
        self.message_entry.insert(tk.INSERT, "\n")
        return "break"  


def start_server():
    server = ChatServer()
    if server.start_server():
        print("Server is running...")
        try:
            
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Shutting down server...")
            server.stop_server()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        start_server()
    else:
        root = tk.Tk()
        app = ChatClient(root)
        root.mainloop()
