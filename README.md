# 💬 ChatSphere - Multi-Room Chat Application  

**ChatSphere** is a feature-rich, multi-room chat application built with **Python** and **Tkinter**.  
It supports **real-time messaging**, **private conversations**, **file sharing**, and **multiple chat rooms**.  

---

## ✨ Features  

- 🔹 **Multi-Room Support**: Create and join different chat rooms  
- ⚡ **Real-Time Messaging**: Instant message delivery with timestamps  
- 👤 **Private Messaging**: Send direct messages to specific users  
- 📎 **File Sharing**: Share files with other users (up to **1MB**)  
- 🧑‍🤝‍🧑 **User List**: See who's online in each room  
- 📝 **Message Formatting**: Bold and italic text formatting  
- 😀 **Emoji Support**: Insert emojis into your messages  
- 🎨 **Custom Colors**: Color-coded usernames and messages  
- 📜 **Message History**: View recent messages when joining a room  
- 💻 **Cross-Platform**: Works on **Windows, macOS, and Linux**  

---

## ⚙️ Installation  

### ✅ Prerequisites  
- **Python 3.6+**  
- **pip** (Python package manager)  

### 📦 Required Libraries  
Install dependencies:  

```bash
pip install pillow emoji check
```

### 🚀 Usage
1. Starting the Server

Run the server:

```bash
python chat_app.py server
```
Default server runs on localhost:5555.


### 2. Starting the Client

Run the client:
```bash
python chat_app.py
```
You can launch multiple clients to simulate multiple users.

### 3. Connecting to the Server

Enter your username

Enter server address (default: localhost:5555)

Click Connect

### 🏠 Room Management

Join a Room → Select a room and click Join Room

Create a Room → Enter a room name and click the + button

### 🔒 Private Messaging

Select a user from the online users list (auto-fills PM field)

Or type username manually in Private to: field

Type your message → Click Send

### 📝 Message Formatting

Bold → Click B or use **bold**

Italic → Click I or use *italic*

Emoji → Click 😀 to insert emojis

Text Color → Choose from color dropdown

### ⚙️ Server Configuration

Modify ChatServer initialization:

```bash
def __init__(self, host='localhost', port=5555):
    # Change host and port as needed
```
Local Network → Use your local IP address

Internet Use → Configure port forwarding

Default TCP port: 5555

### 🛠️ Troubleshooting
Connection Issues

Ensure server is running before clients connect

Verify correct host and port

Check firewall settings for port 5555

File Transfer Issues

Files > 1MB will be rejected

Some networks may block transfers

Username Issues

Must be unique

Case-sensitive
