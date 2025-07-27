# -*- coding: utf-8 -*-
import sys, asyncio, base64, json, datetime, threading, os, secrets, os
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QPushButton, QLabel, QLineEdit,
    QTextEdit, QMessageBox, QInputDialog, QMenu
)
from PyQt5.QtCore import QEventLoop, pyqtSignal
from websockets.asyncio.client import connect
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

def pkcs7_pad(data: bytes, block_size: int = 16):
    padder = sym_padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()

def pkcs7_unpad(data: bytes, block_size: int = 16):
    unpadder = sym_padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def aes_encrypt(data: bytes, key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_decrypt(data: bytes, key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def rsa_encrypt(data: bytes, public_key):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(data: bytes, private_key):
    return private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def hybrid_encrypt(payload, public_key):
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    padded = pkcs7_pad(json.dumps(payload).encode())
    encrypted_payload = aes_encrypt(padded, aes_key, iv)
    encrypted_key = rsa_encrypt(aes_key, public_key)
    return {
        "key": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(encrypted_payload).decode()
    }

def hybrid_decrypt(packet, private_key):
    key = base64.b64decode(packet["key"])
    iv = base64.b64decode(packet["iv"])
    data = base64.b64decode(packet["data"])
    aes_key = rsa_decrypt(key, private_key)
    padded = aes_decrypt(data, aes_key, iv)
    return json.loads(pkcs7_unpad(padded))

def nowtime():
    return datetime.datetime.now().strftime("%d/%m/%Y [%H:%M:%S]")

CONFIG_FILE = "./host.json"

class ChatClientQt(QWidget):
    ask_text_signal = pyqtSignal(str, str)
    ask_question_signal = pyqtSignal(str, str, int)

    def __init__(self):
        super().__init__()
        self.sawoVer = "2025.07.27-0:50-1.3.5"
        self.setWindowTitle("Sawo")
        self.resize(750, 520)
        self.ws = None
        self.username = None
        self.current_chat_id = None
        self.server_public_key = None
        self.chat_history = {}
        self.chats = []
        self.chat_members = {}
        self.is_admin = 0
        self.init_ui()
        self.load_or_generate_keys()
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.run_async_loop, daemon=True).start()
        self.ask_text_signal.connect(self._on_ask_text)
        self.ask_question_signal.connect(self._on_ask_question)
        self._text_future = None
        self._question_future = None
        self.last_requested_chats = None

    def _on_ask_question(self, title, message, buttons):
        if not isinstance(buttons, QMessageBox.StandardButtons):
            buttons = QMessageBox.StandardButtons(buttons)
        result = QMessageBox.question(self, title, message, buttons)
        if self._question_future and not self._question_future.done():
            self._question_future.set_result(result)

    def _on_ask_text(self, title, message):
        text, ok = QInputDialog.getText(self, title, message)
        if self._text_future and not self._text_future.done():
            if ok and text:
                self._text_future.set_result(text)
            else:
                self._text_future.set_result(None)

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        self.chat_listbox = QListWidget()
        self.chat_listbox.currentRowChanged.connect(self.chat_selected)
        self.btn_chat_create = QPushButton("Create group chat")
        self.btn_add_member = QPushButton("Add member")
        self.btn_dm_create = QPushButton("Direct Message")
        self.btn_chat_delete = QPushButton("Delete chat")
        self.btn_chat_create.clicked.connect(self.create_menu)
        self.btn_dm_create.clicked.connect(self.direct_message)
        self.btn_add_member.clicked.connect(self.add_member_to_group)
        self.btn_chat_delete.clicked.connect(self.delete_chat)
        left_layout = QVBoxLayout()
        left_layout.addWidget(self.chat_listbox)
        left_layout.addWidget(self.btn_chat_create)
        left_layout.addWidget(self.btn_add_member)
        left_layout.addWidget(self.btn_dm_create)
        left_layout.addWidget(self.btn_chat_delete)
        self.chat_title = QLabel("Select chat to start messaging")
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.entry = QLineEdit()
        self.status = QLabel("Connecting...")
        right_layout = QVBoxLayout()
        right_layout.addWidget(self.chat_title)
        right_layout.addWidget(self.chat_area, 1)
        right_layout.addWidget(self.entry)
        right_layout.addWidget(self.status)
        main_layout.addLayout(left_layout, 1)
        main_layout.addLayout(right_layout, 3)
        self.entry.returnPressed.connect(self.send_message)
        self.btn_chat_create.setVisible(False)
        self.btn_add_member.setVisible(False)
        self.btn_chat_delete.setVisible(False)
        # self.setContextMenuPolicy(Qt.CustomContextMenu)

    def create_menu(self):
        
        menu = QWidget()
        # hello_option = menu.addAction('Hello World')
        # goodbye_option = menu.addAction('GoodBye')
        # exit_option = menu.addAction('Exit')

        # hello_option.triggered.connect(lambda: print('Hello World'))
        # goodbye_option.triggered.connect(lambda: print('Goodbye'))
        # exit_option.triggered.connect(lambda: exit())

        menu.show()

    def closeEvent(self, a0):
        # return super().closeEvent(a0)
        # confirm = QMessageBox.question(self, "Chat delete", "Are you sure?", QMessageBox.Yes | QMessageBox.No)
        asyncio.run_coroutine_threadsafe(self.ws.close(reason="client_controlled_closed"), self.loop)

    def load_or_generate_keys(self):
        if not os.path.exists(CONFIG_FILE):
            ip, ok = QInputDialog.getText(self, "Server IP", "Enter server's IP:PORT")
            if not ok or not ip:
                sys.exit()
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            config = {
                "ip": ip,
                "private_key": private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode(),
                "public_key": public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
            }
            json.dump(config, open(CONFIG_FILE, "w"))
        else:
            config = json.load(open(CONFIG_FILE))
        self.config = config
        self.private_key = serialization.load_pem_private_key(config["private_key"].encode(), password=None)
        self.public_key = serialization.load_pem_public_key(config["public_key"].encode())

    def run_async_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.websocket_loop())

    def append_text(self, text):
        def update():
            self.chat_area.append(text)
        QTimer.singleShot(0, update)
    
    def chat_area_clear(self):
        def clear():
            self.chat_area.clear()
        QTimer.singleShot(0, clear)

    def send_message(self):
        msg = self.entry.text().strip()
        if not msg or not self.ws or not self.server_public_key or not self.current_chat_id:
            return
        encrypted_msg = rsa_encrypt(msg.encode(), self.server_public_key)
        signature = self.private_key.sign(
            msg.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        payload = {
            "type": "message",
            "encrypted": base64.b64encode(encrypted_msg).decode(),
            "signature": base64.b64encode(signature).decode(),
            "client_public_key": self.config["public_key"],
            "chat_id": self.current_chat_id
        }
        print("[SEND:DECRYPTED]", payload)
        hybrid_packet = hybrid_encrypt(payload, self.server_public_key)
        asyncio.run_coroutine_threadsafe(self.ws.send(json.dumps(hybrid_packet)), self.loop)
        date = datetime.datetime.now().strftime("%d/%m/%Y [%H:%M:%S]")
        self.append_text(f"{date} <{self.username}> {msg}")
        if self.current_chat_id:
            if self.current_chat_id not in self.chat_history:
                self.chat_history[str(self.current_chat_id)] = []
            print(self.current_chat_id)
            self.chat_history[self.current_chat_id].append({
                "timestamp": nowtime(),
                "username": self.username,
                "message": msg
            })
        self.entry.clear()

    def chat_selected(self, index):
        print(index, len(self.chats))
        if index < 0 or index >= len(self.chats):
            return
        print(index)
        chat = self.chats[index]
        self.current_chat_id = str(chat["id"])
        self.chat_title.setText(chat.get("name", f"Chat {chat['id']}"))
        self.chat_area_clear()
        # print(self.chat_history)
        print(self.chat_history)
        self.btn_add_member.setVisible(chat["type"] == 'group')
        for msg in self.chat_history.get(self.current_chat_id, []):
            self.append_text(f"{msg["timestamp"]} <{msg['username']}> {msg['message']}")
        # asyncio.run_coroutine_threadsafe(self.request_history(self.current_chat_id), self.loop)

    def create_chat(self):
        name, ok = QInputDialog.getText(self, "Chat create", "Enter chat name")
        if ok and name:
            payload = {
                "type": "create_group",
                "name": name,
                "client_public_key": self.config["public_key"]
            }
            print("[SEND:DECRYPTED]", payload)
            asyncio.run_coroutine_threadsafe(
                self.ws.send(json.dumps(hybrid_encrypt(payload, self.server_public_key))), self.loop)

    def direct_message(self):
        target, ok = QInputDialog.getText(self, "Direct message chat", "Enter username to chat with")
        if ok and target:
            payload = {
                "type": "create_dm",
                "username": target,
                "client_public_key": self.config["public_key"]
            }
            print("[SEND:DECRYPTED]", payload)
            asyncio.run_coroutine_threadsafe(
                self.ws.send(json.dumps(hybrid_encrypt(payload, self.server_public_key))), self.loop)

    def add_member_to_group(self):
        
        name, ok = QInputDialog.getText(self, "Add member to group",
            "Enter the username of user to add")
        if ok and name:
            payload = {
                "type": "add_member_to_group",
                "chat_id": self.current_chat_id,
                "member_to_add": name,
                "client_public_key": self.config["public_key"]
            }
            print("[SEND:DECRYPTED]", payload)
            asyncio.run_coroutine_threadsafe(
                self.ws.send(json.dumps(hybrid_encrypt(payload, self.server_public_key))), self.loop)

    async def ask_user_text(self, window_title, message):
        self._text_future = asyncio.get_event_loop().create_future()
        self.ask_text_signal.emit(window_title, message)
        return await self._text_future

    def delete_chat(self):
        if self.current_chat_id is None:
            return
        confirm = QMessageBox.question(self, "Chat delete", "Are you sure?", QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            payload = {
                "type": "delete_chat",
                "chat_id": self.current_chat_id,
                "client_public_key": self.config["public_key"]
            }
            print("[SEND:DECRYPTED]", payload)
            asyncio.run_coroutine_threadsafe(
                self.ws.send(json.dumps(hybrid_encrypt(payload, self.server_public_key))), self.loop)

    async def request_chats(self):
        req = {"type": "get_chats", "client_public_key": self.config["public_key"]}
        print("[SEND:DECRYPTED]", req)
        await self.ws.send(json.dumps(hybrid_encrypt(req, self.server_public_key)))

    async def request_chat_members(self, chat_id):
        req = {"type": "chat_members", "chat_id": chat_id, "client_public_key": self.config["public_key"]}
        print("[SEND:DECRYPTED]", req)
        await self.ws.send(json.dumps(hybrid_encrypt(req, self.server_public_key)))

    async def request_history(self, chat_id):
        req = {"type": "history_get", "chat_id": chat_id, "client_public_key": self.config["public_key"]}
        print("[SEND:DECRYPTED]", req)
        await self.ws.send(json.dumps(hybrid_encrypt(req, self.server_public_key)))

    async def main_decrypt(self, object):
        try:
            packet = json.loads(object)
            if all(k in packet for k in ("key", "iv", "data")):
                data: dict = hybrid_decrypt(packet, self.private_key)
            else:
                data: dict = packet
        except Exception:
            data: dict = json.loads(rsa_decrypt(base64.b64decode(object), self.private_key).decode())
        
        return data
    
    async def ask_user_question(self, title, message, buttons):
        loop = asyncio.get_event_loop()
        self._question_future = loop.create_future()
        # Приводим buttons к типу QMessageBox.StandardButtons
        if not isinstance(buttons, QMessageBox.StandardButtons):
            buttons = QMessageBox.StandardButtons(buttons)
        self.ask_question_signal.emit(title, message, buttons)
        return await self._question_future
    
    async def websocket_loop(self):
        uri = f"ws://{self.config['ip']}"
        while True:
            self.status.setText(f"Connecting to {uri}...")
            while True:
                try:
                    ws = await connect(uri, ping_interval=5, ping_timeout=5)
                    break
                except:
                    print("Couldnt connect, try again...")
            self.ws = ws
            self.status.setText("Connected")
            self.server_public_key = serialization.load_pem_public_key((await self.ws.recv()).encode())
            join_payload = {
                "type": "join_request",
                "client_version": self.sawoVer,
                "client_public_key": self.config["public_key"]
            }
            print("[SEND:DECRYPTED]", join_payload)
            await ws.send(json.dumps(hybrid_encrypt(join_payload, self.server_public_key)))

            msg = await ws.recv()
            data = await self.main_decrypt(msg)
            print("[RECV:DECRYPTED]", data)

            if data["type"] == "incorrect_client_version":
                confirm = await self.ask_user_question("Client update", f"Server require {data['actual_version']} version\nYou have installed: {self.sawoVer}\nInstall server update?", QMessageBox.Yes | QMessageBox.No)
                if confirm == QMessageBox.Yes:
                    join_payload = {
                        "type": "client_update_request"
                    }
                    print("[SEND:DECRYPTED]", join_payload)
                    await ws.send(json.dumps(hybrid_encrypt(join_payload, self.server_public_key)))

                    update_response = await ws.recv()
                    update_response = await self.main_decrypt(update_response)
                    print("[RECV:DECRYPTED]", update_response)
                    if update_response["type"] == "client_update":
                        file = open(__file__, "w", encoding="utf-8")
                        file.write(update_response["file"])
                        await ws.close(reason="client_update_restart")
                        self.close()
                        os.execv(__file__, sys.argv)
                else:
                    exit()

            if data["type"] == "set_username_ask": 
                while True:
                    username = await self.ask_user_text("Set username", "Enter your username")
                    # if not username:
                    #     continue
                    set_username_payload = {
                        "type": "set_username",
                        "username": username.strip(),
                        "client_public_key": self.config["public_key"]
                    }
                    print("[SEND:DECRYPTED]", set_username_payload)
                    hybrid_packet = hybrid_encrypt(set_username_payload, self.server_public_key)
                    await ws.send(json.dumps(hybrid_packet))

                    msg = await ws.recv()
                    data = await self.main_decrypt(msg)
                    print("[RECV:DECRYPTED]", data)

                    if data["type"] == "set_username_ok":
                        break
                    else:
                        parent = QApplication.instance().activeWindow() or self
                        QMessageBox.warning(parent, "Error", data.get("message", ""))

                print("[SEND:DECRYPTED]", join_payload)
                await ws.send(json.dumps(hybrid_encrypt(join_payload, self.server_public_key)))

            if data.get("type") == "join_accepted":
                self.username = data.get("username")
                self.is_admin = data.get("is_admin")

                self.btn_chat_create.setVisible(self.is_admin == 1)
                self.btn_chat_delete.setVisible(self.is_admin == 1)
                
            await self.request_chats()
            self.last_requested_chats = datetime.datetime.now()

            chat_request = await self.ws.recv()
            data = await self.main_decrypt(chat_request)
            print("[RECV:DECRYPTED]", data)
            
            if data["type"] == "chats_list":
                # print("request HISTORU")
                chats = data["chats"]
                print(chats)
                for chat in chats:
                    self.chats.append(chat)
                    
                    if chat["id"] not in self.chat_history:
                        self.chat_history[str(chat["id"])] = []

                    self.chat_listbox.addItem(chat.get("name", f"Чат {chat['id']}"))
                    await self.request_history(chat["id"])
                    history = await self.ws.recv()
                    data = await self.main_decrypt(history)

                    print("[RECV:DECRYPTED #1]", data)

                    for entry in data["messages"]:
                        # print(entry)
                        timestamp = datetime.datetime.fromtimestamp(float(entry["timestamp"])).strftime("%d/%m/%Y [%H:%M:%S]")
                        self.chat_history[str(chat["id"])].append({
                            "timestamp": timestamp,
                            "username": entry["username"],
                            "message": entry["message"]
                        })

                    chat_id = str(data.get("chat_id"))
                    # print(chat["id"], type(chat["id"]))
                    print(self.chat_history)
                    for entry in self.chat_history[chat_id]:
                        timestamp = entry["timestamp"]
                        username = entry.get("username", "Unknown")
                        pubkey = entry.get("pubkey")
                        if pubkey and chat_id in self.chat_members and pubkey in self.chat_members[chat_id]:
                            username = self.chat_members[chat_id][pubkey]
                        message = entry.get("message", "")
                        self.append_text(f"{timestamp} <{username}> {message}")

            print("[POS] ENDLESS CYCLE")
            while True: # endless cycle
                msg = await ws.recv()
                data = await self.main_decrypt(msg)

                # print(data)
                print("[RECV:DECRYPTED]", data)
                # print(await self.request_chats())

                if data.get("type") in ["chat_created", "dm_created"]:
                    await self.request_chats()
                
                if data.get("type") == "chats_list":
                    self.chats = data.get("chats", [])
                    self.chat_listbox.clear()
                    for chat in self.chats:
                        self.chat_listbox.addItem(chat.get("name", f"Чат {chat['id']}"))
                    self.chat_members = {}
                    for chat in self.chats:
                        asyncio.run_coroutine_threadsafe(self.request_chat_members(chat['id']), self.loop)

                if data.get("type") == "chat_members":
                    chat_id = data.get("chat_id")
                    members = data.get("members", [])
                    self.chat_members[chat_id] = {m['pubkey']: m for m in members if 'pubkey' in m}

                if data.get("type") == "message":
                    print(data)
                    chat_id = str(data.get("chat_id"))
                    username = data.get("username", "Unknown")
                    pubkey = data.get("pubkey")
                    if pubkey and chat_id in self.chat_members and pubkey in self.chat_members[chat_id]:
                        username = self.chat_members[chat_id][pubkey]

                    if chat_id != self.current_chat_id:
                        if chat_id not in self.chat_history:
                            self.chat_history[chat_id] = []
                        self.chat_history[chat_id].append({
                            "timestamp": datetime.datetime.fromtimestamp(float(data["timestamp"])).strftime("%d/%m/%Y [%H:%M:%S]"),
                            "username": username,
                            "message": data.get("message", "")
                        })
                        continue
                    print("#444 continued")
                    timestamp = datetime.datetime.fromtimestamp(float(data["timestamp"])).strftime("%d/%m/%Y [%H:%M:%S]")
                    message = data.get("message", "")
                    self.chat_area.append(f"{timestamp} <{username}> {message}")
                    print("textadded")

                if data.get("type") == "alert":
                    def show_alert():
                        parent = QApplication.instance().activeWindow() or self
                        QMessageBox.warning(parent, "ALERT", data.get("message", ""))
                    QTimer.singleShot(0, show_alert)
                if data.get("type") == "system":
                    def show_system():
                        parent = QApplication.instance().activeWindow() or self
                        QMessageBox.information(parent, "SYSTEM", data.get("message", ""))
                    QTimer.singleShot(0, show_system)
                
                
                if datetime.datetime.now() - self.last_requested_chats == datetime.timedelta(seconds=15):
                    await self.request_chats()

if __name__ == "__main__":
    dark_style = """
QWidget {
    background-color: #121212;
    color: #e0e0e0;
}
QTextEdit, QLineEdit, QListWidget {
    background-color: #1e1e1e;
    color: #ffffff;
    border: 1px solid #444;
}
QPushButton {
    background-color: #2c2c2c;
    color: #ffffff;
    border: 1px solid #555;
    padding: 5px;
}
QPushButton:hover {
    background-color: #3a3a3a;
}
# QLabel {
#     color: #cccccc;
# }
QMessageBox {
    background-color: #1e1e1e;
    color: #ffffff;
}
QInputDialog {
    background-color: #1e1e1e;
    color: #ffffff;
}
"""

    app = QApplication(sys.argv)
    app.setStyleSheet(dark_style)
    window = ChatClientQt()
    window.show()
    sys.exit(app.exec_())