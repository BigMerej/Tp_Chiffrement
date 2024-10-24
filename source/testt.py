from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from basic_gui import BasicGUI
import os
import base64
import serpent 


import logging

import dearpygui.dearpygui as dpg

from chat_client import ChatClient
from generic_callback import GenericCallback

# default values used to populate connection window
DEFAULT_VALUES = {
    "host" : "127.0.0.1",
    "port" : "6666",
    "name" : "foo"
}

class CipheredGUI(BasicGUI):
    SALT_LENGTH = 16  # Longueur du sel
    KEY_SIZE = 32  # 256 bits pour une meilleure sécurité

    def __init__(self) -> None:
        self._client = None
        self._callback = None
        self._key = None
        self._log = logging.getLogger(self.__class__.__name__)


    def _create_chat_window(self) -> None:
        with dpg.window(label="Chat", pos=(200, 150), width=400, height=300, show=False, tag="chat_windows"):
            dpg.add_input_text(multiline=True, height=200, width=380, tag="screen", readonly=True)
            dpg.add_input_text(height=50, width=300, tag="message_input")
            dpg.add_button(label="Send", callback=self.on_send_message)

    def _create_connection_window(self) -> None:
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            for field in ["host", "port", "name"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")
            dpg.add_text("Password")
            dpg.add_input_text(tag="connection_password", password=True)  
            dpg.add_button(label="Connect", callback=self.run_chat)

    def run_chat(self, sender, app_data) -> None:
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password")
        self._key = self.derive_key(password)
        self._log.info(f"Connecting {name}@{host}:{port}")

        self._callback = GenericCallback()
        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")


    def derive_key(self, password: str) -> bytes:
        fixed_salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=fixed_salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(bytes(password, 'utf-8')) # Retourner la clé et le sel

    def encrypt(self, plaintext: str) -> tuple:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self._key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(bytes(plaintext, 'utf-8')) + encryptor.finalize()
        return iv, ciphertext

    def decrypt(self, data: tuple) -> str:
        iv, ciphertext = data
        cipher = Cipher(algorithms.AES(self._key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_text.decode('utf-8')

    def send(self, text: str) -> None:
        iv, encrypted_message = self.encrypt(text)
        self._log.info(f"Message chiffré : {encrypted_message}")
        iv64=base64.b64encode(iv)
        data64=base64.b64encode(encrypted_message)
        serialized_data = serpent.tobytes({
        "iv": base64.b64encode(iv),  # Conserver le résultat base64 comme bytes
        "data": base64.b64encode(encrypted_message)  # Conserver le message chiffré comme bytes
    })

        self._client.send_message(serialized_data)
        dpg.set_value("message_input", "")

    def create(self):
        # create the context and all windows
        dpg.create_context()

        self._create_chat_window()
        self._create_connection_window()
        self._create_menu()        
            
        dpg.create_viewport(title='Secure chat', width=800, height=600)
        dpg.setup_dearpygui()
        dpg.show_viewport()

    def _create_menu(self)->None:
        # menu (file->connect)
        with dpg.viewport_menu_bar():
            with dpg.menu(label="File"):
                dpg.add_menu_item(label="Connect", callback=self.connect)

    def recv(self) -> None:
        if self._callback is not None:
            for user, serialized_message in self._callback.get():
                data = serpent.loads(serialized_message)
                
                iv = base64.b64decode(data['iv'])
                encrypted_message = base64.b64decode(data['data'])
                decrypted_message = self.decrypt((iv, encrypted_message))

                self.update_text_screen(f"{user} : {decrypted_message}")
            self._callback.clear()


    def connect(self, sender, app_data)->None:
        # callback used by the menu to display connection windows
        dpg.show_item("connection_windows")

    
    def update_text_screen(self, text: str) -> None:
        current_text = dpg.get_value("screen")
        new_text = current_text + "\n" + text
        dpg.set_value("screen", new_text)

    def on_send_message(self, sender, app_data) -> None:
        message = dpg.get_value("message_input")  # Récupère le message entré par l'utilisateur
        if message:  # Si le message n'est pas vide
            self._log.info(f"Message à envoyer : {message}")  # Log le message
            self.send(message)  # Appelle la fonction d'envoi de message chiffré
            dpg.set_value("message_input", "")  # Efface le champ de saisie après l'envoi

    def loop(self):
        # main loop
        while dpg.is_dearpygui_running():
            self.recv()
            dpg.render_dearpygui_frame()
        dpg.destroy_context()

    def update_text_screen(self, new_text:str)->None:
        # from a nex_text, add a line to the dedicated screen text widget
        text_screen = dpg.get_value("screen")
        text_screen = text_screen + "\n" + new_text
        dpg.set_value("screen", text_screen)

    def text_callback(self, sender, app_data)->None:
        # every time a enter is pressed, the message is gattered from the input line
        text = dpg.get_value("input")
        self.update_text_screen(f"Me: {text}")
        self.send(text)
        dpg.set_value("input", "")

    def on_close(self):
        # called when the chat windows is closed
        self._client.stop()
        self._client = None
        self._callback = None

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = CipheredGUI()
    client.create()
    client.loop()
