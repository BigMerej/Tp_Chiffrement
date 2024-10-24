from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import logging
import serpent
import os
from basic_gui import BasicGUI
from chat_client import ChatClient
from generic_callback import GenericCallback
import dearpygui.dearpygui as dpg
import base64
import json

#On reprend les paramètres de connexion par défaut
DEFAULT_VALUES = {
    "host" : "127.0.0.1",
    "port" : "6666",
    "name" : "foo"
}

#Ici on va avoir nos valeurs figées qui serviront dans tout le code
key_size=16 #Taille de clé de 16 bytes 
fixed_salt=b'fixed_salt' #Salt fixe pour simplifier ici mais c'est mieux d'en avoir un pour chaque chiffrement

class CipheredGUI(BasicGUI):

    Key_size=16
    fixed_salt=b'fixed_salt'


    def __init__(self) -> None:
        self._key = None  #Ajout de la clé de chiffrement 
        super().__init__()  #On reprend ici les données de la fonction de BasicGUI

    def _create_connection_window(self) -> None:
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"): #creation de la fenetre
            for field in ["host", "port", "name"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")
            dpg.add_text("Password")#label pour le mdp
            dpg.add_input_text(tag="connection_password", password=True) #champ de saisie du mot de passe 
            dpg.add_button(label="Connect", callback=self.run_chat)
    
    def run_chat(self, sender, app_data) -> None:

        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password").encode("utf-8")
        self._log.info(f"Connecting {name}@{host}:{port}")
        #C'est ici qu'on dérive la clé à partir du mot de passe
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=fixed_salt,
            iterations=100000,
            backend=default_backend()
        )
        self._key=kdf.derive(password)

        self._callback = GenericCallback()
        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows") #Fermeture de la fenetre de connexion
        dpg.show_item("chat_windows")#Affichage de la fenetre de chat
        dpg.set_value("screen", "Connecting")

    def encrypt(self, plaintext: str) -> tuple:
        plaintext_bytes=bytes(plaintext,"utf-8")#Car Serpent ne prend que des bytes tests effectués dans test2
        serialized_data = serpent.tobytes(plaintext_bytes)#Sérialization du message avant cryptage pour éviter des problèmes d'encodage, préserver la structure du message ....
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self._key), modes.CFB(iv), backend=default_backend())#Ici on a le "chiffreur" qui va contenir tout l'algorithme de chiffrement
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(bytes(serialized_data, 'utf-8')) + encryptor.finalize() #Ciphertext sera ici de type byte et non str
        return iv, ciphertext
    
    def decrypt(self, data: tuple) -> str:
        iv, ciphertext = data #Car data est un tuple et il doit être ordonné de la même façon à l'envoi
        cipher = Cipher(algorithms.AES(self._key), modes.CFB(iv), backend=default_backend())#Ici on a le "déchiffreur"
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize() #ici decrypted_text est toujours en byte
        original_text=serpent.tobytes(decrypted_text)#On désérialize le message ici
        return original_text.decode('utf-8') #On retourne ici une chaine de caractère avec decode('utf-8')
    
    def send(self, text: str) -> None:
        iv, encrypted_message = self.encrypt(text) #Cryptage du message à notre fonction encrypt plus haut en prend le texte (text) en paramètres
        self._log.info(f"Message chiffré : {encrypted_message}")
        iv64=base64.b64encode(iv).decode('utf-8')#iv64 est ici chaine de caractères
        data64=base64.b64encode(encrypted_message).decode('utf-8')#Pareil pour data64
        message_dict = { #formatage du message sous forme de dictionnaire
        "iv": iv64,
        "data": data64
        }
        json_message = json.dumps(message_dict) 
        self.client.send_message(json_message)#Appel de la fonction send_message dans chat_client.py et envoie du message sous forme de dictionnaire

    def recv(self) -> None:
        if self._callback is not None:
            for user, serialized_message in self._callback.get():
                message_dict = json.loads(serialized_message)
                iv = base64.b64decode(message_dict['iv'])
                encrypted_message = base64.b64decode(message_dict['data'])
                decrypted_message = self.decrypt((iv, encrypted_message))

                self.update_text_screen(f"{user} : {decrypted_message}")
            self._callback.clear()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG) #Config de base
    client = CipheredGUI()#On crée le client à l'aide de la classe ci dessus 
    client.create()#interface
    client.loop()#Loop principal qui effectuera le programme en boucle