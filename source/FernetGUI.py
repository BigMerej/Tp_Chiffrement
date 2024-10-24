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
from cryptography.fernet import Fernet
from source.cipheredGUI import CipheredGUI

class FernetGUI(CipheredGUI):
    
    def __init__(self) -> None:
        super().__init__()
    
    def run_chat(self, sender, app_data) -> None:
        password = dpg.get_value("connection_password").encode("utf-8")
        digest = hashes.Hash(hashes.SHA256()) #hacheur il va nous servir pour hacher le mdp, il contient le code necessaire
        digest.update(password)#On met le mot de passe dans le hacheur ici
        key = digest.finalize() # finalisation du hachage, on obtient la clé derivée
        self._key = base64.urlsafe_b64encode(key) #encodage en base 64 
        super().run_chat(sender, app_data)#Appel du run chat de CipheredGui grace à l'héritage

    def encrypt(self, plaintext: str) -> str: #Pas besoin de vecteurs d'initialisation ici, l'IV est directement inclue dans le fernet
        fernet = Fernet(self._key)
        serialized_data = serpent.tobytes(bytes(plaintext, 'utf-8'))  # Sérialisation avec serpent
        ciphertext = fernet.encrypt(serialized_data)  # Chiffrement Fernet
        return ciphertext.decode('utf-8')  # Je convertis les données chiffrées en chaine de caracteres pour pouvoir les transmettre sous forme de texte
    #Necessaire pour la transmission de données chiffrées sous une forme manipulable comme le JSON que j'utilise plus bas

    def decrypt(self, ciphertext: str) -> str:
        ciphertext.encode('utf-8') #Conversion en bytes pour décrypter 
        fernet = Fernet(self._key)
        decrypted_data = fernet.decrypt(ciphertext.encode('utf-8'))  # Déchiffrement avec une conversion de ciphertext en données chiffrées au préalable
        original_text = serpent.tobytes(decrypted_data)  # Désérialisation du message
        return original_text.decode('utf-8')  # Retour au texte en utf-8


    #Legeres modifications des fonctons send et recv pour fonctionner sans iv
    def send(self, text: str) -> None:
        encrypted_message = self.encrypt(text)  # Chiffrement du message avec la fonction encrypt
        self._log.info(f"Message chiffré : {encrypted_message}")
        message_dict = {
            "data": encrypted_message
        }
        json_message = json.dumps(message_dict)  # Conversion en json
        self._client.send_message(json_message)  # Envoi du message ici

    def recv(self) -> None: 
        if self._callback is not None:
            for user, serialized_message in self._callback.get():
                message_dict = json.loads(serialized_message) #chargement du message json
                encrypted_message = message_dict['data']
                decrypted_message = self.decrypt(encrypted_message)

                self.update_text_screen(f"{user} : {decrypted_message}")
            self._callback.clear()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG) 
    client = FernetGUI()
    client.create()
    client.loop()
