import time
from cryptography.fernet import Fernet, InvalidToken
from FernetGUI import FernetGUI
import logging
import serpent

class TimeFernetGUI(FernetGUI):
    
    def __init__(self) -> None:
        super().__init__()
        self.ttl = 30 #On définit ici la durée de vie souhaitée, 30 secondes dans l'énoncé

    def encrypt(self, plaintext: str) -> bytes:
        fernet = Fernet(self._key)
        serialized_data = serpent.tobytes(bytes(plaintext, 'utf-8'))  
        current_time = int(time.time())  # Obtenir l'heure courant pour l'heurodatage
        ciphertext = fernet.encrypt_at_time(serialized_data, current_time)  # Utiliser encrypt_at_time
        return ciphertext.decode('utf-8')  # Je convertis les données chiffrées en chaine de caracteres pour pouvoir les transmettre sous forme de texte

    def decrypt(self, ciphertext: bytes) -> str:
        try:
            ciphertext.encode('utf-8') #Conversion en bytes pour décrypter 
            fernet = Fernet(self._key)
            current_time = int(time.time())  # Obtenir l'heure courant pour l'heurodatage
            decrypted_data = fernet.decrypt_at_time(ciphertext, self.ttl, current_time)  #décryptage du message
            original_text = serpent.tobytes(decrypted_data)  # Désérialisation du message
            return original_text.decode('utf-8')  # Retourner le texte original
        except InvalidToken as o:
            logging.error(f"Token invalide ou expiré : {o}")
            return "[Le message a expiré]"


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    client = TimeFernetGUI()
    client.create()
    client.loop()