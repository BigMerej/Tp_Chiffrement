from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import serpent
import os

# Générer une clé AES de 256 bits (32 octets)
key = os.urandom(16)

# Générer un vecteur d'initialisation (IV) de 16 octets pour le mode CBC
iv = os.urandom(16)

# Les données que nous voulons chiffrer
data = b"Bonjour le monde"

# Sérialiser les données avec serpent
serialized_data = serpent.tobytes(data)

# Créer un chiffreur AES en mode CBC
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Chiffrer les données
# AES nécessite des données multiples de la taille du bloc (16 octets), donc il faut padding si nécessaire
from cryptography.hazmat.primitives import padding
padder = padding.PKCS7(128).padder()
padded_data = padder.update(serialized_data) + padder.finalize()

# Chiffrement
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

print(f'Données chiffrées : {ciphertext}')


#Déchiffrement

# Déchiffreur
decryptor = cipher.decryptor()
decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

# Retirer le padding après le déchiffrement
unpadder = padding.PKCS7(128).unpadder()
decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

# Désérialiser les données avec serpent
original_data = serpent.tobytes(decrypted_data)

print(f'Données déchiffrées : {original_data}')
