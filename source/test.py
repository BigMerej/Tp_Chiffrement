from Crypto.Cipher import SERPENT
from Crypto.Random import get_random_bytes
from serpent import Serpent
from Crypto.Cipher import AES
import serpent


#Explication du code nécessaire pour le tp
#La clé doit être de 16 bytes
#Or toutes les opérations se font sur des octets 
#En python les strings sont en utf8
#Donc on a des bytes (octet) des strings et durant les opérations on passe tout en octet
#Faire des tests de conversion déjà pour bien convertir nos données
#Serpent transmet un dictionnaire nécessite serpent.tobytes
#Aller étape par étapes

#Les conversions
t="Bonjour la machine"
tt=b"Bonjour la machine"
a=bytes(t,"utf8") #Pour passer d'un string à un byte
b=str(tt,"utf8") #Pour passer d'un byte à un string
#print(t, ' ',tt, ' ',a,' ',b)

#Test de l'outils serpent
key=get_random_bytes(16) #clé de 16 bytes donc 128 bits
#Il faut avoir un message à chiffrer
#Il faut aussi avoir un objet de chiffrement qui servira à encapsuler l'algorithme et simplifier l'utilisation
cipher = SERPENT.new(key, SERPENT.MODE_EAX)

#maintenant chiffrement
nonce = cipher.nonce #Permet de chiffrer un message de façon unique 
ciphertext, tag = cipher.encrypt_and_digest(t) #Ici t est le message à chiffrer, on va avoir en sortie deux 
#données ciohertext et tag et tag sert à vérifier si nos données ont bien été transmises 

print(f"Clé : {key.hex()}")
print(f"Nonce : {nonce.hex()}")
print(f"Texte chiffré : {ciphertext.hex()}")
