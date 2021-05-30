import PySimpleGUI as sg
import clipboard
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
import base64
from Crypto.Hash import SHA256

def windowAcceuil():

	layoutMiddleTop = [[sg.Text('Chiffrement RSA', size=(100, 2), justification='center')]]

	layoutMiddleBottom = [[sg.Button('Crée une paire de clé')],[sg.Button('Quitter',size=(100, 2))]]

	layoutAcceuilRight = [[sg.Text('Chiffrer')], [sg.Text(''),sg.Text('Veuillez entrer la clé publique du destinataire')],  [sg.In(), sg.FileBrowse()], [sg.Text('Veuillez entrer le message a chiffrer')], [sg.InputText()], [sg.Button('Chiffrez')]]

	layoutAcceuilMiddle = [[sg.Text('Dechiffrer')],[sg.Text(''), sg.Text('Veuillez choisir le chemin vers votre clé privée')], [sg.In(), sg.FileBrowse()], [sg.Text('Veuillez entrer le message a Dechiffrer')], [sg.InputText()], [sg.Button('Dechiffrer')]]

	layoutAcceuilLeft = [[sg.Text('Signature')], [sg.Text('Verifier signature')],[sg.Text('signature a verifier :'),sg.InputText()],[sg.Text('Clé publique de l envoyeur :'), sg.In(), sg.FileBrowse()],[sg.Text('Message déchiffrer :'), sg.InputText()]
		,[sg.Button("Verifier")], [sg.Text('Signer')], [sg.Text('Votre message :'),sg.InputText()],[sg.Text('Chemin vers votre clé privée'),sg.In(), sg.FileBrowse()],[sg.Button('Signer')]]

	layoutAccueil = [[layoutMiddleTop], [sg.Column(layoutAcceuilRight,element_justification='c'), sg.VSeperator(), sg.Column(layoutAcceuilMiddle, element_justification='c'), sg.VSeperator(), sg.Column(layoutAcceuilLeft)],[layoutMiddleBottom]]

	return sg.Window('EasyRSA', layoutAccueil, finalize=True)


def main():
	WindowAcceuil = windowAcceuil()

	while True:
			eventAccueil, valuesAcceuil = WindowAcceuil.read()
			if eventAccueil == sg.WIN_CLOSED or eventAccueil == 'Quitter':
					break
			if eventAccueil == 'Chiffrez':
					cheminPubkey = valuesAcceuil[0]
					Message = valuesAcceuil[1]
					encodedRSA = encrypt(Message, cheminPubkey)
					print(encodedRSA)
					clipboard.copy(str(encodedRSA.decode('utf-8')))
					sg.popup('Voila votre message chiffrer :', encodedRSA.decode('utf-8'), "Your message has been copied to clipboard !")
			if eventAccueil == 'Dechiffrer':
					print(valuesAcceuil[3])
					print(valuesAcceuil[4])
					cheminPrivkey = valuesAcceuil[3]
					Message = valuesAcceuil[4]
					decodedRSA = decrypt(cheminPrivkey, Message)
					print(decodedRSA)
					sg.popup('Voila votre message chiffrer :', decodedRSA.decode("utf-8"), "Your message has been copied to clipboard !")
			if eventAccueil == 'Crée une paire de clé' :
					generateKey()
					sg.popup('Vos clef sont prêtes :', "Elles sont à côté de votre script", "Longueur de la clef privée : 1024")
			if eventAccueil == 'Verifier' :
				signature = valuesAcceuil[6]
				publicKeyOfSender = valuesAcceuil[7]
				messageDechiff =  valuesAcceuil[8]
				resultVerif = verifySignature(signature, publicKeyOfSender, messageDechiff)
				print(resultVerif)
			if eventAccueil == 'Signer' :
				MessageSigner = valuesAcceuil[9]
				cheminPrivkeySigner = valuesAcceuil[10]
				resultSign = signMessage(MessageSigner, cheminPrivkeySigner)
				print(resultSign)
	WindowAcceuil.close()

def encrypt(Message, cheminPubkey):
	key = RSA.importKey(open(cheminPubkey).read())
	encryptor = PKCS1_OAEP.new(key)
	ciphertext = encryptor.encrypt(bytes(Message, 'utf-8'))
	return base64.b64encode(ciphertext)

def decrypt(cheminPrivkey, b64Text):
	key = RSA.importKey(open(cheminPrivkey).read())
	decoded_data = base64.b64decode(b64Text)
	print(decoded_data)
	decryptor = PKCS1_OAEP.new(key)
	decrypted = decryptor.decrypt(decoded_data)
	return decrypted

def generateKey():
	key = RSA.generate(1024)
	with open("private.pem", "wb") as g:
			g.write(key.exportKey('PEM'))
	with open("public.pem", "wb") as f:
			f.write(key.publickey().exportKey())
	return key.publickey().exportKey()
def signMessage(Message, cheminPrivkey):
	key = RSA.importKey(open(cheminPrivkey).read())
	Message = bytes(Message, 'utf-8')
	hash = SHA256.new(Message)
	signature = pkcs1_15.new(key).sign(hash)
	signature = base64.b64encode(signature)
	return signature
def verifySignature(signature, publicKeyOfSender, Message) :
	key = RSA.importKey(open(publicKeyOfSender).read())
	hash = SHA256.new(Message)
	try:
		pkcs1_15.new(key).verify(hash, signature)
		return("The signature is valid.")
	except (ValueError, TypeError):
		return("The signature is not valid.")


if __name__ == "__main__":
    main()
