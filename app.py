import PySimpleGUI as sg
from OpenSSL import crypto
import OpenSSL.crypto
from Crypto.PublicKey import RSA
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import pss
from datetime import datetime
from OpenSSL import crypto, SSL

#Coleccion de usuarios y contraseñas. Debe moverse a base de datos y/o archivo contenedor
admin_usernames = ["admin"]
usernames = ["user1", "user2"]
passwords = ["123","abcd"]

curr_usr = ""


#Función que verifica que el certificado corresponda a la firma

def check_certificate(certificate, key):
    try:
        p_key = open(key).read()
        load = crypto.load_privatekey(crypto.FILETYPE_PEM, p_key)

    except crypto.Error:
        sg.popup("Archivo de llave incorrecto")

    try:

        certific = crypto.load_certificate(crypto.FILETYPE_PEM, open(certificate).read())

    except crypto.Error:
        sg.popup("Archivo de certificado incorrecto")

    verifier = SSL.Context(OpenSSL.SSL.TLSv1_METHOD)

    verifier.use_privatekey(load)
    verifier.use_certificate(certific)
    try:
        verifier.check_privatekey()
        return True
    except SSL.Error:
        sg.popup("Certificado no coincide")
        return False

def check_date_validity(certificate):

    try:

        certific = crypto.load_certificate(crypto.FILETYPE_PEM, open(certificate).read())

    except crypto.Error:
        sg.popup("Archivo de certificado incorrecto")


    expiration_date = certific.get_notAfter().decode()
    y = int(expiration_date[:4])
    m = int(expiration_date[4:6])
    d = int(expiration_date[6:8])

    expiration_date = datetime(y, m ,d)
    today = datetime.now()

    if expiration_date > today:
        return True 

    else:
        sg.popup("El certificado ha expirado y no se puede firmar con él. Por favor solicite uno nuevo.")
        return False



#Funcion que genera un par de llaves publica-privada siguiente el algoritmo RSA
def rsa_key_generation(city="Monterrey", state="Nuevo Leon"):

    priv_name = curr_usr+"_priv.pem" 
    pub_name = curr_usr+"_pub.pem"
    cert_name = curr_usr+"_cert.crt"

    #Clave de 2048 bits (o 256 bytes)
    key = RSA.generate(2048)
    #Se exporta en formato PEM para facilitar su lectura
    private_key = key.export_key(format="PEM", pkcs=8)
    file_out = open(priv_name, "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key(format="PEM")
    file_out = open(pub_name, "wb")
    file_out.write(public_key)
    file_out.close()

    certificate_generation(name = curr_usr, country= "MX", country_code="MX",
    city=city, state=state, organiz="TELETON MTY", serial=0, validity_s=0, validity_e=60*20, pu_key=pub_name, pr_key=priv_name,
    output_f=cert_name)

#Funcion que lee los bits de un archivo de cualquier tipo y les aplica la funcion SHA-256
def get_file_hash(file_name):

    file_hash = hashlib.sha256()

    #Se usa específicamente el modo 'rb' para leer en bits
    with open(file_name, "rb") as file:
        ck = 0
        #Se lee de 1024 en 1024 para evitar errores de lectura
        while ck != b'':
            ck = file.read(1024)
            file_hash.update(ck)
    #Devuelve un hash específico del archivo. No puede haber 2 iguales para archivos distintos
    return file_hash.hexdigest()

#Interfaz y algoritmo de firma de documentos
def sign_document():
    sg.theme("LightBlue2")
    layout = [[sg.T("")],
    [sg.Text("Escoger un documento: "), sg.Input(), sg.FileBrowse(key="-IN-")],
    [sg.Text("Escoger una llave privada: "), sg.Input(), sg.FileBrowse(key="-KEY-")],
    [sg.Text("Escoger un certificado: "), sg.Input(), sg.FileBrowse(key="-CERT-")],
    [sg.Button("Firmar"), sg.Button("Atras")]]

    window = sg.Window("Firma de documentos", layout)

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event =="Exit":
            break
        elif event == "Firmar":

            if check_certificate(certificate = values["-CERT-"], key=values["-KEY-"]):
                if check_date_validity(certificate = values["-CERT-"]):
                    progress_bar(message="Firmando documento...")
                    #Se leen valores de la ventana
                    doc = values["-IN-"]
                    k = values["-KEY-"]
                    file_hash = str(get_file_hash(doc)) #Se hashea el documento para crear un ID identificador
                    key = RSA.import_key(open(k).read()) #Se lee la llave privada
                    hs = SHA256.new(file_hash.encode("utf-8")) #Se hashea el identificador por motivos de seguridad
                    sgnr = pss.new(key)
                    signature = sgnr.sign(hs)
                    file_out = open("document_signature.pem", "wb") #Se firma y se escribe dicha firma en otro archivo PEM
                    file_out.write(signature)
                    file_out.close()
                    sg.popup("Firma exitosa")

        elif event == "Atras":
            window.close()
            signing_interface()
            break

#Interfaz y algoritmo de verificación de firmas
def verify_signature():
    sg.theme("LightBlue2")
    layout = [[sg.T("")], [sg.Text("Escoger una llave publica: "), sg.Input(), sg.FileBrowse(key="-IN-")],
    [sg.Text("Escoger una firma:     "), sg.Input(), sg.FileBrowse(key="-SIG-")],
    [sg.Text("Escoger un documento:     "), sg.Input(), sg.FileBrowse(key="-DOC-")],
    [sg.Button("Verificar"), sg.Button("Atras")]]

    window = sg.Window("Verificación de fimas", layout)

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event =="Exit":
            break
        elif event == "Verificar":

            progress_bar(message="Verificando firma...")
            #Se leen los contenidos de la ventana
            doc = values["-DOC-"]
            p_key = values["-IN-"]
            sig = values["-SIG-"]

            file_hash = str(get_file_hash(doc)) #Se hashea el documento de nuevo para verificar la autenticidad de la firma

            sig = open(sig, "rb") #Se lee la firma en bits
            sig = sig.read()

            key = RSA.import_key(open(p_key).read())
            hs = SHA256.new(file_hash.encode("utf-8")) #Se vuelve a hashear el ID del documento
            verifier = pss.new(key) #Se inicia una instancia de verificación basada en la clave pública

            try: #Diseño de manejo de excepciones para comprobar si la firma es legítima o no
                verifier.verify(hs, sig)
                sg.popup("La firma es auténtica.")
            except (ValueError, TypeError):
                sg.popup("La firma no es auténtica.")



        elif event == "Atras":
            window.close()
            signing_interface()
            break


def certificate_generation(name, country, country_code,
    city, state, organiz, serial, validity_s, validity_e, pu_key, pr_key, output_f):

    cert = crypto.X509()
    cert.get_subject().C = country
    cert.get_subject().ST = state
    cert.get_subject().L = city
    cert.get_subject().O = organiz
    cert.get_subject().OU = "unit"
    cert.get_subject().CN = name 
    cert.get_subject().emailAddress = "example@email.com"
    cert.get_issuer().C = country
    cert.get_issuer().ST = state
    cert.get_issuer().L = city
    cert.get_issuer().O = organiz
    cert.get_issuer().OU = "unit"
    cert.get_issuer().CN = name 
    cert.get_issuer().emailAddress = "example@email.com"
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validity_e)
    cert.set_issuer(cert.get_issuer())
    with open(pu_key, "r") as p_key:
            p_key_s = p_key.read()
            a = crypto.load_publickey(crypto.FILETYPE_PEM, p_key_s)
    cert.set_pubkey(a)


    with open(pr_key, "r") as pri_key:
        pri_key_s = pri_key.read()
        k = crypto.load_privatekey(crypto.FILETYPE_PEM, pri_key_s)

    cert.sign(k, 'sha256')
    with open(output_f, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))


#Animación de la barra de progreso
def progress_bar(message):
    sg.theme('LightBlue2')
    layout = [[sg.Text(message)],
            [sg.ProgressBar(1000, orientation='h', size=(20, 20), key='progbar')],
            [sg.Button("Cancelar")]]

    window = sg.Window('Espere', layout)
    for i in range(1000):
        event, values = window.read(timeout=1)
        if event == 'Cancelar' or event == sg.WIN_CLOSED:
            break
        window['progbar'].update_bar(i + 1)
    window.close()

#Interfaz de la opcion "Firmar documento"
def signing_interface():

    sg.theme("LightBlue2")
    layout_validation = [[sg.Text('Seleccionar una opción:')],         
                    [sg.Button('Firmar Documento'),sg.Button('Verificar Firma'), sg.Button("Atras")]]

    window = sg.Window("Fima y validacion", layout_validation)

    while True:
        event, values = window.read()

        if event == sg.WIN_CLOSED:
            break

        elif event == "Atras":
            window.close()
            menu()
            break

        elif event == "Firmar Documento":
            window.close()
            sign_document()
            break

        elif event == "Verificar Firma":
            window.close()
            verify_signature()
            break


#Interfaz de la opción "Creación de llaves"
def gen_signature():
    sg.theme("LightBlue2")

    layout_key_gen = [[sg.Text('Seleccionar una opción:')],
                    [sg.Button('Generar llave'),sg.Button('Atras')]]

    window = sg.Window("Generacion de Claves", layout_key_gen)

    while True:
        event, values = window.read()

        if event == sg.WIN_CLOSED:
            break

        elif event == "Atras":
            window.close()
            menu()
            break

        elif event == "Generar llave":
            progress_bar(message = "Generando par de llaves...")
            rsa_key_generation()
            sg.popup("Generación completa")


#Lógica del menú
def menu():
    sg.theme("LightBlue2")
    layout = [[sg.Text("Menu")],
                [sg.Button("Creación de llaves"), sg.Button("Firma de documentos"), sg.Button("Salir")]]

    window = sg.Window("Menú principal", layout)

    while True:
        event, values = window.read()
        if event == "Salir" or event == sg.WIN_CLOSED:
            break
        elif event == "Creación de llaves":
            window.close()
            gen_signature()
        elif event == "Firma de documentos":
            window.close()
            signing_interface()

#Lógica del sistema de inicio de sesión
            
def login():
    global usernames, admin_usernames, passwords
    sg.theme("LightBlue2")
    layout = [[sg.Text("Ingresar", size =(15, 1), font=40)],
            [sg.Text("Usuario", size =(15, 1), font=16),sg.InputText(key='-usrnm-', font=16)],
            [sg.Text("Contraseña", size =(15, 1), font=16),sg.InputText(key='-pwd-', password_char='*', font=16)],
            [sg.Button('Entrar'),sg.Button('Salir')]]

    window = sg.Window("Ingresar", layout)

    while True:
        event,values = window.read()
        if event == "Salir" or event == sg.WIN_CLOSED:
            break
        else:
            if event == "Entrar":
                if values['-usrnm-'] in usernames and values['-pwd-'] in passwords:
                    sg.popup("Bienvenido!")
                    global curr_usr
                    curr_usr = values['-usrnm-']
                    window.close()
                    return True
                    break
                elif values['-usrnm-'] not in usernames or values['-pwd-'] not in passwords:
                    sg.popup("Información incorrecta. Intente de nuevo.")

    window.close()

#Función principal
def main():

    if login():
        menu()



#Inicio del programa
main()