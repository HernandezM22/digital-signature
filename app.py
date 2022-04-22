import PySimpleGUI as sg
import os
from Crypto.PublicKey import RSA
import libnum
import sys
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import pss

#Coleccion de usuarios y contraseñas. Debe moverse a base de datos y/o archivo contenedor
admin_usernames = ["admin"]
usernames = ["user1", "user2"]
passwords = ["123","abcd"]

#Funcion que genera un par de llaves publica-privada siguiente el algoritmo RSA
def rsa_key_generation():

    #Clave de 2048 bits (o 256 bytes)
    key = RSA.generate(2048)
    #Se exporta en formato PEM para facilitar su lectura
    private_key = key.export_key(format="PEM")
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key(format="PEM")
    file_out = open("public.pem", "wb")
    file_out.write(public_key)
    file_out.close()

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
    [sg.Button("Firmar"), sg.Button("Atras")]]

    window = sg.Window("Firma de documentos", layout)

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event =="Exit":
            break
        elif event == "Firmar":
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


#def certificate_generation():

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