import PySimpleGUI as sg
import os
from Crypto.PublicKey import RSA
import libnum
import sys
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import pss

admin_usernames = ["admin"]
usernames = ["user1", "user2"]
passwords = ["123","abcd"]




def rsa_key_generation():

    key = RSA.generate(2048)
    private_key = key.export_key(format="PEM")
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key(format="PEM")
    file_out = open("public.pem", "wb")
    file_out.write(public_key)
    file_out.close()


def get_file_hash(file_name):

    file_hash = hashlib.sha256()

    with open(file_name, "rb") as file:
        ck = 0

        while ck != b'':
            ck = file.read(1024)
            file_hash.update(ck)

    return file_hash.hexdigest()


def sign_document():
    sg.theme("LightBlue2")
    layout = [[sg.T("")], [sg.Text("Escoger un documento: "), sg.Input(), sg.FileBrowse(key="-IN-")],[sg.Button("Firmar"), sg.Button("Atras")]]

    window = sg.Window("Firma de documentos", layout)

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event =="Exit":
            break
        elif event == "Firmar":
            progress_bar(message="Firmando documento...")

            doc = values["-IN-"]
            file_hash = str(get_file_hash(doc))
            key = RSA.import_key(open("private.pem").read())
            hs = SHA256.new(file_hash.encode("ascii"))
            sgnr = pss.new(key)
            signature = sgnr.sign(hs)

            file_out = open("document_signature.pem", "wb")
            file_out.write(signature)
            file_out.close()

        elif event == "Atras":
            window.close()
            signing_interface()
            break



#def certificate_generation():


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
            progress_bar(message = "Verificando firma...")



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

def main():

    if login():
        menu()




main()