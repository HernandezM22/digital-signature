import PySimpleGUI as sg

admin_usernames = ["admin"]
usernames = ["user1", "user2"]
passwords = ["123","abcd"]

# 3 Layouts de las diferentes funciones del programa
layout_key_gen = [[sg.Text('Menu')],
                    [sg.Button('Generar llave'),sg.Button('Salir')]]

layout_validation = [[sg.Text('Menu')],         
                    [sg.Button('Firmar Documento'),sg.Button('Verificar Firma'), sg.Button("Salir")]]

layout_login = [[sg.Text("Ingresar", size =(15, 1), font=40)],
            [sg.Text("Nombre de usuario", size =(15, 1), font=16),sg.InputText(key='-usrnm-', font=16)],
            [sg.Text("Contraseña", size =(15, 1), font=16),sg.InputText(key='-pwd-', password_char='*', font=16)],
            [sg.Button('Ok'),sg.Button('Salir')]]


#window = sg.Window('Sistema de Firma Electrónica', layout_login)
#
#layout = 1  # The currently visible layout
#while True:
#    event, values = window.read()
#    print(event, values)
#    if event in (None, 'Exit'):
#        break
#    if event in '123':
#        window[f'-COL{layout}-'].update(visible=False)
#        layout = int(event)
#        window[f'-COL{layout}-'].update(visible=True)
#window.close()

def progress_bar():
    sg.theme('LightBlue2')
    layout = [[sg.Text('Creating your account...')],
            [sg.ProgressBar(1000, orientation='h', size=(20, 20), key='progbar')],
            [sg.Cancel()]]

    window = sg.Window('Working...', layout)
    for i in range(1000):
        event, values = window.read(timeout=1)
        if event == 'Cancel' or event == sg.WIN_CLOSED:
            break
        window['progbar'].update_bar(i + 1)
    window.close()

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
                    break
                elif values['-usrnm-'] not in usernames or values['-pwd-'] not in passwords:
                    sg.popup("Información incorrecta. Intente de nuevo.")

    window.close()

def main():

    login()



main()