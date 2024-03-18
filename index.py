import tkinter as tk
from tkinter.font import Font
import os
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def main_password_exists():
    if os.path.exists("C:\\Betterpasswords\\data\\main.bin"):
        return True
    return False

root = tk.Tk()

main_password_existant = main_password_exists()

def createMainPassword():
    password = main_password_input.get()
    if password == "":
        loginLabel.config(text="Password does not match criteria.")
    else:
        password = password.encode('utf-8')
        key = PBKDF2("mainPassword", salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC)
        ciphered_data = cipher.encrypt(pad(password, AES.block_size))
        with open("C:\\Betterpasswords\\data\\main.bin", "wb") as f:
            f.write(cipher.iv)
            f.write(ciphered_data)
        generateMainScreen()
            
def checkMainPassword():
    enteredPassword = login_password.get()
    key = PBKDF2("mainPassword", salt, dkLen=32)
    with open("C:\\Betterpasswords\\data\\main.bin", "rb") as f:
        iv = f.read(16)
        decrypt_pwd = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pwd = unpad(cipher.decrypt(decrypt_pwd), AES.block_size).decode('utf-8')
        if enteredPassword != pwd:
            loginLabel.config(text="Wrong password!")
        else:
            loginLabel.config(text="Logging in...")
            generateMainScreen()
            
def createPassword():
    name = create_pwd_name_field.get()
    pwd = create_pwd_data_field.get()
    
    if(name == "" or pwd == ""):
        create_pwd_label.config(text="Please enter both a name and a password!")
    elif(name == "main"):
        create_pwd_label.config(text="Cannot name the password \"main\"")
    else:
        pwd = pwd.encode('utf-8')
        key = PBKDF2(name, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC)
        ciphered_data = cipher.encrypt(pad(pwd, AES.block_size))
        with open(f"C:\\Betterpasswords\\data\\{name}.bin", "wb") as f:
            f.write(cipher.iv)
            f.write(ciphered_data)
        
        init_pwd_button.place_forget()
        create_pwd_label.pack_forget()
        create_pwd_name_field.place_forget()
        create_pwd_name_label.place_forget()
        create_pwd_data_field.place_forget()
        create_pwd_data_label.place_forget()
        
        event_label.config(text="Password created!", anchor="center")
        event_label.pack(pady=250)
        generateMainScreen()
        
def findPassword():
    name = find_pwd_name_field.get()
    
    if(name == ""):
        find_pwd_label.config(text="Please enter the name of the password you want to find!")
    elif(name == "main"):
        find_pwd_label.config(text="Searching for password \"main\" is forbidden.")
    else:
        key = PBKDF2(name, salt, dkLen=32)
        try:
            with open(f"C:\\Betterpasswords\\data\\{name}.bin", "rb") as f:
                iv = f.read(16)
                decrypt_pwd = f.read()
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                pwd = unpad(cipher.decrypt(decrypt_pwd), AES.block_size).decode('utf-8')
                
                search_pwd_button.place_forget()
                find_pwd_label.pack_forget()
                find_pwd_name_field.place_forget()
                find_pwd_name_label.place_forget()
                
                event_label.config(text=f"Password: {pwd}", anchor="center")
                event_label.pack(pady=250)
                generateMainScreen()
        except FileNotFoundError:
            find_pwd_label.config(text="Could not find that password")
            
def resetMainPassword():
    old_pwd = change_main_pwd_old_field.get()
    new_pwd = change_main_pwd_new_field.get()
    
    key = PBKDF2("mainPassword", salt, dkLen=32)
    
    with open("C:\\Betterpasswords\\data\\main.bin", "rb") as f:
        iv = f.read(16)
        decrypt_pwd = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pwd = unpad(cipher.decrypt(decrypt_pwd), AES.block_size).decode('utf-8')
        if old_pwd != pwd:
            change_main_pwd_label.config(text="Old password is not correct!")
        else:
            if new_pwd == "":
                change_main_pwd_label.config(text="Password does not match criteria.")
            else:
                #Decrypt all password with the old password, and encrypt them with the new one
                password_list = {}
                for path, dirnames, filenames in os.walk("C:\\Betterpasswords\\data"):
                    for file in filenames:
                        if file != "main.bin":
                            with open(f"{path}/{file}", "rb") as f:
                                key = PBKDF2(file.split(".bin")[0], salt, dkLen=32)
                                iv = f.read(16)
                                decrypt_pwd = f.read()
                                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                                pwd = unpad(cipher.decrypt(decrypt_pwd), AES.block_size).decode('utf-8')
                                password_list[file] = pwd
                for file in password_list:
                    password = password_list[file]
                    file = file.split(".bin")[0]
                    password = password.encode('utf-8')
                    key = PBKDF2(file, salt, dkLen=32)
                    cipher = AES.new(key, AES.MODE_CBC)
                    ciphered_data = cipher.encrypt(pad(password, AES.block_size))
                    with open(f"C:\\Betterpasswords\\data\\{file}.bin", "wb") as f:
                        f.write(cipher.iv)
                        f.write(ciphered_data)
                        
                #Now we change the main password file
                password = new_pwd.encode('utf-8')
                key = PBKDF2("mainPassword", salt, dkLen=32)
                cipher = AES.new(key, AES.MODE_CBC)
                ciphered_data = cipher.encrypt(pad(password, AES.block_size))
                with open("C:\\Betterpasswords\\data\\main.bin", "wb") as f:
                    f.write(cipher.iv)
                    f.write(ciphered_data)
                    
                switch_main_pwd_button.place_forget()
                change_main_pwd_label.pack_forget()
                change_main_pwd_old_field.place_forget()
                change_main_pwd_old_label.place_forget()
                change_main_pwd_new_field.place_forget()
                change_main_pwd_new_label.place_forget()
                create_back_button.place_forget()
                    
                event_label.config(text="Changed main Password!")
                event_label.pack(pady=250)
                generateMainScreen()
                
def forgotPassword():
    #Wipe all data
    for path, dirnames, filenames in os.walk("C:\\Betterpasswords\\data"):
        for file in filenames:
            os.remove(f"{path}/{file}")
    forgot_label.config(text="All data wiped. Main password reset. Plase restart the program.")
    forgot_yes_button.place_forget()
    forgot_no_button.place_forget()
    exit_button.place(x=325, y=400, width=150, height=50)

def loginScreen():
    forgot_label.pack_forget()
    forgot_yes_button.place_forget()
    forgot_no_button.place_forget()
    
    if not main_password_existant:
        
        createLabel.config(anchor="center")
        createLabel.pack(pady=200)
        
        create_button.place(x=275, y=300, width=250, height=50)
        
        main_password_input.place(x=300, y=250)
    else:
        loginLabel.config(anchor="center")
        loginLabel.pack(pady=200)
        
        login_password.place(x=300, y=250)
        
        login_button.place(x=275, y=300, width=250, height=50)
        
        forgot_button.place(x=275, y=400, width=250, height=50)

def generateMainScreen():
    
    createLabel.pack_forget()
    create_button.place_forget()
    main_password_input.place_forget()
    
    loginLabel.pack_forget()
    login_password.place_forget()
    login_button.place_forget()
    forgot_button.place_forget()
    
    create_pwd_button.place(x=0, y=100, width=150, height=50)
    
    find_pwd_button.place(x=0, y=200, width=150, height=50)
    
    change_main_pwd_button.place(x=0, y=300, width=150, height=50)
    
    exit_button.place(x=0, y=400, width=150, height=50)
    
def createPasswordScreen():
    event_label.pack_forget()
    create_pwd_button.place_forget()
    find_pwd_button.place_forget()
    change_main_pwd_button.place_forget()
    exit_button.place_forget()
    
    create_pwd_label.config(anchor="center")
    create_pwd_label.pack(pady=270)
    
    create_pwd_name_field.place(x=137, y=300, width=250, height=50)
    create_pwd_name_label.place(x=247, y=350)
    
    create_pwd_data_field.place(x=412, y=300, width=250, height=50)
    create_pwd_data_label.place(x=512, y=350)
    
    init_pwd_button.place(x=270, y=400, width=250, height=50)
    create_back_button.place(x=270, y=500, width=250, height=50)
    
def findPasswordScreen():
    event_label.pack_forget()
    create_pwd_button.place_forget()
    find_pwd_button.place_forget()
    change_main_pwd_button.place_forget()
    exit_button.place_forget()
    
    search_pwd_button.config(anchor="center")
    find_pwd_label.pack(pady=250)
    
    find_pwd_name_field.place(x=270, y=300, width=250, height=50)
    find_pwd_name_label.place(x=370, y=350)
    
    search_pwd_button.place(x=270, y=400, width=250, height=50)
    create_back_button.place(x=270, y=500, width=250, height=50)
    
def changeMainPasswordScreen():
    event_label.pack_forget()
    create_pwd_button.place_forget()
    find_pwd_button.place_forget()
    change_main_pwd_button.place_forget()
    exit_button.place_forget()
    
    change_main_pwd_label.config(anchor="center")
    change_main_pwd_label.pack(pady=270)
    
    change_main_pwd_old_field.place(x=137, y=300, width=250, height=50)
    change_main_pwd_old_label.place(x=227, y=350)
    
    change_main_pwd_new_field.place(x=412, y=300, width=250, height=50)
    change_main_pwd_new_label.place(x=502, y=350)
    
    switch_main_pwd_button.place(x=270, y=400, width=250, height=50)
    create_back_button.place(x=270, y=500, width=250, height=50)
    
def forgotPasswordScreen():
    loginLabel.pack_forget()
    login_password.place_forget()
    login_button.place_forget()
    forgot_button.place_forget()
    
    forgot_label.config(anchor="center")
    forgot_label.pack(pady=270)
    forgot_yes_button.place(x=187, y=400, width=150, height=50)
    forgot_no_button.place(x=462, y=400, width=150, height=50)
    
def backToMain():
    init_pwd_button.place_forget()
    create_pwd_label.pack_forget()
    create_pwd_name_field.place_forget()
    create_pwd_name_label.place_forget()
    create_pwd_data_field.place_forget()
    create_pwd_data_label.place_forget()
    create_back_button.place_forget()
    
    search_pwd_button.place_forget()
    find_pwd_label.pack_forget()
    find_pwd_name_field.place_forget()
    find_pwd_name_label.place_forget()
    
    switch_main_pwd_button.place_forget()
    change_main_pwd_label.pack_forget()
    change_main_pwd_old_field.place_forget()
    change_main_pwd_old_label.place_forget()
    change_main_pwd_new_field.place_forget()
    change_main_pwd_new_label.place_forget()
    create_back_button.place_forget()
    generateMainScreen()
    
def exit_program():
    exit(1)

#Fonts
text_font = Font(size=15)
button_font = Font(size=10)

#Init create Main pwd data
createLabel = tk.Label(root, text="You don't have a main password set. Type it in the textbox to create one.")
create_button = tk.Button(root, text="Create main password", font=text_font, command=createMainPassword)
main_password_input = tk.Entry(root, show="*", width=30, justify="center")

#Init login data
loginLabel = tk.Label(root, text="Enter main password:")
login_password = tk.Entry(root, show="*", width=30, justify="center")
login_button = tk.Button(root, text="Login", font=text_font, command=checkMainPassword)
forgot_button = tk.Button(root, text="Forgot Password", font=text_font, command=forgotPasswordScreen)

#Init Forgot Password Screen Data
forgot_label = tk.Label(root, text="We cannot restore your saved passwords without your main password.\nResetting it will delete ALL saved password.\nDo you wish to proceed?")
forgot_yes_button = tk.Button(root, text="Yes", font=button_font, command=forgotPassword)
forgot_no_button = tk.Button(root, text="No", font=button_font, command=loginScreen)

#Init main menu data
event_label = tk.Label(root, text="")
create_pwd_button = tk.Button(root, text="Create Password", font=button_font, command=createPasswordScreen)
find_pwd_button = tk.Button(root, text="Find Password", font=button_font, command=findPasswordScreen)
change_main_pwd_button = tk.Button(root, text="Change main password", font=button_font, command=changeMainPasswordScreen)
exit_button = tk.Button(root, text="Exit", font=button_font, command=exit_program)

#Init create menu data
init_pwd_button = tk.Button(root, text="Create Password", font=button_font, command=createPassword)
create_pwd_label = tk.Label(root, text="Enter the name of your password, and the password itself")
create_pwd_name_field = tk.Entry(root, width=30, justify="center")
create_pwd_data_field = tk.Entry(root, show="*", width=30, justify="center")
create_pwd_name_label = tk.Label(root, text="Name")
create_pwd_data_label = tk.Label(root, text="Password")
create_back_button = tk.Button(root, text="Back", font=button_font, command=backToMain)

#Init find menu data
search_pwd_button = tk.Button(root, text="Find Password", font=button_font, command=findPassword)
find_pwd_label = tk.Label(root, text="Enter the name of your password, and the password itself")
find_pwd_name_field = tk.Entry(root, width=30, justify="center")
find_pwd_name_label = tk.Label(root, text="Name")

#Init Change Main Password data
switch_main_pwd_button = tk.Button(root, text="Change Password", font=button_font, command=resetMainPassword)
change_main_pwd_label = tk.Label(root, text="Enter old and new password")
change_main_pwd_old_field = tk.Entry(root, show="*", width=30, justify="center")
change_main_pwd_new_field = tk.Entry(root, show="*", width=30, justify="center")
change_main_pwd_old_label = tk.Label(root, text="Old Password")
change_main_pwd_new_label = tk.Label(root, text="New Password")

if not os.path.exists("C:\\Betterpasswords"):
    os.mkdir("C:\\Betterpasswords")
    path = "C:\\Betterpasswords\\data"
    if not os.path.isdir(path):
        os.mkdir(path)

salt = b'\xc2r\x9f\x04\xfb\xa4\x15\xce\xbeCB`j)\xf1\xa6\xe3\xe1W\x90\x16\xa9\xdc\x89\xc0\xde\x8d3\xb6\xfc\xb1A'

font = Font(size="15")
        
loginScreen()
    
root.geometry("800x600")
root.title("Password Manager")
root.mainloop()