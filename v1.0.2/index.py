import tkinter as tk
from tkinter.font import Font
from tkinter import ttk
import os
import re
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def is_all_lowercase(s):
    return s.isalpha() and s.islower()

def is_only_char(input_string):
    for char in input_string:
        if char.isnumeric():
            return False
    return True

def contains_special_char(str):
    special_chars_pattern = re.compile("[@_!#$%^&*()<>?/\\|}{~:]")
    match = special_chars_pattern.search(str)
    if match is None:
        return False
    else:
        return True

def calculate_password_strength(pwd):
    #Really bad passwords
    length = len(pwd)
    is_numeric = pwd.isnumeric()
    is_only_down = is_all_lowercase(pwd)
    is_upper_and_down = not is_only_down and is_only_char(pwd)
    is_all_without_numeric = not is_upper_and_down
    is_all = False
    if is_all_without_numeric and contains_special_char(pwd):
        is_all_without_numeric = False
        is_all = True
    
    if length <= 6 or (length <= 13 and is_numeric) or (length <= 8 and is_only_down):
        return 0
    elif length <= 8 or is_numeric or (length <= 11 and is_only_down):
        return 1
    elif (length <= 13 and is_only_down) or (length <= 11 and is_upper_and_down):
        return 2
    elif is_all_without_numeric or (length <= 15 and is_upper_and_down) or is_only_down:
        return 3
    elif (len(pwd) > 8 and is_all):
        return 4
    else:
        return 3
    
def calculate_step_size(strength):
    if strength == 0:
        return 10
    elif strength == 1:
        return 25
    elif strength == 2:
        return 50
    elif strength == 3:
        return 75
    else:
        return 100
    
def get_bar_color(strength):
    if strength == 0:
        return "red"
    elif strength == 1:
        return "orange"
    elif strength == 2:
        return "yellow"
    elif strength == 3:
        return "green"
    else:
        return "green"
    
def get_strength_text(strength):
    if strength == 0:
        return "really weak"
    elif strength == 1:
        return "weak"
    elif strength == 2:
        return "average"
    elif strength == 3:
        return "strong"
    else:
        return "really strong"

data_path = os.path.join(os.getenv('APPDATA'), 'BetterPasswords')

if not os.path.isdir(data_path):
    os.mkdir(data_path)
path = data_path + "\\data"
if not os.path.isdir(path):
    os.mkdir(path)
salt_path = path + "\\salt.bin"
if not os.path.exists(salt_path):
    salt = get_random_bytes(32)
    with open(salt_path, "wb") as f:
        f.write(salt)

def main_password_exists():
    if os.path.exists(f"{data_path}\\data\\main.bin"):
        return True
    return False

root = tk.Tk()

main_password_existant = main_password_exists()

def createMainPassword():
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    password = main_password_input.get()
    if password == "":
        loginLabel.config(text="Password does not match criteria.")
    else:
        password = password.encode('utf-8')
        key = PBKDF2("mainPassword", salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC)
        ciphered_data = cipher.encrypt(pad(password, AES.block_size))
        with open(f"{data_path}\\data\\main.bin", "wb") as f:
            f.write(cipher.iv)
            f.write(ciphered_data)
        generateMainScreen()
            
def checkMainPassword():
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    enteredPassword = login_password.get()
    key = PBKDF2("mainPassword", salt, dkLen=32)
    with open(f"{data_path}\\data\\main.bin", "rb") as f:
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
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    name = create_pwd_name_field.get()
    pwd = create_pwd_data_field.get()
    
    if(name == "" or pwd == ""):
        create_pwd_label.config(text="Please enter both a name and a password!")
    elif(name == "main" or name == "salt"):
        create_pwd_label.config(text="Cannot name the password \"main\" or \"salt\"")
    else:
        pwd = pwd.encode('utf-8')
        key = PBKDF2(name, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC)
        ciphered_data = cipher.encrypt(pad(pwd, AES.block_size))
        with open(f"{data_path}\\data\\{name}.bin", "wb") as f:
            f.write(cipher.iv)
            f.write(ciphered_data)
        
        init_pwd_button.place_forget()
        create_pwd_label.place_forget()
        create_pwd_name_field.place_forget()
        create_pwd_name_label.place_forget()
        create_pwd_data_field.place_forget()
        create_pwd_data_label.place_forget()
        strength_label.pack_forget()
        strength_display_label.place_forget()
        strength_o_meter.place_forget()
        
        event_label.config(text="Password created!", anchor="center")
        event_label.pack(pady=250)
        generateMainScreen()
        
def changedPwd(sv):
    pwd = sv.get()
    strength = calculate_password_strength(pwd)
    step_size = calculate_step_size(strength)
    color = get_bar_color(strength)
    strength_o_meter_style.configure("strength.Horizontal.TProgressbar", foreground=color, background=color)
    strength_o_meter_progress.set(step_size)
    strength_o_meter.configure()
    
    #Strength text
    strength_display_label.config(anchor="center")
    strength_display_label.place(x=365, y=230)
    strength_text = get_strength_text(strength)
    strength_display_label.config(text=f"{strength_text}")
        
def findPassword():
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    name = find_pwd_name_field.get()
    
    if(name == ""):
        find_pwd_label.config(text="Please enter the name of the password you want to find!")
    elif(name == "main" or name == "salt"):
        find_pwd_label.config(text="Searching for password \"main\" or \"salt\" is forbidden.")
    else:
        key = PBKDF2(name, salt, dkLen=32)
        try:
            with open(f"{data_path}\\data\\{name}.bin", "rb") as f:
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
    find_pwd_name_field.delete(0, tk.END)
            
def changeMainPassword():
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    old_pwd = change_main_pwd_old_field.get()
    new_pwd = change_main_pwd_new_field.get()
    
    key = PBKDF2("mainPassword", salt, dkLen=32)
    
    with open(f"{data_path}\\data\\main.bin", "rb") as f:
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
                for path, dirnames, filenames in os.walk(f"{data_path}\\data"):
                    for file in filenames:
                        if file != "main.bin" and file != "salt.bin":
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
                    with open(f"{data_path}\\data\\{file}.bin", "wb") as f:
                        f.write(cipher.iv)
                        f.write(ciphered_data)
                        
                #Now we change the main password file
                password = new_pwd.encode('utf-8')
                key = PBKDF2("mainPassword", salt, dkLen=32)
                cipher = AES.new(key, AES.MODE_CBC)
                ciphered_data = cipher.encrypt(pad(password, AES.block_size))
                with open(f"{data_path}\\data\\main.bin", "wb") as f:
                    f.write(cipher.iv)
                    f.write(ciphered_data)
                    
                switch_main_pwd_button.place_forget()
                change_main_pwd_label.pack_forget()
                change_main_pwd_old_field.place_forget()
                change_main_pwd_old_label.place_forget()
                change_main_pwd_new_field.place_forget()
                change_main_pwd_new_label.place_forget()
                back_button.place_forget()
                    
                event_label.config(text="Changed main Password!")
                event_label.pack(pady=250)
                generateMainScreen()
                
def resetPassword():
    #Wipe all data
    for path, dirnames, filenames in os.walk(f"{data_path}\\data"):
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
    
    back_button.place_forget()
    
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
    
    #Password strength visualization
    strength_label.config(anchor="center")
    strength_label.pack(pady=170)
    
    strength_o_meter.place(x=300, y=200, width=200)
    
    create_pwd_label.config(anchor="center")
    create_pwd_label.place(x=250, y=260)
    
    create_pwd_name_field.place(x=137, y=300, width=250, height=50)
    create_pwd_name_label.place(x=247, y=350)
    
    create_pwd_data_field.place(x=412, y=300, width=250, height=50)
    create_pwd_data_label.place(x=512, y=350)
    
    init_pwd_button.place(x=270, y=400, width=250, height=50)
    back_button.place(x=270, y=500, width=250, height=50)
    
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
    back_button.place(x=270, y=500, width=250, height=50)
    
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
    back_button.place(x=270, y=500, width=250, height=50)
    
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
    create_pwd_label.place_forget()
    create_pwd_name_field.place_forget()
    create_pwd_name_label.place_forget()
    create_pwd_data_field.place_forget()
    create_pwd_data_label.place_forget()
    
    strength_label.pack_forget()
    strength_display_label.place_forget()
    strength_o_meter.place_forget()
    
    back_button.place_forget()
    
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
    back_button.place_forget()
    generateMainScreen()
    
def exit_program():
    root.destroy()

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
forgot_label = tk.Label(root, text="We cannot restore your saved passwords without your main password.\nResetting it will delete ALL saved passwords.\nDo you wish to proceed?")
forgot_yes_button = tk.Button(root, text="Yes", font=button_font, command=resetPassword)
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
#Password field
sv = tk.StringVar()
sv.trace_add("write", lambda name, index, mode, sv=sv: changedPwd(sv))
create_pwd_data_field = tk.Entry(root, show="*", width=30, justify="center", textvariable=sv)

create_pwd_name_label = tk.Label(root, text="Name")
create_pwd_data_label = tk.Label(root, text="Password")
back_button = tk.Button(root, text="Back", font=button_font, command=backToMain)
strength_label = tk.Label(root, text="Password strength")
strength_display_label = tk.Label(root, text="really weak")
#Password strength
strength_o_meter_style = ttk.Style()
strength_o_meter_style.theme_use("clam")
strength_o_meter_style.configure("strength.Horizontal.TProgressbar", foreground="red", background="red")
strength_o_meter_progress = tk.IntVar()
strength_o_meter = ttk.Progressbar(style="strength.Horizontal.TProgressbar", variable=strength_o_meter_progress)

#Init find menu data
search_pwd_button = tk.Button(root, text="Find Password", font=button_font, command=findPassword)
find_pwd_label = tk.Label(root, text="Enter the name of your password")
find_pwd_name_field = tk.Entry(root, width=30, justify="center")
find_pwd_name_label = tk.Label(root, text="Name")

#Init Change Main Password data
switch_main_pwd_button = tk.Button(root, text="Change Password", font=button_font, command=changeMainPassword)
change_main_pwd_label = tk.Label(root, text="Enter old and new password")
change_main_pwd_old_field = tk.Entry(root, show="*", width=30, justify="center")
change_main_pwd_new_field = tk.Entry(root, show="*", width=30, justify="center")
change_main_pwd_old_label = tk.Label(root, text="Old Password")
change_main_pwd_new_label = tk.Label(root, text="New Password")

font = Font(size="15")
        
loginScreen()

root.geometry("800x600")
root.resizable(False, False)
root.title("Password Manager")
root.mainloop()