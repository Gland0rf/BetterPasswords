import os
import argparse
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def parse_arguments():
    parser = argparse.ArgumentParser(description="Better Passwords CLI")
    parser.add_argument('--genmain', metavar='ACCOUNT', help='Create a main password')
    parser.add_argument('--forgotmain', action="store_true", help='Forgot your main password.')
    parser.add_argument('--changemain', nargs=2, metavar=('OLD', 'NEW'), help='Change your main password')
    parser.add_argument('--reset', action="store_true", help='Reset your main password')
    parser.add_argument('--main', metavar='ACCOUNT', help='Enter main password')
    parser.add_argument('--add', nargs=2, metavar=('NAME', 'PASSWORD'), help='Add a password')
    parser.add_argument('--get', metavar='ACCOUNT', help='Get a password by name')
    parser.add_argument('--remove', metavar='ACCOUNT', help='Remove a password')
    return parser.parse_args()

def handle_args(args):
    main_password_existant = main_password_exists()
    if args.genmain:
        password_specified = args.genmain
        result = createMainPassword(password_specified)
        print(result)
    elif not main_password_existant:
        print("You don't have a main password set yet! Run \"bps --genmain <password>\" to generate it! Make sure you can remember the password!")
    elif args.add:
        if not args.main:
            print("Invalid usage! bps --main <main_pwd> --add <name> <password>")
            return
        
        main = checkMainPassword(args.main)
        if not main:
            print("Main password incrorrect.")
            return
        name, password = args.add
        result = createPassword(name, password)
        print(result)
    elif args.get:
        if not args.main:
            print("Invalid usage! bps --main <main_pwd> --get <name>")
            return
        
        main = checkMainPassword(args.main)
        if not main:
            print("Main password incrorrect.")
            return
        name = findPassword(args.get)
        print(name)
    elif args.changemain:
        old, new = args.changemain
        result = changeMainPassword(old, new)
        print(result)
    elif args.forgotmain:
        if not args.reset:
            print("If you forgot your password, you have the ability to reset it. Note that ALL of your saved sub-passwords will be deleted if you do so.\
                If you wish to proceed, type \"bps --forgotpassword --reset\"")
        else:
            result = resetPassword()
            print(result)
    else:
        print("Not a valid command.")
        
data_path = os.path.join(os.getenv('APPDATA'), 'BetterPasswords')

def main_password_exists():
    if os.path.exists(f"{data_path}\\data\\main.bin"):
        return True
    return False

def createMainPassword(password):
    createNecessaryFiles()
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    if password == "":
        return "Password does not match criteria."
    else:
        password = password.encode('utf-8')
        key = PBKDF2("mainPassword", salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC)
        ciphered_data = cipher.encrypt(pad(password, AES.block_size))
        with open(f"{data_path}\\data\\main.bin", "wb") as f:
            f.write(cipher.iv)
            f.write(ciphered_data)
            return "Created your main password!"
            
def createNecessaryFiles():
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

def checkMainPassword(password):
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    key = PBKDF2("mainPassword", salt, dkLen=32)
    with open(f"{data_path}\\data\\main.bin", "rb") as f:
        iv = f.read(16)
        decrypt_pwd = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pwd = unpad(cipher.decrypt(decrypt_pwd), AES.block_size).decode('utf-8')
        if password != pwd:
            return False
        else:
            return True
        
def changeMainPassword(old_pwd, new_pwd):
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    
    key = PBKDF2("mainPassword", salt, dkLen=32)
    
    with open(f"{data_path}\\data\\main.bin", "rb") as f:
        iv = f.read(16)
        decrypt_pwd = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pwd = unpad(cipher.decrypt(decrypt_pwd), AES.block_size).decode('utf-8')
        if old_pwd != pwd:
            return "Old password is not correct!"
        else:
            if new_pwd == "":
                return "Password does not match criteria."
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
                    
                return "Changed main Password!"
            
def resetPassword():
    #Wipe all data
    for path, dirnames, filenames in os.walk(f"{data_path}\\data"):
        for file in filenames:
            os.remove(f"{path}/{file}")
    return "All data wiped. Main password reset."
        
def createPassword(name, pwd):
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    
    if(name == "" or pwd == ""):
        return "Either name or password is empty."
    elif(name == "main" or name == "salt"):
        return "Cannot name the password \"main\" or \"salt\""
    else:
        pwd = pwd.encode('utf-8')
        key = PBKDF2(name, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC)
        ciphered_data = cipher.encrypt(pad(pwd, AES.block_size))
        with open(f"{data_path}\\data\\{name}.bin", "wb") as f:
            f.write(cipher.iv)
            f.write(ciphered_data)
        
        return "Password created!"
        
def findPassword(name):
    salt = open(data_path + "\\data\\salt.bin", "rb").read()
    
    if(name == ""):
        return "You didn't enter a name."
    elif(name == "main" or name == "salt"):
        return "Searching for password \"main\" or \"salt\" is forbidden."
    else:
        key = PBKDF2(name, salt, dkLen=32)
        try:
            with open(f"{data_path}\\data\\{name}.bin", "rb") as f:
                iv = f.read(16)
                decrypt_pwd = f.read()
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                pwd = unpad(cipher.decrypt(decrypt_pwd), AES.block_size).decode('utf-8')
                
                return f"Password: {pwd}"
        except FileNotFoundError:
            return "Could not find that password"

def main():
    args = parse_arguments()
    handle_args(args)
    
if __name__ == "__main__":
    main()