# BetterPasswords
<<<<<<< HEAD

=======
<h1>Project Overview</h1>

BetterPasswords is a Password Manager, that securely stores your passwords via AES (Advanced Encryption Standard), making them bascially mpossible to crack. For now, there only is a GUI, but maybe there will be CLI support in the furture.
This program is written in python and was compiled so an exe, only making it available on windows devices.

<h1>How to install/uninstall</h1>
Navigate to the /releases tab of this repo, and download the standalone installer. The installer will guide you through the installation process and generate a shortcut which lets you access the Password Manager via start menu. During the installation proccess you are also able to tick a checkbox with the description "Add CLI Support", which will generate an extra file and add it to the path. If you wish to uninstall this program, navigate to your installation path and run the uninstall file.

<h1>How to use</h1>
On your first launch you will have to create a master password. Do **not** forget this password, because all your saved sub-passwords will be lost if you do so. You can generate those sub-passwords after logging in by giving them a name and their associated password. Those will be saved encrypted in binary located at "C:\Users\USER\AppData\Roaming\BetterPasswords\data".
If you installed CLI Support, you can also run all this from the windows command-line.

<h1>CLI Commands</h1>
bps --genmain (pwd) -> Generates your main password
bps --changemain (old_pwd) (new_pwd) -> Change your main password
bps --forgotmain (--reset) -> Reset your main password
bps --main (main_pwd) -> This argument has to be in combination with add and get commands.
bps --add (name) (pwd) -> Add a password
bps --get (pwd) -> Get a password by name

>>>>>>> 06b76cd3bda3ac18b23dd7171caa352ba801bfd4
