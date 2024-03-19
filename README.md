# BetterPasswords
<h1>Project Overview</h1>

BetterPasswords is a Password Manager, that securely stores your passwords via AES (Advanced Encryption Standard), making them really hard to crack. For now, there only is a GUI, but maybe there will be CLI support in the furture.
This program is written in python and was compiled to an exe, only making it available on windows devices.

<h1>How to install/uninstall</h1>
Navigate to the /releases tab of this repo, and download the standalone installer. The installer will guide you through the installation process and generate a shortcut which lets you access the Password Manager via start menu. If you wish to uninstall this program, navigate to your installation path and run the uninstall file. You can also uninstall it from the Microsoft Program Overview (Open start menu -> type "Add or Remove Programs")

<h1>How to use</h1>
On your first launch you will have to create a master password. Do <b>not</b> forget this password, because all your saved sub-passwords will be lost if you do so. You can generate those sub-passwords after logging in by giving them a name and their associated password. Those will be saved encrypted in binary located at "C:\Users\USER\AppData\Roaming\BetterPasswords\data".
