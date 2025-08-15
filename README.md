# secret_chat
This is a simple chat application which can be used locally and the data are encrypted by using with share key(if needed)

## **Windows**


### 1 Install the `cryptography` library
In **Command Prompt**, run:  
```bash
pip install cryptography
```
### 2 Prepare Your Files

Make sure both files are in the same folder:
```
. crypto_module.py
. secret_chat.py
```

Save both files (crypto_module.py & secret_chat.py) in the same folder.

Run `python secret_chat.py` in two different terminal

At first on getting the prompt write **server** or  **client** to get role

If client is chosen then you need to provide the IP Address of server. Use `ipconfig` to get the IPV4 address for Ethernet2

Normal message will be sent withour any encryption by clicking send.

You may Share Public key from both end and then share  AES key.

After that every conversation will be encyrted and decrypted at both ends.

