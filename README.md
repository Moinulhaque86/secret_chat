# secret_chat
This is a simple chat application which can be used locally and the data are encrypted by using with share key(if needed)

## **Windows**


### 1 Install the `cryptography` library
In **Command Prompt**, run:  
```bash
pip install cryptography
```
### 2 Prepare Your Files

Make sure both files are in the **same folder**:
```
. crypto_module.py
. secret_chat.py
```

### 3 Run the Chat Program

Open two Command Prompt windows and run in each:
```
python secret_chat.py
``` 

### 4 Choose Your Role

When prompted, type:

`server` → Starts as the host

`client` → Connects to the host (requires the host’s IP address)

### 5 Finding the Server IP Address

If you are the client, get the server’s IPv4 address:
```
ipconfig
```

Look for **Ethernet2** → **IPv4 Address**


### 6 Sending Messages
```
. Normal messages are sent without **encryption** 

. You may share public keys from both ends and then exchange an AES key

. After exchanging the AES key, all messages will be encrypted and decrypted automatically on both ends 

```


# Contributor of the project

Moinul Haque moinul.haque@bracu.ac.bd/ moinulmamun5@gmail.com
