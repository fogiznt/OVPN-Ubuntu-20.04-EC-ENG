This script sets up the server configuration for OpenVPN.  
Peculiarities:  
1. Using elliptic curves as a certificate algorithm.  
2. Key exchange algorithm - ECDH. Instead of the typical DH.  
3. Using TLS-crypt min 1.2  
4. Static client addresses   

Installing OpenVPN - EC on Ubuntu 20.04  
``` 
cd ~
wget https://raw.githubusercontent.com/fogiznt/OVPN-Ubuntu-20.04-EC-ENG/main/openvpn.sh -O openvpn-install.sh --secure-protocol=TLSv1
chmod +x openvpn-install.sh
./openvpn-install.sh
```

Adding Users  
Users are on the web page of your server, if the web page does not work, then in the / root / directory   
```
cd ~ 
./account_manager.sh
```
