# Minimal IEEE 1609.2  
Ik heb voor alle datatypes alleen de ASN.1 structuren gemaakt die daarvoor nodig zijn, omdat de nieuwste `pyasn1` library niet kan decoden met univ.Choice, terwijl deze wel nodig is.  

# Unsecure Data  
`enc_unsecure.py` -> `messages/unsecure.txt` -> `dec_unsecure.py`  

# Signed Data  
`enc_signed.py` -> `messages/signed.txt` -> `dec_signed.py`  

# Encrypted Data  
`enc_encrypted.py` -> `messages/encrypted.txt` -> `dec_encrypted.py`  

# Enveloped Data  
<TODO>  