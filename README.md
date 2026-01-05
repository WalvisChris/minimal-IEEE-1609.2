# Minimal IEEE 1609.2  
Ik heb voor alle datatypes alleen de ASN.1 structuren gemaakt die daarvoor nodig zijn, omdat de nieuwste `pyasn1` library niet kan decoden met univ.Choice, terwijl deze wel nodig is.  

# Unsecure Data  
_gebruikt ` pyasn1` dmv `lib/asn1/unsecureASN1.py`._  

`enc_unsecure.py` -> `messages/unsecure.txt` -> `dec_unsecure.py`  

# Signed Data  
_gebruikt ` pyasn1` dmv `lib/asn1/signedASN1.py`._  

`enc_signed.py` -> `messages/signed.txt` -> `dec_signed.py`  

# Encrypted Data  
_gebruikt ` pyasn1` dmv `lib/asn1/encryptedASN1.py`._  

`enc_encrypted.py` -> `messages/encrypted.txt` -> `dec_encrypted.py`  

# Enveloped Data  
<TODO>  