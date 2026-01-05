# Minimal IEEE 1609.2  
Ik heb voor alle datatypes alleen de ASN.1 structuren gemaakt die daarvoor nodig zijn, omdat de nieuwste `pyasn1` library niet kan decoden met univ.Choice, terwijl deze wel nodig is.  

# Unsecure Data  
_gebruikt `pyasn1` dmv `lib/asn1/unsecureASN1.py`._  
_gebruikt `lib/TerminalInterface` als CLI._  

`enc_unsecure.py` -> `messages/unsecure.txt` -> `dec_unsecure.py`  

**Uitleg:** payload bytes worden in Ieee1602Dot2Data presenteer format opgeslagen.  

# Signed Data  
_gebruikt `pyasn1` dmv `lib/asn1/signedASN1.py`._  
_gebruikt `lib/TerminalInterface` als CLI._  

`enc_signed.py` -> `messages/signed.txt` -> `dec_signed.py`  

**Uitleg:** generation time wordt gemeten. expiry time = generation time + 10 seconden. Deze metadata + PSID worden opgeslagen als `HeaderInfo`. HeaderInfo en payload (bytes) worden opgeslagen als `ToBeSignedData`. Zender ondertekent ToBeSignedData met private key. De signature wordt gedecodeerd to `R` en `S`, zodat deze als 32 byte integers worden opgeslagen als `ecdsaNistP256Signature`. Zender wordt geidentificeerd met "demo" in `SignerIdentifier`. Enumeration van gebruikte hashalgoritme wordt opgeslagen als `HashAlgorithm`. HashAlgorithm, ToBeSignedData, Signer en Signature worden opgeslagen als `SignedData`. Deze wordt in `Ieee1602Dot2Data` presenteer format opgeslagen.  

Het is belangrijk om te benoemen dat zowel de signature van de payload als de originele payload (in ToBeSignedData) worden gestuurd naar de ontvanger, zodat deze de signature kan vergelijken en valideren.  

De ontvanger voert tijdscontrole en signature validatie uit.  

# Encrypted Data  
_gebruikt `pyasn1` dmv `lib/asn1/encryptedASN1.py`._  
_gebruikt `lib/TerminalInterface` als CLI._  

`enc_encrypted.py` -> `messages/encrypted.txt` -> `dec_encrypted.py`  

**Uitleg:**  pre shared key is van te voren gedeeld met zender en ontvanger(s) als `psk`. `pskId` = eerste 8 bytes van psk. nonce is random waarde van max 12 bytes. `AESCCM` sleutel wordt aangemaakt o.b.v. psk. `ciphertext` wordt gemaakt door cryptografische functie van AESCCM in combinatie met payload_bytes en nonce. pskId wordt met ontvangers gedeeld in `PreSharedKeyRecipientInfo`. nonce en ciphertext worden gedeeld met `One28BitCcmCiphertext`. `recipients` is een lijst van `recipientInfo`. recipients en ciphertext worden gecombineerd tot `EncryptedData`. Deze wordt in `Ieee1602Dot2Data` presenteer format opgeslagen.  

De ontvanger voert pskId validatie en encryptie uit.  

# Enveloped Data  
_gebruikt `pyasn1` dmv `lib/asn1/envelopedASN1.py`._  
_gebruikt `lib/TerminalInterface` als CLI._  

`enc_enveloped.py` -> `messages/enveloped.txt` -> `dec_enveloped.py`  

**Uitleg:**  
<TODO>  