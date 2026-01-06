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

# Signed Data (certificate) 
_gebruikt `pyasn1` dmv `lib/asn1/signedCertASN1.py`._  
_gebruikt `lib/TerminalInterface` als CLI._  

`enc_signedCert.py` -> `messages/signedCert.txt` -> `dec_signedCert.py`  

**Uitleg:** PSID, generation time en expiry time worden opgeslagen als `HeaderInfo`. De payload (bytes) wordt met de HeaderInfo opgeslagen als `ToBeSignedData`. De public key wordt als `VerificationkeyIndicator/EccP256CurvePoint/UncompressedP256` meegegeven als bytes `X` en `Y` (32 byte integers). "pijlagen1234" wordt als name opgeslagen in `CertificateId`. Het begin van de geldigheid van het certificaat wordt als int opgeslagen als `validityPeriod/start`. De duur van de geldigheid van het certificaat wordt als Duration opgeslagen als `validityPeriod/duration`. crl (certificate revocation list) series blijft leeg (int 0) voor de demo. cracaId wordt gedefinieerd als placeholder hash. CertificateId, cracaId, crlSeries, validityPeriod en verifyKeyIndicator worden samen opgeslagen als `ToBeSignedCertificate`. ToBeSignedCertificate wordt met de PRIVATE_KEY gesigneerd en opgeslagen als `SignerIdentifier/Certificate/signature`. IssuerIdentifier wordt gevuld met random placeholder als `SignerIdentifier/Certificate/IssuerIdentifier/sha256AndDigest`. certificate versie is 1 (int). certificate type is 0 (int, explicit). versie, type, issue en ToBeSignedCertificate worden opgeslagen als `SignerIdentifier`. signature wordt gemaakt door ToBeSignedData te hashen en met de PRIVATE_KEY te ondertekenen, en wordt opgeslagen als bytes `R` en `S` (32 byte integers) als `Signature/EcdsaP256Signature`. hashId is 0 (int, sha256). HashId, ToBeSignedData, Signer en Signature worden samen opgeslagen als `SignedData`. Deze wordt in `Ieee1602Dot2Data` presenteer format opgeslagen.  

De ontvanger valideert de signature in het certificaat, de geldigheid van het certificaat, tijdcontrole van het bericht en valideert de signature op ToBeSignedData.   

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