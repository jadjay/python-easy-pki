python-easy-pki
===============

Outil et bibliothèque permettant de générer une PKI en partant d'un simple fichier de configuration
```
$ python pkitls.py -h
usage: pkitls.py [-h] [-c CONFIG]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Définit le fichier de configuration à utiliser
```

Exemple de fichier de configuration
===================================

pki_domain.tld.cfg
```
[CA_domain.tld] # On définit une section pour le CA dont le nom commence par CA
privkeyFile=caprivkey.pem
CertFile=cacert.pem
tempFile=catemplate.cfg
CSRFile=
# Type de certificat : valeur possible ca,server,client,ipsec
certtype=ca
# Taille de la clé privée, On préferera indiquer sec-param à bits mais les deux sont possibles,
# si les deux sont indiqués on préferera sec-param.
bits=2048
# sec-pram les choix possibles sont : low,normal,high
sec-param=high
expiration_days=1800
email=contact@domain.tld
common_name=Certificat Autorite domain.tld
organization=domain.tld
# unit permet d'indiquer le Service
unit=Internet
locality=Saint Etienne
# state permet d'indiquer la Region
state=RHONE-ALPES
country=FR
domain=
ip=
# Attention devrait servir pour les clés privée mais ne fonctionne pas encore
password=
[serveur_web] # Chaque certificat fait l'object d'une section à part, le nom de la section deviendra un dossier
privkeyFile=webkey.pem
CertFile=webcert.pem
tempFile=webtemplate.cfg
CSRFile=webcsr.pem
# Type de certificat : valeur possible ca,server,client,ipsec
certtype=server
# Taille de la clé privée, On préferera indiquer sec-param à bits mais les deux sont possibles
# si les deux sont indiqués on préferera sec-param.
bits=
# sec-pram les choix possibles sont : low,normal,high
sec-param=high
common_name=Certificat serveur web domain.tld
# unit permet d'indiquer le Service
unit=web
organization=domain.tld
email=contact@domain.tld
locality=Saint Etienne
# Region
state=RHONE-ALPES
country=FR
expiration_days=700
# Attention limité à 4 (a 5 certtool boucle indéfiniment, audela il refuse de créer le certificat)
domain=blog.domain.tld,cloud.domain.tld,www.domain.tld,webmail.domain.tld
ip=31.33.73.66
password=
[serveur_mail]
privkeyFile=mailkey.pem
CertFile=mailcert.pem
tempFile=mailtemplate.cfg
CSRFile=mailcsr.pem
certtype=server,client
# Attention même vide les paramètres doivent figurer
bits=
sec-param=high
common_name=Certificat serveur mail domain.tld
unit=mail
organization=domain.tld
email=contact@domain.tld
locality=Saint Etienne
state=RHONE-ALPES
country=FR
expiration_days=700
domain=mail.domain.tld,smtp.domain.tld,imap.domain.tld
ip=31.33.73.66
password=
[serveur_xmpp]
privkeyFile=xmppkey.pem
CertFile=xmppcert.pem
tempFile=xmpptemplate.cfg
CSRFile=xmppcsr.pem
certtype=server,client
bits=
sec-param=high
common_name=Certificat serveur xmpp domain.tld
unit=mail
organization=domain.tld
email=contact@domain.tld
locality=Saint Etienne
state=RHONE-ALPES
country=FR
expiration_days=700
domain=xmpp.domain.tld,jabber.domain.tld
ip=31.33.73.66
password=
```
