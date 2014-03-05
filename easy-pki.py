#!/usr/bin/env python
# -*- coding:utf-8 -*- #

# Le module certtool ne dispose pas de fonction pour signer un certificat... il est très limité...
# sa documentation est trop petite, le projet ne semble pas très avancé.
# J'utilise donc directement la commande certtool avec subprocess

#import certtool # vestigial ne sert plus a grand chose
import re,ConfigParser,subprocess,shlex,os,argparse,sys


class certificates(list):
	"""
	La class certificates permet de modeliser l'ensemble
	des fichiers nécessaire à la création d'un certificat :
	- clé_privée
	- template de configuration du certificat pour certtool
	- éventuellement certificat_autosigné
	- éventuellement requète
	- éventuellement certificat signé par l'autorité
	"""

	def __init__(self, configfile, section):
		""" L'initialisation se fait en indiquant un fichier de configuration au format [section]/paramètre=
		et une section définissant le certificat
		"""

		self.config = ConfigParser.ConfigParser()
		try:
			self.config.read(configfile)
		except IOError:
			print "Erreur lors de la lecture du fichier %s" % configfile
		self.directory = re.sub(".cfg","",configfile) 	# le répertoire de tout les certificats est
								# basé sur le nom du fichier de configuration
		tempDir="./%s/%s" % (self.directory,section)	# ainsi le fichier de configuration devient en fait
								# la configuration d'une PKI complète
		if not os.path.exists(tempDir):
			os.makedirs(tempDir)

		self.cI = dict(self.config.items(section)	# cI ~ configItems 
		# J'obtiens un dictionnaire !
		for k, v in cI.items():
			setattr(self, k, v)
		# Je viens d'en faire les attributs de l'objet !!

		self.privKeyFile = "%s/%s/%s" % (self.directory,section,	# Configuration des noms des fichiers
				self.cI(section,"privKeyFile"))
		self.tempFile = "%s/%s/%s" % (self.directory,section,
				self.tempFile)
		self.CSRFile = "%s/%s/%s" % (self.directory,section,
				self.CSRFile)
		self.CertFile = "%s/%s/%s" % (self.directory,section,
				self.CertFile)
#		self.bits = self.config.get(section,"bits")			# Configuration de la taille de la clé
#		self.secparam = self.config.get(section,"sec-param")
#		self.common_name = self.config.get(section,"common_name")	# Nom commun
#		self.unit = self.config.get(section,"unit")			# Service
#		self.organization = self.config.get(section,"organization")	#
#		self.email = self.config.get(section,"email")
#		self.locality = self.config.get(section,"locality")
#		self.state = self.config.get(section,"state")			# Région
#		self.country = self.config.get(section,"country")
#		self.expiration_days = self.config.getint(section,"expiration_days")	# doit être un entier
#		self.password = self.config.get(section,"password")
#		self.domains = self.config.get(section,"domain").split(",")	# gestion des alternativesDomainesNames
#		self.ips = self.config.get(section,"ip").split(",")		# idem pour les IPs
#		self.certtypes = self.config.get(section,"certtype").split(",") # récupération des types de certificats (ca,server,client...)
		if self.domain:
			self.domains = self.domain.split(",")	# gestion des alternativesDomainesNames
		if self.ip:
			self.ips = self.ip.split(",")		# idem pour les IPs
		if self.certtype:
			self.certtypes = self.certtype.split(",") # récupération des types de certificats (ca,server,client...)

	def getCA(self):
		""" Cette fonction permet de récupérer les fichiers Cert et privKey d'un CA """
		if "ca" in self.certtypes:
			return (self.CertFile,self.privKeyFile)

	def make_template(self):
		""" Fonction qui génère le template à partir des informations du fichier de configuration """
		self.template = """
# X.509 Certificate options
#
# DN options
# The organization of the subject.
organization = %s
# The organizational unit of the subject.
unit = %s
# The locality of the subject.
locality = %s
# The state of the certificate owner.
state = %s
# The country of the subject. Two letter code.
country = %s
# The common name of the certificate owner.
cn = %s
""" % (self.organization,self.unit,self.locality,self.state,self.country,self.common_name)
		

		## VISIBLEMENT certtool ne maîtrise pas cette option dn donc on laisse tomber
		#			self.template += """
		#	# An alternative way to set the certificate's distinguished name directly
		#	# is with the "dn" option. The attribute names allowed are:
		#	# C (country), street, O (organization), OU (unit), title, CN (common name),
		#	# L (locality), ST (state), placeOfBirth, gender, countryOfCitizenship, 
		#	# countryOfResidence, serialNumber, telephoneNumber, surName, initials, 
		#	# generationQualifier, givenName, pseudonym, dnQualifier, postalCode, name, 
		#	# businessCategory, DC, UID, jurisdictionOfIncorporationLocalityName, 
		#	# jurisdictionOfIncorporationStateOrProvinceName,
		#	# jurisdictionOfIncorporationCountryName, XmppAddr, and numeric OIDs.
		#	
		#	#dn = "cn=%s,L=%s,st=%s,C=%s,O=%s,OU=%s" """ % (self.common_name,self.locality,self.state,self.country,self.organization,self.unit)

		# A faire pour plus tard : une fonction qui gère proprement le serial
		#			self.template += """
		#	# The serial number of the certificate
		#	# Comment the field for a time-based serial number.
		#	serial = %s """ % 


		self.template += """
# In how many days, counting from today, this certificate will expire.
# Use -1 if there is no expiration date.
expiration_days = %s """ % self.expiration_days

		self.template += """
# X.509 v3 extensions
# A dnsname in case of a WWW server. """
		for domain in self.domains:		# Ajoute une ligne dns_name pour chaque domaine
			self.template += """
dns_name = %s """ % domain

		self.template += """
# An IP address in case of a server. """
		for ip in self.ips:			# Idem pour chaque ip
			self.template += """
ip_address = %s """ % ip

		self.template += """
# An email in case of a person
email = %s """ % self.email

		if (self.password):
			self.template += """
# Password when encrypting a private key
password = %s """ % self.password

		# On ajoute signing et encryption par défaut, je ne suis pas sur que ce soit correct. 
		# Je n'ai rien trouvé sur gnutls.org
		self.template += """
# Whether this certificate will be used to sign data (needed
# in TLS DHE ciphersuites).
signing_key
# Whether this certificate will be used to encrypt data (needed
# in TLS RSA ciphersuites). Note that it is preferred to use different
# keys for encryption and signing.
encryption_key """

		# En fonction des type de certificat, on ajoute des possibilités
		if ("ca" in self.certtypes):
			self.template += """
# Whether this is a CA certificate or not
ca
# Whether this key will be used to sign other certificates.
cert_signing_key
# Whether this key will be used to sign CRLs.
crl_signing_key """

		if ("server" in self.certtypes):
			self.template += """
# Whether this certificate will be used for a TLS server
tls_www_server
"""

		if ("client" in self.certtypes):
			self.template += """
# Whether this certificate will be used for a TLS client
tls_www_client
"""
		if ("ipsec" in self.certtypes):
			self.template += """
# Whether this key will be used for IPsec IKE operations.
ipsec_ike_key
"""
		# Enfin on écrit le fichier template
		open(self.tempFile,"w").write(self.template)

	def createKey(self):
		""" Fonction de création de la clé privée
		En fonction des paramètres bits et sec-param ont indique la taille de la clé """
		if (self.secparam):
			command_line="certtool -p --sec-param %s --outfile %s" % (self.secparam,self.privKeyFile)
		elif (self.bits and not self.secparam):
			command_line="certtool -p --bits %s --outfile %s" % (self.bits,self.privKeyFile)
		print "\n\n %s" % command_line
		subprocess.call(shlex.split(command_line))

	def createSelf(self):
		""" Fonction de création du certificat autosigné (utile pour le CA) """
		command_line="certtool -s --load-privkey %s --template %s --outfile %s" % (self.privKeyFile,self.tempFile,self.CertFile)
		print "\n\n %s" % command_line
		subprocess.call(shlex.split(command_line))

	def createCSR(self):
		""" Fonction de création de la requète de certificat (avant signature) """
		command_line="certtool -q --load-privkey %s --template %s --outfile %s" % (self.privKeyFile,self.tempFile,self.CSRFile)
		print "\n\n %s" % command_line
		subprocess.call(shlex.split(command_line))

	def sign(self,CAcrt,CApriv):
		""" Fonction de signature de la requète 
		Nécessite le nom des fichiers cert et key du CA """
		command_line="certtool -c --load-request %s --load-ca-certificate %s --load-ca-privkey %s --template %s --outfile %s" % (self.CSRFile,CAcrt,CApriv,self.tempFile,self.CertFile)
		print "\n\n %s" % command_line
		subprocess.call(shlex.split(command_line))

if __name__ == "__main__":

	arguments = argparse.ArgumentParser()
	arguments.add_argument("-c","--config",help="Définit le fichier de configuration à utiliser")
	
	args = arguments.parse_args()

	if not args.config:
		print "Erreur : Pas de fichier de configuration indiqué"
		arguments.print_help()
		sys.exit(1)
	elif not os.path.exists(args.config):
		print "Erreur : Le fichier de configuration indiqué n'existe pas"
		arguments.print_help()
		sys.exit(2)
	
	myConfig = ConfigParser.ConfigParser()
	myConfig.read(args.config)		# On lit le fichier de configuration

	for section in myConfig.sections():
		if (re.search("^CA",section)):		# On traite en premier la section du CA
			print section
			myCert = certificates(args.config,section)
			myCert.make_template()
			myCert.createKey()
			myCert.createSelf()
			(CAcert,CAkey) = myCert.getCA()
		if (not re.search("^CA",section)):	# Ensuite on traite chaque section de certificat
			myCert = certificates(args.config,section)
			myCert.make_template()
			myCert.createKey()
			myCert.createCSR()
			myCert.sign(CAcert,CAkey)
	sys.exit(0)
