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

		self.cI = dict(self.config.items(section))	# cI ~ configItems 

		for k,v in self.cI.items():
			setattr(self, k, v)

		print self.cI

		self.privKeyFile = "%s/%s/%s" % (self.directory,section,	# Configuration des noms des fichiers
				self.privkeyfile)
		self.tempFile = "%s/%s/%s" % (self.directory,section,
				self.tempfile)
		self.CSRFile = "%s/%s/%s" % (self.directory,section,
				self.csrfile)
		self.CertFile = "%s/%s/%s" % (self.directory,section,
				self.certfile)
		try:
			self.domains = self.domain.split(",")	# gestion des alternativesDomainesNameso
		except:
			pass
		try:
			self.ips = self.ip.split(",")		# idem pour les IPs
		except:
			pass
		try:
			self.certtypes = self.certtype.split(",") # récupération des types de certificats (ca,server,client...)
		except:
			pass

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

		self.template += """
# In how many days, counting from today, this certificate will expire.
# Use -1 if there is no expiration date.
expiration_days = %s """ % self.expiration_days

		try:		# Ajoute une ligne dns_name pour chaque domaine
			if self.domains:
				self.template += """
# X.509 v3 extensions
# A dnsname in case of a WWW server. """
				for domain in self.domains:
					self.template += """
dns_name = %s """ % domain
		except:
			pass


		try:			# Idem pour chaque ip
			if self.ips:
				self.template += """
# An IP address in case of a server. """
				for ip in self.ips:
					self.template += """
ip_address = %s """ % ip
		except:
			pass

		self.template += """
# An email in case of a person
email = %s """ % self.email

		try:			# test password
			if self.password:
				self.template += """
# Password when encrypting a private key
password = %s """ % self.password
		except:
			pass

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
		En fonction des paramètres bits et secparam ont indique la taille de la clé """
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
