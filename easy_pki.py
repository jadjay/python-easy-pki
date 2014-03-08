#!/usr/bin/env python
# -*- coding:utf-8 -*- #

# Le module certtool ne dispose pas de fonction pour signer un certificat... il est très limité...
# sa documentation est trop petite, le projet ne semble pas très avancé.
# J'utilise donc directement la commande certtool avec subprocess

#import certtool # vestigial ne sert plus a grand chose
import re,ConfigParser,subprocess,shlex,os,argparse,sys,filecmp

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

	def __init__(self, configfile, section, TEMP=False):
		""" L'initialisation se fait en indiquant un fichier de configuration au format [section]/paramètre=
		et une section définissant le certificat
		"""

		self.config = ConfigParser.ConfigParser()
		try:
			self.config.read(configfile)
		except IOError:
			print "Erreur lors de la lecture du fichier %s" % configfile
		# le répertoire de tout les certificats est
		# basé sur le nom du fichier de configuration
		# ainsi le fichier de configuration devient en fait
		# la configuration d'une PKI complète
		if TEMP:
			self.directory = "%s_%s" % ("tmp",re.sub(".cfg","",configfile))
		else:
			self.directory = re.sub(".cfg","",configfile)

		self.tempDir="./%s/%s" % (self.directory,section)

		if not os.path.exists(self.tempDir):
			os.makedirs(self.tempDir)

		self.oldconfigfile="%s/oldconfig.cfg" % self.tempDir

		if not os.path.exists(self.oldconfigfile):
			self.config.write(open(self.oldconfigfile,"w"))
			self.oldexist=False
		else:
			self.oldexist=True
			self.oldconfig = ConfigParser.ConfigParser()
			self.oldconfig.read(self.oldconfigfile)
			self.oldCI = dict(self.oldconfig.items(section))	# cI ~ configItems 

		self.cI = dict(self.config.items(section))	# cI ~ configItems 

		for k,v in self.cI.items():
			setattr(self, k, v)

		# gestion des alternativesDomainesNameso
		try:
			self.domains = self.domain.split(",")
		except:
			pass
		# idem pour les IPs
		try:
			self.ips = self.ip.split(",")
		except:
			pass
		# récupération des types de certificats (ca,server,client...)
		try:
			self.certtypes = self.certtype.split(",")
		except:
			pass

		# Configuration des noms des fichiers
		self.privKeyFile = "%s/%s/%s" % (self.directory,section,
				self.privkeyfile)
		self.tempFile,self.tempTempFile = "%s/%s/%s" % (
				self.directory,section,self.tempfile), (
				self.directory,section,"tempTemplate.cfg")
		self.CSRFile = "%s/%s/%s" % (self.directory,section,
				self.csrfile)
		self.CertFile = "%s/%s/%s" % (self.directory,section,
				self.certfile)
		if ("ca" in self.certtypes):
			self.caSerialFile = "%s/%s/serial" % (self.directory,section)

	def getCA(self):
		""" Cette fonction permet de récupérer les fichiers Cert et privKey d'un CA """
		if "ca" in self.certtypes:
			return (self.CertFile,self.privKeyFile,self.caSerialFile)

	def exist(self):
		if os.path.isfile(self.privKeyFile) and os.path.isfile(self.CertFile):
			return True
		else:
			return False

	def newtemplate(self, CAserial=None, TEMP=False):
		self.oTemplate = ConfigParser.ConfigParser()
		self.oTemplate.add_section(self.directory)
		self.oTemplate.set(self.directory,"organization",self.organization)
		self.oTemplate.set(self.directory,"unit",self.unit)
		self.oTemplate.set(self.directory,"locality",self.locality)
		self.oTemplate.set(self.directory,"state",self.state)
		self.oTemplate.set(self.directory,"country",self.country)
		self.oTemplate.set(self.directory,"cn",self.cn)
		self.oTemplate.set(self.directory,"expiration_days",self.expiration_days)
		self.oTemplate.set(self.directory,"signing_key",None)
		self.oTemplate.set(self.directory,"encryption_key",None)
		if ("server" in self.certtypes):
			self.oTemplate.set(self.directory,"tls_www_server",None)
			try:
				for domain in self.domains:
					self.oTemplate.set(self.directory,"dns_name",domain)
			except:
				pass
			try:			# Idem pour chaque ip
				for ip in self.ips:
					self.oTemplate.set(self.directory,"ip_address",ip)
			except:
				pass
		if ("client" in self.certtypes):
			self.oTemplate.set(self.directory,"tls_www_client",None)
			self.oTemplate.set(self.directory,"email",self.email)
		if ("ipsec" in self.certtypes):
			self.oTemplate.set(self.directory,"ipsec_ike_key",None)
		try:			# test password
			self.oTemplate.set(self.directory,"password",self.password)
		except:
			pass
		# En fonction des type de certificat, on ajoute des possibilités
		if ("ca" in self.certtypes):
			serialfile = open(self.caSerialFile, "w+")
			serialfile.write("001\n")
			serialfile.close()
			self.oTemplate.set(self.directory,"serial","001")
			self.oTemplate.set(self.directory,"ca",None)
			self.oTemplate.set(self.directory,"cert_signing_key",None)
			self.oTemplate.set(self.directory,"crl_signing_key",None)
		else:
			oldserial = open(CAserial, "rb")
			oldserials = oldserial.readlines()
			oldserial.close()
			newserial =int(oldserials[-1])+1
			appserial = open(CAserial, "a")
			appserial.write("%03i\n" % newserial )
			appserial.close()
			self.oTemplate.set(self.directory,"serial","%03i" % newserial )

		# Enfin on écrit le fichier template
		if (TEMP==True):
			self.oTemplate.write(open(self.tempTempFile,"w"))
		else:
			self.oTemplate.write(open(self.tempFile,"w"))

		# On elimine la section [default]
		with open(self.tempFile,"r") as cropfile:
			cropfile.readline()
			contentscroped = cropfile.read()
		with open(self.tempFile,"w") as cropedfile:
			cropedfile.write(contentscroped)
		

	def make_template(self, CAserial=None, TEMP=False):
		""" Fonction qui génère le template à partir des informations du fichier de configuration """
		self.template = """
# X.509 Certificate options
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
""" % (self.organization,self.unit,self.locality,self.state,self.country,self.cn)

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
			serialfile = open(self.caSerialFile, "w+")
			serialfile.write("001\n")
			serialfile.close()
			self.template += """
# Serial Number
serial = 001
# Whether this is a CA certificate or not
ca
# Whether this key will be used to sign other certificates.
cert_signing_key
# Whether this key will be used to sign CRLs.
crl_signing_key """
		else:
			oldserial = open(CAserial, "rb")
			oldserials = oldserial.readlines()
			oldserial.close()
			newserial =int(oldserials[-1])+1
			appserial = open(CAserial, "a")
			appserial.write("%03i\n" % newserial )
			appserial.close()
			self.template += """
# Serial Number
serial = %03i """ % newserial
		if ("server" in self.certtypes):
			self.template += """
# Whether this certificate will be used for a TLS server
tls_www_server """
		if ("client" in self.certtypes):
			self.template += """
# Whether this certificate will be used for a TLS client
tls_www_client """
		if ("ipsec" in self.certtypes):
			self.template += """
# Whether this key will be used for IPsec IKE operations.
ipsec_ike_key """
		# Enfin on écrit le fichier template
		if (TEMP==True):
			open(self.tempTempFile,"w").write(self.template)
		else:
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
		""" Fonction de création de la requête de certificat (avant signature) """
		command_line="certtool -q --load-privkey %s --template %s --outfile %s" % (self.privKeyFile,self.tempFile,self.CSRFile)
		print "\n\n %s" % command_line
		subprocess.call(shlex.split(command_line))

	def sign(self,CAcrt,CApriv,CAserial):
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
		if re.search("^CA",section):		# On traite en premier la section du CA
			print section
			myCA = certificates(args.config,section)
			if not myCA.exist():
				myCA.newtemplate()
				#myCA.make_template()
				myCA.createKey()
				myCA.createSelf()
		else:					# Ensuite on traite chaque section de certificat
			print section
			myCert = certificates(args.config,section)
			if myCert.oldexist:
				print "%s exist!" % section
				count,diff=0,[]
				for (tempK,tempV) in myCert.oldCI.items():
					try:
						K = myCert.cI.get(section,tempK)
						V = myCert.cI.get(section,tempV)
						print "%s %s %s %s" % (tempK,tempV,K,V)
						if (tempV != V ):
							#print "%s: %s\t\t%s: %s" % (tempK,tempV,tempK,V)
							count+=1
							diff.append(tempK)
					except:
							count+=1
							diff.append(tempK)
				if count > 0:
					print "Le certificat %s a été modifié" % section
					print "Voici la liste des modifications :"
					for d in diff:
						print " - %s" % d
					reponse = raw_input("Voulez vous changer le certificat %s ? [O/n] " % section)
					if reponse == None or reponse == "0" or reponse == "o":
						myCert.newtemplate(myCA.caSerialFile)
						#myCert.make_template(myCA.caSerialFile)
						myCert.createCSR()
						myCert.sign(myCA.CertFile,myCA.privKeyFile,myCA.caSerialFile)
						myCert.config.write(open(myCert.oldconfigfile,"w"))
			else:
				myCert.newtemplate(myCA.caSerialFile)
				#myCert.make_template(myCA.caSerialFile)
				myCert.createKey()
				myCert.createCSR()
				myCert.sign(myCA.CertFile,myCA.privKeyFile,myCA.caSerialFile)
	sys.exit(0)
