#### keystore Manager

[![Build Status](https://travis-ci.org/MideO/keystore-manager.svg?branch=master)](https://travis-ci.org/MideO/keystore-manager)

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.mideo/keystore-manager_2.11/badge.svg)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.github.mideo%22%20a%3A%22keystore-manager_2.11%22)


###### Key management module backed by Java KeyStore on file system as default storage

###### Usage

```scala
    //save certficatificate with default FileSystemJKeyStoreManager
    val certificates: Array[Certificate] = 	httpsURLConnection.getServerCertificates()
    val certManager: KeyStoreEntryManager = KeyStoreEntryManager.CertificateManager(KeyStoreManager.FileSystemJKeyStoreManager)
    
    certificates.foreach(
      certManager.saveCertificate(_, testKeyStoreName, password)
    )
    
    //Check certificate is known
    certificates.foreach(
      certManager.isKnown(_, testKeyStoreName, password)
    )
    
    //or implement custom KeyStoreManager
    object MongoJKeyStoreManagerImpl extends KeyStoreManager {
      override def create(keystoreAbsolutePath: String, password: String): KeyStore = {
        ....
      } 
    
      override def load(keyStoreAbsolutePath: String, password: String): KeyStore = {     
        ....
      } 
    
      override def isKnownCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Boolean = {
         ...                                                                                                                                               
      } 
    
      override def delete(path: String): Unit = {
         ...                                                                                                                                               
      } 
    
      override def save(keyStore: KeyStore, keystoreName: String, password: String): Unit = {
         ...                                                                                                                                                
       }
     
    }
    
    val mongoCertManager: KeyStoreEntryManager = KeyStoreEntryManager.CertificateManager(MongoJKeyStoreManagerImpl)
    
    
    //save private key entry
      protected def makePrivateKeyEntry():PrivateKeyEntry = {
        val gen = new CertAndKeyGen("RSA", "SHA1WithRSA")
        gen.generate(1024)
        val pk: PrivateKey = gen.getPrivateKey
        val cert: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))
        new PrivateKeyEntry(pk, Array(cert))
      }
    
      val testPrivateKeyEntry: PrivateKeyEntry = makePrivateKeyEntry()
      val privateKeyManager: KeyStoreEntryManager[PrivateKeyEntry] = KeyStoreEntryManager
        .PrivateKeyEntryManager(KeyStoreManager.FileSystemJKeyStoreManager, testKeyStoreName, password)

      privateKeyManager.save(testPrivateKeyEntry)
   
   // check is known private key
      privateKeyManager.isKnown(testPrivateKeyEntry) should be(true)
    //delete private key entry
    privateKeyManager.delete(testPrivateKeyEntry)
    
    
    
    
    //save a secret key entry
      val testSecretKeyEntry = new KeyStore.SecretKeyEntry(
        new SecretKeySpec(password.getBytes(), 0, password.getBytes().length, "AES"))
      val secretKeyManager: KeyStoreEntryManager[SecretKeyEntry] = KeyStoreEntryManager
        .SecretKeyEntryManager(KeyStoreManager.FileSystemJKeyStoreManager, testKeyStoreName, password)       
     secretKeyManager.save(testSecretKeyEntry)
    
    //check is known secret key entry
    secretKeyManager.isKnown(testSecretKeyEntry) 
     
    //delete secret key entry
    secretKeyManager.delete(testSecretKeyEntry)
    
    
```