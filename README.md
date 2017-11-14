#### keystore Manager - WIP

[![Build Status](https://travis-ci.org/MideO/keystore-manager.svg?branch=master)](https://travis-ci.org/MideO/keystore-manager)

###### Key management module backed by Java KeyStore on file system as default storage

###### Usage

```scala
    //save certficatificate
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
    
    
    
```