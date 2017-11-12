#### Certificate Manager

[![Build Status](https://travis-ci.org/MideO/cert-manager.svg?branch=master)](https://travis-ci.org/MideO/cert-manager)

###### Certificate management module backed by Java KeyStore on file system as default storage

###### Usage

```scala
    //save certficatificate
    val certificates: Array[Certificate] = 	httpsURLConnection.getServerCertificates()
    val certManager: CertManager = CertManager(FileSystemJKeyStoreManagerImpl)
    
    certificates.foreach(
      certManager.saveCertificate(_, testKeyStoreName, password)
    )
    
    //Check certificate is trusted i.e. saved
    certificates.foreach(
      certManager.isTrustedCertificate(_, testKeyStoreName, password)
    )
    
    //or implement you custom KeyStoreManager
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
    
    val mongoCertManager: CertManager = CertManager(MongoJKeyStoreManagerImpl)
    
    
    
```