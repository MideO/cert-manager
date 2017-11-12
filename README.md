#### Certificate Manager

[![Build Status](https://travis-ci.org/MideO/cert-manager.svg?branch=master)](https://travis-ci.org/MideO/cert-manager)

###### Certificate management module backed by Java KeyStore on file system as default storage

###### Usage

```scala
    //save certficatificate
    val certificates: Array[Certificate] = 	httpsURLConnection.getServerCertificates()
    certificates.foreach(
      certManager.saveCertificate(_, testKeyStoreName, password)
    )
    
    //Check certificate is trusted i.e. saved
    certificates.foreach(
      certManager.isTrustedCertificate(_, testKeyStoreName, password)
    ) 
    
```