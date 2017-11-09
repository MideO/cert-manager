package com.github.mideo

import java.io.InputStream
import java.security.cert.Certificate

class CertManagerSpec extends TestSpec {

  behavior of "CertManagerSpec"
  private def getResourceFile(name:String): InputStream ={
    getClass.getClassLoader.getResourceAsStream(name)
  }

  it should "saveCertificate" in {
    //Given
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))

    //When
    certManager.saveCertificate(certificate, testKeyStoreName, password)

    //Then
    certManager.isTrustedCertificate(certificate, testKeyStoreName, password) should be(true)

  }

  it should "isTrustedCertificate" in {
    //When
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))


    //Then
    certManager.isTrustedCertificate(certificate, testKeyStoreName, password) should be(false)

  }

  it should "deleteCertificate" in {
    //Given
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))

    //When
    certManager.saveCertificate(certificate, testKeyStoreName, password)

    //Then
    certManager.isTrustedCertificate(certificate, testKeyStoreName, password) should be(true)

    //When
    certManager.deleteCertificate(certificate, testKeyStoreName, password)


    //Then
    certManager.isTrustedCertificate(certificate, testKeyStoreName, password) should be(false)



  }

}
