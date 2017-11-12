import java.security.cert.Certificate

import com.github.mideo.{CertManager, FileSystemJKeyStoreManagerImpl, TestSpec}

class CertManagerSpec extends TestSpec {

  behavior of "CertManager"
  val certManager: CertManager = CertManager(FileSystemJKeyStoreManagerImpl)


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
