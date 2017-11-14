import java.security.cert.Certificate

import com.github.mideo.keystore.{KeyStoreEntryManager, KeyStoreManager}
import com.github.mideo.TestSpec

class CertificateKeyStoreEntryManagerImplSpec extends TestSpec {

  behavior of "CertificateManager"
  val certificateManager: KeyStoreEntryManager[Certificate] = KeyStoreEntryManager.CertificateManager(KeyStoreManager.FileSystemJKeyStoreManager)


  it should "saveCertificate" in {
    //Given
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))

    //When
    certificateManager.save(certificate, testKeyStoreName, password)

    //Then
    certificateManager.isKnown(certificate, testKeyStoreName, password) should be(true)

  }

  it should "isTrustedCertificate" in {
    //When
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))


    //Then
    certificateManager.isKnown(certificate, testKeyStoreName, password) should be(false)

  }

  it should "deleteCertificate" in {
    //Given
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))

    //When
    certificateManager.save(certificate, testKeyStoreName, password)

    //Then
    certificateManager.isKnown(certificate, testKeyStoreName, password) should be(true)

    //When
    certificateManager.delete(certificate, testKeyStoreName, password)


    //Then
    certificateManager.isKnown(certificate, testKeyStoreName, password) should be(false)



  }

}
