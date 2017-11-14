import java.security.cert.Certificate

import com.github.mideo.TestSpec
import com.github.mideo.keystore.{KeyStoreEntryManager, KeyStoreManager}

class CertificateKeyStoreEntryManagerImplSpec extends TestSpec {

  behavior of "CertificateManager"
  val certificateManager: KeyStoreEntryManager[Certificate] = KeyStoreEntryManager
    .CertificateManager(KeyStoreManager.FileSystemJKeyStoreManager, testKeyStoreName, password)


  it should "save" in {
    //Given
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))

    //When
    certificateManager.save(certificate)

    //Then
    certificateManager.isKnown(certificate) should be(true)

  }

  it should "isKnown" in {
    //When
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))


    //Then
    certificateManager.isKnown(certificate) should be(false)

  }

  it should "delete" in {
    //Given
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))

    //When
    certificateManager.save(certificate)

    //Then
    certificateManager.isKnown(certificate) should be(true)

    //When
    certificateManager.delete(certificate)


    //Then
    certificateManager.isKnown(certificate) should be(false)



  }

}
