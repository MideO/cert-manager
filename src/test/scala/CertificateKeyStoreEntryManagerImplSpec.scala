import java.security.cert.Certificate

import com.github.mideo.keystore.{KeyStoreEntryManager, KeyStoreManager, KeyStoreManagerException}

class CertificateKeyStoreEntryManagerImplSpec extends TestSpec {

  behavior of "CertificateManager"
  val certificateManager: KeyStoreEntryManager[Certificate] = KeyStoreEntryManager
    .CertificateManager(KeyStoreManager.FileSystemJKeyStoreManager, testKeyStoreName, password)

  val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))


  it should "save" in {
    //When
    certificateManager.save(certificate)

    //Then
    certificateManager.isKnown(certificate) should be(true)

  }

  it should "isKnown" in {
    //Given
    certificateManager.save(certificate)

    //When
    certificateManager.delete(certificate)

    //Then
    certificateManager.isKnown(certificate) should be(false)
  }

  it should "throw error when no keystore is found for isKnown" in {
    the [KeyStoreManagerException] thrownBy {
      certificateManager.isKnown(certificate) should be(false)
    } should have message "No keystore found with name: MyKeyStore.jks"
  }

  it should "delete" in {
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
