import java.io.FileOutputStream
import java.security.cert.Certificate

import com.github.mideo.keystore.{KeyStoreEntryManager, KeyStoreManager, KeyStoreManagerException, KeyStoreTypes}

class CertificateKeyStoreEntryManagerImplSpec extends TestSpec {

  behavior of "CertificateManager"
  val certificateManager: KeyStoreEntryManager[Certificate] = KeyStoreEntryManager
    .CertificateManager(KeyStoreManager.FileSystemJKeyStoreManager, testKeyStoreName, password)

  val testCertificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))


  it should "save" in {
    //When
    certificateManager.save(testCertificate)

    //Then
    certificateManager.isKnown(testCertificate) should be(true)

  }

  it should "save if keystore exists" in {

    //Given
    KeyStoreManager
      .FileSystemJKeyStoreManager
      .create(testKeyStoreName, password = password, KeyStoreTypes.JKS)
      .store(new FileOutputStream(testKeyStoreName), password.toCharArray)

    //When
    certificateManager.save(testCertificate)

    //Then
    certificateManager.isKnown(testCertificate) should be(true)

  }

  it should "isKnown" in {
    //Given
    certificateManager.save(testCertificate)

    //When
    certificateManager.delete(testCertificate)

    //Then
    certificateManager.isKnown(testCertificate) should be(false)
  }

  it should "throw error when no keystore is found for isKnown" in {
    the [KeyStoreManagerException] thrownBy {
      certificateManager.isKnown(testCertificate) should be(false)
    } should have message "No keystore found with name: MyKeyStore.jks"
  }

  it should "delete" in {
    //When
    certificateManager.save(testCertificate)

    //Then
    certificateManager.isKnown(testCertificate) should be(true)

    //When
    certificateManager.delete(testCertificate)


    //Then
    certificateManager.isKnown(testCertificate) should be(false)
  }

}
