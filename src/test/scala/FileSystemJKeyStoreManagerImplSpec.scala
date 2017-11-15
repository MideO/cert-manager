import java.io.FileOutputStream
import java.nio.file.{Files, Paths}
import java.security.KeyStore
import java.security.cert.Certificate

import com.github.mideo.keystore.{KeyStoreManager, KeyStoreManagerException, KeyStoreTypes}

class FileSystemJKeyStoreManagerImplSpec extends TestSpec {
  val keyStoreManager: KeyStoreManager = KeyStoreManager.FileSystemJKeyStoreManager

  behavior of "FileSystemJKeyStoreManagerImpl"

  it should "create" in {
    //When
    val keyStore: KeyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.JKS)

    //Then
    keyStore.getType should be(KeyStoreTypes.JKS)
    Paths.get(testKeyStoreName) should not be null
    keyStoreManager.keyStoreExists(testKeyStoreName) should be(false)
  }

  it should "load" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.JKS).store(f, password.toCharArray)

    //When
    val keyStore = keyStoreManager.load(testKeyStoreName, password, KeyStoreTypes.JKS)

    //Then
    keyStoreManager.keyStoreExists(testKeyStoreName) should be(true)
    keyStore.getType should be(KeyStoreTypes.JKS)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "error if there is not keystore to load" in {
    the [KeyStoreManagerException] thrownBy {
      keyStoreManager.load("lalala", password, KeyStoreTypes.JKS)
    } should have message "No keystore found with name: lalala"
  }

  it should "save" in {
    //Given

    val keyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.JKS)

    //When
    keyStoreManager.save(keyStore, testKeyStoreName, password)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be(true)

    //When

  }

  it should "delete" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.JKS).store(f, password.toCharArray)

    //When
    keyStoreManager.delete(testKeyStoreName)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be(false)
  }

  it should "error if keystore does exist for delete" in {

    the [KeyStoreManagerException] thrownBy {
      keyStoreManager.delete("lalalala")
    } should have message "No keystore found with name: lalalala"
  }

  it should "keyStoreExists" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.JKS).store(f, password.toCharArray)

    //Then
    keyStoreManager.keyStoreExists(testKeyStoreName) should be(true)

    //And
    keyStoreManager.keyStoreExists("lalalla") should be(false)
  }


  it should "isKnownCertificate" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.JKS).store(f, password.toCharArray)

    //When
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))

    //Then
    keyStoreManager.isKnownCertificate(certificate, testKeyStoreName, password) should be(false)
  }

  it should "throw error if keystore doesn't exist for isKnownCertificate" in {

    //When
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))

    //Then
    the [KeyStoreManagerException] thrownBy {
      keyStoreManager.isKnownCertificate(certificate, "someUnKnownCertificate", "pass")
    } should have message "No keystore found with name: someUnKnownCertificate"

  }

  it should "isKnownEntry PrivateKey" in {
    //Given
    val keyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.JKS)

    //When
    keyStore.setEntry(testPrivateKeyEntry.hashCode().toString, testPrivateKeyEntry, protectionParam)

    keyStoreManager.save(keyStore, testKeyStoreName, password)


    //Then
    keyStoreManager.isKnownEntry(testPrivateKeyEntry, testKeyStoreName, password, KeyStoreTypes.JKS) should be(true)


  }

  it should "isKnownEntry SecretKey" in {
    //Given
    val keyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.JCEKS)


    //When
    keyStore.setEntry(testSecretKeyEntry.hashCode().toString, testSecretKeyEntry, protectionParam)
    keyStoreManager.save(keyStore, testKeyStoreName, password)


    //Then
    keyStoreManager.isKnownEntry(testSecretKeyEntry, testKeyStoreName, password, KeyStoreTypes.JCEKS) should be(true)


  }

}
