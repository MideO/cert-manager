import java.io.FileOutputStream
import java.nio.file.{Files, Paths}
import java.security.KeyStore
import java.security.cert.Certificate

import com.github.mideo.keystore.{KeyStoreManager, KeyStoreTypes}

class FileSystemJKeyStoreManagerImplSpec extends TestSpec {
  val keyStoreManager: KeyStoreManager = KeyStoreManager.FileSystemJKeyStoreManager

  behavior of "FileSystemJKeyStoreManagerImpl"

  it should "create" in {
    //When
    val keyStore: KeyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType)

    //Then
    keyStore.getType should be(KeyStoreTypes.DefaultKeyStoreType)
    Paths.get(testKeyStoreName) should not be null
    keyStoreManager.keyStoreExists(testKeyStoreName) should be(false)
  }

  it should "load" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType).store(f, password.toCharArray)

    //When
    val keyStore = keyStoreManager.load(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType)

    //Then
    keyStoreManager.keyStoreExists(testKeyStoreName) should be(true)
    keyStore.getType should be(KeyStoreTypes.DefaultKeyStoreType)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "save" in {
    //Given

    val keyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType)

    //When
    keyStoreManager.save(keyStore, testKeyStoreName, password)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be(true)

  }

  it should "delete" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType).store(f, password.toCharArray)

    //When
    keyStoreManager.delete(testKeyStoreName)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be(false)
  }

  it should "keyStoreExists" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType).store(f, password.toCharArray)

    //Then
    keyStoreManager.keyStoreExists(testKeyStoreName) should be(true)

    //And
    keyStoreManager.keyStoreExists("lalalla") should be(false)
  }


  it should "isKnownCertificate" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType).store(f, password.toCharArray)

    //When
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))


    //Then
    keyStoreManager.isKnownCertificate(certificate, testKeyStoreName, password) should be(false)
    keyStoreManager.isKnownCertificate(certificate, "someUnKnownCertificate", "pass") should be(false)

  }

  it should "isKnownEntry PrivateKey" in {
    //Given
    val keyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType)

    //When
    keyStore.setEntry(testPrivateKeyEntry.hashCode().toString, testPrivateKeyEntry, protectionParam)

    keyStoreManager.save(keyStore, testKeyStoreName, password)


    //Then
    keyStoreManager.isKnownEntry(testPrivateKeyEntry, testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType) should be(true)


  }

  it should "isKnownEntry SecretKey" in {
    //Given
    val keyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.SecretKeyStoreType)


    //When
    keyStore.setEntry(testSecretKeyEntry.hashCode().toString, testSecretKeyEntry, protectionParam)
    keyStoreManager.save(keyStore, testKeyStoreName, password)


    //Then
    keyStoreManager.isKnownEntry(testSecretKeyEntry, testKeyStoreName, password, KeyStoreTypes.SecretKeyStoreType) should be(true)


  }

}
