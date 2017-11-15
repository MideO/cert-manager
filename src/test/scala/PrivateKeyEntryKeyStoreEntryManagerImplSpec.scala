import java.io.FileOutputStream
import java.security.KeyStore.PrivateKeyEntry

import com.github.mideo.keystore.{KeyStoreEntryManager, KeyStoreManager, KeyStoreManagerException, KeyStoreTypes}

class PrivateKeyEntryKeyStoreEntryManagerImplSpec extends TestSpec {
  behavior of "PrivateKeyManager"
  val privateKeyManager: KeyStoreEntryManager[PrivateKeyEntry] = KeyStoreEntryManager
    .PrivateKeyEntryManager(KeyStoreManager.FileSystemJKeyStoreManager, testKeyStoreName, password)

  it should "save" in {
    //When
    privateKeyManager.save(testPrivateKeyEntry)

    //Then
    privateKeyManager.isKnown(testPrivateKeyEntry) should be(true)
  }

  it should "save if keystore exists" in {

    //Given
    KeyStoreManager
      .FileSystemJKeyStoreManager
      .create(testKeyStoreName, password = password, KeyStoreTypes.JKS)
      .store(new FileOutputStream(testKeyStoreName), password.toCharArray)

    //When
    privateKeyManager.save(testPrivateKeyEntry)

    //Then
    privateKeyManager.isKnown(testPrivateKeyEntry) should be(true)

  }


  it should "isKnown" in {
    //Given
    privateKeyManager.save(testPrivateKeyEntry)

    //When
    privateKeyManager.delete(testPrivateKeyEntry)

    //Then
    privateKeyManager.isKnown(testPrivateKeyEntry) should be(false)
  }

  it should "throw error when no keystore is found for isKnown" in {
    the [KeyStoreManagerException] thrownBy {
      privateKeyManager.isKnown(testPrivateKeyEntry) should be(false)
    } should have message "No keystore found with name: MyKeyStore.jks"
  }

  it should "delete" in {
    //When
    privateKeyManager.save(testPrivateKeyEntry)

    //Then
    privateKeyManager.isKnown(testPrivateKeyEntry) should be(true)

    //When
    privateKeyManager.delete(testPrivateKeyEntry)


    //Then
    privateKeyManager.isKnown(testPrivateKeyEntry) should be(false)
  }

  it should "error if keystore does exist for delete" in {

    the [KeyStoreManagerException] thrownBy {
      privateKeyManager.delete(testPrivateKeyEntry)
    } should have message "No keystore found with name: MyKeyStore.jks"
  }
}
