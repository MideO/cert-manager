import java.security.KeyStore.PrivateKeyEntry

import com.github.mideo.keystore.{KeyStoreEntryManager, KeyStoreManager, KeyStoreManagerException}

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
}
