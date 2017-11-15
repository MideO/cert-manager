import java.security.KeyStore.PrivateKeyEntry

import com.github.mideo.keystore.{KeyStoreEntryManager, KeyStoreManager}

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
    //Then
    privateKeyManager.isKnown(testPrivateKeyEntry) should be(false)

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
