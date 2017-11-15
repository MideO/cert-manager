import java.security.KeyStore.SecretKeyEntry

import com.github.mideo.keystore.{KeyStoreEntryManager, KeyStoreManager}

class SecretKeyEntryKeyStoreEntryManagerImplSpec
  extends TestSpec {
  behavior of "SecretKeyManager"
  val secretKeyManager: KeyStoreEntryManager[SecretKeyEntry] = KeyStoreEntryManager
    .SecretKeyEntryManager(KeyStoreManager.FileSystemJKeyStoreManager, testKeyStoreName, password)

  it should "save" in {
    //When
    secretKeyManager.save(testSecretKeyEntry)

    //Then
    secretKeyManager.isKnown(testSecretKeyEntry) should be(true)

  }

  it should "isKnown" in {
    //Then
    secretKeyManager.isKnown(testSecretKeyEntry) should be(false)

  }

  it should "delete" in {
    //When
    secretKeyManager.save(testSecretKeyEntry)

    //Then
    secretKeyManager.isKnown(testSecretKeyEntry) should be(true)

    //When
    secretKeyManager.delete(testSecretKeyEntry)


    //Then
    secretKeyManager.isKnown(testSecretKeyEntry) should be(false)
  }
}
