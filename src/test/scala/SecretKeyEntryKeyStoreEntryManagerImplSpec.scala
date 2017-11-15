import java.io.FileOutputStream
import java.security.KeyStore.SecretKeyEntry

import com.github.mideo.keystore.{KeyStoreEntryManager, KeyStoreManager, KeyStoreManagerException, KeyStoreTypes}

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


  it should "save if keystore exists" in {

    //Given
    KeyStoreManager
      .FileSystemJKeyStoreManager
      .create(testKeyStoreName, password = password, KeyStoreTypes.JKS)
      .store(new FileOutputStream(testKeyStoreName), password.toCharArray)

    //When
    secretKeyManager.save(testSecretKeyEntry)

    //Then
    secretKeyManager.isKnown(testSecretKeyEntry) should be(true)

  }

  it should "isKnown" in {
    //Given
    secretKeyManager.save(testSecretKeyEntry)

    //When
    secretKeyManager.delete(testSecretKeyEntry)

    //Then
    secretKeyManager.isKnown(testSecretKeyEntry) should be(false)
  }

  it should "throw error when no keystore is found for isKnown" in {
    the [KeyStoreManagerException] thrownBy {
      secretKeyManager.isKnown(testSecretKeyEntry) should be(false)
    } should have message "No keystore found with name: MyKeyStore.jks"
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

  it should "error if keystore does exist for delete" in {

    the [KeyStoreManagerException] thrownBy {
      secretKeyManager.delete(testSecretKeyEntry)
    } should have message "No keystore found with name: MyKeyStore.jks"
  }
}
