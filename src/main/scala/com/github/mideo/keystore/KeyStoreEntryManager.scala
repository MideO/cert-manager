package com.github.mideo.keystore

import java.security.KeyStore
import java.security.KeyStore.{PasswordProtection, PrivateKeyEntry, SecretKeyEntry}
import java.security.cert.Certificate

object KeyStoreEntryManager {
  def CertificateManager(keyStoreManager: KeyStoreManager,
                         keystoreName: String = "keystore.jks",
                         password: String = "password"): KeyStoreEntryManager[Certificate] = new CertificateKeyStoreEntryManagerImpl(keyStoreManager, keystoreName, password)


  def PrivateKeyEntryManager(keyStoreManager: KeyStoreManager,
                         keystoreName: String = "keystore.jks",
                         password: String = "password"): KeyStoreEntryManager[PrivateKeyEntry] = new PrivateKeyEntryKeyStoreEntryManagerImpl(keyStoreManager, keystoreName, password)

  def SecretKeyEntryManager(keyStoreManager: KeyStoreManager,
                             keystoreName: String = "keystore.jks",
                             password: String = "password"): KeyStoreEntryManager[SecretKeyEntry] = new SecretKeyEntryKeyStoreEntryManagerImpl(keyStoreManager, keystoreName, password)
}

trait KeyStoreEntryManager[Entry] {
  val Manager: KeyStoreManager
  val keyStoreType:String = KeyStoreTypes.DefaultKeyStoreType
  val KeystoreName:String
  val Password:String

  def save(entry: Entry): Unit = {

    val keyStore: KeyStore = if (Manager.keyStoreExists(KeystoreName)) {
      Manager.load(KeystoreName, Password, keyStoreType)
    } else {
      Manager.create(KeystoreName, Password, keyStoreType)
    }
    doSave(entry, keyStore)
    Manager.save(keyStore, KeystoreName, Password)
  }

  def delete(entry: Entry): Unit = {
    val keyStore: KeyStore = Manager.load(KeystoreName, Password, keyStoreType)
    keyStore.deleteEntry(entry.hashCode().toString)
    Manager.save(keyStore, KeystoreName, Password)

  }

  def isKnown(entry: Entry): Boolean = {
    checkIsKnown(entry)
  }

  def doSave(entry: Entry, keyStore: KeyStore): Unit

  def doDelete(entry: Entry, keyStore: KeyStore): Unit = keyStore.deleteEntry(entry.hashCode().toString)

  def checkIsKnown(entry: Entry): Boolean
}

private[keystore]
class CertificateKeyStoreEntryManagerImpl(keyStoreManager: KeyStoreManager, keystoreName: String , password: String )
  extends KeyStoreEntryManager[Certificate] {

  override val Manager: KeyStoreManager = keyStoreManager
  override val KeystoreName:String= keystoreName
  override val Password:String= password

  override def doSave(certificate: Certificate, keyStore: KeyStore): Unit = {
    keyStore.setCertificateEntry(certificate.hashCode().toString, certificate)
  }

  override def checkIsKnown(certificate: Certificate): Boolean = {
    Manager.isKnownCertificate(certificate, keystoreName, password)

  }

}

private[keystore]
class PrivateKeyEntryKeyStoreEntryManagerImpl(keyStoreManager: KeyStoreManager, keystoreName: String , password: String )
  extends KeyStoreEntryManager[PrivateKeyEntry] {

  override val Manager: KeyStoreManager = keyStoreManager
  override val KeystoreName: String = keystoreName
  override val Password: String = password

  override def doSave(privateKeyEntry: PrivateKeyEntry, keyStore: KeyStore): Unit = {
    val protectionParam: KeyStore.ProtectionParameter = new PasswordProtection(Password.toCharArray)
    keyStore.setEntry(privateKeyEntry.hashCode().toString, privateKeyEntry, protectionParam)
  }
  override def checkIsKnown(privateKeyEntry: PrivateKeyEntry): Boolean = {
        Manager.isKnownEntry(privateKeyEntry.hashCode().toString, keystoreName, password, keyStoreType)
  }
}

private[keystore]
class SecretKeyEntryKeyStoreEntryManagerImpl(keyStoreManager: KeyStoreManager, keystoreName: String , password: String )
  extends KeyStoreEntryManager[SecretKeyEntry] {

  override val Manager: KeyStoreManager = keyStoreManager
  override val KeystoreName: String = keystoreName
  override val Password: String = password
  override val keyStoreType:String = KeyStoreTypes.SecretKeyStoreType

  override def doSave(secretKeyEntry: SecretKeyEntry, keyStore: KeyStore): Unit = {
    val protectionParam: KeyStore.ProtectionParameter = new PasswordProtection(Password.toCharArray)
    keyStore.setEntry(secretKeyEntry.hashCode().toString, secretKeyEntry, protectionParam)
  }


  override def checkIsKnown(secretKeyEntry: SecretKeyEntry): Boolean = {
    Manager.isKnownEntry(secretKeyEntry.hashCode().toString, keystoreName, password, keyStoreType)
  }
}
