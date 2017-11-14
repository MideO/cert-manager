package com.github.mideo.keystore

import java.security.KeyStore
import java.security.KeyStore.{PasswordProtection, PrivateKeyEntry}
import java.security.cert.Certificate

object KeyStoreEntryManager {
  def CertificateManager(keyStoreManager: KeyStoreManager,
                         keystoreName: String = "keystore.jks",
                         password: String = "password"): KeyStoreEntryManager[Certificate] = new CertificateKeyStoreEntryManagerImpl(keyStoreManager, keystoreName, password)

  def PrivateKeyEntryManager(keyStoreManager: KeyStoreManager,
                         keystoreName: String = "keystore.jks",
                         password: String = "password"): KeyStoreEntryManager[PrivateKeyEntry] = new PrivateKeyEntryKeyStoreEntryManagerImpl(keyStoreManager, keystoreName, password)
}

trait KeyStoreEntryManager[Entry] {
  val Manager: KeyStoreManager
  val KeystoreName:String
  val Password:String

  def save(entry: Entry): Unit = {

    val keyStore: KeyStore = if (Manager.keyStoreExists(KeystoreName)) {
      Manager.load(KeystoreName, Password)
    } else {
      Manager.create(KeystoreName, Password)
    }
    doSave(entry, keyStore)
    Manager.save(keyStore, KeystoreName, Password)
  }

  def delete(entry: Entry): Unit = {
    val keyStore: KeyStore = Manager.load(KeystoreName, Password)
    doDelete(entry, keyStore)
    Manager.save(keyStore, KeystoreName, Password)

  }

  def isKnown(entry: Entry): Boolean = {
    checkIsKnown(entry)
  }

  def doSave(entry: Entry, keyStore: KeyStore)

  def doDelete(entry: Entry, keyStore: KeyStore)

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

  override def doDelete(certificate: Certificate, keyStore: KeyStore): Unit = {
    keyStore.deleteEntry(certificate.hashCode().toString)
  }

  override def checkIsKnown(certificate: Certificate): Boolean = {
    Manager.isKnownCertificate(certificate, keystoreName, password)

  }

}


private[keystore] class PrivateKeyEntryKeyStoreEntryManagerImpl(keyStoreManager: KeyStoreManager, keystoreName: String , password: String )
  extends KeyStoreEntryManager[PrivateKeyEntry] {

  override val Manager: KeyStoreManager = keyStoreManager
  override val KeystoreName: String = keystoreName
  override val Password: String = password

  override def doSave(privateKeyEntry: PrivateKeyEntry, keyStore: KeyStore): Unit = {
    val protectionParam: KeyStore.ProtectionParameter = new PasswordProtection(Password.toCharArray)
    keyStore.setEntry(privateKeyEntry.hashCode().toString, privateKeyEntry, protectionParam)
  }

  override def doDelete(privateKeyEntry: PrivateKeyEntry, keyStore: KeyStore): Unit = {
        keyStore.deleteEntry(privateKeyEntry.hashCode().toString)
  }

  override def checkIsKnown(privateKeyEntry: PrivateKeyEntry): Boolean = {
        Manager.isKnownEntry(privateKeyEntry.hashCode().toString, keystoreName, password)
  }


}
