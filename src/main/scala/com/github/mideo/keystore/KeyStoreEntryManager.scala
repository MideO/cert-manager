package com.github.mideo.keystore

import java.security.KeyStore
import java.security.cert.Certificate

object KeyStoreEntryManager {
  def CertificateManager(keyStoreManager: KeyStoreManager): KeyStoreEntryManager[Certificate] = new CertificateKeyStoreEntryManagerImpl(keyStoreManager)
}

trait KeyStoreEntryManager[Entry] {
  val manager: KeyStoreManager

  def save(entry: Entry, keystoreName: String = "keystore.jks", password: String = "password"): Unit = {

    val keyStore: KeyStore = if (manager.keyStoreExists(keystoreName)) {
      manager.load(keystoreName, password)
    } else {
      manager.create(keystoreName, password)
    }
    doSave(entry, keyStore)
    manager.save(keyStore, keystoreName, password)
  }

  def delete(entry: Entry, keystoreName: String = "keystore.jks", password: String = "password"): Unit = {
    val keyStore: KeyStore = manager.load(keystoreName, password)
    doDelete(entry, keyStore)
    manager.save(keyStore, keystoreName, password)

  }

  def isKnown(entry: Entry, keystoreName: String = "keystore.jks", password: String = "password"): Boolean = {
    checkIsKnown(entry, keystoreName, password)
  }

  def doSave(entry: Entry, keyStore: KeyStore)

  def doDelete(entry: Entry, keyStore: KeyStore)

  def checkIsKnown(entry: Entry, keystoreName: String = "keystore.jks", password: String = "password"): Boolean
}

private[keystore] class CertificateKeyStoreEntryManagerImpl(keyStoreManager: KeyStoreManager) extends KeyStoreEntryManager[Certificate] {

  override val manager: KeyStoreManager = keyStoreManager

  override def doSave(certificate: Certificate, keyStore: KeyStore): Unit = {
    keyStore.setCertificateEntry(certificate.hashCode().toString, certificate)
  }

  override def doDelete(certificate: Certificate, keyStore: KeyStore): Unit = {
    keyStore.deleteEntry(certificate.hashCode().toString)
  }

  override def checkIsKnown(certificate: Certificate, keystoreName: String, password: String): Boolean = {
    manager.isKnownCertificate(certificate, keystoreName, password)

  }
}

