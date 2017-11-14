package com.github.mideo.keystore

import java.security.KeyStore.{PrivateKeyEntry, SecretKeyEntry}
import java.security.cert.Certificate

object KeyStoreEntryManager {
  def CertificateManager(keyStoreManager: KeyStoreManager): KeyStoreEntryManager[Certificate] = new CertificateKeyStoreEntryManagerImpl(keyStoreManager)
}

trait KeyStoreEntryManager[Entry] {
  def save(entry: Entry, keystoreName: String = "keystore.jks", password: String = "password"): Unit
  def delete(entry: Entry, keystoreName: String = "keystore.jks", password: String = "password"): Unit
  def isKnown(entry: Entry, keystoreName: String = "keystore.jks", password: String = "password"): Boolean
}

private[keystore] class CertificateKeyStoreEntryManagerImpl(keyStoreManager: KeyStoreManager) extends KeyStoreEntryManager[Certificate]{

  def save(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Unit = {

    val keyStore = if (keyStoreManager.keyStoreExists(keystoreName)) {
      keyStoreManager.load(keystoreName, password)
    } else {
      keyStoreManager.create(keystoreName, password)
    }

    keyStore.setCertificateEntry(certificate.hashCode().toString, certificate)
    keyStoreManager.save(keyStore, keystoreName, password)

  }

  def delete(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Unit = {
    val keyStore = keyStoreManager.load(keystoreName, password)
    keyStore.deleteEntry(certificate.hashCode().toString)
    keyStoreManager.save(keyStore, keystoreName, password)
  }

  def isKnown(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Boolean = {
    keyStoreManager.isKnownCertificate(certificate, keystoreName, password)
  }
}