package com.github.mideo

import java.security.cert.Certificate

object CertManager {
  def apply(keyStoreManager: KeyStoreManager): CertManager = new CertManager(keyStoreManager)
}

class CertManager(keyStoreManager: KeyStoreManager) {

  def saveCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Unit = {
    val keyStore = keyStoreManager.create(keystoreName, password)
    keyStore.setCertificateEntry(certificate.hashCode().toString, certificate)
    keyStoreManager.save(keyStore, keystoreName, password)

  }

  def deleteCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Unit = {
    val keyStore = keyStoreManager.load(keystoreName, password)
    keyStore.deleteEntry(certificate.hashCode().toString)
    keyStoreManager.save(keyStore, keystoreName, password)
  }

  def isTrustedCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Boolean = {
    keyStoreManager.isKnownCertificate(certificate, keystoreName, password)
  }
}