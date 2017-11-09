package com.github.mideo

import java.io.{Closeable, FileOutputStream}
import java.nio.file.{Files, Paths, StandardOpenOption}
import java.security.KeyStore
import java.security.cert.Certificate

object CertManager {
  def apply(keyStoreManager: KeyStoreManager): CertManager = new CertManager(keyStoreManager)
}


class CertManager(keyStoreManager: KeyStoreManager) {


  def withCloseable(c: Closeable, func: () => Unit): Unit = {
    func()
    c.close()
  }

  def saveCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Unit = {
    val f = new FileOutputStream(keystoreName)
    val keyStore = keyStoreManager.create(f, password)

    withCloseable(f, () => {
      keyStore.setCertificateEntry(certificate.hashCode().toString, certificate)
      keyStore.store(f, password.toCharArray)
    })
    keyStore.size()
  }

  def deleteCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Unit = {
    val f = Files.newInputStream(Paths.get(keystoreName), StandardOpenOption.READ)
    val keyStore = keyStoreManager.load(f, password)
    keyStore.deleteEntry(certificate.hashCode().toString)

}

  def isTrustedCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Boolean = {
    var isTrusted: Boolean = false
    if (!Files.exists(Paths.get(keystoreName))) {
      return false
    }
    val f = Files.newInputStream(Paths.get(keystoreName), StandardOpenOption.READ)

    val keyStore = keyStoreManager.load(f, password)

    withCloseable(f, () => {
      isTrusted = keyStore.isCertificateEntry(certificate.hashCode().toString)
    })
    keyStore.size()

    isTrusted
  }
}