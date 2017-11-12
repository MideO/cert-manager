package com.github.mideo

import java.io.{Closeable, FileOutputStream}
import java.nio.file.{Files, Paths, StandardOpenOption}
import java.security.KeyStore
import java.security.cert.Certificate

object FileSystemJKeyStoreManagerImpl extends KeyStoreManager {
  val KeyStoreType = "JKS"

  def withCloseable(c: Closeable, func: (Closeable) => Unit): Unit = {
    try {
      func(c)
    } finally {
      c.close()
    }
  }


  override def create(keystoreAbsolutePath: String, password: String): KeyStore = {
    val keyStore: KeyStore = KeyStore.getInstance(KeyStoreType)
    keyStore.load(null, password.toCharArray)
    keyStore
  }

  override def load(keystoreAbsolutePath: String, password: String): KeyStore = {
    val f = Files.newInputStream(Paths.get(keystoreAbsolutePath), StandardOpenOption.READ)
    val keyStore: KeyStore = KeyStore.getInstance(KeyStoreType)
    keyStore.load(f, password.toCharArray)
    keyStore
  }

  override def delete(path: String): Unit = Files.delete(Paths.get(path))

  override def isKnownCertificate(certificate: Certificate, keystoreName: String, password: String): Boolean = {
    if (!Files.exists(Paths.get(keystoreName))) {
      return false
    }
    val keyStore = load(keystoreName, password)

    keyStore.isCertificateEntry(certificate.hashCode().toString)

  }

  override def save(keyStore: KeyStore, keystoreName: String, password: String): Unit = {
    val f = new FileOutputStream(keystoreName)
    withCloseable(f, (f) => {
      keyStore.store(f.asInstanceOf[FileOutputStream], password.toCharArray)
    })

  }
}
