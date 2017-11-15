package com.github.mideo.keystore

import java.io.{Closeable, FileOutputStream, InputStream}
import java.nio.file.{Files, Paths, StandardOpenOption}
import java.security.KeyStore
import java.security.KeyStore.Entry
import java.security.cert.Certificate


object KeyStoreManager {
  def FileSystemJKeyStoreManager: KeyStoreManager = FileSystemJKeyStoreManagerImpl
}

object KeyStoreTypes extends Enumeration {
  val DefaultKeyStoreType: String = "JKS"
  val SecretKeyStoreType: String = "JCEKS"
}


trait KeyStoreManager {
  def create(keystoreAbsolutePath: String, password: String, keyStoreType: String): KeyStore

  def load(keyStoreAbsolutePath: String, password: String, keyStoreType: String): KeyStore

  def keyStoreExists(keyStoreAbsolutePath: String): Boolean

  def isKnownCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Boolean

  def isKnownEntry(entry: Entry, keystoreName: String = "keystore.jks", password: String = "password", keyStoreType: String): Boolean

  def delete(path: String): Unit

  def save(keyStore: KeyStore, keystoreName: String, password: String): Unit
}

private[keystore] object FileSystemJKeyStoreManagerImpl
  extends KeyStoreManager {


  private def withCloseable(c: Closeable, func: (Closeable) => Unit): Unit = {
    try {
      func(c)
    } finally {
      c.close()
    }
  }


  override def create(keystoreAbsolutePath: String, password: String, keyStoreType: String = KeyStoreTypes.DefaultKeyStoreType): KeyStore = {
    val keyStore: KeyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null, password.toCharArray)
    keyStore
  }

  override def load(keystoreAbsolutePath: String, password: String, keyStoreType: String = KeyStoreTypes.DefaultKeyStoreType): KeyStore = {
    if (!keyStoreExists(keystoreAbsolutePath)) {
      throw KeyStoreManagerException(s"No keystore found with name: $keystoreAbsolutePath")
    }
    val f: InputStream = Files.newInputStream(Paths.get(keystoreAbsolutePath), StandardOpenOption.READ)
    val keyStore: KeyStore = KeyStore.getInstance(keyStoreType)
    withCloseable(f, (f) => {
      keyStore.load(f.asInstanceOf[InputStream], password.toCharArray)

    })
    keyStore
  }

  override def delete(path: String): Unit = {
    if (!keyStoreExists(path)) {
      throw KeyStoreManagerException(s"No keystore found with name: $path")
    }
    Files.delete(Paths.get(path))
  }

  override def isKnownCertificate(certificate: Certificate, keystoreName: String, password: String): Boolean = {
    if (!keyStoreExists(keystoreName)) {
      throw KeyStoreManagerException(s"No keystore found with name: $keystoreName")
    }
    val keyStore = load(keystoreName, password)

    keyStore.isCertificateEntry(certificate.hashCode().toString) &&
      keyStore.getCertificate(certificate.hashCode().toString).equals(certificate)

  }

  override def save(keyStore: KeyStore, keystoreName: String, password: String): Unit = {
    val f = new FileOutputStream(keystoreName)
    withCloseable(f, (f) => {
      keyStore.store(f.asInstanceOf[FileOutputStream], password.toCharArray)
    })
  }

  override def keyStoreExists(keyStoreAbsolutePath: String): Boolean = {
    Files.exists(Paths.get(keyStoreAbsolutePath))
  }

  override def isKnownEntry(entry: Entry, keystoreName: String, password: String, keyStoreType: String = KeyStoreTypes.DefaultKeyStoreType): Boolean = {
    if (!keyStoreExists(keystoreName)) {
      throw KeyStoreManagerException(s"No keystore found with name: $keystoreName")
    }
    val keyStore = load(keystoreName, password, keyStoreType)
    val protectionParam = new KeyStore.PasswordProtection(password.toCharArray)
    keyStore.isKeyEntry(entry.hashCode().toString) &&
      keyStore.getEntry(entry.hashCode().toString, protectionParam).toString.equals(entry.toString)

  }
}

case class KeyStoreManagerException(private val message: String = "") extends Exception(message)
