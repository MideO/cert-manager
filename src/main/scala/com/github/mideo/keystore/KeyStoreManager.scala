package com.github.mideo.keystore

import java.io.{Closeable, FileOutputStream, InputStream}
import java.nio.file.{Files, Paths, StandardOpenOption}
import java.security.KeyStore
import java.security.cert.Certificate


object KeyStoreManager {
  def FileSystemJKeyStoreManager: KeyStoreManager = FileSystemJKeyStoreManagerImpl
}

object KeyStoreTypes extends Enumeration {
  val DefaultKeyStoreType: String = "JKS"
  val SecretKeyStoreType: String = "JCEKS"
}


trait KeyStoreManager {



  def create(keystoreAbsolutePath: String, password: String, keyStoreType:String): KeyStore

  def load(keyStoreAbsolutePath: String, password: String, keyStoreType:String): KeyStore

  def keyStoreExists(keyStoreAbsolutePath: String): Boolean

  def isKnownCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Boolean

  def isKnownEntry(entryName: String, keystoreName: String = "keystore.jks", password: String = "password", keyStoreType:String): Boolean

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


  override def create(keystoreAbsolutePath: String, password: String, keyStoreType:String = KeyStoreTypes.DefaultKeyStoreType): KeyStore = {
    val keyStore: KeyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null, password.toCharArray)
    keyStore
  }

  override def load(keystoreAbsolutePath: String, password: String, keyStoreType:String = KeyStoreTypes.DefaultKeyStoreType): KeyStore = {
    val f: InputStream = Files.newInputStream(Paths.get(keystoreAbsolutePath), StandardOpenOption.READ)
    val keyStore: KeyStore = KeyStore.getInstance(keyStoreType)
    withCloseable(f, (f) => {
      keyStore.load(f.asInstanceOf[InputStream], password.toCharArray)

    })
    keyStore
  }

  override def delete(path: String): Unit = Files.delete(Paths.get(path))

  override def isKnownCertificate(certificate: Certificate, keystoreName: String, password: String): Boolean = {
    if (!keyStoreExists(keystoreName)) {
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

  override def keyStoreExists(keyStoreAbsolutePath: String): Boolean = {
    Files.exists(Paths.get(keyStoreAbsolutePath))
  }

  override def isKnownEntry(entryName: String, keystoreName: String, password: String, keyStoreType:String =KeyStoreTypes.DefaultKeyStoreType): Boolean = {
    if (!keyStoreExists(keystoreName)) {
      return false
    }
    val keyStore = load(keystoreName, password, keyStoreType)
    keyStore.isKeyEntry(entryName)

  }
}
