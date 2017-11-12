package com.github.mideo

import java.security.KeyStore
import java.security.cert.Certificate

protected trait KeyStoreManager {
  def create(keystoreAbsolutePath: String, password: String): KeyStore

  def load(keyStoreAbsolutePath: String, password: String): KeyStore

  def isKnownCertificate(certificate: Certificate, keystoreName: String = "keystore.jks", password: String = "password"): Boolean

  def delete(path: String): Unit

  def save(keyStore: KeyStore, keystoreName: String, password: String): Unit
}
