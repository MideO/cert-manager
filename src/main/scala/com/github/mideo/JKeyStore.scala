package com.github.mideo

import java.io.{InputStream, OutputStream}
import java.nio.file.{Files, Paths}
import java.security.KeyStore

object JKeyStore extends KeyStoreManager{
  val KeyStoreType = "JKS"

  def create(outputStream: OutputStream, password: String): KeyStore = {
      val keyStore: KeyStore = KeyStore.getInstance(KeyStoreType)
      keyStore.load(null, password.toCharArray)
      keyStore
  }

  def load(inputStream: InputStream, password: String): KeyStore = {
      val keyStore: KeyStore = KeyStore.getInstance(KeyStoreType)
      keyStore.load(inputStream, password.toCharArray)
      keyStore
  }

  def delete(path:String): Unit = Files.delete(Paths.get(path))
}
