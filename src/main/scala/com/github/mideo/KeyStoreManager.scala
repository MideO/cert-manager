package com.github.mideo

import java.io.{InputStream, OutputStream}
import java.security.KeyStore

trait KeyStoreManager {
  def create(outputStream: OutputStream, password: String): KeyStore
  def load(inputStream: InputStream, password: String): KeyStore
  def delete(path:String)

}
