package com.github.mideo

import java.io.{FileInputStream, FileOutputStream}
import java.nio.file.{Files, Paths}
import java.security.KeyStore

class JKeyStoreSpec extends TestSpec {
  behavior of "JKeyStore"

  it should "create" in {
    //When
    val keyStore: KeyStore = JKeyStore.create(new FileOutputStream(testKeyStoreName), password)

    //Then
    keyStore.getType should be (JKeyStore.KeyStoreType)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "load" in {
    //Given
    JKeyStore.create(new FileOutputStream(testKeyStoreName), password)

    //When
    val keyStore = JKeyStore.load(new FileInputStream(testKeyStoreName), password)

    //Then
    keyStore.getType should be (JKeyStore.KeyStoreType)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "delete" in {
    //Given
    JKeyStore.create(new FileOutputStream(testKeyStoreName), password)

    //When
    JKeyStore.delete(testKeyStoreName)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be (false)
  }

}