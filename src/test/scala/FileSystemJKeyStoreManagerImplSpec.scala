package com.github.mideo

import java.io.FileOutputStream
import java.nio.file.{Files, Paths}
import java.security.KeyStore
import java.security.cert.Certificate

import com.github.mideo.keystore.KeyStoreManager

class FileSystemJKeyStoreManagerImplSpec extends TestSpec {
  val keyStoreManager:KeyStoreManager = KeyStoreManager.FileSystemJKeyStoreManager

  behavior of "FileSystemJKeyStoreManagerImpl"

  it should "create" in {
    //When
    val keyStore: KeyStore = keyStoreManager.create(testKeyStoreName, password)

    //Then
    keyStore.getType should be (keyStoreManager.KeyStoreType)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "load" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password).store(f, password.toCharArray)

    //When
    val keyStore = keyStoreManager.load(testKeyStoreName, password)

    //Then
    keyStore.getType should be (keyStoreManager.KeyStoreType)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "save" in {
    //Given

    val keyStore = keyStoreManager.create(testKeyStoreName, password)

    //When
    keyStoreManager.save(keyStore, testKeyStoreName, password)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be (true)

  }

  it should "delete" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password).store(f, password.toCharArray)

    //When
    keyStoreManager.delete(testKeyStoreName)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be (false)
  }

  it should "isKnownCertificate" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password).store(f, password.toCharArray)

    //When
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))


    //Then
    keyStoreManager.isKnownCertificate(certificate, testKeyStoreName, password) should be (false)
    keyStoreManager.isKnownCertificate(certificate, "someUnKnownCertificate", "pass") should be (false)

  }

}
