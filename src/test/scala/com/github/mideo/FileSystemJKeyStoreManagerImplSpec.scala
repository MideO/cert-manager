package com.github.mideo

import java.io.FileOutputStream
import java.nio.file.{Files, Paths}
import java.security.KeyStore
import java.security.cert.Certificate

class FileSystemJKeyStoreManagerImplSpec extends TestSpec {
  behavior of "FileSystemJKeyStoreManagerImpl"

  it should "create" in {
    //When
    val keyStore: KeyStore = FileSystemJKeyStoreManagerImpl.create(testKeyStoreName, password)

    //Then
    keyStore.getType should be (FileSystemJKeyStoreManagerImpl.KeyStoreType)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "load" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    FileSystemJKeyStoreManagerImpl.create(testKeyStoreName, password).store(f, password.toCharArray)

    //When
    val keyStore = FileSystemJKeyStoreManagerImpl.load(testKeyStoreName, password)

    //Then
    keyStore.getType should be (FileSystemJKeyStoreManagerImpl.KeyStoreType)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "save" in {
    //Given

    val keyStore = FileSystemJKeyStoreManagerImpl.create(testKeyStoreName, password)

    //When
    FileSystemJKeyStoreManagerImpl.save(keyStore, testKeyStoreName, password)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be (true)

  }

  it should "delete" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    FileSystemJKeyStoreManagerImpl.create(testKeyStoreName, password).store(f, password.toCharArray)

    //When
    FileSystemJKeyStoreManagerImpl.delete(testKeyStoreName)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be (false)
  }

  it should "isKnownCertificate" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    FileSystemJKeyStoreManagerImpl.create(testKeyStoreName, password).store(f, password.toCharArray)

    //When
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))


    //Then
    FileSystemJKeyStoreManagerImpl.isKnownCertificate(certificate, testKeyStoreName, password) should be (false)
    FileSystemJKeyStoreManagerImpl.isKnownCertificate(certificate, "someUnKnownCertificate", "pass") should be (false)

  }

}
