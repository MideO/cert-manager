package com.github.mideo

import java.io.FileOutputStream
import java.nio.file.{Files, Paths}
import java.security.KeyStore
import java.security.KeyStore.PrivateKeyEntry
import java.security.cert.Certificate
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import com.github.mideo.keystore.{KeyStoreManager, KeyStoreTypes}
import sun.security.tools.keytool.CertAndKeyGen

class FileSystemJKeyStoreManagerImplSpec extends TestSpec {
  val keyStoreManager: KeyStoreManager = KeyStoreManager.FileSystemJKeyStoreManager

  behavior of "FileSystemJKeyStoreManagerImpl"

  it should "create" in {
    //When
    val keyStore: KeyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType)

    //Then
    keyStore.getType should be(KeyStoreTypes.DefaultKeyStoreType)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "load" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType).store(f, password.toCharArray)

    //When
    val keyStore = keyStoreManager.load(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType)

    //Then
    keyStore.getType should be(KeyStoreTypes.DefaultKeyStoreType)
    Paths.get(testKeyStoreName) should not be null
  }

  it should "save" in {
    //Given

    val keyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType)

    //When
    keyStoreManager.save(keyStore, testKeyStoreName, password)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be(true)

  }

  it should "delete" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType).store(f, password.toCharArray)

    //When
    keyStoreManager.delete(testKeyStoreName)

    //Then
    Files.exists(Paths.get(testKeyStoreName)) should be(false)
  }

  it should "keyStoreExists" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType).store(f, password.toCharArray)

    //Then
    keyStoreManager.keyStoreExists(testKeyStoreName) should be(true)

    //And
    keyStoreManager.keyStoreExists("lalalla") should be(false)
  }


  it should "isKnownCertificate" in {
    //Given
    val f = new FileOutputStream(testKeyStoreName)
    keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType).store(f, password.toCharArray)

    //When
    val certificate: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))


    //Then
    keyStoreManager.isKnownCertificate(certificate, testKeyStoreName, password) should be(false)
    keyStoreManager.isKnownCertificate(certificate, "someUnKnownCertificate", "pass") should be(false)

  }

  it should "isKnownEntry PrivateKey" in {
    //Given
    val keyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType)

    val gen = new CertAndKeyGen("RSA", "SHA1WithRSA")
    gen.generate(1024)
    val key = gen.getPrivateKey
    val cert: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))

    val protParam = new KeyStore.PasswordProtection(password.toCharArray)

    //When
    keyStore.setEntry(key.hashCode().toString, new PrivateKeyEntry(key, Array(cert)), protParam)

    keyStoreManager.save(keyStore, testKeyStoreName, password)


    //Then
    keyStoreManager.isKnownEntry(key.hashCode().toString, testKeyStoreName, password, KeyStoreTypes.DefaultKeyStoreType) should be(true)


  }

  it should "isKnownEntry SecretKey" in {
    //Given
    val keyStore = keyStoreManager.create(testKeyStoreName, password, KeyStoreTypes.SecretKeyStoreType)

    val mySecretKey: SecretKey = new SecretKeySpec(password.getBytes(), 0, password.getBytes().length, "AES")

    val skEntry = new KeyStore.SecretKeyEntry(mySecretKey)

    val protParam = new KeyStore.PasswordProtection(password.toCharArray)

    //When
    keyStore.setEntry(key.hashCode().toString, skEntry, protParam)
    keyStoreManager.save(keyStore, testKeyStoreName, password)


    //Then
    keyStoreManager.isKnownEntry(key.hashCode().toString, testKeyStoreName, password, KeyStoreTypes.SecretKeyStoreType) should be(true)


  }

}
