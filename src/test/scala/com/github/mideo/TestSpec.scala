package com.github.mideo

import java.nio.file.{Files, Paths}

import org.scalatest.{BeforeAndAfterEach, FlatSpec, Matchers}
import java.security.cert.CertificateFactory

trait TestSpec
  extends FlatSpec
    with BeforeAndAfterEach
    with Matchers {

  val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")

  val certManager: CertManager = CertManager(JKeyStore)

  val testKeyStoreName: String = "MyKeyStore.jks"
  val password: String = "Password1"


  override def beforeEach() {
    deleteIfFileExist(testKeyStoreName)
  }

  override def afterEach() {
    deleteIfFileExist(testKeyStoreName)
  }




  protected def deleteIfFileExist(fileName: String): Unit = {
    if (Files.exists(Paths.get(fileName))) {
      Files.delete(Paths.get(fileName))
    }
  }



}
