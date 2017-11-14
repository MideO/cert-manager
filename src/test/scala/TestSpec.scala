package com.github.mideo

import java.io.InputStream
import java.nio.file.{Files, Paths}
import java.security.cert.CertificateFactory

import org.scalatest.{BeforeAndAfterEach, FlatSpec, Matchers}

trait TestSpec
  extends FlatSpec
    with BeforeAndAfterEach
    with Matchers {

  val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")

  val testKeyStoreName: String = "MyKeyStore.jks"
  val password: String = "Password1"


  override def beforeEach() {
    deleteIfFileExist(testKeyStoreName)
  }

  override def afterEach() {
    deleteIfFileExist(testKeyStoreName)
  }


  protected def getResourceFile(name:String): InputStream ={
    getClass.getClassLoader.getResourceAsStream(name)
  }

  protected def deleteIfFileExist(fileName: String): Unit = {
    if (Files.exists(Paths.get(fileName))) {
      Files.delete(Paths.get(fileName))
    }
  }



}
