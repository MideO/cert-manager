import java.io.InputStream
import java.nio.file.{Files, Paths}
import java.security.{KeyStore, PrivateKey}
import java.security.KeyStore.PrivateKeyEntry
import java.security.cert.{Certificate, CertificateFactory}
import javax.crypto.spec.SecretKeySpec

import org.scalatest.{BeforeAndAfterEach, FlatSpec, Matchers}
import sun.security.tools.keytool.CertAndKeyGen

trait TestSpec
  extends FlatSpec
    with BeforeAndAfterEach
    with Matchers {

  val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")

  val testKeyStoreName: String = "MyKeyStore.jks"
  val password: String = "Password1"
  val protectionParam = new KeyStore.PasswordProtection(password.toCharArray)

  protected def makePrivateKeyEntry():PrivateKeyEntry = {
    val gen = new CertAndKeyGen("RSA", "SHA1WithRSA")
    gen.generate(1024)
    val pk: PrivateKey = gen.getPrivateKey
    val cert: Certificate = certificateFactory.generateCertificate(getResourceFile("selfsigned.cert"))
    new PrivateKeyEntry(pk, Array(cert))
  }

  val testPrivateKeyEntry: PrivateKeyEntry = makePrivateKeyEntry()

  val testSecretKeyEntry = new KeyStore.SecretKeyEntry(
    new SecretKeySpec(password.getBytes(), 0, password.getBytes().length, "AES"))


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
