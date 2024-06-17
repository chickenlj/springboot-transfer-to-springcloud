package org.springframework.http.client.cert;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;

import com.alibaba.nacos.shaded.com.google.common.io.BaseEncoding;

public class TlsCenterTest {


  public static final String ALG_RSA = "RSA";

  public static final String PEM_CERTIFICATE_START = "-----BEGIN CERTIFICATE-----";

  public static final String PEM_CERTIFICATE_END = "-----END CERTIFICATE-----";

  public static final String PEM_PRIVATE_START = "-----BEGIN PRIVATE KEY-----";

  public static final String PEM_PRIVATE_END = "-----END PRIVATE KEY-----";

  public static CertPair getClientCertPair() {
    CertPair certPair = new CertPair();
    String certificateFilePath = "certs/client.pem";
    Certificate[] certificates = loadCertificateFromPath(certificateFilePath);

    String privateKeyPath = "certs/client.key";
    PrivateKey privateKey = loadPrivateKeyFromPath(privateKeyPath);

    String caCertFilePath = "certs/ca.pem";
    Certificate caCertificate = loadCertificateFromPath(caCertFilePath)[0];

    CertPairResolver.setCertificateChain(certPair,certificates);
    CertPairResolver.setPrivateKey(certPair,privateKey);
    certPair.setRootCA(caCertificate);
    certPair.setExpireTime(1000 * 1000L + System.currentTimeMillis());
    return certPair;
  }


  public static CertPair getCertPair() {
    CertPair certPair = new CertPair();
    String certificateFilePath = "certs/client.pem";
    Certificate[] certificates = loadCertificateFromPath(certificateFilePath);

    String privateKeyPath = "certs/client.key";
    PrivateKey privateKey = loadPrivateKeyFromPath(privateKeyPath);

    String caCertFilePath = "certs/ca.pem";
    Certificate caCertificate = loadCertificateFromPath(caCertFilePath)[0];

    CertPairResolver.setCertificateChain(certPair,certificates);
    CertPairResolver.setPrivateKey(certPair,privateKey);
    certPair.setRootCA(caCertificate);
    certPair.setExpireTime(1000 * 1000L + System.currentTimeMillis());
    return certPair;
  }
  public static Certificate[] loadCertificateFromPath(String path) {
    try {
      URL urlResource = TlsCenterTest.class.getClassLoader().getResource(path);
      try (InputStream inputStream = urlResource.openStream()) {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs = factory.generateCertificates(inputStream);
        return certs.toArray(new X509Certificate[0]);
      }
    } catch (Throwable t) {
      t.printStackTrace();
    }
    return new Certificate[0];
  }

  public static PrivateKey loadPrivateKeyFromPath(String path) {
    try {
      URL urlResource = TlsCenterTest.class.getClassLoader().getResource(path);
      try (InputStream inputStream = urlResource.openStream()) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
        String line;
        while ((line = reader.readLine()) != null) {
          if (PEM_PRIVATE_START.equals(line)) {
            break;
          }
        }
        StringBuilder keyContent = new StringBuilder();
        while ((line = reader.readLine()) != null) {
          if (PEM_PRIVATE_END.equals(line)) {
            break;
          }
          keyContent.append(line);
        }
        byte[] decodedKeyBytes = BaseEncoding.base64().decode(keyContent.toString());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKeyBytes);
        try {
          return KeyFactory.getInstance(ALG_RSA).generatePrivate(keySpec);
        } catch (InvalidKeySpecException ignore) {
          try {
            return KeyFactory.getInstance("EC").generatePrivate(keySpec);
          } catch (InvalidKeySpecException e) {
            throw new InvalidKeySpecException("Neither RSA nor EC worked", e);
          }
        }
      }
    } catch (Throwable t) {
      t.printStackTrace();
    }
    return null;
  }
}
