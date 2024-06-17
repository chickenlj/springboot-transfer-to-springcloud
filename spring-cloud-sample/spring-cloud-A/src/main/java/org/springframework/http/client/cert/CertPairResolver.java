package org.springframework.http.client.cert;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

public class CertPairResolver {
    public static void setPrivateKey(CertPair certPair, PrivateKey privateKey){
        certPair.setPrivateKey(privateKey);
        try {
            PemObject pemObject = new PemObject("RSA PRIVATE KEY",
                    privateKey.getEncoded());
            StringWriter str = new StringWriter();
            JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(str);
            jcaPEMWriter.writeObject(pemObject);
            jcaPEMWriter.close();
            str.close();
            byte[] rawPrivateKey = str.toString().getBytes(StandardCharsets.UTF_8);
            certPair.setRawPrivateKey(rawPrivateKey);
        } catch (Exception e) {
            throw new RuntimeException("Unable to parse raw private key");
        }
    }


    public static void setCertificateChain(CertPair certPair, List<String> certificateChain){
        final int n = certificateChain.size();
        Certificate[] certificates = new Certificate[n];
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; ++i) {
            sb.append(certificateChain.get(i));
            certificates[i] = loadCertificate(certificateChain.get(i));
            if (certificates[i] == null) {
                throw new RuntimeException(
                        "Failed to load certificate, pem is " + certificateChain.get(i));
            }
        }
        certPair.setRawCertificateChain(sb.toString().getBytes(StandardCharsets.UTF_8));
        certPair.setCertificateChain(certificates);
    }


    public static void setCertificateChain(CertPair certPair, Certificate[] certificateChain){
        final int n = certificateChain.length;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; ++i) {
            sb.append(certificateChain[i]);

        }
        certPair.setRawCertificateChain(sb.toString().getBytes(StandardCharsets.UTF_8));
        certPair.setCertificateChain(certificateChain);
    }
    public static Certificate loadCertificate(String certificatePem) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            certificatePem = certificatePem.replaceAll("-----BEGIN CERTIFICATE-----", "");
            certificatePem = certificatePem.replaceAll("-----END CERTIFICATE-----", "");
            certificatePem = certificatePem.replaceAll("\\s*", "");
            return certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(certificatePem)));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
