package org.springframework.boot.web.servlet.context.cert;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Arrays;

public class CertPair {

    private Certificate[] certificateChain;

    private PrivateKey privateKey;

    private byte[] rawCertificateChain;

    private byte[] rawPrivateKey;

    private Certificate rootCA;

    //轮转周期
    private long expireTime;

    public CertPair() {

    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setRawPrivateKey(byte[] rawPrivateKey) {
        this.rawPrivateKey = rawPrivateKey;
    }

    public Certificate[] getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(Certificate[] certificateChain) {
        this.certificateChain = certificateChain;
    }


    public void setRawCertificateChain(byte[] rawCertificateChain){
        this.rawCertificateChain=rawCertificateChain;
    }


    public long getExpireTime() {
        return expireTime;
    }

    public void setExpireTime(long expireTime) {
        this.expireTime = expireTime;
    }

    public byte[] getRawCertificateChain() {
        return rawCertificateChain;
    }

    public byte[] getRawPrivateKey() {
        return rawPrivateKey;
    }

    public Certificate getRootCA() {
        if (rootCA == null) {
            return certificateChain[certificateChain.length - 1];
        }
        return rootCA;
    }

    public void setRootCA(Certificate rootCA) {
        this.rootCA = rootCA;
    }


    @Override
    public String toString() {
        return "CertPair{" +
                "certificateChain=" + Arrays.toString(certificateChain) +
                ", privateKey=" + privateKey +
                ", rawCertificateChain=" + Arrays.toString(rawCertificateChain) +
                ", rawPrivateKey=" + Arrays.toString(rawPrivateKey) +
                ", rootCA=" + rootCA +
                ", expireTime=" + expireTime +
                '}';
    }
}
