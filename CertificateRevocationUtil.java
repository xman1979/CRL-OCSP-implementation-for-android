import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;

import android.util.Log;

@SuppressWarnings("deprecation")
public class CertificateRevocationUtil {
    private static final String OID_CRL_DISTRIBUTION_POINT = "2.5.29.31";
    private static final String OID_AUTHORITY_INFORMATION_ACCESS = "1.3.6.1.5.5.7.1.1";
    private static final int HTTP_FETCH_TIMEOUT = 3000;
    private static final String LOGGER_TAG = "CertRevoke"

    private static ASN1Primitive getExtensionObject(final X509Certificate certificate, String oid)
    {
        byte[] derEncodedBytes = certificate.getExtensionValue(oid);
        if (derEncodedBytes != null) {
            ASN1Primitive obj = null;
            ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(derEncodedBytes));
            try {
                ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
                aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
                obj = aIn.readObject();
                return obj;
            } catch (IOException e) {
                Log.e(LOGGER_TAG, "Failed to get extension object:" + e.getMessage());
            }
        }
        return null;
    }

    private static Set<X509CRL> loadCRLs(final X509Certificate certificate)
    {
        Set<X509CRL> crlSet = new HashSet<X509CRL>();
        ASN1Primitive obj = getExtensionObject(certificate, OID_CRL_DISTRIBUTION_POINT);
        if (obj == null) {
            Log.d(LOGGER_TAG, "No CRL distribution point found.");
            return crlSet;
        }
        CRLDistPoint dist = CRLDistPoint.getInstance(obj);
        DistributionPoint[] dists = dist.getDistributionPoints();
        for (DistributionPoint p : dists) {
            DistributionPointName distributionPointName = p.getDistributionPoint();
            if (DistributionPointName.FULL_NAME != distributionPointName.getType()) {
                continue;
            }
            GeneralNames generalNames = (GeneralNames)distributionPointName.getName();
            GeneralName[] names = generalNames.getNames();
            for (GeneralName name : names) {
                if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                    continue;
                }
                DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject)name.toASN1Primitive(), false);
                String url = derStr.getString();
                try {
                    Log.d(LOGGER_TAG, "Fetching " + url);
                    URLConnection urlConnection = new URL(url).openConnection();
                    urlConnection.setConnectTimeout(HTTP_FETCH_TIMEOUT);
                    urlConnection.setReadTimeout(HTTP_FETCH_TIMEOUT);
                    InputStream crlInputStream = urlConnection.getInputStream();
                    X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(crlInputStream);
                    if (crl != null) {
                         crlSet.add(crl);
                    }
                    Log.d(LOGGER_TAG, "Fetched url " + url);
                } catch (Exception e) {
                    Log.e(LOGGER_TAG, "Failed to fetch URL " + url + " Reason:" + e.getMessage());
                }
            }
        }
        return crlSet;
    }

    public static boolean isRevokedByCRL(final X509Certificate certificate)
    {
        Set<X509CRL> crlSet = loadCRLs(certificate);
        for (X509CRL crl : crlSet) {
            if (crl.isRevoked(certificate)) {
                Log.d(LOGGER_TAG, "CRL check: certificate (" + certificate.getSubjectDN() + ") revoked by " + crl.getIssuerDN());
                return true;
            }
        }
        Log.d(LOGGER_TAG, "CRL check: certificate ("+ certificate.getSubjectDN() + ") is good");
        return false;
    }

    @SuppressWarnings("deprecation")
    public static boolean isRevokedByOCSP(final X509Certificate certificate, final X509Certificate issuerCert)
    {
        ASN1Primitive obj = getExtensionObject(certificate, OID_AUTHORITY_INFORMATION_ACCESS);
        if (obj == null) {
            Log.d(LOGGER_TAG, "No OCSP Responder found, skip OCSP check");
            return false;
        }

        // Now find out OCSP Responder locations, also possibly replace the issuer cert if it is mentioned.
        List<String> ocspLocations = new ArrayList<String>();
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(obj);
        X509Certificate fetchedIssuerCert = null;
        for (AccessDescription ad : aia.getAccessDescriptions()) {
            GeneralName gn = ad.getAccessLocation();
            if (gn.getTagNo() == GeneralName.uniformResourceIdentifier && gn.getName() instanceof DERIA5String) {
                DERIA5String derStr = DERIA5String.getInstance(gn.getName());
                String url = derStr.getString();
                if (ad.getAccessMethod().equals(AccessDescription.id_ad_caIssuers)) {
                    URLConnection urlConnection;
                    try {
                        Log.d(LOGGER_TAG, "Fetching OCSP issuerCA from " + url);
                        urlConnection = new URL(url).openConnection();
                        urlConnection.setConnectTimeout(HTTP_FETCH_TIMEOUT);
                        urlConnection.setReadTimeout(HTTP_FETCH_TIMEOUT);
                        InputStream caInputStream = urlConnection.getInputStream();
                        fetchedIssuerCert = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(caInputStream);
                        Log.d(LOGGER_TAG, "Fetched OCSP issuerCA : " + issuerCert.getSubjectDN());
                    } catch (Exception e) {
                        Log.e(LOGGER_TAG, "Failed to fetch issuerCA:" + e.getMessage());
                    }
                }
                else if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)){
                    ocspLocations.add(url);
                }
            }
        }
        if (ocspLocations.isEmpty()) {
            Log.d(LOGGER_TAG, "No OCSP url is found. Skip OCSP check" + certificate);
            return false;
        }

        // Construct the OCSP request.
        OCSPReq request = null;
        BigInteger serialNumber = certificate.getSerialNumber();
        CertificateID id = null;
        try {
            id = new CertificateID(CertificateID.HASH_SHA1,
                    fetchedIssuerCert == null ? issuerCert : fetchedIssuerCert, serialNumber);
            OCSPReqGenerator gen = new OCSPReqGenerator();
            gen.addRequest(id);
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            Vector<ASN1ObjectIdentifier> oids = new Vector<ASN1ObjectIdentifier>();
            Vector<X509Extension> values = new Vector<X509Extension>();
            oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
            gen.setRequestExtensions(new X509Extensions(oids, values));
            request = gen.generate();
        } catch (OCSPException e) {
            Log.e(LOGGER_TAG, "Failed to create OCSP request:" + e.getMessage());
            return false;
        }

        // Check against each OCSP responder, ideally, there should be only one OCSP location.
        for (String url: ocspLocations) {
            Log.d(LOGGER_TAG, "Checking OCSP url " + url);
            HttpURLConnection con;
            try {
                con = (HttpURLConnection)new URL(url).openConnection();
                con.setConnectTimeout(HTTP_FETCH_TIMEOUT);
                con.setReadTimeout(HTTP_FETCH_TIMEOUT);
                con.setDoOutput(true);
                con.setDoInput(true);
                con.setRequestMethod("POST");
                con.setRequestProperty("Content-type", "application/ocsp-request");
                con.setRequestProperty("Accept","application/ocsp-response");
                byte[] bytes = request.getEncoded();
                con.setRequestProperty("Content-length", String.valueOf(bytes.length));
                OutputStream out = con.getOutputStream();
                out.write(bytes);
                out.flush();
                if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                    Log.d(LOGGER_TAG, "Received HTTP error: " + con.getResponseCode() +
                            " - " + con.getResponseMessage());
                    return false;
                }
                InputStream in = con.getInputStream();
                OCSPResp ocspResponse = new OCSPResp(in);
                BasicOCSPResp brep = (BasicOCSPResp) ocspResponse.getResponseObject();
                SingleResp[] singleResp = brep.getResponses();
                for (SingleResp resp : singleResp) {
                    CertificateID respCertID = resp.getCertID();
                    if (respCertID.equals(id)) {
                        Object status = resp.getCertStatus();
                        if (status == CertificateStatus.GOOD) {
                            Log.d(LOGGER_TAG, "OCSP check: Certificate is good by " + url);
                            return false;
                        }
                        if (status instanceof RevokedStatus) {
                            Log.d(LOGGER_TAG, "OCSP check: Certificate is revoked by " + url);
                            return true;
                        }
                        Log.d(LOGGER_TAG, "OCSP check: Unknown, skip");
                        return false;
                    }
                }
            } catch (Exception e) {
                Log.e(LOGGER_TAG, "Failed to connect to " + url + ": Skip OCSP check" + e.getMessage());
            }
        }
        return false;
    }
    private static class checkCRLAsyncTask implements Callable<Boolean> {
        public checkCRLAsyncTask(X509Certificate cert) {
            mCert = cert;
        }
        @Override
        public Boolean call() throws Exception {
            return isRevokedByCRL(mCert);
        }
        final X509Certificate mCert;
    }

    private static class checkOCSPAsyncTask implements Callable<Boolean> {
        public checkOCSPAsyncTask(X509Certificate cert, X509Certificate issuer) {
            mCert = cert;
            mIssuer = issuer;
        }
        @Override
        public Boolean call() throws Exception {
            return isRevokedByOCSP(mCert, mIssuer);
        }
        final X509Certificate mCert;
        final X509Certificate mIssuer;
    }

    public static boolean isRevoked(final X509Certificate[] certs, int size)
    {
        ExecutorService exService = Executors.newFixedThreadPool(10);
        List<FutureTask<Boolean>> futureTasks = new ArrayList<FutureTask<Boolean>>();
        for (int i = 0; i < size; i++) {
            FutureTask<Boolean> ftask = new FutureTask<Boolean>(new checkCRLAsyncTask(certs[i]));
            exService.execute(ftask);
            futureTasks.add(ftask);
        }
        for (int i = 0; i < size-1; i++) {
            FutureTask<Boolean> ftask = new FutureTask<Boolean>(new checkOCSPAsyncTask(certs[i], certs[i+1]));
            exService.execute(ftask);
            futureTasks.add(ftask);
        }
        while(!futureTasks.isEmpty()) {
            for (FutureTask<Boolean> ftask : futureTasks) {
                if (ftask.isDone()) {
                    try {
                        if (ftask.get()) {
                            // as long as one of the checks says it is revoked, then it is revoked.
                            return true;
                        }
                    } catch (InterruptedException e) {
                        Log.e(LOGGER_TAG, "Task failed with InterruptedException: " + e.getMessage());
                    } catch (ExecutionException e) {
                        Log.e(LOGGER_TAG, "Task failed with ExecutionException: " + e.getMessage());
                    }
                    futureTasks.remove(ftask);
                    break;
                }
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
            }
        }
        return false;
    }

}
