using iTextSharp.text;
using iTextSharp.text.error_messages;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace pdfsign
{
    class AdobeLtvEnabling
    {

        //
        // member variables
        //
        PdfStamper pdfStamper;
        ISet<X509Certificate> seenCertificates = new HashSet<X509Certificate>();
        IDictionary<PdfName, ValidationData> validated = new Dictionary<PdfName, ValidationData>();

        public static List<X509Certificate> extraCertificates = new List<X509Certificate>();

        /**
         * Use this constructor with a {@link PdfStamper} in append mode. Otherwise
         * the existing signatures will be damaged.
         */
        public AdobeLtvEnabling(PdfStamper pdfStamper)
        {
            this.pdfStamper = pdfStamper;
        }

        /**
         * Call this method to have LTV information added to the {@link PdfStamper}
         * given in the constructor.
         */
        public void enable(IOcspClient ocspClient, ICrlClient crlClient)
        {
            AcroFields fields = pdfStamper.AcroFields;
            bool encrypted = pdfStamper.Reader.IsEncrypted();

            List<String> names = fields.GetSignatureNames();
            foreach (String name in names)
            {
                PdfPKCS7 pdfPKCS7 = fields.VerifySignature(name);
                PdfDictionary signatureDictionary = fields.GetSignatureDictionary(name);
                X509Certificate certificate = pdfPKCS7.SigningCertificate;
                addLtvForChain(certificate, ocspClient, crlClient, getSignatureHashKey(signatureDictionary, encrypted));
            }

            outputDss();
        }

        //
        // the actual LTV enabling methods
        //
        void addLtvForChain(X509Certificate certificate, IOcspClient ocspClient, ICrlClient crlClient, PdfName key)
        {
            if (seenCertificates.Contains(certificate))
                return;
            seenCertificates.Add(certificate);
            ValidationData validationData = new ValidationData();

            while (certificate != null)
            {
                Console.WriteLine(certificate.SubjectDN);
                X509Certificate issuer = getIssuerCertificate(certificate);
                validationData.certs.Add(certificate.GetEncoded());
                byte[] ocspResponse = ocspClient.GetEncoded(certificate, issuer, null);
                if (ocspResponse != null)
                {
                    Console.WriteLine("  with OCSP response");
                    validationData.ocsps.Add(ocspResponse);
                    X509Certificate ocspSigner = getOcspSignerCertificate(ocspResponse);
                    if (ocspSigner != null)
                    {
                        Console.WriteLine("  signed by {0}\n", ocspSigner.SubjectDN);
                    }
                    addLtvForChain(ocspSigner, ocspClient, crlClient, getOcspHashKey(ocspResponse));
                }
                else
                {
                    ICollection<byte[]> crl = crlClient.GetEncoded(certificate, null);
                    if (crl != null && crl.Count > 0)
                    {
                        Console.WriteLine("  with {0} CRLs\n", crl.Count);
                        foreach (byte[] crlBytes in crl)
                        {
                            validationData.crls.Add(crlBytes);
                            addLtvForChain(null, ocspClient, crlClient, getCrlHashKey(crlBytes));
                        }
                    }
                }
                certificate = issuer;
            }

            validated[key] = validationData;
        }

        void outputDss()
        {
            PdfWriter writer = pdfStamper.Writer;
            PdfReader reader = pdfStamper.Reader;

            PdfDictionary dss = new PdfDictionary();
            PdfDictionary vrim = new PdfDictionary();
            PdfArray ocsps = new PdfArray();
            PdfArray crls = new PdfArray();
            PdfArray certs = new PdfArray();

            writer.AddDeveloperExtension(PdfDeveloperExtension.ESIC_1_7_EXTENSIONLEVEL5);
            writer.AddDeveloperExtension(new PdfDeveloperExtension(PdfName.ADBE, new PdfName("1.7"), 8));

            PdfDictionary catalog = reader.Catalog;
            pdfStamper.MarkUsed(catalog);
            foreach (PdfName vkey in validated.Keys)
            {
                PdfArray ocsp = new PdfArray();
                PdfArray crl = new PdfArray();
                PdfArray cert = new PdfArray();
                PdfDictionary vri = new PdfDictionary();
                foreach (byte[] b in validated[vkey].crls)
                {
                    PdfStream ps = new PdfStream(b);
                    ps.FlateCompress();
                    PdfIndirectReference iref = writer.AddToBody(ps, false).IndirectReference;
                    crl.Add(iref);
                    crls.Add(iref);
                }
                foreach (byte[] b in validated[vkey].ocsps)
                {
                    PdfStream ps = new PdfStream(buildOCSPResponse(b));
                    ps.FlateCompress();
                    PdfIndirectReference iref = writer.AddToBody(ps, false).IndirectReference;
                    ocsp.Add(iref);
                    ocsps.Add(iref);
                }
                foreach (byte[] b in validated[vkey].certs)
                {
                    PdfStream ps = new PdfStream(b);
                    ps.FlateCompress();
                    PdfIndirectReference iref = writer.AddToBody(ps, false).IndirectReference;
                    cert.Add(iref);
                    certs.Add(iref);
                }
                if (ocsp.Length > 0)
                    vri.Put(PdfName.OCSP, writer.AddToBody(ocsp, false).IndirectReference);
                if (crl.Length > 0)
                    vri.Put(PdfName.CRL, writer.AddToBody(crl, false).IndirectReference);
                if (cert.Length > 0)
                    vri.Put(PdfName.CERT, writer.AddToBody(cert, false).IndirectReference);
                vri.Put(PdfName.TU, new PdfDate());
                vrim.Put(vkey, writer.AddToBody(vri, false).IndirectReference);
            }
            dss.Put(PdfName.VRI, writer.AddToBody(vrim, false).IndirectReference);
            if (ocsps.Length > 0)
                dss.Put(PdfName.OCSPS, writer.AddToBody(ocsps, false).IndirectReference);
            if (crls.Length > 0)
                dss.Put(PdfName.CRLS, writer.AddToBody(crls, false).IndirectReference);
            if (certs.Length > 0)
                dss.Put(PdfName.CERTS, writer.AddToBody(certs, false).IndirectReference);
            catalog.Put(PdfName.DSS, writer.AddToBody(dss, false).IndirectReference);
        }

        //
        // VRI signature hash key calculation
        //
        static PdfName getCrlHashKey(byte[] crlBytes)
        {
            X509Crl crl = new X509Crl(CertificateList.GetInstance(crlBytes));
            byte[] signatureBytes = crl.GetSignature();
            DerOctetString octetString = new DerOctetString(signatureBytes);
            byte[] octetBytes = octetString.GetEncoded();
            byte[] octetHash = hashBytesSha1(octetBytes);
            PdfName octetName = new PdfName(Utilities.ConvertToHex(octetHash));
            return octetName;
        }

        static PdfName getOcspHashKey(byte[] basicResponseBytes)
        {
            BasicOcspResponse basicResponse = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(basicResponseBytes));
            byte[] signatureBytes = basicResponse.Signature.GetBytes();
            DerOctetString octetString = new DerOctetString(signatureBytes);
            byte[] octetBytes = octetString.GetEncoded();
            byte[] octetHash = hashBytesSha1(octetBytes);
            PdfName octetName = new PdfName(Utilities.ConvertToHex(octetHash));
            return octetName;
        }

        static PdfName getSignatureHashKey(PdfDictionary dic, bool encrypted)
        {
            PdfString contents = dic.GetAsString(PdfName.CONTENTS);
            byte[] bc = contents.GetOriginalBytes();
            if (PdfName.ETSI_RFC3161.Equals(PdfReader.GetPdfObject(dic.Get(PdfName.SUBFILTER))))
            {
                using (Asn1InputStream din = new Asn1InputStream(bc))
                {
                    Asn1Object pkcs = din.ReadObject();
                    bc = pkcs.GetEncoded();
                }
            }
            byte[] bt = hashBytesSha1(bc);
            return new PdfName(Utilities.ConvertToHex(bt));
        }

        static byte[] hashBytesSha1(byte[] b)
        {
            SHA1 sha = new SHA1CryptoServiceProvider();
            return sha.ComputeHash(b);
        }

        //
        // OCSP response helpers
        //
        static X509Certificate getOcspSignerCertificate(byte[] basicResponseBytes)
        {
            BasicOcspResponse borRaw = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(basicResponseBytes));
            BasicOcspResp bor = new BasicOcspResp(borRaw);

            foreach (X509Certificate x509Certificate in bor.GetCerts())
            {
                if (bor.Verify(x509Certificate.GetPublicKey()))
                    return x509Certificate;
            }

            return null;
        }

        static byte[] buildOCSPResponse(byte[] BasicOCSPResponse)
        {
            DerOctetString doctet = new DerOctetString(BasicOCSPResponse);
            Asn1EncodableVector v2 = new Asn1EncodableVector();
            v2.Add(OcspObjectIdentifiers.PkixOcspBasic);
            v2.Add(doctet);
            DerEnumerated den = new DerEnumerated(0);
            Asn1EncodableVector v3 = new Asn1EncodableVector();
            v3.Add(den);
            v3.Add(new DerTaggedObject(true, 0, new DerSequence(v2)));
            DerSequence seq = new DerSequence(v3);
            return seq.GetEncoded();
        }

        //
        // X509 certificate related helpers
        //
        static X509Certificate getIssuerCertificate(X509Certificate certificate)
        {
            String url = getCACURL(certificate);
            if (url != null && url.Length > 0)
            {
                HttpWebRequest con = (HttpWebRequest)WebRequest.Create(url);
                HttpWebResponse response = (HttpWebResponse)con.GetResponse();
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new IOException(MessageLocalization.GetComposedMessage("invalid.http.response.1", (int)response.StatusCode));
                //Get Response
                Stream inp = response.GetResponseStream();
                byte[] buf = new byte[1024];
                MemoryStream bout = new MemoryStream();
                while (true)
                {
                    int n = inp.Read(buf, 0, buf.Length);
                    if (n <= 0)
                        break;
                    bout.Write(buf, 0, n);
                }
                inp.Close();

                var cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(bout.ToArray());

                return new X509Certificate(X509CertificateStructure.GetInstance(cert2.GetRawCertData()));
            }

            try
            {
                certificate.Verify(certificate.GetPublicKey());
                return null;
            }
            catch (Exception e)
            {
            }

            foreach (X509Certificate candidate in extraCertificates)
            {
                try
                {
                    certificate.Verify(candidate.GetPublicKey());
                    return candidate;
                }
                catch (Exception e)
                {
                }
            }

            return null;
        }

        static String getCACURL(X509Certificate certificate)
        {
            try
            {
                Asn1Object obj = getExtensionValue(certificate, X509Extensions.AuthorityInfoAccess.Id);
                if (obj == null)
                {
                    return null;
                }

                Asn1Sequence AccessDescriptions = (Asn1Sequence)obj;
                for (int i = 0; i < AccessDescriptions.Count; i++)
                {
                    Asn1Sequence AccessDescription = (Asn1Sequence)AccessDescriptions[i];
                    if (AccessDescription.Count != 2)
                    {
                        continue;
                    }
                    else
                    {
                        if ((AccessDescription[0] is DerObjectIdentifier) && ((DerObjectIdentifier)AccessDescription[0]).Id.Equals("1.3.6.1.5.5.7.48.2"))
                        {
                            String AccessLocation = getStringFromGeneralName((Asn1Object)AccessDescription[1]);
                            return AccessLocation == null ? "" : AccessLocation;
                        }
                    }
                }
            }
            catch
            {
            }
            return null;
        }

        static Asn1Object getExtensionValue(X509Certificate certificate, String oid)
        {
            byte[] bytes = certificate.GetExtensionValue(new DerObjectIdentifier(oid)).GetDerEncoded();
            if (bytes == null)
            {
                return null;
            }
            Asn1InputStream aIn = new Asn1InputStream(new MemoryStream(bytes));
            Asn1OctetString octs = (Asn1OctetString)aIn.ReadObject();
            aIn = new Asn1InputStream(new MemoryStream(octs.GetOctets()));
            return aIn.ReadObject();
        }

        private static String getStringFromGeneralName(Asn1Object names)
        {
            Asn1TaggedObject taggedObject = (Asn1TaggedObject)names;
            return Encoding.GetEncoding(1252).GetString(Asn1OctetString.GetInstance(taggedObject, false).GetOctets());
        }

        //
        // inner class
        //
        class ValidationData
        {
            public IList<byte[]> crls = new List<byte[]>();
            public IList<byte[]> ocsps = new List<byte[]>();
            public IList<byte[]> certs = new List<byte[]>();
        }

    }
}
