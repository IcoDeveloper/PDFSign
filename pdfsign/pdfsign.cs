/*
 * pdfsign.cs: digitaly sign pdf files
 *
 * Copyright (C) 2019 icomedias GmbH
 *
 * originally based on code/samples from itext project by:
 * Copyright (C) 1999-2011 by 1T3XT BVBA, Bruno Lowagie and Paulo Soares.
 * updated to use itextsharp 5.5 libary
 * Copyright (C) 1999-2018 by iText Group NV
 *
 * This program is licensed unter the terms of the 
 * GNU Affero General Public License v3.0, see LICENSE File
 */

using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Mono.Options;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;

namespace pdfsign
{
    class Program
    {

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("pdfsign v1.2.0, (c) 2019 icomedias GmbH");
            Console.WriteLine("powered by iTextSharp 5.5 Copyright (C) 1999-2018 by iText Group NV");
            Console.WriteLine("Usage: pdfsign [OPTIONS]");
            Console.WriteLine("Sign a PDF file using a signing certificate");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
            Console.WriteLine("Return Values:");
            Console.WriteLine("\t {0}: Success", (int)Retvals.SUCCESS);
            Console.WriteLine("\t{0}: Bad Command Line Option(s)", (int)Retvals.ERR_PARAMETER);
            Console.WriteLine("\t{0}: Error processing signing certificate", (int)Retvals.ERR_CERT);
            Console.WriteLine("\t{0}: Error getting secret key", (int)Retvals.ERR_KEY);
            Console.WriteLine("\t{0}: Error getting certificate chain", (int)Retvals.ERR_CHAIN);
            Console.WriteLine("\t{0}: Error processing input file", (int)Retvals.ERR_INPUT);
            Console.WriteLine("\t{0}: Error opening output file", (int)Retvals.ERR_OUTPUT);
            Console.WriteLine("\t{0}: Error generating signature", (int)Retvals.ERR_SIGN);
        }

        enum Retvals
        {
            SUCCESS = 0,
            ERR_PARAMETER = -1,
            ERR_CERT = -2,
            ERR_KEY = -3,
            ERR_CHAIN = -4,
            ERR_INPUT = -5,
            ERR_OUTPUT = -6,
            ERR_SIGN = -7
        }

        static int Main(string[] args)
        {
            int width = 180;
            int height = 80;
            int cols = 1;
            int hsep = 10;
            int vsep = 10;
            int hoffset = 350;
            int voffset = 5;
            string infile = null;
            string outfile = null;
            string certfile = null;
            string thumbprint = null;
            string tsaUrl = null;
            string store = "LocalMachine";
            //string storeLocation = "My";
            string password = null;
            string reason = "proof of authenticity";
            string location = null;
            string contact = null;
            bool show_signature = true;
            bool show_validity = false;
            bool multi_signature = true;
            bool show_help = false;

            Retvals retval;

            var p = new OptionSet() {
                { "i|infile=", "PDF input file", v => infile = v },
                { "o|outfile=", "output file for signed PDF", v => outfile = v },
                { "c|certfile=", "PKCS12 signing certificate", v => certfile = v },
                { "p|password=", "import password for signing certificate", v => password = v },
                { "thumbprint=", "thumbprint for signing certificate from windows store", v => thumbprint = v },
                { "store=", "store for signing certificate from windows (CurrentUser or LocalMachine (default LocalMachine))", v => store = v },
                //{ "storeLocation=", "location in store for signing certificate from windows (default My)", v => storeLocation = v },
                { "r|reason=", "signature reason (gets embedded in signature)", v => reason = v },
                { "l|location=", "signature location (gets embedded in signature)", v => location = v },
                { "t|contact=", "signature contact (gets embedded in signature)", v => contact = v },
                { "s|show", "show signature (signature field visible), on: -s+ off: -s-, default on", v => show_signature = v != null },
                { "showvalidity", "show signature validity (deprecated), on: -showvalidity+ off: -showvalidity-, default off", v => show_validity = v != null },
                { "tsa=", "URL of rfc3161 TSA (Time Stamping Authority)", v => tsaUrl = v },
                { "width=", "signature width, default 180", (int v) => width = v},
                { "height=", "signature height, default 80", (int v) => height = v},
                { "hsep=", "horizontal seperation of signatures, default 10", (int v) => hsep=v},
                { "vsep=", "vertical seperation of signatures, default 10", (int v) => vsep=v},
                { "hoffset=", "horizontal offset of signatures, default 350", (int v) => hoffset=v},
                { "voffset=", "vertical offset of signatures, default 5", (int v) => voffset=v},
                { "cols=","number of signature columns, default 1", (int v) => cols = v},
                { "m|multi", "allow multiple signatures, on: -m+, off: -m-, default on", v => multi_signature = v != null },
                { "h|?|help", "show this help message and exit", v => show_help = v != null },
            };

            retval = Retvals.ERR_PARAMETER; // Option Error
            List<string> extra;
            try
            {
                extra = p.Parse(args);

                if (show_help)
                {
                    ShowHelp(p);
                    return (int)Retvals.SUCCESS;
                }

                if (extra.Count > 0)
                    throw new OptionException("uncrecognised parameters", string.Join(" ", extra.ToArray()));

                if (infile == null)
                    throw new OptionException("required parameter {0} missing", "infile");

                if (outfile == null)
                    throw new OptionException("required parameter {0} missing", "outfile");


                if (String.IsNullOrEmpty(thumbprint))
                {
                    if (certfile == null)
                        throw new OptionException("required parameter {0} missing", "certfile");

                    if (password == null)
                        throw new OptionException("required parameter {0} missing", "password");
                }
                if (!File.Exists(infile))
                    throw new OptionException("input file {0} does not exist", infile);

                if (!String.IsNullOrEmpty(certfile) && !File.Exists(certfile))
                    throw new OptionException("certfile {0} does not exist", certfile);

            }
            catch (OptionException e)
            {
                Console.Write("pdfsign: ");
                Console.WriteLine(e.Message, e.OptionName);
                Console.WriteLine("Try `pdfsign --help' for more information.");
                return (int)retval;
            }

            try
            {
                retval = Retvals.ERR_CERT; // Error processing certificate file
                Stream fs = null; 
                if (!String.IsNullOrEmpty(thumbprint))
                {
                    System.Security.Cryptography.X509Certificates.X509Certificate2 cer = null;
                    System.Security.Cryptography.X509Certificates.StoreLocation certStoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine;
                    if (store.Equals("CurrentUser", StringComparison.OrdinalIgnoreCase))
                        certStoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser;
                    System.Security.Cryptography.X509Certificates.X509Store certStore = 
                        new System.Security.Cryptography.X509Certificates.X509Store(certStoreLocation);
                    certStore.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
                    System.Security.Cryptography.X509Certificates.X509Certificate2Collection certs =
                        certStore.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, thumbprint, false);
                    if (certs.Count > 0)
                    {
                        cer = certs[0];
                    } else
                    {
                        throw new InvalidOperationException("Certificate with specified thumbnail not found");
                    }
                    System.Security.Cryptography.X509Certificates.X509Certificate2Collection certCol = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
                    System.Security.Cryptography.X509Certificates.X509Chain x509chain = new System.Security.Cryptography.X509Certificates.X509Chain();
                    x509chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                    x509chain.Build(cer);
                    for (int chainIDX = 0; chainIDX < x509chain.ChainElements.Count; chainIDX++)
                        certCol.Add(x509chain.ChainElements[chainIDX].Certificate);
                    password = "12345";
                    byte[] pkcs12 = certCol.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12, password);
                    fs = new MemoryStream(pkcs12);
                    fs.Seek(0, SeekOrigin.Begin);
                }
                else
                {
                    fs = new FileStream(certfile, FileMode.Open, FileAccess.Read);
                }
                Pkcs12Store ks = new Pkcs12Store(fs, password.ToCharArray());
                string alias = null;
                foreach (string al in ks.Aliases)
                {
                    if (ks.IsKeyEntry(al) && ks.GetKey(al).Key.IsPrivate)
                    {
                        alias = al;
                        break;
                    }
                }
                fs.Close();

                retval = Retvals.ERR_KEY; // Error extracting secret key
                ICipherParameters pk = ks.GetKey(alias).Key;

                retval = Retvals.ERR_CHAIN; // Error extracting certificate chain
                X509CertificateEntry[] x = ks.GetCertificateChain(alias);
                X509Certificate[] chain = new X509Certificate[x.Length];
                for (int k = 0; k < x.Length; ++k)
                {
                    chain[k] = x[k].Certificate;
                }

                retval = Retvals.ERR_INPUT; // Error processing input file
                PdfReader reader = new PdfReader(infile);

                retval = Retvals.ERR_OUTPUT; // Error opening output file
                FileStream fout = new FileStream(outfile, FileMode.Create, FileAccess.Write);

                MemoryStream tmpOut = new MemoryStream();

                retval = Retvals.ERR_SIGN; // Error generating signature
                PdfStamper stp = PdfStamper.CreateSignature(reader, fout, '\0', null, multi_signature);
                PdfSignatureAppearance sap = stp.SignatureAppearance;
                //LtvVerification v = stp.LtvVerification;
                //sap.SetCrypto(null, chain, null, PdfSignatureAppearance.SELF_SIGNED);

                sap.Reason = reason;
                sap.Contact = contact;
                sap.Location = location;
                sap.Acro6Layers = !show_validity;


                // when using visible signatures: find an unused field name for the signature
                if (show_signature)
                {
                    string basename = "Signature";
                    AcroFields form = reader.AcroFields;
                    int cnt = -1;
                    string name;
                    do
                    {
                        cnt++;
                        name = basename;
                        if (cnt != 0)
                            name = name + cnt;

                    } while (form.GetField(name) != null);
                    int xoff = (cnt % cols) * (width + hsep) + hoffset;
                    int yoff = cnt / cols * (height + vsep) + voffset;
                    sap.SetVisibleSignature(new Rectangle(xoff, yoff, xoff + width, yoff + height), 1, name);
                }


                //List<ICrlClient> crlClients = new List<ICrlClient>();
                //crlClients.Add(new CrlClientOnline());
                ICrlClient crlClient = new CrlClientOnline();
                var ocspClient = new OcspClientBouncyCastle();
                TSAClientBouncyCastle tsa = null;
                if (!string.IsNullOrEmpty(tsaUrl))
                    tsa = new TSAClientBouncyCastle(tsaUrl); 

                IExternalSignature es = new PrivateKeySignature(pk, "SHA-256");
                MakeSignature.SignDetached(sap,
                                           es,
                                           chain, //new X509Certificate[] { ks.GetCertificate(alias).Certificate },
                                           null,
                                           null,
                                           tsa,
                                           0,
                                           CryptoStandard.CMS);

                // Make LTV
                /*
                MemoryStream tmpInput = new MemoryStream(tmpOut.GetBuffer());
                reader = new PdfReader(tmpInput);
                stp = PdfStamper.CreateSignature(reader, fout, '\0', null, true);
                AcroFields fields = stp.AcroFields;
                List<String> names = fields.GetSignatureNames();
                String sigName = names[names.Count - 1];
                PdfPKCS7 pkcs7 = fields.VerifySignature(sigName);
                LtvVerification v = stp.LtvVerification;
                if (pkcs7.IsTsp)
                {
                    v.AddVerification(sigName, ocspClient, crlClient,
                        LtvVerification.CertificateOption.SIGNING_CERTIFICATE,
                        LtvVerification.Level.OCSP_CRL,
                        LtvVerification.CertificateInclusion.NO);
                }
                else
                {
                    foreach (var name in names)
                    {
                        v.AddVerification(name, ocspClient, crlClient,
                            LtvVerification.CertificateOption.WHOLE_CHAIN,
                            LtvVerification.Level.OCSP_CRL,
                            LtvVerification.CertificateInclusion.NO);
                    }
                }
                sap = stp.SignatureAppearance;
                LtvTimestamp.Timestamp(sap, tsa, "SHA-256");
                */
                stp.Close();

                //PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, new PdfName("adbe.pkcs7.detached"));
                //dic.Reason = sap.Reason;
                //dic.Location = sap.Location;
                //dic.Contact = sap.Contact;
                //dic.Date = new PdfDate(sap.SignDate);
                //sap.CryptoDictionary = dic;

                //int contentEstimated = 15000;
                //Dictionary<PdfName, int> exc = new Dictionary<PdfName, int>();
                //exc[PdfName.CONTENTS] = contentEstimated * 2 + 2;
                //sap.PreClose(exc);

                //PdfPKCS7 sgn = new PdfPKCS7(pk, chain, null, "SHA1", false);
                //IDigest messageDigest = DigestUtilities.GetDigest("SHA1");
                //Stream data = sap.RangeStream;
                //byte[] buf = new byte[8192];
                //int n;
                //while ((n = data.Read(buf, 0, buf.Length)) > 0)
                //{
                //    messageDigest.BlockUpdate(buf, 0, n);
                //}
                //byte[] hash = new byte[messageDigest.GetDigestSize()];
                //messageDigest.DoFinal(hash, 0);
                //DateTime cal = DateTime.Now;
                //byte[] ocsp = null;
                //if (chain.Length >= 2)
                //{
                //    String url = PdfPKCS7.GetOCSPURL(chain[0]);
                //    if (url != null && url.Length > 0)
                //        ocsp = new OcspClientBouncyCastle(chain[0], chain[1], url).GetEncoded();
                //}
                //byte[] sh = sgn.GetAuthenticatedAttributeBytes(hash, cal, ocsp);
                //sgn.Update(sh, 0, sh.Length);


                //byte[] paddedSig = new byte[contentEstimated];


                //byte[] encodedSig = sgn.GetEncodedPKCS7(hash, cal);
                //System.Array.Copy(encodedSig, 0, paddedSig, 0, encodedSig.Length);
                //if (contentEstimated + 2 < encodedSig.Length)
                //    throw new Exception("Not enough space for signature");

                //PdfDictionary dic2 = new PdfDictionary();
                //dic2.Put(PdfName.CONTENTS, new PdfString(paddedSig).SetHexWriting(true));
                //sap.Close(dic2);
            }
            catch (Exception e)
            {
                Console.Write("pdfsign: ");
                Console.WriteLine(e.Message);
                return (int)retval;
            }

            // looks like it worked, return success
            return (int)Retvals.SUCCESS;
        }
    }
}
