# PDFSign
Basic command line tool for signing PDF Files using itextsharp library

## Notes
This is a command line tool that allows signing of pdf files using certificates.
the actual PDF manipulation is performed using the itextsharp library v5.5
This tool was originaly published on [codeplex](https://archive.codeplex.com/?p=pdfsign)


The signing certificate can can either be provided as a pkcs12 file or it can come from 
the windows certificate store. In order to use a certificate from the windows store,
the certificate must
  - be have the private key marked as exportable
  - the user running pdfsign must have read access to the private key
  
In Addition to nuget packages, the build process uses Microsofts [ILMerge](http://www.microsoft.com/download/en/details.aspx?displaylang=en&id=17630) 
tool to produce a consolidated single binary including all dlls. 

Currently, the signatures created are not LTV capable, i.e they expire with the validity of the signing certificate

## usage
```
pdfsign v1.2.0, (c) 2019 icomedias GmbH
powered by iTextSharp 5.5 Copyright (C) 1999-2018 by iText Group NV
Usage: pdfsign [OPTIONS]
Sign a PDF file using a signing certificate

Options:
  -i, --infile=VALUE         PDF input file
  -o, --outfile=VALUE        output file for signed PDF
  -c, --certfile=VALUE       PKCS12 signing certificate
  -p, --password=VALUE       import password for signing certificate
      --thumbprint=VALUE     thumbprint for signing certificate from windows
                               store
      --store=VALUE          store for signing certificate from windows (
                               CurrentUser or LocalMachine (default
                               LocalMachine))
  -r, --reason=VALUE         signature reason (gets embedded in signature)
  -l, --location=VALUE       signature location (gets embedded in signature)
  -t, --contact=VALUE        signature contact (gets embedded in signature)
  -s, --show                 show signature (signature field visible), on: -s+
                               off: -s-, default on
      --showvalidity         show signature validity (deprecated), on: -
                               showvalidity+ off: -showvalidity-, default off
      --tsa=VALUE            URL of rfc3161 TSA (Time Stamping Authority)
      --width=VALUE          signature width, default 180
      --height=VALUE         signature height, default 80
      --hsep=VALUE           horizontal seperation of signatures, default 10
      --vsep=VALUE           vertical seperation of signatures, default 10
      --hoffset=VALUE        horizontal offset of signatures, default 350
      --voffset=VALUE        vertical offset of signatures, default 5
      --cols=VALUE           number of signature columns, default 1
  -m, --multi                allow multiple signatures, on: -m+, off: -m-,
                               default on
  -h, -?, --help             show this help message and exit
Return Values:
         0: Success
        -1: Bad Command Line Option(s)
        -2: Error processing signing certificate
        -3: Error getting secret key
        -4: Error getting certificate chain
        -5: Error processing input file
        -6: Error opening output file
        -7: Error generating signature
```

## multiple signatures

Multiple signatures are supported; if you leave signature visibility turned on, additional signatures get 
seperate signature field names (Signature, Signature1, Signature2...) and are automatically positioned as 
a grid with --cols columns from left to right and bottom to top.
