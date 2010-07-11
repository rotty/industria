;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2009, 2010 Göran Weinholt <goran@weinholt.se>
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
#!r6rs

;; X.509 certificates as per RFC 5280.

;; The decoding routines are implemented manually, but should maybe be
;; automatically generated from the ASN.1 types in the RFC.

;; A little on how people implement X.509 differently:
;; http://www.cs.auckland.ac.nz/~pgut001/pubs/x509guide.txt

(library (weinholt crypto x509 (0 0 20100705))
  (export certificate?
          certificate-from-bytevector
          certificate-public-key
          decipher-certificate-signature
          validate-certificate-path
          CA-path CA-file CA-procedure

          certificate-key-usage
          certificate-tbs-data

          print-certificate)
  (import (rnrs)
          (only (srfi :13 strings) string-join
                string-pad string-prefix? string-suffix-ci?
                string-count)
          (srfi :19 time)
          (srfi :39 parameters)
          (weinholt bytevectors)
          (weinholt crypto dsa)
          (weinholt crypto md5)
          (weinholt crypto rsa)
          (weinholt crypto sha-1)
          (weinholt crypto sha-2)
          (prefix (weinholt struct der (0 0)) der:)
          (weinholt struct pack)
          (weinholt text base64))

  (define (print . x) (for-each display x) (newline))

  ;; The CA-path has to end with the system's path separator, because
  ;; there's no standard way to find the path separator.
  (define CA-path (make-parameter "/etc/ssl/certs/"))
  (define CA-file (make-parameter "/etc/ssl/certs/ca-certificates.crt"))
  (define CA-procedure (make-parameter (lambda (issuer . _) #f)))

;;; The Certificate ASN.1 type from the RFC (parsed by hand).
  (define (RelativeDistinguishedName)
    `(set-of 1 +inf.0 ,(AttributeTypeAndValue)))

  (define (RDNSequence)
    `(sequence-of 0 +inf.0 ,(RelativeDistinguishedName)))

  (define (AttributeType) 'object-identifier)

  (define (AttributeValue) 'ANY)

  (define (AttributeTypeAndValue)
    `(sequence (type ,(AttributeType))
               (value ,(AttributeValue))))

  (define (Time)
    `(choice (utcTime utc-time)
             (generalTime generalized-time)))

  (define (Validity)
    `(sequence (notBefore ,(Time))
               (notAfter ,(Time))))

  (define (AlgorithmIdentifier)
    `(sequence (algorithm object-identifier)
               (parameters ANY (default #f))))

  (define (Version)
    `(integer ((v1 . 0) (v2 . 1) (v3 . 2))))

  (define (SubjectPublicKeyInfo)
    `(sequence (algorithm ,(AlgorithmIdentifier))
               (subjectPublicKey bit-string)))

  (define (Extensions)
    `(sequence-of 1 +inf.0 ,(Extension)))

  (define (Extension)
    `(sequence (extnID object-identifier)
               (critical boolean (default #f))
               (extnValue octet-string)))

  (define (UniqueIdentifier)
    'bit-string)

  (define (Name)
    (RDNSequence))

  (define (Certificate)
    `(sequence (tbsCertificate ,(TBSCertificate))
               (signatureAlgorithm ,(AlgorithmIdentifier))
               (signatureValue bit-string)))

  (define (TBSCertificate)
    `(sequence (version (explicit context 0 ,(Version)) (default v1))
               (serialNumber integer)
               (signature ,(AlgorithmIdentifier))
               (issuer ,(Name))
               (validity ,(Validity))
               (subject ,(Name))
               (subjectPublicKeyInfo ,(SubjectPublicKeyInfo))
               (issuerUniqueID (implicit context 1 ,(UniqueIdentifier)) (default #vu8()))
               (subjectUniqueID (implicit context 2 ,(UniqueIdentifier)) (default #vu8()))
               (extensions (explicit context 3 ,(Extensions)) (default ()))))

  (define (DSAPublicKey)
    'integer)

  (define (Dss-Parms)
    '(sequence (p integer)
               (q integer)
               (g integer)))

  (define (BasicConstraints)
    '(sequence (cA boolean (default #f))
               (pathLenConstraint integer (default #f))))

  (define (SubjectAltName)
    `(sequence-of 1 +inf.0 ,(GeneralName)))

  (define (GeneralName)
    `(choice (otherName (implicit context 0 ,(OtherName)))
             (rfc822Name (implicit context 1 ia5-string))
             (dNSName (implicit context 2 ia5-string))
             ;; FIXME:
             ;; (x400Address (implicit context 3 ,(ORAddress)))
             (directoryName (explicit context 4 ,(Name)))
             (ediPartyName (implicit context 5 ,(EDIPartyName)))
             (uniformResourceIdentifier (implicit context 6 ia5-string))
             (iPAddress (implicit context 7 octet-string))
             (registeredID (implicit context 8 object-identifier))))

  (define (OtherName)
    '(sequence (type-id object-identifier)
               (value (explicit context 0 ANY)))) ;XXX: might be mistranslated

  (define (EDIPartyName)                ;XXX: mistranslated maybe
    `(sequence (nameAssigner (implicit context 0 ,(DirectoryString)) (default #f))
               (partyName (implicit context 1 ,(DirectoryString)))))

  (define (DirectoryString)
    '(choice (teletexString TeletexString)
             (printableString PrintableString)
             (universalString UniversalString)
             (utf8String UTF8String)
             (bmpString BMPString)))

  (define (KeyUsage)
    'bit-string)

;;;

  (define (symbol<-oid oid)
    (define oids
      '( ;; http://www.iana.org/assignments/dssc/dssc.xhtml
        ((1 2 840 10040 4 1) . dsa)
        ((1 2 840 10040 4 3) . sha1WithDSA)
        ((1 2 840 113549 1 1 1) . rsaEncryption)
        ((1 2 840 113549 1 1 2) . md2WithRSAEncryption) ;wontfix
        ((1 2 840 113549 1 1 4) . md5withRSAEncryption) ;wontfix
        ((1 2 840 113549 1 1 5) . sha1WithRSAEncryption)
        ((1 2 840 113549 1 1 11) . sha256WithRSAEncryption)
        ((1 2 840 113549 1 1 12) . sha384WithRSAEncryption)
        ((1 2 840 113549 1 1 13) . sha512WithRSAEncryption)

        ((1 3 36 3 3 1 2) . rsaSignatureWithripemd160) ;maybe fix?
        ((1 3 36 3 2 1) . ripemd160) ;maybe fix?

        ((0 9 2342 19200300 100 1 25) . domainComponent)
        ((1 2 840 113549 1 9 1) . emailAddress)

        ((1 3 6 1 5 5 7 1 1) . authorityInfoAccess)
        ((2 5 4 3) . commonName)
        ((2 5 4 5) . serialNumber)
        ((2 5 4 6) . countryName)
        ((2 5 4 7) . localityName)
        ((2 5 4 8) . stateOrProvinceName)
        ((2 5 4 9) . streetAddress)
        ((2 5 4 10) . organizationName)
        ((2 5 4 11) . organizationalUnitName)
        ((2 5 4 16) . postalAddress)
        ((2 5 4 17) . postalCode)

        ((2 5 29 14) . subjectKeyIdentifier)
        ((2 5 29 15) . keyUsage)
        ((2 5 29 17) . subjectAltName)
        ((2 5 29 18) . issuerAltName)
        ((2 5 29 19) . basicConstraints)
        ((2 5 29 31) . cRLDistributionPoints)
        ((2 5 29 32) . certificatePolicies)
        ((2 5 29 35) . authorityKeyIdentifier)
        ((2 5 29 37) . extKeyUsage)

        ;; http://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml
        ((1 2 840 113549 2 2) . md2)    ;wontfix
        ((1 2 840 113549 2 5) . md5)    ;wontfix
        ((1 3 14 3 2 26) . sha-1)
        #;((2 16 840 1 101 3 4 2 4) . sha-224)
        ((2 16 840 1 101 3 4 2 1) . sha-256)
        ((2 16 840 1 101 3 4 2 2) . sha-384)
        ((2 16 840 1 101 3 4 2 3) . sha-512)))
    (cond ((assoc oid oids) => cdr)
          (else (string->symbol (string-append
                                 "oid-"
                                 (string-join (map number->string oid) "."))))))

  (define (dsa-algorithm? alg)
    (eq? alg 'sha1WithDSA))
  (define (rsa-algorithm? alg)
    (memq alg '(md2WithRSAEncryption
                md5withRSAEncryption
                sha1WithRSAEncryption
                sha256WithRSAEncryption
                sha384WithRSAEncryption
                sha512WithRSAEncryption
                rsaSignatureWithripemd160)))

  (define-record-type certificate
    (fields tbs-data                    ;Bytevector with the tbs-certificate
            tbs-certificate             ;"To Be Signed"
            signature-algorithm
            signature-value))

  (define-record-type tbs-certificate
    (fields version
            serial-number
            signature-algorithm
            issuer
            validity
            subject
            subject-public-key-info
            issuer-unique-id            ;unused
            subject-unique-id           ;unused
            extensions))

  (define certificate-from-bytevector
    (case-lambda
      ((bv)
       (certificate-from-bytevector bv 0 (bytevector-length bv)))
      ((bv start end)
       (let* ((parse-tree (der:decode bv start end))
              (cert-data (der:translate parse-tree (Certificate)
                                        (lambda (name type value start len)
                                          (asn1translate bv name type value start len)))))
         ;; (write (der:translate parse-tree (Certificate)
         ;;                       (lambda (x y z . w) (list x z))))
         (let* ((tbs (car (der:data-value parse-tree)))
                (tbs-data (make-bytevector (der:data-length tbs))))
           ;; Copy the To Be Signed certificate, so the signature can
           ;; be verified.
           (bytevector-copy! bv (der:data-start-index tbs)
                             tbs-data 0
                             (bytevector-length tbs-data))
           (apply make-certificate tbs-data cert-data))))))

  (define (translate-algorithm value)
    ;; Ignores the parameters
    (symbol<-oid (car value)))

  (define (asn1translate bv name type value start len)
    ;; This uses the sequence field names to interpret the ASN.1
    ;; certificate data.
    (case name
      ((issuer subject)
       (let ((name-hash
              (string-pad
               (string-downcase
                (number->string
                 (unpack "<L"
                         (md5->bytevector
                          (md5 (subbytevector bv start (+ start len)))))
                 16))
               8 #\0)))
         ;; The name hash is used to locate CA certificates in
         ;; directories populated by OpenSSL's c_rehash.
         (cons (cons 'name-hash name-hash)
               (map (lambda (e)
                      ;; FIXME: This is actually defined by the attribute type
                      ;; in some maze-like way.
                      (cons (symbol<-oid (car e))
                            (der:translate (cadr e)
                                           '(choice (teletexString teletex-string)
                                                    (printableString printable-string)
                                                    (universalString universal-string)
                                                    (utf8String utf8-string)
                                                    (bmpString bmp-string)
                                                    (IA5String ia5-string)
                                                    (T61String t61-string)))))
                    (map car value)))))
      ((signature signatureAlgorithm) (translate-algorithm value))
      ((tbsCertificate) (apply make-tbs-certificate value))
      ((subjectPublicKeyInfo)
       (let ((algo (translate-algorithm (car value))))
         (case algo
           ((rsaEncryption)
            (rsa-public-key-from-bytevector (der:bit-string->bytevector
                                             (cadr value))))
           ((dsa)
            (let ((key (der:translate (der:decode (der:bit-string->bytevector
                                                   (cadr value)))
                                      (DSAPublicKey)))
                  (params (der:translate (cadar value) (Dss-Parms))))
              (make-dsa-public-key (car params) (cadr params) (caddr params) key)))
           (else
            (error 'certificate-bytevector
                   "Unimplemented public key algorithm" algo)))))
      (else value)))

  (define (certificate-public-key cert)
    (tbs-certificate-subject-public-key-info (certificate-tbs-certificate cert)))

;;; Certificate signatures etc

  ;; `equal?' should be ok, because according to rfc5280 4.1.2.6 the
  ;; DER encoding of subject and issuer must match.
  (define dn=? equal?) ;compare distinguished names

  ;; FIXME: This doesn't really work, because the name must be
  ;; converted to ascii (punycode) first, etc. Or it might be an IP
  ;; address in a non-canonical form, I suppose. See section 7.1.
  (define (common-name-matches? cn pattern)
    ;; `pattern' is from the certificate.
    (and (string? cn)
         (cond ((and (string-prefix? "*" pattern)
                     (> (string-count pattern #\.) 1))
                ;; Support one * at the start of a certificate's
                ;; commonName or subjectAltName (partial support for
                ;; RFC2818). Require that the pattern has more than
                ;; one dot. Interesting reading on wildcards:
                ;; http://nils.toedtmann.net/pub/subjectAltName.txt
                ;; TODO: use Mozilla's effective_tld_names.dat?
                (and (string-suffix-ci? (substring pattern 1 (string-length pattern))
                                        cn)
                     ;; Match only a single part:
                     (zero? (string-count cn #\. 0
                                          (- (string-length cn)
                                             (- (string-length pattern) 1))))))
               (else
                (string-ci=? pattern cn)))))

  (define (find-extension cert extension)
    (let ((cert (certificate-tbs-certificate cert)))
      (find (lambda (ext) (eq? extension (symbol<-oid (car ext))))
            (tbs-certificate-extensions cert))))

  (define (subject-alt-names cert)
    (cond ((find-extension cert 'subjectAltName)
           =>
           (lambda (ext)
             ;; TODO: should probably discriminate between the
             ;; different types in GeneralName here.
             (der:translate (der:decode (caddr ext)) (SubjectAltName))))
          (else '())))

  (define (basic-constraints cert)
    ;; Returns a list. The first entry is true if the certificate is
    ;; supposed to belong to a CA, and the second entry is a path
    ;; length constraint.
    (cond ((find-extension cert 'basicConstraints)
           =>
           (lambda (ext)
             (der:translate (der:decode (caddr ext)) (BasicConstraints))))
          (else '(#f #f))))             ;default

  ;; Return #f or a list of the symbolic names for the bits. RFC 5280
  ;; explains their meaning.
  (define (certificate-key-usage cert)
    (define (bits->symbols ku)
      (define bitnames
        '(digitalSignature
          nonRepudiation ;aka contentCommitment
          keyEncipherment
          dataEncipherment
          keyAgreement
          keyCertSign
          cRLSign
          encipherOnly
          decipherOnly))
      (do ((i 0 (fx+ i 1))
           (names bitnames (cdr names))
           (bits '() (if (der:bit-string-bit-set? ku i)
                         (cons (car names) bits)
                         bits)))
          ((null? names) (reverse bits))))
    (cond ((find-extension cert 'keyUsage)
           =>
           (lambda (ext)
             (bits->symbols (der:translate (der:decode (caddr ext))
                                           (KeyUsage)))))
          (else #f)))

  (define (decipher-certificate-signature signed-cert signer-cert)
    (unless (dn=? (tbs-certificate-subject (certificate-tbs-certificate signer-cert))
                  (tbs-certificate-issuer  (certificate-tbs-certificate signed-cert)))
      (error 'decipher-certificate-signature
             "Issuer on signed certificate does not match subject on signer"
             (tbs-certificate-issuer  (certificate-tbs-certificate signed-cert))
             (tbs-certificate-subject (certificate-tbs-certificate signer-cert))))
    (unless (eq? (certificate-signature-algorithm signed-cert)
                 (tbs-certificate-signature-algorithm
                  (certificate-tbs-certificate signed-cert)))
      (error 'validate-certificate-path
             "Signature algorithms differ"
             (certificate-signature-algorithm signed-cert)
             (tbs-certificate-signature-algorithm
              (certificate-tbs-certificate signed-cert))))
    (let ((key (certificate-public-key signer-cert)))
      (cond ((rsa-public-key? key)
             (unless (rsa-algorithm? (certificate-signature-algorithm signed-cert))
               (error 'decipher-certificate-signature
                      "RSA key but invalid signature algorithm"
                      (certificate-signature-algorithm signed-cert)))
             (let ((digest (rsa-pkcs1-decrypt-digest
                            (der:bit-string->integer
                             (certificate-signature-value signed-cert))
                            key)))
               (list (translate-algorithm (car digest))
                     (cadr digest))))
            ((dsa-public-key? key)
             (unless (dsa-algorithm? (certificate-signature-algorithm signed-cert))
               (error 'decipher-certificate-signature
                      "DSA key but invalid signature algorithm"
                      (certificate-signature-algorithm signed-cert)))
             (list (certificate-signature-algorithm signed-cert)
                   (dsa-signature-from-bytevector
                    (der:bit-string->bytevector
                     (certificate-signature-value signed-cert)))))
            (else
             (error 'decipher-certificate-signature
                    "Unimplemented public key algorithm" key)))))

  (define (get-root-certificate issuer)
    (let ((name-hash (cdr (assq 'name-hash issuer))))
      (let lp ((index 0))
        (let ((fn (string-append (CA-path) name-hash "." (number->string index))))
          (cond (((CA-procedure) issuer))
                ((file-exists? fn)
                 (call-with-port (open-input-file fn)
                   (lambda (p)
                     (let-values (((type bv) (get-delimited-base64 p)))
                       (cond ((and (string=? type "CERTIFICATE")
                                   (certificate-from-bytevector bv))
                              =>
                              (lambda (cert)
                                (if (dn=? issuer
                                          (tbs-certificate-subject
                                           (certificate-tbs-certificate cert)))
                                    cert
                                    (lp (+ index 1)))))
                             (else (lp (+ index 1))))))))
                ((file-exists? (CA-file))
                 ;; TODO:
                 #f)
                (else #f))))))

  (define (self-issued? cert)
    (let ((tbs (certificate-tbs-certificate cert)))
      (dn=? (tbs-certificate-subject tbs)
            (tbs-certificate-issuer tbs))))

  (define (cross-signed? signed signer)
    (let ((signed-tbs (certificate-tbs-certificate signed))
          (signer-tbs (certificate-tbs-certificate signer)))
      (dn=? (tbs-certificate-issuer signed-tbs)
            (tbs-certificate-subject signer-tbs))))

  (define (cert=? x y)
    (bytevector=? (certificate-tbs-data x)
                  (certificate-tbs-data y)))

  (define (time-ok? cert time)
    (let ((validity (tbs-certificate-validity
                     (certificate-tbs-certificate cert))))
      (and (time>=? time (date->time-utc (car validity)))
           (time<=? time (date->time-utc (cadr validity))))))

  (define (signature-ok? signed signer)
    (define (check algorithm md->bv md sig)
      (unless (eq? algorithm (certificate-signature-algorithm signed))
        (error 'validate-certificate-path
               "Signature algorithm does not match with deciphered digest"
               algorithm (certificate-signature-algorithm signed)))
      (bytevector=? sig (md->bv (md (certificate-tbs-data signed)))))
    (let ((signature (decipher-certificate-signature signed signer)))
      (case (car signature)
        ((sha-1) (check 'sha1WithRSAEncryption sha-1->bytevector
                        sha-1 (cadr signature)))
        ((sha-256) (check 'sha256WithRSAEncryption sha-256->bytevector
                          sha-256 (cadr signature)))
        ((sha-384) (check 'sha384WithRSAEncryption sha-384->bytevector
                          sha-384 (cadr signature)))
        ((sha-512) (check 'sha512WithRSAEncryption sha-512->bytevector
                          sha-512 (cadr signature)))
        ((sha1WithDSA)
         (apply dsa-verify-signature
                (sha-1->bytevector (sha-1 (certificate-tbs-data signed)))
                (certificate-public-key signer)
                (cadr signature)))      ;r and s
        (else (error 'validate-certificate-path
                     "Unimplemented signature algorithm"
                     (car signature))))))

  (define (common-name-ok? cert common-name)
    (cond ((assq 'commonName
                 (tbs-certificate-subject
                  (certificate-tbs-certificate cert)))
           => (lambda (cn) (common-name-matches? common-name (cdr cn))))
          (else #f)))

  (define (alternative-name-ok? cert common-name)
    (exists (lambda (name) (common-name-matches? common-name name))
            (subject-alt-names cert)))

  (define (revoked? cert)
    ;; TODO: CRLs and so on
    #f)

  (define (critical-extensions-handled? cert)
    (let ((cert (certificate-tbs-certificate cert)))
      (for-all (lambda (ext)
                 (or (not (cadr ext))   ;not critical
                     (let ((name (symbol<-oid (car ext))))
                       (memv name '(basicConstraints keyUsage)))))
               (tbs-certificate-extensions cert))))

  ;; Validate a certificate path as per section 6 of RFC 5280. The
  ;; path is a list of certificates where the first certificate is
  ;; issued by a trusted certificate and the last certificate is the
  ;; end-entity (e.g. the server). Trust anchor information is passed
  ;; either via the CA-path and CA-file parameters or the root-cert
  ;; argument. If this returns ok you should call
  ;; certificate-key-usage and see if what you want to use the cert
  ;; for is allowed.
  (define validate-certificate-path
    (case-lambda
      ((path)
       (validate-certificate-path path #f #f #f))
      ((path common-name)
       (validate-certificate-path path common-name #f #f))
      ((path common-name time)
       (validate-certificate-path path common-name time #f))
      ((path common-name time root-cert)
       ;; XXX: Policy mappings and the permitted/excluded subtrees
       ;; stuff is not (yet) implemented.
       (guard (cnd
               (else
                ;; TODO: return better error messages when know error
                ;; causes appear.
                (display cnd (current-error-port))
                (newline (current-error-port))
                'internal-error))
         (let ((root-cert (or root-cert
                              (get-root-certificate
                               (tbs-certificate-issuer
                                (certificate-tbs-certificate (car path))))))
               (time (or time (current-time))))
           (let lp ((path path)
                    (maxlen (length path))
                    (signer root-cert))
             (cond ((not signer)
                    'root-certificate-not-found)
                   ((not (signature-ok? (car path) signer))
                    ;; TODO: fails when the root certificate signed
                    ;; itself using md2WithRSAEncryption.
                    'bad-signature)
                   ((not (time-ok? (car path) time))
                    'expired)
                   ((revoked? (car path))
                    'revoked)
                   ((not (cross-signed? (car path) signer))
                    'bad-issuer)
                   ((not (critical-extensions-handled? (car path)))
                    'unhandled-critical-extension)
                   ;; TODO: check subtrees
                   ((not (null? (cdr path)))
                    ;; Prepare for the next certificate. (car path) is
                    ;; now the root certificate or an intermediate.
                    (let ((self-issued (self-issued? (car path)))
                          (bc (basic-constraints (car path)))
                          (ku (certificate-key-usage (car path))))
                      (let ((ca? (car bc))
                            (maxlen-constraint (cadr bc)))
                        (cond ((and (not ca?) (not (cert=? root-cert (car path))))
                               ;; Some root CAs don't have basic
                               ;; constraints at all. Be forgiving to
                               ;; them. But any CA not at the root will
                               ;; need one.
                               'intermediate-is-not-ca)
                              ((and (not self-issued) (<= maxlen 0))
                               'maximum-path-length-exceeded)
                              ((and ku (not (memq 'keyCertSign ku)))
                               'intermediate-without-keyCertSign)
                              (else
                               (lp (cdr path)
                                   (min (if self-issued maxlen (- maxlen 1))
                                        (or maxlen-constraint maxlen))
                                   (car path)))))))
                   ;; This is the last certificate in the path
                   ((not (or (not common-name)
                             (common-name-ok? (car path) common-name)
                             (alternative-name-ok? (car path) common-name)))
                    'bad-common-name)
                   (else
                    'ok))))))))

  ;; Verify a certificate chain. The chain is a list of certificates
  ;; where the first certificate is the end-entity that should
  ;; correspond to the given common-name (often the server name).
  (define (load-certificates fn)
    (call-with-port (open-input-file fn)
      (lambda (p)
        (let lp ()
          (let-values (((type bv) (get-delimited-base64 p)))
            (cond ((eof-object? bv)
                   '())
                  ((string=? type "CERTIFICATE")
                   (cons (certificate-from-bytevector bv)
                         (lp)))
                  (else (lp))))))))

  ;; XXX: should probably not be here
  (define (print-certificate c)
    (let ((cert (certificate-tbs-certificate c)))
      (print "---------------")
      (print "X.509 certificate version " (tbs-certificate-version cert))
      (print "- Serial number: " (tbs-certificate-serial-number cert))
      (print "- Signature algorithm: " (tbs-certificate-signature-algorithm cert))
      (print "- Subject Public Key: ")
      (print (certificate-public-key c))
      (display "- Issuer: ") (write (tbs-certificate-issuer cert)) (newline)
      (let ((v (tbs-certificate-validity cert)))
        (print "- Not valid before: " (date->string (car v)))
        (print "- Not valid after: " (date->string (cadr v))))
      (display "- Subject: ") (write (tbs-certificate-subject cert)) (newline)
      (print "- Extensions: ")
      (for-each (lambda (x)
                  (display (if (cadr x) "  Critical: " "  Ignoreable: "))
                  (case (symbol<-oid (car x))
                    ((keyUsage)
                     (display "key usage: ")
                     (display (certificate-key-usage c)))
                    ((basicConstraints)
                     (display "basic constraints: ")
                     (let ((bc (der:translate (der:decode (caddr x))
                                              (BasicConstraints))))
                       (write bc)))
                    ((subjectAltName)
                     (display "subject alt names: ")
                     (let ((an (der:translate (der:decode (caddr x)) (SubjectAltName))))
                       (write an)))
                    (else
                     (write (list (symbol<-oid (car x))
                                  (caddr x)))))
                  (newline))
                (tbs-certificate-extensions cert))
      (print "Signature algorithm: " (certificate-signature-algorithm c))
      #;(print "Signature: " (certificate-signature-value c))
      ))


  )

