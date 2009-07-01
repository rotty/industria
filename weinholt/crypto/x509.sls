;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2009 Göran Weinholt <goran@weinholt.se>
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

(library (weinholt crypto x509)
  (export certificate<-bytevector
          certificate<-asn1data
          public-key<-certificate
          decipher-certificate-signature
          verify-certificate-chain)
  (import (rnrs)
          (weinholt crypto rsa)
          (weinholt crypto sha-1)
          (weinholt struct der (0)))

  (define (print . x) (for-each display x) (newline))

  (define (symbol<-oid oid)
    (define oids
      '(((1 2 840 113549 1 1 1) . rsaEncryption)
        ((1 2 840 113549 1 1 4) . md5withRSAEncryption)
        ((1 2 840 113549 1 1 5) . sha1WithRSAEncryption)
        ((1 3 14 3 2 26) . sha1)
        ((2 5 4 3) . id-at-commonName)
        ((2 5 4 6) . id-at-countryName)
        ((2 5 4 7) . id-at-localityName)
        ((2 5 4 8) . id-at-stateOrProvinceName)
        ((2 5 4 9) . id-at-streetAddress)
        ((2 5 4 10) . id-at-organizationName)
        ((2 5 4 11) . id-at-organizationalUnitName)
        ((2 5 4 16) . id-at-postalAddress)
        ((2 5 4 17) . id-at-postalCode)))
    (cond ((assoc oid oids) => cdr)
          (else oid)))

  (define-record-type certificate
    (fields tbs-certificate             ;"To Be Signed"
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
            issuer-unique-id
            subject-unique-id
            extensions))

  (define (certificate<-bytevector . x)
    (print "certificate bytevector: " x)
    (certificate<-asn1data (apply der-decode x)))

  (define (certificate<-asn1data d)
    (print "certificate ASN.1 data: " d)
    (make-certificate (tbs-certificate<-asn1data (car d))
                      (apair<-asn1data (cadr d))
                      (caddr d)))

  (define (apair<-asn1data d)
    (let ((oid (oid-value (car d))))
      (if (null? (cdr d))
          (cons (symbol<-oid oid) '())
          (cons (symbol<-oid oid) (cadr d)))))

  (define (alist<-asn1data d)
    (map apair<-asn1data
         (map car d)))
  
  (define (tbs-certificate<-asn1data d)
    (make-tbs-certificate (version<-asn1data (car d))
                          (cadr d)
                          (apair<-asn1data (list-ref d 2))
                          (alist<-asn1data (list-ref d 3))
                          (list-ref d 4)
                          (alist<-asn1data (list-ref d 5))
                          (subject-public-key-info<-asn1data (list-ref d 6))
                          #f
                          #f
                          #f))

  (define (version<-asn1data d)
    (let ((v (construct-ref d 0 'context 0)))
      (case v
        ((0) 'v0)
        ((1) 'v1)
        ((2) 'v3)
        (else v))))

  (define-record-type subject-public-key-info
    (fields algorithm
            subject-public-key))
  
  (define (subject-public-key-info<-asn1data d)
    (make-subject-public-key-info (apair<-asn1data (car d))
                                  (cadr d)))


  (define (parse-subject-public-key-info key)
    (case (car (subject-public-key-info-algorithm key))
      ((rsaEncryption)
       (rsa-public-key<-bytevector (bit-string-bytes (subject-public-key-info-subject-public-key key))))
      (else
       (error 'parse-subject-public-key-info
              "unknown encryption algorithm"
              (car (subject-public-key-info-algorithm key))))))


  (define (public-key<-certificate cert)
    (parse-subject-public-key-info
     (tbs-certificate-subject-public-key-info
      (certificate-tbs-certificate cert))))

;;; Certificate signatures etc
  
  (define (decipher-certificate-signature signed-cert signer-cert)
    (print-certificate signed-cert)
    (let ((key (public-key<-certificate signer-cert)))
      (cond ((rsa-public-key? key)
             (let* ((sig (rsa-encrypt (bit-string-value (certificate-signature-value signed-cert)) key))
                    (len (bit-string-bit-length (certificate-signature-value signed-cert)))
                    (bvsig (make-bytevector (/ len 8))))
               (bytevector-uint-set! bvsig 0 sig (endianness big) (/ len 8))
               (print "with " len " bits")
               (unless (zero? (bytevector-u8-ref bvsig 0))
                 (error 'decipher-certificate-signature "no leading zero"))
               (case (bytevector-u8-ref bvsig 1)
                 ((#x01)
                  (do ((i 2 (fx+ i 1)))
                      ((fxzero? (bytevector-u8-ref bvsig i))
                       (let ((asn1data (der-decode bvsig (fx+ i 1) (/ len 8))))
                         (cons (apair<-asn1data (car asn1data))
                               (cdr asn1data))))))
                 (else
                  (error 'decipher-certificate-signature
                         "can't find the end of the padding")))))
            (else
             (error 'decipher-certificate-signature
                    "unimplemented crypto?")))))

  (define (verify-certificate-chain l)
    (print "length of certificate chain: " (length l))
    (cond ((= (length l) 1)
           (print "Self-signed!!!")
           (let ((signature (decipher-certificate-signature (car l) (car l))))
             (print "sig: " signature)
             'self-signed))
          (else
           (let lp ((l l))
             (cond ((null? (cdr l))
                    ;; TODO: parse e.g. the CAfile /etc/ssl/certs/ca-certificates.crt
                    (print "Would need to find root certificate for:")
                    (write (tbs-certificate-issuer
                            (certificate-tbs-certificate (car l))))
                    (newline)
                    'no-root-certificate)
                   (else
                    (let ((signature (decipher-certificate-signature (car l) (cadr l))))
                      ;; TODO: verify the checksum. this only proves
                      ;; that there is _a_ signature on the
                      ;; certificate. :)
                      (lp (cdr l)))))))))
  
  (define (print-certificate c)
    (let ((cert (certificate-tbs-certificate c)))
      (print "---------------")
      (print "X.509 certificate version " (tbs-certificate-version cert))
      (print "- Serial number: " (tbs-certificate-serial-number cert))
      (print "- Signature algorithm: " (tbs-certificate-signature-algorithm cert))
      (print "- Subject Public Key: ")
      (let ((key (parse-subject-public-key-info
                  (tbs-certificate-subject-public-key-info cert))))
        (print key)

        (display "Issuer: ") (write (tbs-certificate-issuer cert)) (newline)
        (print "Validity: " (tbs-certificate-validity cert))
        (display "Subject: ") (write (tbs-certificate-subject cert)) (newline)

      
        (print "Signature algorithm: " (certificate-signature-algorithm c))
        (print "Signature: " (bit-string-value (certificate-signature-value c))))))



  )
