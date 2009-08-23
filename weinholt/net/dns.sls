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

;; Procedures and data structures for the domain name system (DNS)

;; This is a work in progress.

;; STD0013 Domain name system
;; RFC1034: DOMAIN NAMES - CONCEPTS AND FACILITIES
;; RFC1035: DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION

;; RFC1035 is updated by RFC1101, RFC1183, RFC1348, RFC1876, RFC1982,
;; RFC1995, RFC1996, RFC2065, RFC2136, RFC2181, RFC2137, RFC2308,
;; RFC2535, RFC2845, RFC3425, RFC3658, RFC4033, RFC4034, RFC4035,
;; RFC4343.

;; Current errata: http://www.rfc-editor.org/errata_search.php?rfc=1035

;; Constants are here: http://www.iana.org/assignments/dns-parameters

;; labels          63 octets or less
;; names           255 octets or less
;; TTL             positive values of a signed 32 bit number.

;; XXX: The fact that TTLs are s32 means that there's a gotcha when
;; encoding large extended rcodes.

;; UDP messages can be at most 512 bytes

;; RFC 5452 DNS Resilience against Forged Answers

(library (weinholt net dns (0 0 20090816))
  (export print-dns-message
          make-normal-query
          put-dns-message
          put-dns-message/delimited
          parse-dns-message
          parse-dns-message/delimited

          make-dns-message dns-message?
          dns-message-id dns-message-opcode dns-message-rcode
          dns-message-flagbits dns-message-question dns-message-authority
          dns-message-additional

          make-question question?
          question-qname question-qtype question-qclass
          question=?

          rrtypes classes opcodes rcodes

          ;; TODO: export all these... or export them in a syntax or
          ;; something else. Lots of exports are probably missing.
          rr-A rr-NS rr-CNAME rr-SOA rr-PTR rr-HINFO
          rr-MINFO rr-MX rr-TXT rr-AAAA rr-SRV rr-DNAME rr-OPT
          rr-DS rr-SSHFP rr-RRSIG rr-NSEC rr-DNSKEY rr-TSIG

          rr-AXFR rr-MAILB rr-MAILA rr-*

          class-IN class-CH class-HS class-*

          flag-response flag-authoritative-answer flag-truncated
          flag-recursion-desired flag-recursion-available
          flag-authentic-data flag-checking-disabled

          edns-flag-DO edns-flag-dnssec-answer-ok

          opcode-QUERY opcode-STATUS

          rcode-NOERROR rcode-FORMERR rcode-SERVFAIL rcode-NXDOMAIN
          rcode-NOTIMP rcode-REFUSED
          )
  (import (rnrs)
          (only (srfi :1 lists) iota append-map filter-map)
          (except (srfi :13 strings) string-copy string->list string-titlecase
                  string-upcase string-downcase string-hash string-for-each)
          (srfi :14 char-sets)
          (srfi :19 time)
          (srfi :27 random-bits)
          (weinholt struct pack)
          (weinholt text base64)
          (only (ikarus) udp-connect
                tcp-connect))

  (define (print . x) (for-each display x) (newline))

  (define rand
    (let ((s (make-random-source)))
      (random-source-randomize! s)
      (random-source-make-integers s)))

  (define ash fxarithmetic-shift-left)

  (define (integer->rrtype x)
    (cond ((assv x rrtypes) => cdr)
          (else (string->symbol (string-append "TYPE"
                                               (number->string x))))))

  (define-syntax define-constants
    (lambda (x)
      (define (symcat prefix name)
        (datum->syntax name (string->symbol (string-append
                                             (symbol->string (syntax->datum prefix))
                                             (symbol->string (syntax->datum name))))))
      (syntax-case x ()
        ((_ listname prefix (name int) ...)
         (with-syntax (((prefixed-names ...)
                        (map (lambda (n) (symcat #'prefix n))
                             #'(name ...))))
           #`(begin
               (define listname '((int . name) ...))
               (define prefixed-names int) ...))))))

  (define-constants
   rrtypes rr-
   (A            1) ;a host address                               [RFC1035]
   (NS           2) ;an authoritative name server                 [RFC1035]
   (MD           3) ;a mail destination (Obsolete - use MX)       [RFC1035]
   (MF           4) ;a mail forwarder (Obsolete - use MX)         [RFC1035]
   (CNAME        5) ;the canonical name for an alias              [RFC1035]
   (SOA          6) ;marks the start of a zone of authority       [RFC1035]
   (MB           7) ;a mailbox domain name (EXPERIMENTAL)         [RFC1035]
   (MG           8) ;a mail group member (EXPERIMENTAL)           [RFC1035]
   (MR           9) ;a mail rename domain name (EXPERIMENTAL)     [RFC1035]
   (NULL         10) ;a null RR (EXPERIMENTAL)                    [RFC1035]
   (WKS          11) ;a well known service description            [RFC1035]
   (PTR          12) ;a domain name pointer                       [RFC1035]
   (HINFO        13) ;host information                            [RFC1035]
   (MINFO        14) ;mailbox or mail list information            [RFC1035]
   (MX           15) ;mail exchange                               [RFC1035]
   (TXT          16) ;text strings                                [RFC1035]
   (RP           17) ;for Responsible Person                      [RFC1183]
   (AFSDB        18) ;for AFS Data Base location                  [RFC1183]
   (X25          19) ;for X.25 PSDN address                       [RFC1183]
   (ISDN         20) ;for ISDN address                            [RFC1183]
   (RT           21) ;for Route Through                           [RFC1183]
   (NSAP         22) ;for NSAP address, NSAP style A record       [RFC1706]
   (NSAP-PTR     23) ;for domain name pointer, NSAP style         [RFC1348]
   (SIG          24) ;for security signature                      [RFC4034][RFC3755][RFC2535]
   (KEY          25) ;for security key                            [RFC4034][RFC3755][RFC2535]
   (PX           26) ;X.400 mail mapping information              [RFC2163]
   (GPOS         27) ;Geographical Position                       [RFC1712]
   (AAAA         28) ;IP6 Address                                 [RFC3596]
   (LOC          29) ;Location Information                        [RFC1876]
   (NXT          30) ;Next Domain - OBSOLETE                      [RFC3755][RFC2535]
   (EID          31) ;Endpoint Identifier                         [Patton]
   (NIMLOC       32) ;Nimrod Locator                              [Patton]
   (SRV          33) ;Server Selection                            [RFC2782]
   (ATMA         34) ;ATM Address                                 [ATMDOC]
   (NAPTR        35) ;Naming Authority Pointer                    [RFC2915][RFC2168]
   (KX           36) ;Key Exchanger                               [RFC2230]
   (CERT         37) ;CERT                                        [RFC4398]
   (A6           38) ;A6 (Experimental)                           [RFC3226][RFC2874]
   (DNAME        39) ;DNAME                                       [RFC2672]
   (SINK         40) ;SINK                                        [Eastlake]
   (OPT          41) ;OPT                                         [RFC2671]
   (APL          42) ;APL                                         [RFC3123]
   (DS           43) ;Delegation Signer                           [RFC4034][RFC3658]
   (SSHFP        44) ;SSH Key Fingerprint                         [RFC4255]
   (IPSECKEY     45) ;IPSECKEY                                    [RFC4025]
   (RRSIG        46) ;RRSIG                                       [RFC4034][RFC3755]
   (NSEC         47) ;NSEC                                        [RFC4034][RFC3755]
   (DNSKEY       48) ;DNSKEY                                      [RFC4034][RFC3755]
   (DHCID        49) ;DHCID                                       [RFC4701]
   (NSEC3        50) ;NSEC3                                       [RFC5155]
   (NSEC3PARAM   51) ;NSEC3PARAM                                  [RFC5155]
   (HIP          55) ;Host Identity Protocol                      [RFC5205]
   (NINFO        56) ;NINFO                                       [Reid]
   (RKEY         57) ;RKEY                                        [Reid]
   (SPF          99) ;                                            [RFC4408]
   (UINFO        100) ;                                           [IANA-Reserved]
   (UID          101) ;                                           [IANA-Reserved]
   (GID          102) ;                                           [IANA-Reserved]
   (UNSPEC       103) ;                                           [IANA-Reserved]
   (TKEY         249) ;Transaction Key                            [RFC2930]
   (TSIG         250) ;Transaction Signature                      [RFC2845]
   (IXFR         251) ;incremental transfer                       [RFC1995]
   (AXFR         252) ;transfer of an entire zone                 [RFC1035]
   (MAILB        253) ;mailbox-related RRs (MB, MG or MR)         [RFC1035]
   (MAILA        254) ;mail agent RRs (Obsolete - see MX)         [RFC1035]
   (*            255) ;A request for all records                  [RFC1035]
   (TA           32768) ;DNSSEC Trust Authorities                 [Weiler]
   (DLV          32769) ;DNSSEC Lookaside Validation              [RFC4431]
   )

  (define (pseudo-rr? r)
    ;; Returns #t if the given RR type should never occur in zone
    ;; data.
    (or (<= 128 r 255)                  ;Q and Meta
        (= r rr-OPT)
        (= r 0)))

  (define (integer->class x)
    (cond ((assv x classes) => cdr)
          (else (string->symbol (string-append "CLASS"
                                               (number->string x))))))

  (define-constants
   classes class-
   (IN 1)                               ;the Internet
   (CH 3)                               ;the CHAOS class
   (HS 4)                               ;Hesiod
   (NONE 254)                           ;[RFC2136]
   (* 255))                             ;any class

  (define flag-QR #b1000000000000000)   ;Query=0/response=1
  (define flag-AA #b0000010000000000)   ;Authoritative answer
  (define flag-TC #b0000001000000000)   ;message was TrunCated
  (define flag-RD #b0000000100000000)   ;Recursion Desired
  (define flag-RA #b0000000010000000)   ;Recursion Available
  (define flag-Z  #b0000000001000000)   ;Reserved, set to zero
  ;; DNS Security Extensions, RFC2535, RFC3655
  (define flag-AD #b0000000000100000)   ;Authentic Data
  (define flag-CD #b0000000000010000)   ;Checking Disabled

  (define flag-mask (fxior flag-QR flag-AA flag-TC flag-RD
                           flag-RA flag-AD flag-CD))

  (define flag-response flag-QR)
  (define flag-authoritative-answer flag-AA)
  (define flag-truncated flag-TC)
  (define flag-recursion-desired flag-RD)
  (define flag-recursion-available flag-RA)
  (define flag-authentic-data flag-AD)
  (define flag-checking-disabled flag-CD)

  (define edns-flag-DO #b1000000000000000) ;DNSSEC answer OK [RFC4035][RFC3225]

  (define edns-flag-dnssec-answer-ok edns-flag-DO)

  (define-constants
   opcodes opcode-
   (QUERY 0)
   (IQUERY 1)                           ;obsoleted by RFC3425
   (STATUS 2))

  ;; Mnemonics from the IANA dns-parameters file
  (define-constants
   rcodes rcode-
   (NOERROR   0) ;No Error                             [RFC1035]
   (FORMERR   1) ;Format Error                         [RFC1035]
   (SERVFAIL  2) ;Server Failure                       [RFC1035]
   (NXDOMAIN  3) ;Non-Existent Domain                  [RFC1035]
   (NOTIMP    4) ;Not Implemented                      [RFC1035]
   (REFUSED   5) ;Query Refused                        [RFC1035]
   (YXDOMAIN  6) ;Name Exists when it should not       [RFC2136]
   (YXRRSET   7) ;RR Set Exists when it should not     [RFC2136]
   (NXRRSET   8) ;RR Set that should exist does not    [RFC2136]
   (NOTAUTH   9) ;Server Not Authoritative for zone    [RFC2136]
   (NOTZONE  10) ;Name not contained in zone           [RFC2136]
   ;; EDNS0:
   (BADVERS  16) ;Bad OPT Version                      [RFC2671]
   (BADSIG   16) ;TSIG Signature Failure               [RFC2845]
   (BADKEY   17) ;Key not recognized                   [RFC2845]
   (BADTIME  18) ;Signature out of time window         [RFC2845]
   (BADMODE  19) ;Bad TKEY Mode                        [RFC2930]
   (BADNAME  20) ;Duplicate key name                   [RFC2930]
   (BADALG   21) ;Algorithm not supported              [RFC2930]
   (BADTRUNC 22) ;Bad Truncation                       [RFC4635]
   )


  (define-record-type dns-message
    (fields id opcode rcode flagbits
            question                    ;list of type question
            ;; lists of type resource
            answer authority additional))

  (define-record-type question
    (fields qname qtype qclass))

  (define (question=? x y)
    (and (= (question-qclass x) (question-qclass y))
         (= (question-qtype x) (question-qtype y))
         (string=? (question-qname x) (question-qname y))))

  (define (question-ci=? x y)
    (and (= (question-qclass x) (question-qclass y))
         (= (question-qtype x) (question-qtype y))
         (string=? (question-qname x) (question-qname y))))

  (define question-ci-hash
    (let ((mix-it-up (rand #x1000000)))
      (lambda (q)
        (+ (abs (string-ci-hash (question-qname q)))
           (question-qtype q)
           (question-qclass q)
           mix-it-up))))

  (define-record-type resource
    ;; The contents of rdata depends on the type and the class. It's a
    ;; list of numbers, strings and bytevectors. It's in the same
    ;; order as the fields in the master zone format. If the record
    ;; type is unknown, rdata is a bytevector and not a list. A and
    ;; AAAA records are lists with a single bytevector.
    (fields name type class ttl rdata))

  (define string-split
    (case-lambda
      ((str c max start end)
       (cond ((zero? max)
              (list (substring str start end)))
             ((string-index str c start end) =>
              (lambda (i)
                (cons (substring str start i)
                      (string-split str c (- max 1) (+ i 1) end))))
             (else
              (list (substring str start end)))))
      ((str c max start)
       (string-split str c max start (string-length str)))
      ((str c max)
       (string-split str c max 0 (string-length str)))
      ((str c)
       (string-split str c -1 0 (string-length str)))))

  (define (name->labels name)
    ;; TODO: punycode. TODO: labels can actually contain dots, escaped
    ;; with \.
    (cond ((string=? name ".")
           '(#vu8()))
          ((or (string-contains name "..")
               (string-prefix? "." name)
               (> (string-length name) 255))
           (error 'name->labels "invalid name" name))
          (else
           (let ((labels (map string->utf8 (string-split name #\.))))
             (unless (for-all (lambda (l) (<= 0 (bytevector-length l) 63))
                              labels)
               (error 'name->labels "overlong label in name" name))
             labels))))

  (define (labels->name labels)
    (if (equal? labels '(#vu8()))
        "."
        (string-join (map utf8->string labels) ".")))

  (define (canonicalize-name name)
    ;; Add the trailing dot if it's missing, decode punycode, etc
    (let ((labels (name->labels name)))
      (if (member #vu8() labels)
          (labels->name labels)
          (labels->name (append labels '(#vu8()))))))

  (define (randomize-case name)
    ;; draft-wijngaards-dnsext-resolver-side-mitigation-01
    (string-map (lambda (c) ((if (zero? (rand 2)) char-upcase char-downcase) c))
                name))

  (define (put-dns-message port msg)
    ;; TODO: resource encoding, compression.
    (define (put-labels x)
      ;; TODO: check that there's only one end label
      (for-each (lambda (label)
                  (assert (<= 0 (bytevector-length label) 63))
                  (put-u8 port (bytevector-length label))
                  (put-bytevector port label))
                x))
    (define (put-question x)
      (put-labels (name->labels (question-qname x)))
      (put-bytevector port (pack "!SS" (question-qtype x) (question-qclass x))))
    (define (put-resource x)
      (put-labels (name->labels (resource-name x)))
      (put-bytevector port (pack "!SSLS" (resource-type x) (resource-class x)
                                 (resource-ttl x) (bytevector-length (resource-rdata x))))
      ;; FIXME: handle the various types...
      (put-bytevector port (resource-rdata x)))
    (let ((etc (fxior (fxand (dns-message-flagbits msg) flag-mask)
                      (ash (fxand (dns-message-opcode msg) #xf) 11)
                      (fxand (dns-message-rcode msg) #xf))))
      (put-bytevector port (pack "!SSSSSS" (dns-message-id msg) etc
                                 (length (dns-message-question msg))
                                 (length (dns-message-answer msg))
                                 (length (dns-message-authority msg))
                                 (length (dns-message-additional msg))))
      ;; TODO: the DNS can handle multiple questions in the same
      ;; query, but this is not done... find out why.
      (for-each put-question (dns-message-question msg))
      (for-each put-resource (dns-message-answer msg))
      (for-each put-resource (dns-message-authority msg))
      (for-each put-resource (dns-message-additional msg))))

;;; DNS message parsing

  (define (bytevector-copy* bv start len)
    (let ((ret (make-bytevector len)))
      (bytevector-copy! bv start ret 0 len)
      ret))


  ;; TODO: handle truncation (see RFC2181)

  (define (parse-labels bv start)
    (let lp ((start start)
             (ret '())
             (acclen 0)
             (used-offsets '())
             (end #f)) ;the end offset of the label (does not follow pointers)
      (when (> start (bytevector-length bv)) (error 'get-message "invalid pointer in a name" start))
      ;; Detect pointer loops. If I was much too clever for anyone's
      ;; good I might have translated these into circular lists
      ;; instead, and even supported them in put-dns-message. Who
      ;; wants an infinite domain name?
      (when (memv start used-offsets) (error 'get-message "looping name"))
      (let* ((len (bytevector-u8-ref bv start))
             (tag (fxbit-field len 6 8)))
        (cond ((zero? len)
               (values (labels->name (reverse (cons #vu8() ret))) (or end (+ start 1))))
              ((zero? tag)              ;normal label
               (when (> (+ acclen len 1) 255) (error 'get-message "overlong name" acclen))
               (lp (+ start 1 len)
                   (cons (bytevector-copy* bv (+ start 1) len)
                         ret)
                   (+ acclen len 1) (cons start used-offsets) end))
              ((= #b11 tag)             ;pointer
               (lp (fxior (ash (fxand len #b111111) 8)
                          (bytevector-u8-ref bv (+ start 1)))
                   ret acclen (cons start used-offsets)
                   (or end (+ start 2))))
              ;; TODO: #b01 EDNS0 rfc2671
              (else (error 'get-message "reserved bits in a length field" len))))))

  (define (parse-type-bitmap bv start count)
    ;; Suppose that one was to encode the type space in a 65536-bit
    ;; number. That would be wasteful of space. But since there are
    ;; big sequences of zero bits, those sequences are removed: Type
    ;; bitmaps are sequences of a block window number, a length and a
    ;; few bytes. The block window number is the upper eight bits of a
    ;; type number, and the bytes represent an integer in little
    ;; endian byte and big endian bit order (hello IBM!). The bits in
    ;; this integer are ones for any types that should be included in
    ;; the bitmap.

    ;; TODO: test this with more than one block window
    (if (< count 3)
        '()
        (let-values (((block len) (unpack "CC" bv start)))
          (unless (and (< len 32) (< len count))
            (error 'parse-type-bitmap "invalid length in type bitmap"))
          (append
           (append-map (lambda (base i)
                         (let ((byte (bytevector-u8-ref bv i)))
                           (filter (lambda (type)
                                     ;; Remove Q, Meta etc
                                     (and type (not (pseudo-rr? type))))
                                   (map (lambda (b)
                                          (and (fxbit-set? byte b)
                                               (fxior (fxarithmetic-shift-left block 8)
                                                      (+ base (- 7 b))))) ;network bit order!
                                        (iota 8 7 -1))))) ;reverse
                       (iota len 0 8)
                       (iota len (+ start 2)))
           (parse-type-bitmap bv (+ start 2 len) (- count 2 len))))))

  (define (parse-character-strings bv start count)
    (if (zero? count)
        '()
        (let ((len (unpack "C" bv start)))
          (cons (bytevector-copy* bv (+ start 1) len)
                (parse-character-strings bv (+ start 1 len) (- count 1 len))))))

  (define (parse-rdata bv type class start count)
    ;; TODO: what about junk appended to the rdata? and what if
    ;; there's less data than expected?
    (cond ((or (= type rr-NS) (= type rr-CNAME) (= type rr-DNAME))
           (let-values (((name _) (parse-labels bv start)))
             (list name)))
          ((= type rr-SOA)
           (let*-values (((mname end-mname) (parse-labels bv start))
                         ((rname end-rname) (parse-labels bv end-mname))
                         ((serial refresh retry expire minimum)
                          (unpack "!uLLLLL" bv end-rname)))
             (list mname rname serial refresh retry expire minimum)))
          ((= type rr-TXT)
           (parse-character-strings bv start count))
          ((= type rr-MX)
           (let-values (((preference) (unpack "!uS" bv start))
                        ((exchange _) (parse-labels bv (+ start 2))))
             (list preference exchange)))
          ((= type rr-DS)
           (let-values (((key-tag algorithm digest-type) (unpack "!uSCC" bv start)))
             (list key-tag algorithm digest-type
                   (bytevector-copy* bv (+ start (format-size "!uSCC"))
                                     (- count (format-size "!uSCC"))))))
          ((= type rr-DNSKEY)
           (let-values (((flags protocol algorithm) (unpack "!uSCC" bv start)))
             (list flags protocol algorithm
                   (bytevector-copy* bv (+ start (format-size "!uSCC"))
                                     (- count (format-size "!uSCC"))))))
          ((= type rr-RRSIG)
           (let-values (((type-covered algorithm labels original-ttl
                                       signature-expiration ;FIXME: check the type
                                       signature-inception
                                       key-tag)
                         (unpack "!uSCClLLS" bv start))
                        ((signers-name end-sn)
                         (parse-labels bv (+ start (format-size "!uSCClLLS")))))
             (list type-covered algorithm labels original-ttl
                   signature-expiration signature-inception
                   key-tag signers-name
                   (bytevector-copy* bv end-sn (- (+ start count) end-sn)))))
          ((= type rr-NSEC)
           (let-values (((next-domain-name end-ndn) (parse-labels bv start)))
             (cons next-domain-name (parse-type-bitmap
                                     bv end-ndn (- ( + start count) end-ndn)))))
          ((= type rr-SRV)
           (let-values (((priority weight port) (unpack "!uSSS" bv start))
                        ((target _) (parse-labels bv (+ start (format-size "!uSSS")))))
             (list priority weight port target)))
          ((or (= type rr-A) (= type rr-AAAA))
           (list (bytevector-copy* bv start count)))
          (else
           (bytevector-copy* bv start count))))

  ;; This procedure a complete DNS message ,without any framing, and
  ;; returns a dns-message record.
  (define (parse-dns-message bv)
    (define (questions start)
      (let*-values (((qname end) (parse-labels bv start))
                    ((qtype qclass) (unpack "!uSS" bv end)))
        (values (make-question qname qtype qclass)
                (+ end (format-size "!uSS")))))
    (define (resources start)
      ;; The RRs NS, SOA, CNAME and PTR can contain compressed labels
      (let*-values (((name end) (parse-labels bv start))
                    ((type class ttl rdlength) (unpack "!uSSlS" bv end)))
        (values (make-resource name type class ttl
                               (parse-rdata bv type class (+ end (format-size "!uSSlS"))
                                            rdlength))
                (+ end (format-size "!uSSlS") rdlength))))
    (define (get f i start)
      (let lp ((i i) (start start) (ret '()))
        (if (zero? i) (values (reverse ret) start)
            (let-values (((entry end) (f start)))
              (lp (- i 1) end (cons entry ret))))))
    (let-values (((id etc qdcount ancount nscount arcount) (unpack "!SSSSSS" bv)))
      (let ((opcode (fxbit-field etc 11 15))
            (rcode (fxbit-field etc 0 4)))
        (let*-values (((qd end-qd) (get questions qdcount (format-size "!SSSSSS")))
                      ((an end-an) (get resources ancount end-qd))
                      ((ns end-ns) (get resources nscount end-an))
                      ((ar end-ar) (get resources arcount end-ns)))
          (make-dns-message id opcode rcode (fxand etc flag-mask)
                            qd an ns ar)))))

  (define (put-dns-message/delimited port msg)
    (let-values (((p extract) (open-bytevector-output-port)))
      (put-dns-message p msg)
      (let ((bv (extract)))
        (put-bytevector port (pack "!S" (bytevector-length bv)))
        (put-bytevector port bv))))

  (define (parse-dns-message/delimited port)
    (parse-dns-message (get-bytevector-n port (get-unpack port "!S"))))

;;; Printing in the master zone format

  (define (bytevector->hex bv)
    (call-with-string-output-port
      (lambda (p)
        (do ((i 0 (+ i 1)))
            ((= i (bytevector-length bv)))
          (let ((v (bytevector-u8-ref bv i)))
            (if (< v #x10) (write-char #\0 p))
            (display (number->string v 16) p))))))

  (define (integer->algorithm x)
    (case x
      ((1) 'RSAMD5)
      ((2) 'DH)
      ((3) 'DSA)
      ((4) 'ECC)
      ((5) 'RSASHA1)
      ((252) 'INDIRECT)
      ((253) 'PRIVATEDNS)
      ((254) 'PRIVATEOID)
      (else x)))

  (define (print-resource r)
    ;; TODO: escape characters in labels...
    (define (printl x)
      (display (car x))
      (for-each (lambda (x) (display #\space) (display x)) (cdr x))
      (newline))
    (let* ((class (integer->class (resource-class r)))
           (type (integer->rrtype (resource-type r)))
           (rdata (resource-rdata r)))
      (for-each display
                (list (resource-name r) "\t" (resource-ttl r) "\t" class "\t" type "\t"))
      (cond ((and (eq? class 'IN) (eq? type 'A)
                  (= 4 (bytevector-length (car rdata))))
             ;; This doesn't actually have to be 4 bytes. But because
             ;; everyone just assumed it did, they had to make a new
             ;; type for IPv6.
             (print (string-join (map number->string (bytevector->u8-list (car rdata))) ".")))
            ((and (eq? class 'IN) (eq? type 'AAAA)
                  (= 16 (bytevector-length (car rdata))))
             (print (string-join (map (lambda (x) (number->string x 16))
                                      (bytevector->uint-list (car rdata) (endianness big) 2))
                                 ":")))
            ((memq type '(SOA NS MX CNAME SRV DNAME))
             (printl rdata))
            ((eq? type 'DS)
             (print (car rdata) " " (integer->algorithm (cadr rdata)) " " (caddr rdata) " "
                    (bytevector->hex (cadddr rdata))))
            ((eq? type 'DNSKEY)
             (print (car rdata) " " (cadr rdata) " " (integer->algorithm (caddr rdata)) " "
                    (base64-encode (cadddr rdata)))
             (when (fxbit-set? (car rdata) (- 16 1 7)) (print "; Zone-signing key"))
             (when (fxbit-set? (car rdata) (- 16 1 15)) (print "; Secure Entry Point")))
            ((eq? type 'RRSIG)
             (display (integer->rrtype (car rdata))) (display #\space)
             (display (integer->algorithm (cadr rdata))) (display #\space)
             (do ((rdata (cddr rdata) (cdr rdata)))
                 ((null? rdata))
               (cond ((null? (cdr rdata))
                      (print (base64-encode (car rdata))))
                     (else
                      (display (car rdata))
                      (display #\space)))))
            ((eq? type 'NSEC)
             (display (car rdata)) (display #\space)
             (printl (map integer->rrtype (cdr rdata))))
            ((eq? type 'TXT)
             (do ((rdata rdata (cdr rdata)))
                 ((null? rdata))
               (display #\")
               (do ((i 0 (+ i 1)))
                   ((= i (bytevector-length (car rdata))))
                 (let ((b (bytevector-u8-ref (car rdata) i)))
                   (cond ((or (= b (char->integer #\\))
                              (= b (char->integer #\")))
                          (display #\\)
                          (display (integer->char b)))
                         ((<= 32 b 127)
                          (display (integer->char b)))
                         (else
                          (display #\\)
                          (if (< b 100) (display #\0))
                          (if (< b 10) (display #\0))
                          (display b)))))
               (display #\")
               (unless (null? (cdr rdata))
                 (display #\space)))
             (newline))
            (else
             ;; RFC3597: Handling of Unknown DNS Resource Record (RR) Types
             (cond ((bytevector? rdata)
                    (display "\\# ")
                    (display (bytevector-length rdata))
                    (display #\space)
                    (display (bytevector->hex rdata))
                    (newline))
                   (else
                    ;; Well... looks like we've parsed some rdata, but
                    ;; haven't made a printer for it yet.
                    (print rdata)
                    (print ";;; WARNING! The above line is likely not in the master zone format!")))))))



  (define (print-dns-message x)
    ;; Print a DNS message in the master zone format
    (define (printq q)
      (print ";" (question-qname q)
             "\t\t" (integer->class (question-qclass q))
             "\t" (integer->rrtype (question-qtype q))))
    (define (printo r)
      (print "; " r))
    (define (rcode->msg rcode)
      (cond ((= rcode rcode-NOERROR) "No error")
            ((= rcode rcode-FORMERR) "Format error (our fault)")
            ((= rcode rcode-SERVFAIL) "Server failure (their fault)")
            ((= rcode rcode-NXDOMAIN) "Name error (no such domain)")
            ((= rcode rcode-NOTIMP) "Not implemented")
            ((= rcode rcode-REFUSED) "Refused by the server")
            (else rcode)))
    (print ";; id: " (dns-message-id x) " opcode: " (dns-message-opcode x) " rcode: "
           (rcode->msg (dns-message-rcode x)))
    (display ";; flags:")
    (for-each (lambda (flag name)
                (when (= flag (fxand flag (dns-message-flagbits x)))
                  (display #\space)
                  (display name)))
              (list flag-QR flag-AA flag-TC flag-RD flag-RA flag-Z flag-AD flag-CD)
              (list "response" "authoritative-answer" "truncated" "recursion-desired"
                    "recursion-available" "reserved-flag" "authentic-data" "checking-disabled"))
    (newline)
    (print ";; Question section")
    (for-each printq (dns-message-question x))
    (print ";; Answer section")
    (for-each print-resource (dns-message-answer x))
    (print ";; Authority section")
    (for-each print-resource (dns-message-authority x))
    (print ";; Additional section")
    (for-each print-resource
              (remp (lambda (r) (= (resource-type r) rr-OPT))
                    (dns-message-additional x)))
    (print ";; EDNS options")
    (for-each printo
              (filter (lambda (r) (= (resource-type r) rr-OPT))
                      (dns-message-additional x))))

;;; Helpers for making messages

  (define (make-edns-resource udp-payload-size extended-rcode version flags options)
    (make-resource "." rr-OPT udp-payload-size
                   (bitwise-ior (bitwise-arithmetic-shift-left extended-rcode 24)
                                (bitwise-arithmetic-shift-left version 16)
                                (fxand #xffff flags))
                   #vu8()))             ;FIXME: options

  (define (make-normal-query qname qtype qclass edns?)
    (make-dns-message (rand #x10000)
                      opcode-QUERY rcode-NOERROR
                      (fxior flag-recursion-desired
                             #;flag-checking-disabled) ;DNSSEC?
                      (list (make-question (randomize-case (canonicalize-name qname)) qtype qclass))
                      '() '()
                      (if edns?
                          (list (make-edns-resource 4096 0 0 edns-flag-dnssec-answer-ok '()))
                          '())))

;;; Caching

  ;; (define-record-type cache-key
  ;;   (fields question))

  ;; (define (cache-key-hash x)
  ;;   (question-ci-hash (cache-key-question x)))

  ;; (define (cache-key-question=? x y)
  ;;   (question-ci=? (cache-key-question x) (cache-key-question y)))

  ;; (define-record-type dns-cache
  ;;   (fields data)
  ;;   (protocol (lambda (n)
  ;;               (lambda ()
  ;;                 (n (make-hashtable cache-key-hash cache-key-question=?))))))

  ;; XXX: should unsigned resources be cached at all? should they be used in the ttl calculation?
  ;; rfc4035 sec 4.5
  ;; (define (dns-cache-set! cache question response)
  ;;   (assert (and (question? question) (dns-message? response)))
  ;;   (hashtable-set! (dns-cache-data cache)
  ;;                   (make-cache-key question)
  ;;                   (cons (+ (time-second (current-time))
  ;;                            (fold-right min (* 3600 24) ;TODO: what minimum ttl?
  ;;                                        (append
  ;;                                         (map resource-ttl (dns-message-answer response))
  ;;                                         (map resource-ttl (dns-message-authority response))
  ;;                                         (map resource-ttl
  ;;                                              (remp (lambda (r)
  ;;                                                      (pseudo-rr? (resource-type r)))
  ;;                                                    (dns-message-additional response))))))
  ;;                         response)))

  ;; (define (dns-cache-ref cache question)
  ;;   (cond ((hashtable-ref (dns-cache-data cache)
  ;;                         (make-cache-key question) #f) =>
  ;;          (lambda (entry)
  ;;            (and (< (time-second (current-time)) (car entry))
  ;;                 (cdr entry))))
  ;;         (else #f)))


  )


