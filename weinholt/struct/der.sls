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

;; Distinguished Encoding Rules (DER)

;; http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf

;; TODO: output

(library (weinholt struct der (1))
  (export decode translate
          data-type
          data-start-index
          data-length
          data-value)
  (import (rnrs)
          (srfi :19 time)
          (srfi :26 cut))

  (define (print . x)
    ;; (for-each display x) (newline)
    (values))

;;; The code that follows reads DER encoded data from bytevectors and
;;; turns it into a parse tree.

  (define (get-type bv start end)
    (let* ((t (bytevector-u8-ref bv start))
           (class (vector-ref '#(universal application context private)
                              (fxbit-field t 6 8)))
           (constructed (fxbit-set? t 5))
           (number (fxbit-field t 0 5)))
      (if (fx=? number #b11111)
          (let lp ((i (+ start 1)) (number 0))
            (unless (< i end)
              (error 'get-type "went over a cliff"))
            (let* ((v (bytevector-u8-ref bv i))
                   (number (bitwise-ior (bitwise-arithmetic-shift-left number 7)
                                        (fxand v #x7f))))
              (if (fxbit-set? v 7)
                  (lp (+ i 1) number)
                  (values constructed class number (+ i 1)))))
          (values constructed class number (+ start 1)))))

  (define (get-length bv start end)
    (let ((b1 (bytevector-u8-ref bv start)))
      (cond ((fx=? b1 #b10000000)       ;indefinite form
             (error 'get-length "indefinite length encountered in DER coding"))
            ((fxbit-set? b1 7)          ;long form
             (let ((extra (fxbit-field b1 0 7)))
               (unless (< (+ start extra 1) end)
                 (error 'get-length "went over a cliff"))
               (let ((len (bytevector-uint-ref bv (+ start 1) (endianness big)
                                               extra)))
                 (when (< len 128)
                   (error 'get-length "unnecessarily long length in DER coding" len))
                 (values len (+ start 1 extra)))))
            (else                       ;short form
             (values b1 (+ start 1))))))

  (define (get-boolean bv start length)
    (unless (= length 1)
      (error 'get-boolean "boolean of illegal length"))
    (let ((v (bytevector-u8-ref bv start)))
      (cond ((= v #xff) #t)
            ((= v #x00) #f)
            (else
             (error 'get-boolean
                    "illegal boolean encoding in DER mode" v)))))

  (define (get-integer bv start length)
    (bytevector-uint-ref bv start (endianness big) length))

  (define (get-T61String bv start length)
    ;; T.61 TeletexString. The world's most complicated character
    ;; encoding ever designed by committee, but according to RFC5280
    ;; everyone treats this as ISO-8859-1. Support is optional...
    (let ((ret (make-bytevector length)))
      (bytevector-copy! bv start ret 0 length)
      (list->string (map integer->char (bytevector->u8-list ret)))))

  (define (get-IA5String bv start length)
    ;; T.50: The International Reference Alphabet No. 5. This used to
    ;; be weird, but they changed it in 1992 so it can be interpreted
    ;; precisely like US-ASCII.
    (let ((ret (make-bytevector length)))
      (bytevector-copy! bv start ret 0 length)
      (let ((bytes (bytevector->u8-list ret)))
        (unless (for-all (cut < <> #x80) bytes)
          (error 'get-IA5String "invalid character"))
        (list->string (map integer->char bytes)))))

  (define (get-PrintableString bv start length)
    (let ((ret (make-bytevector length)))
      (bytevector-copy! bv start ret 0 length)
      (let ((chars (map integer->char (bytevector->u8-list ret))))
        (unless (for-all (lambda (c)
                           (or (char<=? #\0 c #\9)
                               (char<=? #\a c #\z)
                               (char<=? #\A c #\Z)
                               (memq c '(#\space #\' #\( #\) #\+ #\,
                                         #\- #\. #\/ #\: #\= #\?))))
                         chars)
          (error 'get-PrintableString "invalid character"))
        (list->string chars))))

  (define (get-UTF8String bv start length)
    (let ((ret (make-bytevector length)))
      (bytevector-copy! bv start ret 0 length)
      (utf8->string ret)))

  (define (get-UniversalString bv start length)
    (let ((ret (make-bytevector length)))
      (bytevector-copy! bv start ret 0 length)
      (utf16->string ret (endianness big)))) ;FIXME: verify this

  (define (get-octet-string bv start length)
    (let ((ret (make-bytevector length)))
      (bytevector-copy! bv start ret 0 length)
      ret))

  (define (get-bit-string bv start length)
    ;; This is an arbitrary string of bits, which is not exactly the
    ;; same thing as a string of octets. The length doesn't have to
    ;; divide eight. The first byte specifies how many bits at the end
    ;; are unused. Sometimes this value is to be interpreted as an
    ;; integer, other times as a bytevector since they hid a DER
    ;; encoded value in it. It's weird. There can also be trailing
    ;; bits, as many as you like. All this seems to be forbidden in
    ;; DER, luckily. If they aren't forbidden, then there are multiple
    ;; valid encodings, and that's not very Distinguished.
    (unless (zero? (bytevector-u8-ref bv start))
      (error 'get-bit-string "trailing bits in bit-string"))
    (get-octet-string bv (+ start 1) (- length 1)))

  (define (get-UTCTime bv start length)
    ;; YYMMDDHHMMSSZ
    (string->date (string-append (get-IA5String bv start length)
                                 "+0000")
                  "~y~m~d~H~M~SZ~z"))

  (define (get-oid bv start length relative?)
    (define (get i)
      (if (= i (+ start length))
          '()
          (let lp ((i i) (number 0))
            (unless (< i (+ start length))
              (error 'decode "went over a cliff"))
            (let* ((v (bytevector-u8-ref bv i))
                   (number (bitwise-ior (bitwise-arithmetic-shift-left number 7)
                                        (fxand v #x7f))))
              (if (fxbit-set? v 7)
                  (lp (+ i 1) number)
                  (cons number (get (+ i 1))))))))
    (define (solve-oid p)
      ;; Solve for X,Y in p=(X*40)+Y, X=0..2. For X in (0,1): Y=0..39.
      (cond ((< p 40) (values 0 p))
            ((< p 80) (values 1 (- p 40)))
            (else     (values 2 (- p 80)))))
    (let ((subids (get start)))
      (cond ((null? subids)
             (error 'decode "empty OID"))
            (relative?
             subids)
            (else
             (let-values (((x y) (solve-oid (car subids))))
               (unless (= (car subids) (+ (* 40 x) y))
                 (error 'decode "unable to decode first byte in OID"
                        (car subids)))
               (cons x (cons y (cdr subids))))))))

  (define (get-sequence/set bv start length)
    (let ((end (+ start length)))
      (let lp ((start start)
               (ret '()))
        (if (= start end)
            (reverse ret)
            (let-values (((start* value) (get-value bv start end)))
              (lp start* (cons value ret)))))))

  ;; These are the names you need to use in your type definitions.
  (define universal-types
    `#((reserved #f #f)                 ;end of contents marker, not used in DER
       (boolean ,get-boolean #f)
       (integer ,get-integer #f)
       (bit-string ,get-bit-string #f)
       (octet-string ,get-octet-string #f)
       (null ,(lambda (bv start length) #f) #f)
       (object-identifier ,(lambda (bv start length) (get-oid bv start length #f)) #f)
       (object-descriptor #f #f)
       (external #f #f)
       (real #f #f)
       (enumerated #f #f)
       (embedded-pdv #f #f)
       (utf8-string ,get-UTF8String #f)
       (relative-oid ,(lambda (bv start length) (get-oid bv start length #t)) #f)
       (reserved #f #f)
       (reserved #f #f)
       (sequence #f ,get-sequence/set)
       (set #f ,get-sequence/set)
       (numeric-string #f #f)
       (printable-string ,get-PrintableString #f)
       (t61-string ,get-T61String #f)
       (videotex-string #f #f)
       (ia5-string ,get-IA5String #f)
       (utc-time ,get-UTCTime #f)
       (generalized-time #f #f)         ;FIXME: implement this
       (graphic-string #f #f)
       (visible-string #f #f)
       (general-string #f #f)
       (universal-string ,get-UniversalString #f)
       (character-string #f #f)
       (bmp-string ,get-UniversalString #f)
       (reserved #f #f)))                       ;used in get-type

  (define (get-value bv start* end*)
    ;; DER uses a Tag-Length-Value encoding. This procedure
    ;; recursively parses the value at index `start*'.
    (let*-values (((constructed class number startl) (get-type bv start* end*))
                  ((len start) (get-length bv startl end*))
                  ((end) (+ start len)))
      (unless (<= end end*)
        (error 'decode "over the edge now" end end*))
      (if (eq? class 'universal)
          (let* ((decoder (vector-ref universal-types number))
                 (offset (if constructed 2 1))
                 (type-name (car decoder)))
            (print ";" type-name)
            (cond ((list-ref decoder offset) =>
                   (lambda (dec)
                     (values end (list type-name start* (- end start*)
                                       (dec bv start len)))))
                  (else
                   (error 'decode
                          "can't handle this universal value"
                          type-name constructed))))
          ;; Delay parsing implicitly encoded types (their real type
          ;; is in the ASN.1 type, so the translation below must
          ;; handle it). Explicitly tagged values have their tag
          ;; stripped below.
          (values end (list (list (if constructed 'explicit 'implicit) class number)
                            start* (- end start*)
                            (if constructed
                                (car (get-sequence/set bv start len))
                                (get-octet-string bv start len)))))))

  (define decode
    (case-lambda
      ((bv start end)
       (let-values (((len value) (get-value bv start end)))
         value))
      ((bv)
       (let-values (((len value) (get-value bv 0 (bytevector-length bv))))
         value))))

;;; These procedures take a parse tree and an ASN.1 type and mixes the
;;; two together, taking care of naming fields and handling default
;;; values etc.

  (define field-name car)               ;SEQUENCE fields
  (define field-type cadr)
  (define field-opts cddr)

  (define data-type car)
  (define data-start-index cadr)
  (define data-length caddr)
  (define data-value cadddr)

  ;; TODO: rewrite this function. It's a horrible mess of duplicated
  ;; functionality.

  (define (translate-sequence data type format-field)
    (case (car type)
      ((integer)
       ;; An integer with named values
       (unless (eq? (car data) 'integer)
         (error 'translate "expected integer"))
       (let ((names (map (lambda (x) (cons (cdr x) (car x))) (cadr type))))
         (cond ((assv (cadddr data) names) => cdr)
               (else (error 'translate "bad named integer maybe?"
                            (data-value data))))))

      ((choice)
       (let ((choice (find (lambda (choice)
                             ;; FIXME: eq? is not good enough
                             (eq? (cadr choice) (data-type data)))
                           (cdr type))))
         (unless choice
           (error 'translate "no right choice" type data))
         (format-field (car choice)
                       (cadr choice)
                       (translate data (cadr choice)
                                  format-field))))

      ((sequence-of set-of)
       (unless (or (and (eq? (car type) 'sequence-of) (eq? (car data) 'sequence))
                   (and (eq? (car type) 'set-of) (eq? (car data) 'set)))
         (error 'translate "expected set/sequence" (car data)))
       (unless (<= (cadr type) (length data) (caddr type))
         (error 'translate "too little data for set"))
       (map (cut translate <> (cadddr type)) (data-value data)))

      ((sequence set)
       (print ";SEQUENCE/SET")
       (unless (eq? (car type) (car data))
         (error 'translate "expected set/sequence" type (car data)))
       (let lp ((fields (cdr type))
                (data (cadddr data))
                (ret '()))
         (print "---")
         (print "These are the fields: " (length fields) " " fields)
         (print "And this is the data: " data)

         (cond ((null? fields)
                (reverse ret))
               ((and (null? data) (assoc 'default (field-opts (car fields)))) =>
                (lambda (default)
                  ;; There's no more data, but here is a field with a default
                  (print ";using default")
                  (lp (cdr fields)
                      data
                      (cons (format-field (field-name (car fields))
                                          (field-type (car fields))
                                          (cadr default))
                            ret))))
               ((null? data)
                (error 'translate "non-optional data missing" fields))
               (else
                (let ((f (car fields))
                      (d (car data)))
                  (print ";Field:\n  " (field-name f) ", " (field-type f) ", "
                         (field-opts f))
                  (print ";data1:\n  " (data-type d) ", " (data-value d))
                  (cond ((and (list? (field-type f)) (list? (data-type d))
                              (eq? 'explicit (car (field-type f)))
                              (eq? 'explicit (car (data-type d)))
                              (eq? (cadr (field-type f)) (cadr (data-type d)))
                              (eq? (caddr (field-type f)) (caddr (data-type d))))
                         ;; (field-type f): (explicit context number type)
                         ;; (data-type d): (explicit context number)
                         (lp (cdr fields)
                             (cdr data)
                             (cons (format-field (field-name f)
                                                 (cadddr (field-type f))
                                                 (translate (data-value d)
                                                            (cadddr (field-type f))
                                                            format-field))
                                   ret)))

                        ;; CHOICE
                        ((and (list? (field-type f))
                              (eq? (car (field-type f)) 'choice)
                              (find (lambda (choice)
                                      ;; FIXME: eq? is not good enough
                                      (eq? (cadr choice) (data-type d)))
                                    (cdr (field-type f))))
                         =>
                         (lambda (choice)
                           (lp (cdr fields)
                               (cdr data)
                               (cons (format-field (car choice)
                                                   (cadr choice)
                                                   (translate (car data) (cadr choice)
                                                              format-field))
                                     ret))))

                        ;; FIXME: implicit
                        ((and (list? (field-type f)) (list? (data-type d))
                              (eq? 'implicit (car (field-type f)))
                              (eq? 'implicit (car (data-type d)))
                              (eq? (cadr (field-type f)) (cadr (data-type d)))
                              (eq? (caddr (field-type f)) (caddr (data-type d))))
                         ;; (field-type f): (implicit context number type)
                         ;; (data-type d): (implicit context number)
                         (error 'translate "implicit data handling not implemented"
                                f d))

                        ((or (and (list? (field-type f))
                                  (not (memq (car (field-type f))
                                             '(implicit explicit choice))))
                             (eq? (data-type d) (field-type f))
                             (eq? (field-type f) 'ANY))
                         ;; The field type matches the data type
                         (lp (cdr fields)
                             (cdr data)
                             (cons (format-field (field-name f)
                                                 (field-type f)
                                                 (translate (car data) (field-type f)
                                                            format-field))
                                   ret)))

                        ((assoc 'default (field-opts f)) =>
                         (lambda (default)
                           (print ";using default")
                           (lp (cdr fields)
                               data
                               (cons (format-field (field-name f)
                                                   (field-type f)
                                                   (cadr default))
                                     ret))))
                        (else
                         (error 'translate
                                "unexpected data" (caar data) (field-type f)))))))))
      (else

       (error 'translate "error in type" type))))

  (define translate
    (case-lambda
      ((data type)
       (translate data type (lambda (name type value) value)))
      ((data type format-field)
       (cond ((list? type)
              (translate-sequence data type format-field))
             ((eq? 'ANY type)
              ;; Delay interpretation. Usually the ANY type is
              ;; combined with an OID which decides the type.
              data)
             ((eq? type (data-type data))
              (data-value data))
             (else
              (error 'translate "unexpected type" type (car data))))))))
