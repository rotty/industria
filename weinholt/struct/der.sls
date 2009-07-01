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

;; This is just a quick hack for (weinholt crypto x509) and (... rsa).

;; The proper way to do this is to have the ASN.1 type (preferably
;; parsed from the ASN.1 data) and use that in the parser to guide the
;; selection of types.

(library (weinholt struct der (0))
  (export der-decode
          construct-ref
          bit-string-bit-length
          bit-string-value
          bit-string-bytes
          oid-value)
  (import (rnrs))

  (define (print . x)
    ;; (for-each display x) (newline)
    (values))

  (define-record-type oid
    (fields value))

  (define-record-type bit-string
    (fields bit-length value bytes))    ;FIXME: don't keep the value here, -ref it

  (define-record-type construct
    (fields class type values))

  (define (construct-ref x index class type)
    (unless (and (eq? (construct-class x) class)
                 (eq? (construct-type x) type))
      (error 'construct-ref "wrong type in DER value"))
    (list-ref (construct-values x) index))

  (define (get-type bv start end)
    (let* ((t (bytevector-u8-ref bv start))
           (class (cdr (assq (fxbit-field t 6 8)
                             '((0 . universal) (1 . application)
                               (2 . context) (3 . private)))))
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
             (error 'get-boolean "illegal boolean encoding in DER mode" v)))))

  (define (get-integer bv start length)
    (bytevector-uint-ref bv start (endianness big) length))

  (define (get-IA5String bv start length)
    ;; TODO: check for high bits?
    (let ((ret (make-bytevector length)))
      (bytevector-copy! bv start
                        ret 0
                        length)
      (utf8->string ret)))

  (define (get-octet-string bv start length)
    (let ((ret (make-bytevector length)))
      (bytevector-copy! bv start
                        ret 0
                        length)
      ret))

  (define (get-bit-string bv start length)
    (make-bit-string (- (* (- length 1) 8)
                        (bytevector-u8-ref bv start))
                     (bitwise-arithmetic-shift-right
                      (bytevector-uint-ref bv (+ start 1) (endianness big) (- length 1))
                      (bytevector-u8-ref bv start))
                     (get-octet-string bv (+ start 1) (- length 1))))

  (define (get-oid bv start length relative?)
    (define (get i)
      (if (= i (+ start length))
          '()
          (let lp ((i i) (number 0))
            (unless (< i (+ start length))
              (error 'get-type "went over a cliff"))
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
      (if (null? subids)
          (error 'get-oid "empty OID")
          (make-oid
           (if relative?
               subids
               (let-values (((x y) (solve-oid (car subids))))
                 (unless (= (car subids) (+ (* 40 x) y))
                   (error 'get-oid "unable to decode first byte in OID"
                          (car subids)))
                 (cons x (cons y (cdr subids)))))))))

  (define (get-constructed-value bv start length)
    (let ((end (+ start length)))
      (let lp ((start start)
               (ret '()))
        (if (= start end)
            (reverse ret)
            (let-values (((start* value) (get-value bv start end)))
              (lp start* (cons value ret)))))))

  (define (get-value bv start* end*)
    (let*-values (((constructed class number startl) (get-type bv start* end*))
                  ((length start) (get-length bv startl end*))
                  ((end) (+ start length))
                  ((t) (bytevector-u8-ref bv start*)))
      (print ";TAG " start* "-" startl " class: " class " number: " number)
      (print ";LENGTH " startl "-" start " = " length)
      (unless (<= end end*)
        (error 'get-value "over the edge now" end end*))
      (values
        end
        (cond (constructed
               (print ";SEQUENCE/SET " start "-" end " [.." end "]")
               (cond ((eq? class 'universal)
                      (case number
                        ((#x10)         ;sequence
                         (get-constructed-value bv start length))
                        ((#x11)         ;set
                         (get-constructed-value bv start length))
                        (else
                         (error 'get-value
                                "invalid universal constructed value in DER coding"
                                number))))
                     (else
                      (make-construct class number
                                      (get-constructed-value bv start length)))))
              ((eq? class 'universal)
               (case number
                 ((#x01)
                  (print ";BOOLEAN at " start "-" end)
                  (get-boolean bv start length))
                 ((#x02)
                  (print ";INTEGER at " start "-" end)
                  (get-integer bv start length))
                 ((#x03)
                  (print ";BIT STRING " start "-" end)
                  (print ";Unused bits at the end: " (bytevector-u8-ref bv start))
                  (get-bit-string bv start length))
                 ((#x04)
                  (print ";OCTET STRING " start "-" end)
                  (get-octet-string bv start length))
                 ((#x05)
                  (print ";NULL " start "-" end)
                  '())
                 ((#x06 #x0D)
                  (print ";OID " start "-" end)
                  (get-oid bv start length (= number #x0D)))
                 ((#x13 #x14 #x16 #x17)
                  (print ";IA5String " start "-" end)
                  (get-IA5String bv start length))
                 ((#x10 #x11)
                  (error 'get-value "non-constructed sequence or set"))
                 ;; ... #x1f
                 (else
                  (list 'primitive class number
                        (get-octet-string bv start length))
                  ;; (error 'get-value "unknown universal..." number)
                  )))
              (else
               ;; TODO: what to do here?               
               (print ";PRIMITIVE " start "-" end)
               (list 'primitive class number
                     (get-octet-string bv start length))
               )))))

  (define der-decode
    (case-lambda
      ((bv start end)
       (let-values (((len value) (get-value bv start end)))
         value))
      ((bv)
       (let-values (((len value) (get-value bv 0 (bytevector-length bv))))
         value)))))
