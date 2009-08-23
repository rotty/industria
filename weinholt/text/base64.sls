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

;; RFC 4648 Base-N Encodings

(library (weinholt text base64 (1 0 20090821))
  (export base64-encode
          base64-decode
          base64-alphabet
          base64url-alphabet
          get-delimited-base64
          put-delimited-base64)
  (import (rnrs)
          (only (srfi :13 strings)
                string-index
                string-prefix? string-suffix?
                string-concatenate string-trim-both))

  (define base64-alphabet
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

  (define base64url-alphabet
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

  (define base64-encode
    (case-lambda
      ;; Simple interface. Returns a string containing the canonical
      ;; base64 representation of the given bytevector.
      ((bv)
       (let-values (((p extract) (open-string-output-port)))
         (base64-encode bv p 0 (bytevector-length bv) #f #f base64-alphabet)
         (extract)))
      ;; Writes the base64 encoding of the bytes [start,end[ in the
      ;; given bytevector to the given port. Lines are limited to
      ;; line-length characters (unless #f), which should be a
      ;; multiple of four. To omit the padding characters (#\=) set
      ;; disable-padding to a true value.
      ((bv p start end line-length disable-padding alphabet)
       (letrec ((put (if line-length
                         (let ((chars 0))
                           (lambda (p c)
                             (when (fx=? chars line-length)
                               (set! chars 0)
                               (put-char p #\linefeed))
                             (set! chars (fx+ chars 1))
                             (put-char p c)))
                         put-char)))
         (let lp ((i start))
           (cond ((= i end))
                 ((<= (+ i 3) end)
                  (let ((x (bytevector-uint-ref bv i (endianness big) 3)))
                    (put p (string-ref alphabet (fxbit-field x 18 24)))
                    (put p (string-ref alphabet (fxbit-field x 12 18)))
                    (put p (string-ref alphabet (fxbit-field x 6 12)))
                    (put p (string-ref alphabet (fxbit-field x 0 6)))
                    (lp (+ i 3))))
                 ((<= (+ i 2) end)
                  (let ((x (fxarithmetic-shift-left (bytevector-u16-ref bv i (endianness big)) 8)))
                    (put p (string-ref alphabet (fxbit-field x 18 24)))
                    (put p (string-ref alphabet (fxbit-field x 12 18)))
                    (put p (string-ref alphabet (fxbit-field x 6 12)))
                    (unless disable-padding
                      (put p #\=))))
                 (else
                  (let ((x (fxarithmetic-shift-left (bytevector-u8-ref bv i) 16)))
                    (put p (string-ref alphabet (fxbit-field x 18 24)))
                    (put p (string-ref alphabet (fxbit-field x 12 18)))
                    (unless disable-padding
                      (put p #\=)
                      (put p #\=))))))))))

  ;; Decodes a base64 string. The string must contain only pure
  ;; unpadded base64 data.
  (define (base64-decode str)
    (unless (zero? (mod (string-length str) 4))
      (error 'base64-decode
             "input string must be a multiple of four characters"))
    (let-values (((p extract) (open-bytevector-output-port)))
      (do ((i 0 (+ i 4)))
          ((= i (string-length str))
           (extract))
        (let ((c1 (string-ref str i))
              (c2 (string-ref str (+ i 1)))
              (c3 (string-ref str (+ i 2)))
              (c4 (string-ref str (+ i 3))))
          (let ((i1 (string-index base64-alphabet c1))
                (i2 (string-index base64-alphabet c2))
                (i3 (string-index base64-alphabet c3))
                (i4 (string-index base64-alphabet c4)))
            (cond ((and i1 i2 i3 i4)
                   (let ((x (fxior (fxarithmetic-shift-left i1 18)
                                   (fxarithmetic-shift-left i2 12)
                                   (fxarithmetic-shift-left i3 6)
                                   i4)))
                     (put-u8 p (fxbit-field x 16 24))
                     (put-u8 p (fxbit-field x 8 16))
                     (put-u8 p (fxbit-field x 0 8))))
                  ((and i1 i2 i3 (char=? c4 #\=)
                        (= i (- (string-length str) 4)))
                   (let ((x (fxior (fxarithmetic-shift-left i1 18)
                                   (fxarithmetic-shift-left i2 12)
                                   (fxarithmetic-shift-left i3 6))))
                     (put-u8 p (fxbit-field x 16 24))
                     (put-u8 p (fxbit-field x 8 16))))
                  ((and i1 i2 (char=? c3 #\=) (char=? c4 #\=)
                        (= i (- (string-length str) 4)))
                   (let ((x (fxior (fxarithmetic-shift-left i1 18)
                                   (fxarithmetic-shift-left i2 12))))
                     (put-u8 p (fxbit-field x 16 24))))
                  (else
                   (error 'base64-decode "invalid input"
                          (list c1 c2 c3 c4)))))))))

  (define (get-line-comp f port)
    (if (eof-object? (lookahead-char port))
        (eof-object)
        (f (get-line port))))
  
  ;; Reads the common -----BEGIN/END type----- delimited format from
  ;; the given port. Returns two values: a string with the type and a
  ;; bytevector containing the base64 decoded data. The second value
  ;; is the eof object if there is an eof before the BEGIN delimiter.
  (define (get-delimited-base64 port)
    (let ((line (get-line-comp string-trim-both port)))
      (cond ((eof-object? line)
             (values "" (eof-object)))
            ((string=? line "")
             (get-delimited-base64 port))
            ((and (string-prefix? "-----BEGIN " line)
                  (string-suffix? "-----" line))
             (let* ((type (substring line 11 (- (string-length line) 5)))
                    (endline (string-append "-----END " type "-----")))
               (let lp ((lines '()))
                 (let ((line (get-line-comp string-trim-both port)))
                   ;; TODO: some basic error checking by keeping track
                   ;; of line lengths.
                   (cond ((eof-object? line)
                          (error 'get-delimited-base64
                                 "unexpected end of file"))
                         ((string-prefix? "-" line)
                          (unless (string=? line endline)
                            (error 'get-delimited-base64
                                   "bad end delimiter" type line))
                          (values type (base64-decode (string-concatenate
                                                       (reverse lines)))))
                         (else
                          (lp (cons line lines))))))))
            (else ;skip garbage (like in openssl x509 -in foo -text output).
             (get-delimited-base64 port)))))

  (define put-delimited-base64
    (case-lambda
      ((port type bv line-length)
       (display (string-append "-----BEGIN " type "-----\n") port)
       (base64-encode bv port 0 (bytevector-length bv)
                      line-length #f base64-alphabet)
       (display (string-append "\n-----END " type "-----\n") port))
      ((port type bv)
       (put-delimited-base64 port type bv 76)))))
