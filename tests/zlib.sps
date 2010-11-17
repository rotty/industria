#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*- !#
;; Copyright © 2010 Göran Weinholt <goran@weinholt.se>
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

;; Tests zlib decompression.

(import (rnrs)
        (srfi :78 lightweight-testing)
        (weinholt compression adler-32)
        (weinholt compression zlib (0)))

(define dicts
  (let ((d (string->utf8 "(library ))((import (rnrs (export (define (lambda ")))
    (list (cons (adler-32 d) d))))

(define expected
  "(library (x) (export) (import (rnrs)) ((lambda (x) (x x)) (lambda (x) (x x))))")

(define (extract-bv bv chunksize)
  (call-with-port
      (make-zlib-input-port (open-bytevector-input-port bv)
                            "zlibtest" chunksize 'close-it dicts)
    (lambda (zp) (get-bytevector-all zp))))

;; Compressed data was flushed with "full" flush and chunksize 32
(define chunked
  #vu8(120 187 173 237 16 238 210 128 233 208 168 208 132 41 2
           50 224 122 1 0 0 0 255 255 202 43 42 214 212 84 208 208
           200 73 204 77 74 73 84 208 168 0 114 42 20 42 64 98 96
           33 0 0 0 0 255 255 2 0 0 0 255 255 75 84 208 168 208 4
           98 133 10 77 32 0 0 211 248 23 78))
(check (utf8->string (extract-bv chunked 32))
       => expected)

;; Larger chunk size, so no flushes in the middle
(check (utf8->string
        (extract-bv #vu8(120 187 173 237 16 238 211 128 233 208 168 208 132 41 2
                             50 144 245 106 2 249 112 229 32 85 21 10 21 32 49 12 33
                             77 77 0 211 248 23 78)
                    32768))
       => expected)

;; Did not use a dictionary
(check (utf8->string
        (extract-bv #vu8(120 156 211 200 201 76 42 74 44 170 84 208 168 208 84
                             208 72 173 40 200 47 42 1 50 50 115 65 12 5 141 162 188
                             162 98 77 32 95 35 39 49 55 41 37 17 162 170 66 161 2
                             36 134 33 164 169 9 0 211 248 23 78)
                    32768))
       => expected)

;; No data
(check (extract-bv #vu8(120 156 3 0 0 0 0 1) #f)
       => (eof-object))

;; Bad checksum
(check (guard (cnd
               ((and (message-condition? cnd)
                     (string=? (condition-message cnd) "bad ZLIB checksum"))
                'bad-checksum))
         (extract-bv #vu8(120 156 3 0 0 0 0 2) #f))
       => 'bad-checksum)

(call-with-port
    (open-bytevector-input-port chunked)
  (lambda (p)
    (call-with-port (make-zlib-input-port p "zlibtest" 32 #f dicts)
      (lambda (zp)
        (check (get-u8 zp) => (char->integer #\())
        ;; Check that all it didn't consume all the deflate blocks
        (check (port-position p) (=> <) (- (bytevector-length chunked) 4))))))

(check-report)
