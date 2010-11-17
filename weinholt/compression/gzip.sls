;; -*- mode: scheme; coding: utf-8 -*-
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

;; GZIP file format reader

;; RFC1952: GZIP file format specification version 4.3
;; http://www.gzip.org/format.txt

;; This library ignores FTEXT and OS and always treats data as binary.
;; The "extra" data in the header is also ignored. Only DEFLATEd data
;; is supported.

;; TODO: reduce maximum memory usage (see the note about call/cc)

(library (weinholt compression gzip (1 0 20101117))
  (export make-gzip-input-port open-gzip-file-input-port extract-gzip
          is-gzip-file? get-gzip-header
          gzip-text? gzip-mtime gzip-extra-data gzip-filename gzip-comment
          gzip-method gzip-os)
  (import (rnrs)
          (srfi :19 time)
          (weinholt bytevectors)
          (weinholt crypto crc (1))
          (weinholt compression inflate (1))
          (weinholt struct pack (1 (>= 3))))

  (define-crc crc-32)

  (define-record-type gzip
    (fields text? mtime extra-data filename comment method os))

  (define (flg-ftext? x) (fxbit-set? x 0))
  (define (flg-fhcrc? x) (fxbit-set? x 1))
  (define (flg-fextra? x) (fxbit-set? x 2))
  (define (flg-fname? x) (fxbit-set? x 3))
  (define (flg-fcomment? x) (fxbit-set? x 4))
  (define (flg-reserved? x) (not (fxzero? (fxbit-field x 6 8))))

  (define compression-method-deflate 8)

  (define gzip-magic #vu8(#x1f #x8b))
  
  (define (get-asciiz p)
    (call-with-string-output-port
      (lambda (r)
        (let lp ()
          (let ((b (get-u8 p)))
            (unless (fxzero? b)
              (put-char r (integer->char b))
              (lp)))))))

  (define (is-gzip-file? f)
    (let* ((f (if (input-port? f) f (open-file-input-port f)))
           (pos (port-position f)))
      (set-port-position! f 0)
      (let ((bv (get-bytevector-n f 2)))
        (set-port-position! f pos)
        (equal? bv gzip-magic))))

  (define (get-gzip-header* p who)
    (let*-values (((cm flg mtime xfl os) (get-unpack p "<uCCLCC"))
                  ((extra) (if (flg-fextra? flg)
                               (get-bytevector-n p (get-unpack p "<S"))
                               #vu8()))
                  ((fname) (and (flg-fname? flg) (get-asciiz p)))
                  ((fcomment) (and (flg-fcomment? flg) (get-asciiz p)))
                  ((crc16) (and (flg-fhcrc? flg) (get-unpack p "<S"))))
      (unless (= cm compression-method-deflate)
        (error who "invalid compression method" cm))
      (when (flg-reserved? flg)
        (error who "reserved flags set" flg))
      (make-gzip (flg-ftext? flg)
                 (and (not (zero? mtime))
                      (time-monotonic->date (make-time 'time-monotonic 0 mtime)))
                 extra fname fcomment
                 (if (= xfl 2) 'slowest (if (= xfl 4) 'fastest xfl)) os)))

  (define get-gzip-header
    (case-lambda
      ((p)
       (get-gzip-header p 'get-gzip-header))
      ((p who)
       (unless (eqv? (lookahead-u8 p) #x1f) (error who "not GZIP data" p)) (get-u8 p)
       (unless (eqv? (lookahead-u8 p) #x8b) (error who "not GZIP data" p)) (get-u8 p)
       (get-gzip-header* p who))))

  (define (get-crc in bv*)
    ;; The bv* is taken from the bit-reader state for the inflater.
    (let ((len (- (format-size "<L") (bytevector-length bv*))))
      (unpack "<L" (bytevector-append bv* (get-bytevector-n in len)))))

  (define (make-gzip-input-port in id close-underlying-port?)
    (define who 'make-gzip-input-port)
    (get-gzip-header in who)
    (let ((buffer (make-bytevector 256))
          (offsetr 0)
          (offsetw 0)
          (checksum (crc-32-init))
          (output-len 0)
          (last-member #f))
      (define (sink bv start count)
        ;; Only called when there's no data in the buffer.
        (set! checksum (crc-32-update checksum bv start (+ start count)))
        (set! output-len (bitwise-and #xffffffff (+ output-len count)))
        (let lp ()
          ;; The sender can cause a lot of memory to be allocated
          ;; while sending very little data himself. TODO: do
          ;; call/cc back to read! when this happens.
          (when (> (+ offsetw count) (bytevector-length buffer))
            (let ((new (make-bytevector (* 2 (bytevector-length buffer)))))
              (bytevector-copy! buffer offsetr new 0 (- offsetw offsetr))
              (set! offsetw (- offsetw offsetr))
              (set! offsetr 0)
              (set! buffer new)
              (lp))))
        (bytevector-copy! bv start buffer offsetw count)
        (set! offsetw (+ offsetw count)))
      (define inflater
        (make-inflater in sink 32768 #f))
      (define (read! bytevector start count)
        ;; Read up to `count' bytes from the source, write them to
        ;; `bytevector' at index `start'. Return the number of bytes
        ;; read (zero means end of file).
        (define (return)
          (let* ((valid (- offsetw offsetr))
                 (returned (min count valid)))
            (bytevector-copy! buffer offsetr bytevector start returned)
            (cond ((= returned valid)
                   (set! offsetr 0)
                   (set! offsetw 0))
                  (else
                   (set! offsetr (+ offsetr returned))))
            returned))
        (cond ((zero? offsetw)
               (if (or last-member (port-eof? in))
                   0
                   (let lp ()
                     (case (inflater)
                       ((more)          ;more deflate blocks available
                        (if (zero? offsetw)
                            (lp)        ;encountered a sync block
                            (return)))
                       ((done)          ;end of deflate data
                        (let ((expect (crc-32-finish checksum))
                              (actual (get-crc in (inflater 'get-buffer))))
                          (unless (eqv? expect actual)
                            (error 'gzip-read! "bad GZIP checksum"
                                   expect actual)))
                        (let ((expect (get-unpack in "<L")))
                          (unless (= expect output-len)
                            (error 'gzip-read! "bad GZIP output length"
                                   expect output-len)))
                        ;; Check if there's another GZIP member
                        ;; after this one,
                        (cond ((equal? (get-bytevector-n in 2)
                                       gzip-magic)
                               ;; Discard the next member's header
                               (get-gzip-header* in who)
                               (set! checksum (crc-32-init))
                               (set! output-len 0))
                              (else
                               ;; Some sort of garbage appended to
                               ;; the gzip data, ignore it.
                               (set! last-member #t)))
                        (return))))))
              (else (return))))
      (define (close)
        (set! buffer #f)
        (when close-underlying-port? (close-port in))
        (set! in #f)
        (set! inflater #f))
      (make-custom-binary-input-port id read! #f #f close)))

  (define (open-gzip-file-input-port filename)
    (make-gzip-input-port (open-file-input-port filename)
                          (string-append "gzip " filename)
                          'close))

  (define (extract-gzip in out)
    (define who 'extract-gzip)
    (let lp ((headers (list (get-gzip-header in who))))
      (let-values (((crc size buf)
                    (inflate in out
                             crc-32-init
                             crc-32-update
                             crc-32-finish)))
        (let* ((crc* (get-crc in buf))
               (isize (get-unpack in "<L")))
          (unless (= crc crc*)
            (error who "bad CRC" crc crc*))
          (unless (= isize (bitwise-bit-field size 0 32))
            (error who "bad file size" size isize))
          (if (equal? (get-bytevector-n in 2)
                      gzip-magic)
              (lp (cons (get-gzip-header* in who) headers))
              (reverse headers)))))))
