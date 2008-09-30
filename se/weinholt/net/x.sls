;; -*- mode: scheme; coding: utf-8 -*-
;; The Industria Libraries
;; Copyright © 2008 Göran Weinholt <goran@weinholt.se>
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

;; X11 library

;; This library is not ready for any sort of use!

(library (se weinholt net x)
    (export (x-open-display))
    (import (rnrs))
  ...)

;;; Utilities

;; temporary bug fixes for ikarus
(define (bytevector-u16-native-ref b i) (bytevector-u16-ref b i 'little))
(define (bytevector-u32-native-ref b i) (bytevector-u32-ref b i 'little))

(define (print . x) (for-each display x) (newline))

(define (seq from to)
  (if (= from to)
      '()
      (cons from (seq (+ from 1) to))))

(define (round4 x)
  ;; Round to next multiple of four
  (+ x (bitwise-and (- 4 (bitwise-and x #b11)) #b11)))

;;; Delicious syntax to sweeten the protocol

(define-syntax define-x-struct
  (lambda (x)
    (syntax-case x ()
      ((_ struct-name fields ...)
       (with-syntax (((t) (generate-temporaries #'(struct-name))))
         (letrec ((make-accessor-name
                   (lambda (field-name)
                     (datum->syntax #'struct-name
                                    (string->symbol
                                     (string-append
                                      (symbol->string
                                       (syntax->datum #'struct-name))
                                      "-"
                                      (symbol->string
                                       (syntax->datum field-name)))))))
                  (ref
                   (lambda (type offset)
                     (syntax-case type (u8 u16 u32 string8)
                       (u8 #`(read-u8 t #,offset))
                       (u16 #`(read-u16 t #,offset))
                       (u32 #`(read-u32 t #,offset))
                       ((string8 length)
                        #`(read-string8 t #,offset
                                        (#,(make-accessor-name #'length) t))))))
                  (get-size
                   (lambda (type)
                     (syntax-case type (u8 u16 u32 string8)
                       (u8 1)
                       (u16 2)
                       (u32 4)
                       ((string8 length)
                        #`(round4 (#,(make-accessor-name #'length) t)))))))

           #`(begin
               #,@(let lp ((fields* #'(fields ...))
                           (offset '()))
                    (syntax-case fields* ()
                      (((type name) fields* ...)
                       #`((define #,(make-accessor-name #'name)
                            (case-lambda
                              ((t)
                               #,(ref #'type
                                      (cons #'+ offset)))
                              ((t offset*)
                               #,(ref #'type
                                      (cons #'+ (cons #'offset* offset))))))
                          #,@(lp #'(fields* ...)
                                 (cons (get-size #'type) offset))))
                      (((type) fields* ...)
                       (lp #'(fields* ...)
                           (cons (get-size #'type) offset)))
                      (() #`((define #,(make-accessor-name #'sizeof*)
                               (lambda (t)
                                 #,(cons #'+ offset))))))))))))))

;;; Data structures

(define-x-struct init-reply
  (u8 status)
  (u8 reason-length)
  (u16 protocol-major-version)
  (u16 protocol-minor-version)
  (u16 additional-data)
  ((string8 reason-length) reason)
  (u32 release-number)
  (u32 resource-id-base)
  (u32 resource-id-mask)
  (u32 motion-buffer-size)
  (u16 vendor-length)
  (u16 maximum-request-length)
  (u8 number-of-screens)
  (u8 number-of-formats)
  (u8 image-byte-order)
  (u8 bitmap-format-bit-order)
  (u8 bitmap-format-scanline-unit)
  (u8 bitmap-format-scanline-pad)
  (u8 min-keycode)
  (u8 max-keycode)
  (u32)
  ((string8 vendor-length) vendor))
;; followed by a list of FORMAT and a list of SCREEN

(define (init-reply-image-byte-order->symbol n)
  (define x '#(LSBFirst MSBFirst))
  (if (< n (vector-length x))
      (vector-ref x n)
      n))

(define (init-reply-bitmap-format-bit-order->symbol n)
  (define x '#(LeastSignificant MostSignificant))
  (if (< n (vector-length x))
      (vector-ref x n)
      n))

(define-record-type x-display
  (fields inport output protocol-major-version protocol-minor-version
          release-number resource-id-base resource-id-mask motion-buffer-size
          maximum-request-length image-byte-order bitmap-format-bit-order
          bitmap-format-scanline-unit bitmap-format-scanline-pad min-keycode
          max-keycode vendor pixmap-formats roots))

(define-x-struct format
  (u8 depth)
  (u8 bits-per-pixel)
  (u8 scanline-pad)
  (u8)
  (u32))

(define-record-type x-format
  (fields depth bits-per-pixel scanline-pad))

(define-x-struct screen
  (u32 root)
  (u32 default-colormap)
  (u32 white-pixel)
  (u32 black-pixel)
  (u32 current-input-masks)
  (u16 width-in-pixels)
  (u16 height-in-pixels)
  (u16 width-in-millimeters)
  (u16 height-in-millimeters)
  (u16 min-installed-maps)
  (u16 max-installed-maps)
  (u32 root-visual)
  (u8 backing-stores)
  (u8 save-unders)
  (u8 root-depth)
  (u8 number-of-depths))
;; followed by a list of DEPTHs

(define (screen-backing-stores->symbol bs)
  (define x '#(Never WhenMapped Always))
  (if (< bs (vector-length x))
      (vector-ref x bs)
      bs))

(define-record-type x-screen
  (fields root default-colormap white-pixel black-pixel
          current-input-masks width-in-pixels height-in-pixels
          width-in-millimeters height-in-millimeters min-installed-maps
          max-installed-maps root-visual backing-stores save-unders root-depth
          allowed-depths))

(define-x-struct depth
  (u8 depth)
  (u8)
  (u16 number-of-visualtypes)
  (u32))
;; followed by a list of VISUALTYPEs

(define-record-type x-depth
  (fields depth visualtypes))

(define-x-struct visualtype
  (u32 visual-id)
  (u8 class)
  (u8 bits-per-rgb-value)
  (u16 colormap-entries)
  (u32 red-mask)
  (u32 green-mask)
  (u32 blue-mask)
  (u32))

(define (visualtype-class->symbol class)
  (define x '#(StaticGray GrayScale StaticColor PseudoColor TrueColor DirectColor))
  (if (< class (vector-length x))
      (vector-ref x class)
      class))


(define-record-type x-visualtype
  (fields visual-id class bits-per-rgb-value colormap-entries
          red-mask green-mask blue-mask))

(define (family->symbol f)
  (case f
    ((0) 'Internet)
    ((1) 'DECnet)
    ((2) 'Chaos)
    ((5) 'ServerInterpreted)
    ((6) 'Internet6)
    ((252) 'LocalHost)
    ((253) 'Krb5Principal)
    ((254) 'Netname)
    ((256) 'Local)                      ;UNIX domain socket
    ((65535) 'Wild)
    (else f)))

;;; Input buffering

(define-record-type buffer
  (fields (immutable port)
          (mutable data)
          (mutable bottom))
  (protocol (lambda (p)
              (lambda (port)
                (p port (make-bytevector 8192) 0)))))

(define (buffer-read! buf n)
  (cond ((> (+ (buffer-bottom buf) n)
            (bytevector-length (buffer-data buf)))
         ;; Extend the buffer size
         (let* ((old (buffer-data buf))
                (new (make-bytevector (* (bytevector-length old) 2))))
           (buffer-data-set! buf new)
           (bytevector-copy! old 0
                             new 0 (buffer-bottom buf))
           (buffer-read! buf n)))
        (else
         (let ((bytes-read (get-bytevector-n! (buffer-port buf)
                                              (buffer-data buf)
                                              (buffer-bottom buf) n)))
           (cond ((eof-object? bytes-read)
                  (error 'buffer-read! "port closed, whyyyy!?"))
                 ((< bytes-read n)
                  (error 'buffer-read! "premature end of data!! yikes!"))
                 (else
                  (buffer-bottom-set! buf (+ (buffer-bottom buf) n))))))))

(define (buffer-reset! buf)
  (buffer-bottom-set! buf 0))

(define (read-generic buf ref size index)
  (when (> (+ index size) (buffer-bottom buf))
    (error 'read-generic "attempt to read past bottom of buffer" ref))
  (ref (buffer-data buf) index))

(define (read-u8 buf i) (read-generic buf bytevector-u8-ref 1 i))
(define (read-u16 buf i) (read-generic buf bytevector-u16-native-ref 2 i))
(define (read-u32 buf i) (read-generic buf bytevector-u32-native-ref 4 i))

(define (read-string8 buf start size)
  (when (> (+ start size) (buffer-bottom buf))
    (print buf)
    (error 'read-string8 "attempt to read past bottom of buffer" start size))
  (do ((i start (+ i 1))
       (j 0 (+ j 1))
       (s (make-string size)))
      ((= j size)
       s)
    (string-set! s j
                 (integer->char
                  (bytevector-u8-ref (buffer-data buf) i)))))

;;; Output

(define (put-u16 p i)
  (let ((x (make-bytevector 2)))
    (bytevector-u16-set! x 0 i (native-endianness))
    (put-bytevector p x)))


(define (put-string8 port s)
  (if (string? s)
      (let ((padding (- (round4 (string-length s))
                        (string-length s))))
        (put-bytevector port (string->utf8 s))
        (put-bytevector port (make-bytevector padding 0)))
      (let ((padding (- (round4 (bytevector-length s))
                        (bytevector-length s))))
        (put-bytevector port s)
        (put-bytevector port (make-bytevector padding 0)))))

;;; X authority

(define-record-type x-authority
  (fields family address number name data))

(define (get-xauthority file)
  ;; The .Xauthority file is in big endian format.
  (define (really-get-bytevector-n port n)
    (let ((bv (get-bytevector-n port n)))
      (when (or (eof-object? bv) (< (bytevector-length bv) n))
        (error 'get-xauthority "Premature end of file" port))
      bv))
  (define (get-u16 port)
    (bytevector-u16-ref (really-get-bytevector-n port 2)
                        0 (endianness big)))
  (define (read-bv p)
    (really-get-bytevector-n p (get-u16 p)))
  (let ((p (open-file-input-port file)))
    (let lp ((entries '()))
      (cond ((eof-object? (lookahead-u8 p))
             (reverse entries))
            (else
             (let* ((family (get-u16 p))
                    (address (read-bv p))
                    (number (read-bv p))
                    (name (read-bv p))
                    (data (read-bv p)))
               (lp (cons (make-x-authority (family->symbol family)
                                           address
                                           (utf8->string number)
                                           (utf8->string name)
                                           data)
                         entries))))))))

;;;


(define (x-open-display host port)
  (call-with-values (lambda () (tcp-connect host port))
    (lambda (o i)
      (let ((b (make-buffer i)))
        (let ((auth (car (get-xauthority "/home/weinholt/.Xauthority"))))
          (put-u8 o (case (native-endianness)
                      ((little) #x6C)
                      ((big) #x42)
                      (else (error 'x-connect "Unsupported native endianness"))))
          (put-u8 o #x00)               ;unused
          (put-u16 o 11)                ;major version
          (put-u16 o 0)                 ;minor version
          (put-u16 o (string-length (x-authority-name auth)))
          (put-u16 o (bytevector-length (x-authority-data auth)))
          (put-u16 o 0)                 ;unused
          (put-string8 o (x-authority-name auth))
          (put-string8 o (x-authority-data auth))
          
          (flush-output-port o))

        (buffer-read! b 8)
        (buffer-read! b (* 4 (init-reply-additional-data b)))

        (case (init-reply-status b)
          ((0)
           (error 'x-open-display "Connection to X server denied"
                  (init-reply-reason b)))

          ((2)
           (error 'x-open-display "The X server demands further authorization"))

          ((1)
           (letrec ((get-screens (lambda (num offset acc)
                                   (if (zero? num)
                                       (list->vector (reverse acc))
                                       (call-with-values
                                           (lambda ()
                                             (get-depths (screen-number-of-depths b offset)
                                                         (+ offset (screen-sizeof* b))
                                                         '()))
                                         (lambda (offset* depths)
                                           (get-screens (- num 1)
                                                        offset*
                                                        (cons (make-x-screen
                                                               (screen-root b offset)
                                                               (screen-default-colormap b offset)
                                                               (screen-white-pixel b offset)
                                                               (screen-black-pixel b offset)
                                                               (screen-current-input-masks b offset)
                                                               (screen-width-in-pixels b offset)
                                                               (screen-height-in-pixels b offset)
                                                               (screen-width-in-millimeters b offset)
                                                               (screen-height-in-millimeters b offset)
                                                               (screen-min-installed-maps b offset)
                                                               (screen-max-installed-maps b offset)
                                                               (screen-root-visual b offset)
                                                               (screen-backing-stores->symbol
                                                                (screen-backing-stores b offset))
                                                               (screen-save-unders b offset)
                                                               (screen-root-depth b offset)
                                                               depths)
                                                              acc)))))))
                    (get-depths (lambda (num offset acc)
                                  (if (zero? num)
                                      (values offset (reverse acc))
                                      (call-with-values
                                          (lambda ()
                                            (get-visualtypes (depth-number-of-visualtypes b offset)
                                                             (+ offset (depth-sizeof* b))
                                                             '()))
                                        (lambda (offset* visualtypes)
                                          (get-depths (- num 1)
                                                      offset*
                                                      (cons (make-x-depth (depth-depth b offset)
                                                                          visualtypes)
                                                            acc)))))))
                    (get-visualtypes (lambda (num offset acc)
                                       (if (zero? num)
                                           (values offset (reverse acc))
                                           (get-visualtypes
                                            (- num 1)
                                            (+ offset (visualtype-sizeof* b))
                                            (cons (make-x-visualtype
                                                   (visualtype-visual-id b offset)
                                                   (visualtype-class->symbol
                                                    (visualtype-class b offset))
                                                   (visualtype-bits-per-rgb-value b offset)
                                                   (visualtype-colormap-entries b offset)
                                                   (visualtype-red-mask b offset)
                                                   (visualtype-green-mask b offset)
                                                   (visualtype-blue-mask b offset))
                                                  acc))))))

             (make-x-display
              i o
              (init-reply-protocol-major-version b)
              (init-reply-protocol-minor-version b)
              (init-reply-release-number b)
              (init-reply-resource-id-base b)
              (init-reply-resource-id-mask b)
              (init-reply-motion-buffer-size b)
              (init-reply-maximum-request-length b)
              (init-reply-image-byte-order->symbol 
               (init-reply-image-byte-order b))
              (init-reply-bitmap-format-bit-order->symbol
               (init-reply-bitmap-format-bit-order b))
              (init-reply-bitmap-format-scanline-unit b)
              (init-reply-bitmap-format-scanline-pad b)
              (init-reply-min-keycode b)
              (init-reply-max-keycode b)
              (init-reply-vendor b)
              (map (lambda (x)
                     (make-x-format (format-depth b x)
                                    (format-bits-per-pixel b x)
                                    (format-scanline-pad b x)))
                   (map (lambda (o)
                          (+ (init-reply-sizeof* b) (* (format-sizeof* b) o)))
                        (seq 0 (init-reply-number-of-formats b))))
              (get-screens (init-reply-number-of-screens b)
                           (+ (init-reply-sizeof* b)
                              (* (format-sizeof* b)
                                 (init-reply-number-of-formats b)))
                           '())))))))))

(define dpy (x-open-display "localhost" "x11-1"))
(define screen (vector-ref (x-display-roots dpy) 0))


