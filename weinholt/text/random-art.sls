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

;; Random art for cryptographic key hashes, compatible with OpenSSH

(library (weinholt text random-art (1 0 20100829))
  (export random-art random-art-box-style
          random-art-style-ascii random-art-style-ascii-2
          random-art-style-unicode)
  (import (rnrs)
          (only (srfi :13 strings) string-pad string-pad-right)
          (srfi :25 multi-dimensional-arrays)
          (srfi :39 parameters)
          (weinholt crypto dsa)
          (weinholt crypto rsa))

  ;; The algorithm is the same as in OpenSSH's random art generator.
  ;; It creates a 2D array, puts a marker in the middle and then
  ;; iterates over the bits in the key, moving the marker in different
  ;; directions based on the bits of the digest.

  ;; OpenSSH's random art uses MD5 digests, and MD5's shorter digest
  ;; length also makes the art less dense, which seems to give nicer
  ;; art.

  (define ylen 9)
  (define xlen 17)
  (define chars " .o+=*BOX@%&#/^SE")

  (define random-art-style-ascii
    (vector #\+ #\- "[" "]" "+\n"
            #\|             "|\n"
            #\+ #\-         "+\n"))

  (define random-art-style-ascii-2
    (vector #\, #\- "[" "]" ".\n"
            #\|             "|\n"
            #\` #\-         "'\n"))

  (define random-art-style-unicode
    (vector #\╭ #\─ "┤" "├" "╮\n"
            #\│             "│\n"
            #\╰ #\─         "╯\n"))

  (define random-art-box-style (make-parameter random-art-style-ascii))

  (define random-art
    (case-lambda
      ((digest header)
       (random-art digest header xlen ylen chars))
      ((digest header xlen ylen chars)
       (define (perambulate! field x y b)
         (let ((x (min (- xlen 1) (max 0 (+ x (if (fxbit-set? b 0) 1 -1)))))
               (y (min (- ylen 1) (max 0 (+ y (if (fxbit-set? b 1) 1 -1))))))
           (array-set! field x y (+ (array-ref field x y) 1))
           (values x y (fxarithmetic-shift-right b 2))))
       (let ((field (make-array (shape 0 xlen 0 ylen) 0)))
         ;; Fill in the field
         (let lp ((i 0)
                  (x0 (div xlen 2))
                  (y0 (div ylen 2)))
           (cond ((= i (bytevector-length digest))
                  (array-set! field (div xlen 2) (div ylen 2)
                              (- (string-length chars) 2))
                  (array-set! field x0 y0 (- (string-length chars) 1)))
                 (else
                  (let ((b0 (bytevector-u8-ref digest i)))
                    (let*-values (((x1 y1 b1) (perambulate! field x0 y0 b0))
                                  ((x2 y2 b2) (perambulate! field x1 y1 b1))
                                  ((x3 y3 b3) (perambulate! field x2 y2 b2))
                                  ((x4 y4 b4) (perambulate! field x3 y3 b3)))
                      (lp (+ i 1) x4 y4))))))
         ;; Draw the field
         (call-with-string-output-port
           (lambda (p)
             (let ((box (random-art-box-style)))
               (display (vector-ref box 0) p)
               (display
                (let* ((header (string-append (vector-ref box 2)
                                              header
                                              (vector-ref box 3)))
                       (line (make-string (div (- xlen (string-length header)) 2)
                                          (vector-ref box 1))))
                  (string-pad-right (string-append line header line)
                                    xlen (vector-ref box 1)))
                p)
               (display (vector-ref box 4) p)
               (do ((y 0 (+ y 1)))
                   ((= y ylen))
                 (display (vector-ref box 5) p)
                 (do ((x 0 (+ x 1)))
                     ((= x xlen))
                   (display (string-ref chars (min (array-ref field x y)
                                                   (- (string-length chars) 1)))
                            p))
                 (display (vector-ref box 6) p))
               (display (vector-ref box 7) p)
               (display (make-string xlen (vector-ref box 8)) p)
               (display (vector-ref box 9) p)))))))))
