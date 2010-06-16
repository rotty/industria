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

;; Entropic helpers.

;; TODO: procedures for estimating entropy.

;; TODO: support for EGD?

;; TODO: use this library everywhere instead of SRFI-27. helps to
;; guarantee that cryptographically strong random numbers are used
;; everwhere, when that matter has been investigated.

;; TODO: is this a fine way to generate entropy? The host's srfi-27
;; might be predictable and it might be initialized predictably.

(library (weinholt crypto entropy (1 0 20100616))
  (export make-random-bytevector
          bytevector-randomize!)
  (import (rnrs)
          (srfi :27 random-bits))

  (define make-random-bytevector
    (lambda (n)
      (let ((bv (make-bytevector n)))
        (bytevector-randomize! bv)
        bv)))

  ;; The same interface as bytevector-copy! except with no source
  ;; arguments.
  (define bytevector-randomize!
    (if (file-exists? "/dev/urandom")
        (let ((urandom (open-file-input-port "/dev/urandom"
                                             (file-options)
                                             (buffer-mode none))))
          (case-lambda
            ((bv) (bytevector-randomize! bv 0 (bytevector-length bv)))
            ((bv start) (bytevector-randomize! bv start (bytevector-length bv)))
            ((bv start count)
             (let lp ((start start)
                      (count count))
               (unless (zero? count)
                 (let ((n (get-bytevector-n! urandom bv start count)))
                   (lp (+ start n) (- count n))))))))
        (let* ((s (make-random-source))
               (make-int (random-source-make-integers s)))
          (case-lambda
            ((bv) (bytevector-randomize! bv 0 (bytevector-length bv)))
            ((bv start) (bytevector-randomize! bv start (bytevector-length bv)))
            ((bv start count)
             (random-source-randomize! s)
             (do ((start start (+ start 1))
                  (count count (- count 1)))
                 ((zero? count))
               (bytevector-u8-set! bv start (make-int 255)))))))))
