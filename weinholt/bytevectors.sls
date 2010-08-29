;; -*- mode: scheme; coding: utf-8 -*-
;; Bytevector utilities
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

(library (weinholt bytevectors (1 0 20100825))
  (export bytevector-append
          bytevectors-length
          bytevector-concatenate
          subbytevector
          bytevector-u8-index
          bytevector-u8-index-right
          bytevector->uint
          uint->bytevector)
  (import (rnrs))

  (define (bytevector-append . bvs)
    ;; TODO: is the other version faster?
    (call-with-bytevector-output-port
      (lambda (p)
        (for-each (lambda (bv)
                    (put-bytevector p bv))
                  bvs))))

  (define (bytevectors-length bvs)
    (do ((l bvs (cdr l))
         (sum 0 (+ sum (bytevector-length (car l)))))
        ((null? l) sum)))

  (define (bytevector-concatenate x)
    (let ((length (bytevectors-length x)))
      (do ((bv (make-bytevector length))
           (x x (cdr x))
           (n 0 (+ n (bytevector-length (car x)))))
          ((null? x) bv)
        (bytevector-copy! (car x) 0 bv n (bytevector-length (car x))))))

  (define subbytevector
    (case-lambda
      ((bv start end)
       (if (and (zero? start)
                (= end (bytevector-length bv)))
           bv
           (let ((ret (make-bytevector (- end start))))
             (bytevector-copy! bv start
                               ret 0 (- end start))
             ret)))
      ((bv start)
       (subbytevector bv start (bytevector-length bv)))))

  (define bytevector-u8-index
    (case-lambda
      ((bv c start end)
       (let lp ((i start))
         (cond ((= end i)
                #f)
               ((= (bytevector-u8-ref bv i) c)
                i)
               (else
                (lp (+ i 1))))))
      ((bv c start)
       (bytevector-u8-index bv c start (bytevector-length bv)))
      ((bv c)
       (bytevector-u8-index bv c 0 (bytevector-length bv)))))

  (define bytevector-u8-index-right
    (case-lambda
      ((bv c start end)
       (assert (<= 0 c 255))
       (assert (<= 0 start end (bytevector-length bv)))
       (let lp ((i (- end 1)))
         (cond ((< i start) #f)
               ((= (bytevector-u8-ref bv i) c) i)
               (else (lp (- i 1))))))
      ((bv c start)
       (bytevector-u8-index-right bv c start (bytevector-length bv)))
      ((bv c)
       (bytevector-u8-index-right bv c 0 (bytevector-length bv)))))

  (define (bytevector->uint bv)
    (if (zero? (bytevector-length bv))
        0
        (bytevector-uint-ref bv 0 (endianness big) (bytevector-length bv))))

  (define (uint->bytevector int)
    (if (zero? int)
        #vu8()
        (let ((ret (make-bytevector (div (bitwise-and -8 (+ 7 (bitwise-length int))) 8))))
          (bytevector-uint-set! ret 0 int (endianness big) (bytevector-length ret))
          ret)))


  )
