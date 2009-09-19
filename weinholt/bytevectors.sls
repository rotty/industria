;; -*- mode: scheme; coding: utf-8 -*-
;; Bytevector utilities
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

(library (weinholt bytevectors (0 0 20090919))
  (export subbytevector
          bytevector-u8-index
          bytevector-u8-index-right
          bytevector->uint
          uint->bytevector)
  (import (rnrs))

  (define (subbytevector bv start end)
    (let ((ret (make-bytevector (- end start))))
      (bytevector-copy! bv start
                        ret 0 (- end start))
      ret))

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
       (let lp ((i (- end 1)))
         (cond ((= start i) #f)
               ((= (bytevector-u8-ref bv i) c) i)
               (else (lp (- i 1))))))
      ((bv c start)
       (bytevector-u8-index-right bv c start (bytevector-length bv)))
      ((bv c)
       (bytevector-u8-index-right bv c 0 (bytevector-length bv)))))

  (define (bytevector->uint bv)
    (bytevector-uint-ref bv 0 (endianness big) (bytevector-length bv)))

  (define (uint->bytevector int)
    (let ((ret (make-bytevector (div (bitwise-and -8 (+ 7 (bitwise-length int))) 8))))
      (bytevector-uint-set! ret 0 int (endianness big) (bytevector-length ret))
      ret))


  )
