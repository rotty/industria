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

;; Entropic helpers.

;; TODO: procedures for estimating entropy.

;; TODO: is this a fine way to generate entropy? The host's srfi-27
;; might be predictable and it might be initialized predictably.

(library (weinholt crypto entropy (0 0 20091015))
  (export make-random-bytevector)
  (import (rnrs)
          (srfi :27 random-bits))

  (define make-random-bytevector        ;also present in net/tls
    (let* ((s (make-random-source))
           (make-int (random-source-make-integers s))
           (urandom (and (file-exists? "/dev/urandom")
                         (open-file-input-port "/dev/urandom"
                                               (file-options)
                                               (buffer-mode none)))))
      (lambda (len)
        (unless urandom
          (random-source-randomize! s))
        (do ((bv (make-bytevector len))
             (i 0 (fx+ i 1)))
            ((fx=? i len) bv)
          (if urandom
              (bytevector-u8-set! bv i (get-u8 urandom))
              (bytevector-u8-set! bv i (make-int 255)))))))

  )
