#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
;; Print the SHA-1 hash of a file
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

(import (weinholt crypto sha-1)
        (rnrs))

(define (checksum-port port)
  (let ((state (make-sha-1))
        (data (make-bytevector 8192 0)))
    (let lp ()
      (let ((bytes-read (get-bytevector-n! port data 0 8192)))
        (unless (eof-object? bytes-read)
          (sha-1-update! state data 0 bytes-read)
          (lp))))
    (sha-1-finish! state)
    (sha-1->string state)))

(when (null? (cdr (command-line)))
  (display "Usage: sha1sum.sps filename\n" (current-error-port))
  (exit 1))

(display (checksum-port (open-file-input-port (cadr (command-line)))))
(display "  ")
(display (cadr (command-line)))
(newline)
