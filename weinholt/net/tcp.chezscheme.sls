#!r6rs
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

;; There is a proper way of doing TCP in Chez, and this is not it.
;; This is the embarrassing way. But it's useful for testing.

(library (weinholt net tcp (0 0 20090921))
  (export tcp-connect)
  (import (chezscheme))

  (define (tcp-connect host service)
    (putenv "_CHEZHOST_" host)
    (putenv "_CHEZSERVICE_" service)
    ;; Talk with netcat...
    (let-values (((o i e pid)
                  (open-process-ports "nc \"$_CHEZHOST_\" \"$_CHEZSERVICE_\"")))
      (close-port e)
      (values i o))))
