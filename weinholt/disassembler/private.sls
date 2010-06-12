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

;; Code shared between the disassemblers. Should not be imported by
;; anyone else.

(library (weinholt disassembler private (0 0 20100607))
  (export raise-UD invalid-opcode?)
  (import (rnrs))

  (define-condition-type &invalid-opcode &condition
    make-invalid-opcode invalid-opcode?)

  (define (raise-UD msg . irritants)
    (raise (condition
            (make-who-condition 'get-instruction)
            (make-message-condition msg)
            (make-irritants-condition irritants)
            (make-invalid-opcode)))))
