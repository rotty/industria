#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2008, 2009 Göran Weinholt <goran@weinholt.se>
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

(import (rnrs)
        (weinholt assembler x86)
        (weinholt disassembler x86))

(define (print . x) (for-each display x) (newline))

(define (test instruction mode . rest)
  ;; Check that it's possible to encode the given instruction, and
  ;; compare the disassembly with the input.
  (let ((expected (if (pair? rest) (car rest) instruction)))
    (let*-values (((bv symbols) (assemble (list '(%origin 0)
                                                `(%mode ,mode)
                                                instruction)))
                  ((port) (open-bytevector-input-port bv))
                  ((bytes-returned) 0))
      (let ((instruction
             (get-instruction port mode
                              (lambda (_ . bytes)
                                (set! bytes-returned (+ (length bytes)
                                                        bytes-returned))))))
        (unless (equal? instruction expected)
          (print "Expected: " expected)
          (print "Result: " instruction)
          (print "Binary: " bv)
          (error 'test "Disassembly is not as expected"
                 expected instruction bv)))

      (unless (eof-object? (lookahead-u8 port))
        (error 'test "After disassembly there are bytes unread."
               (get-instruction port mode #f)))
      (unless (= bytes-returned (bytevector-length bv))
        (error 'test "There are bytes missing in the collector function."
               bytes-returned (bytevector-length bv)))))
  (display "OK\n"))

(define (testf instruction mode)
  ;; Check that it's not possible to encode the given instruction
  (unless (guard (con (else (display "OK\n")))
            (call-with-values
              (lambda () (assemble (list '(%origin 0)
                                         `(%mode ,mode)
                                         instruction)))
              list)
            #f)
    (error 'testf "test did not fail" instruction mode)))

(define (test= instruction mode expected)
  ;; Encode the instruction and compare it with the given bytevector
  (let-values (((bv syms) (assemble (list '(%origin 0)
                                          `(%mode ,mode)
                                          instruction))))
    (unless (bytevector=? expected bv)
      (error 'test "Assembly is not as expected"
             instruction expected bv))))


(test '(hlt) 64)

(test '(ret) 64)
(test '(ret 4) 64)

(test '(mov ax #xffff) 64)
(test '(mov eax #xffff) 64)
(test '(mov rax #xffff) 64)
(test '(mov r8 #xffff) 64)
(test '(mov r8w #xffff) 64)
(test '(mov r8d #xffff) 64)

(test '(mov rsp #x100010) 64)

;;; REX

(test '(mov al 1) 64)
(test '(mov r8b 1) 64)

;;; Operand size

(test '(mov ax (mem16+ rax)) 64)
(test '(mov eax (mem32+ rax)) 64)
(test '(mov rax (mem64+ rax)) 64)

(test '(in al dx) 64)
(test '(in ax dx) 64)
(test '(in eax dx) 64)

(test '(mov cr15 r15) 64)
(test '(mov cr15 rax) 64)
(test '(mov cr3 r15) 64)
(test '(mov dr5 r13) 64)
(test '(mov dr5 rax) 64)
(test '(mov dr14 rax) 64)

(test '(mov (mem8+ rax) #xff) 64)
(test '(mov (mem16+ rax) #xffff) 64)
(test '(mov (mem32+ rax) #xffffffff) 64)
(test '(mov (mem64+ rax) #x-7fffffff) 64
      '(mov (mem64+ rax) #xffffffff80000001))

(for-each (lambda (i) (test i 64))
          '((cbw) (cwde) (cdqe)
            (cwd) (cdq) (cqo)))


;; Default operand size of 64:
(test= '(jmp rax) 64 '#vu8(#xff #xe0))
(testf '(jmp eax) 64)
;; FIXME: the operand size override is missing here... not that important.
;; (test= '(jmp ax) 64 '#vu8(#x66 #xff #xe0))

(test= '(jmp eax) 32 '#vu8(#xff #xe0))

;;; Segment and address size override

(for-each (lambda (i) (test i 64))
          '((stos (mem8+ edi) al)
            (stos (mem8+ rdi) al)
            (stos (mem16+ rdi) ax)
            (stos (mem32+ rdi) eax)
            (stos (mem64+ rdi) rax)
            (movs (mem32+ rdi) (mem32+ rsi))
            (movs (mem32+ rdi) (mem32+ fs rsi))))

(testf '(movs (mem32+ rdi) (mem32+ rsi es)) 64)

(for-each (lambda (i) (test i 32))
          '((movs (mem8+ es edi) (mem8+ ds esi))
            (movs (mem8+ es edi) (mem8+ es esi))
            (movs (mem8+ es edi) (mem8+ fs esi))))

(test '(movs (mem+ es edi) (mem16+ esi)) 32
      '(movs (mem16+ es edi) (mem16+ ds esi)))

;;; Prefixes

(for-each (lambda (i) (test i 64))
          '((rep.stos (mem8+ rdi) al)
            (rep.stos (mem32+ rdi) eax)
            (repz.scas rax (mem64+ rdi))
            (repnz.scas rax (mem64+ rdi))
            (lock.xchg (mem64+ rax) rbx)))

;;; Various memory references

(test '(mov r15 (mem+ rax 12 (* rbx wordsize))) 64
      '(mov r15 (mem64+ rax 12 (* rbx 8))))

(test '(mov rax (mem64+ rax #x0a00)) 64)
(test '(mov (mem64+ rax #x0a00) rax) 64)

(test '(mov rax (mem64+ rip 0)) 64)
(test '(mov rax (mem64+ rip #x100)) 64)
(test '(mov rax (mem64+ 0)) 64)
(test '(mov rax (mem64+ rbp)) 64
      '(mov rax (mem64+ rbp 0)))
(test '(mov rax (mem64+ rbp 0)) 64)
(test '(mov rax (mem64+ rbp #xff)) 64)
(test '(mov rax (mem64+ rbp #x100)) 64)
(test '(mov rax (mem64+ rax)) 64)

(test '(mov rax (mem64+ rax 1)) 64)
(test '(mov rax (mem64+ rax 127)) 64)
(test '(mov rax (mem64+ rax 128)) 64)

(test '(mov rax (mem64+ rax -1)) 64)
(test '(mov rax (mem64+ rax -128)) 64)
(test '(mov rax (mem64+ rax -129)) 64)


(test '(mov rax (mem64+ rax rbx)) 64
      '(mov rax (mem64+ rax (* rbx 1))))

(test '(mov rax (mem64+ (* rbx 4))) 64
      '(mov rax (mem64+ 0 (* rbx 4))))

(test '(mov rax (mem64+ rdx (* rbx 4))) 64)

(test '(mov rax (mem64+ rdx 0 (* rbx 8))) 64
      '(mov rax (mem64+ rdx (* rbx 8))))

(test '(mov rax (mem64+ rdx 127 (* rbx 8))) 64)

(test '(mov rax (mem64+ rdx 128 (* rbx 8))) 64)


(test '(mov rax (mem64+ rbp (* 8 rbx))) 64
      '(mov rax (mem64+ rbp 0 (* rbx 8))))


(test '(mov r15 (mem64+ r15 -1 (* r15 8))) 64)

;; 32-bit memory in 64-bit mode
(test '(mov r15 (mem64+ edi -1 (* eax 8))) 64) 
(test '(mov r15 (mem64+ 0)) 64)
(test '(mov r15d (mem32+ edi -1)) 64)
(test '(mov eax (mem32+ ebp 0)) 64) 

;;; 64-bit stuff in 32-bit mode

(testf '(mov r15d eax) 32)
(testf '(addpd xmm14 xmm15) 32)

;;; SSE

(test '(addpd xmm14 xmm15) 64)
(test '(addpd xmm0 (mem128+ r14)) 64)

;;; VEX

;; (test '(vpermil2ps xmm0 xmm1 xmm2 xmm3 13) 64) ;3-byte prefix
;; (test '(vandps xmm1 xmm2 xmm3) 64)      ;2-byte prefix

;; (test '(vandps xmm1 xmm2 (mem128+ r8)) 64)

;; ;; Swizzling r/m and /is4
;; (test '(vpermil2ps xmm0 xmm1 xmm2 (mem128+ rbx -1) 13) 64)
;; (test '(vpermil2ps xmm0 xmm1 (mem128+ rbx -1) xmm3 13) 64)

;;; NOP

(for-each (lambda (mode)
            (test '(nop) mode)
            (test '(pause) mode))
          '(16 32 64))

(test '(xchg eax eax) 16)
(test '(xchg rax rax) 64)
(test '(xchg r8w ax) 64)
(test '(xchg r8d eax) 64)
(test '(xchg r8 rax) 64)
(test '(xchg ax ax) 32)

