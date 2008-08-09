#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
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

(import (rnrs)
        (se weinholt disassembler x86))

(define (print-test filename mode)
  "Improvised pretty-printer (not so pretty really) that prints an
unindented test case, given a file and a mode."
  (let ((p (open-file-input-port filename))
        (p2 (open-file-input-port filename)))
    (display "(test")
    (display mode)
    (display " '#vu8(")
    (let lp ((pos (port-position p))
             (instrs '()))
      (let* ((i (guard (con
                        ((invalid-opcode? con)
                         (list 'bad:
                               (condition-message con))))
                       (get-instruction p mode #f)))
             (new-pos (port-position p)))
        (cond ((eof-object? i)
               (for-each (lambda (i)
                           (display #\')
                           (display i)
                           (newline))
                         (map (lambda (i)
                                (let lp ((i i))
                                  (cond ((pair? i)
                                         (cons (lp (car i))
                                               (lp (cdr i))))
                                        ((number? i)
                                         (string-append "#x" (number->string i 16)))
                                        (else i))))
                              (reverse instrs)))
               (display ")"))
              (else
               (for-each (lambda (byte)
                           (display "#x")
                           (when (< byte #x10)
                             (display #\0))
                           (display (number->string byte 16))
                           (display #\space))
                         (bytevector->u8-list (get-bytevector-n p2 (- new-pos pos))))
               (if (eof-object? (lookahead-u8 p))
                   (display ")"))
               (newline)
               (lp new-pos (cons i instrs))))))))

(define (test mode input . expected)
  (let ((port (open-bytevector-input-port input))
        (bytes-returned 0))
    (for-each (lambda (expect)
                (let ((instruction (get-instruction port mode
                                                    (lambda (_ . bytes)
                                                      (set! bytes-returned (+ (length bytes)
                                                                              bytes-returned))))))
                  (unless (equal? expect instruction)
                    (error 'test "Disassembly is not as expected"
                           expect instruction))))
              expected)
    (unless (eof-object? (lookahead-u8 port))
      (error 'test "After disassembly there are bytes unread."
             (get-instruction port mode #f)))
    (unless (= bytes-returned (bytevector-length input))
      (error 'test "There are bytes missing in the collector function."
             bytes-returned (bytevector-length input)))))


(define (test64 input . expected) (apply test 64 input expected))
(define (test32 input . expected) (apply test 32 input expected))
(define (test16 input . expected) (apply test 16 input expected))

;;; Various

(test64 '#vu8(#x03 #x05 #x00 #x00 #x00 #x00)
        '(add eax (mem32+ rip 0)))

(test32 '#vu8(#x03 #x05 #x00 #x00 #x00 #x00)
        '(add eax (mem32+ 0)))

(test64 '#vu8(#x0F #x01 #xC3)
        '(vmresume))

(test64 '#vu8(#x0F #xA4 #x05 #x00 #x00 #x00 #x00 #x03)
        '(shld (mem32+ rip 0) eax 3))

(test64 '#vu8(#x66 #x0F #x3A #x0F #xC1 #x08)
        '(palignr xmm0 xmm1 8))

(test64 '#vu8(#x66 #x90)
        '(xchg ax ax))

(test64 '#vu8(#x90)
        '(nop))

(test64 '#vu8(#x69 #x6c #x6c #x65 #x6e #x69 #x75 #x6d)
        '(imul ebp (mem32+ rsp 101 (* rbp 2)) #x6d75696e))

(test64 '#vu8(#x0F #x01 #xF8)
        '(swapgs))

(test64 '#vu8(#x0F #x01 #xF9)
        '(rdtscp))

(test64 '#vu8(#x0F #x00 #xD8)
        '(ltr ax))

(test64 '#vu8(#x0F #x01 #xDE #x0F #x01 #xC9)
        '(skinit)
        '(mwait))

(test64 '#vu8(#x66 #x41 #x0F #x38 #xDC #xC5)
        '(aesenc xmm0 xmm13))

(test64 '#vu8(#x66 #x44 #x0F #x7C #xE9)
        '(haddpd xmm13 xmm1))

(test64 '#vu8(#xC4 #xE3 #x79 #x05 #xF2 #x2A)
        '(vpermilpd xmm6 xmm2 42))

(test64 '#vu8(#x41 #x8d #x44 #x24 #xff)
        '(lea eax (mem+ r12 -1)))

(test64 '#vu8(#x41 #x8d #x54 #x24 #x20)
        '(lea edx (mem+ r12 #x20)))

;;; Test the REP/REPE/REPNZ prefix

(test64 '#vu8(#xF3 #xAC
                   #xF3 #xAD
                   #xF3 #x48 #xAD)
        '(rep.lodsb al (mem8+ rsi))
        '(rep.lodsd eax (mem32+ rsi))
        '(rep.lodsq rax (mem64+ rsi)))

(test64 '#vu8(#xF3 #x6E
                   #xF3 #x66 #x6F
                   #xF3 #x6F
                   #x6E
                   #x66 #x6F
                   #x6F)
        '(rep.outsb dx (mem8+ rsi))
        '(rep.outsw dx (mem16+ rsi))
        '(rep.outsd dx (mem32+ rsi))
        '(outsb dx (mem8+ rsi))
        '(outsw dx (mem16+ rsi))
        '(outsd dx (mem32+ rsi)))

(test64 '#vu8(#xF3 #xAA
                   #xF3 #x66 #xAB
                   #xF3 #xAB
                   #xF3 #x48 #xAB
                   #x66 #xAB)
        '(rep.stosb (mem8+ rdi) al)
        '(rep.stosw (mem16+ rdi) ax)
        '(rep.stosd (mem32+ rdi) eax)
        '(rep.stosq (mem64+ rdi) rax)
        '(stosw (mem16+ rdi) ax))

(test64 '#vu8(#xF3 #xA6
                   #xF2 #xA6
                   #xF3 #x48 #xA7
                   #xF2 #x66 #xA7
                   #xA6)
        '(repz.cmpsb (mem8+ rsi) (mem8+ rdi))
        '(repnz.cmpsb (mem8+ rsi) (mem8+ rdi))
        '(repz.cmpsq (mem64+ rsi) (mem64+ rdi))
        '(repnz.cmpsw (mem16+ rsi) (mem16+ rdi))
        '(cmpsb (mem8+ rsi) (mem8+ rdi)))

(test64 '#vu8(#xF2 #x66 #xAF
                   #xF3 #xAE
                   #x48 #xAF)
        '(repnz.scasw ax (mem16+ rdi))
        '(repz.scasb al (mem8+ rdi))
        '(scasq rax (mem64+ rdi)))

(test64 '#vu8(#xf3 #xae
                   #xf3 #xaa
                   #xf3 #x6c
                   #xf3 #xa6
                   #xf3 #xa4
                   #xf3 #xac
                   #xf3 #x6e)
        ;;repz scas %es:(%rdi),%al
        '(repz.scasb al (mem8+ rdi))
        ;;rep stos %al,%es:(%rdi)
        '(rep.stosb (mem8+ rdi) al)
        ;;rep insb (%dx),%es:(%rdi)
        '(rep.insb (mem8+ rdi) dx)
        ;;repz cmpsb %es:(%rdi),%ds:(%rsi)
        '(repz.cmpsb (mem8+ rsi) (mem8+ rdi))
        ;;rep movsb %ds:(%rsi),%es:(%rdi)
        '(rep.movsb (mem8+ rdi) (mem8+ rsi))
        ;;rep lods %ds:(%rsi),%al
        '(rep.lodsb al (mem8+ rsi))
        ;;rep outsb %ds:(%rsi),(%dx)
        '(rep.outsb dx (mem8+ rsi)))

;;; Test a bunch of ModR/M bytes
(test64 '#vu8(#x8D #x0
                   #x8D #x1
                   #x8D #x2
                   #x8D #x3
                   #x8D #x4
                   #x25 #x0 #x0 #x0 #x0
                   #x8D #x5 #xEB #xFF #xFF #xFF
                   #x8D #x6
                   #x8D #x7 #x41
                   #x8D #x0 #x41
                   #x8D #x1 #x41
                   #x8D #x2 #x41
                   #x8D #x3 #x41
                   #x8D #x4 #x25 #x0 #x0 #x0 #x0 #x41
                   #x8D #x5 #xCC #xFF #xFF #xFF #x41
                   #x8D #x6 #x41
                   #x8D #x7
                   #x8D #x40 #x7F
                   #x8D #x41 #x7F
                   #x8D #x42 #x7F
                   #x8D #x43 #x7F
                   #x8D #x44 #xC0 #x7F
                   #x8D #x45 #x7F
                   #x8D #x46 #x7F
                   #x8D #x47 #x7F
                   #x41 #x8D #x40 #x7F
                   #x41 #x8D #x41 #x7F
                   #x41 #x8D #x42 #x7F
                   #x41 #x8D #x43 #x7F
                   #x41 #x8D #x44 #x24 #x7F
                   #x41 #x8D #x44 #xC0 #x7F
                   #x41 #x8D #x45 #x7F
                   #x41 #x8D #x46 #x7F
                   #x41 #x8D #x47 #x7F
                   #x8D #x80 #x80 #x0 #x0 #x0
                   #x8D #x81 #x80 #x0 #x0 #x0
                   #x8D #x82 #x80 #x0 #x0 #x0
                   #x8D #x83 #x80 #x0 #x0 #x0
                   #x8D #x84 #xC0 #x80 #x0 #x0 #x0
                   #x8D #x85 #x80 #x0 #x0 #x0
                   #x8D #x86 #x80 #x0 #x0 #x0
                   #x8D #x87 #x80 #x0 #x0 #x0
                   #x41 #x8D #x80 #x80 #x0 #x0 #x0
                   #x41 #x8D #x81 #x80 #x0 #x0 #x0
                   #x41 #x8D #x82 #x80 #x0 #x0 #x0
                   #x41 #x8D #x83 #x80 #x0 #x0 #x0
                   #x41 #x8D #x84 #x24 #x80 #x0 #x0 #x0
                   #x41 #x8D #x84 #xC0 #x80 #x0 #x0 #x0
                   #x41 #x8D #x85 #x80 #x0 #x0 #x0
                   #x41 #x8D #x86 #x80 #x0 #x0 #x0
                   #x41 #x8D #x87 #x80 #x0 #x0 #x0
                   #x30 #xC0
                   #x30 #xC1
                   #x30 #xC2
                   #x30 #xC3
                   #x30 #xC4
                   #x30 #xC5
                   #x30 #xC6
                   #x30 #xC7
                   #x40 #x30 #xC0
                   #x40 #x30 #xC1
                   #x40 #x30 #xC2
                   #x40 #x30 #xC3
                   #x40 #x30 #xC4
                   #x40 #x30 #xC5
                   #x40 #x30 #xC6
                   #x40 #x30 #xC7
                   #x41 #x30 #xC0
                   #x41 #x30 #xC1
                   #x41 #x30 #xC2
                   #x41 #x30 #xC3
                   #x41 #x30 #xC4
                   #x41 #x30 #xC5
                   #x41 #x30 #xC6
                   #x41 #x30 #xC7
                   #x41 #x30 #xCF
                   #x41 #x30 #xD7
                   #x41 #x30 #xDF
                   #x41 #x30 #xE7
                   #x41 #x30 #xEF
                   #x41 #x30 #xF7
                   #x41 #x30 #xFF
                   #x45 #x30 #xC7
                   #x45 #x30 #xCF
                   #x45 #x30 #xD7
                   #x45 #x30 #xDF
                   #x45 #x30 #xE7
                   #x45 #x30 #xEF
                   #x45 #x30 #xF7
                   #x45 #x30 #xFF)
        '(lea eax (mem+ rax))
        '(lea eax (mem+ rcx))
        '(lea eax (mem+ rdx))
        '(lea eax (mem+ rbx))
        '(lea eax (mem+ 0))
        '(lea eax (mem+ rip -21))
        '(lea eax (mem+ rsi))
        '(lea eax (mem+ rdi))
        '(lea eax (mem+ r8))
        '(lea eax (mem+ r9))
        '(lea eax (mem+ r10))
        '(lea eax (mem+ r11))
        '(lea eax (mem+ 0))
        '(lea eax (mem+ rip -52))
        '(lea eax (mem+ r14))
        '(lea eax (mem+ r15))
        '(lea eax (mem+ rax 127))
        '(lea eax (mem+ rcx 127))
        '(lea eax (mem+ rdx 127))
        '(lea eax (mem+ rbx 127))
        '(lea eax (mem+ rax 127 (* rax 8)))
        '(lea eax (mem+ rbp 127))
        '(lea eax (mem+ rsi 127))
        '(lea eax (mem+ rdi 127))
        '(lea eax (mem+ r8 127))
        '(lea eax (mem+ r9 127))
        '(lea eax (mem+ r10 127))
        '(lea eax (mem+ r11 127))
        '(lea eax (mem+ r12 127))
        '(lea eax (mem+ r8 127 (* rax 8)))
        '(lea eax (mem+ r13 127))
        '(lea eax (mem+ r14 127))
        '(lea eax (mem+ r15 127))
        '(lea eax (mem+ rax 128))
        '(lea eax (mem+ rcx 128))
        '(lea eax (mem+ rdx 128))
        '(lea eax (mem+ rbx 128))
        '(lea eax (mem+ rax 128 (* rax 8)))
        '(lea eax (mem+ rbp 128))
        '(lea eax (mem+ rsi 128))
        '(lea eax (mem+ rdi 128))
        '(lea eax (mem+ r8 128))
        '(lea eax (mem+ r9 128))
        '(lea eax (mem+ r10 128))
        '(lea eax (mem+ r11 128))
        '(lea eax (mem+ r12 128))
        '(lea eax (mem+ r8 128 (* rax 8)))
        '(lea eax (mem+ r13 128))
        '(lea eax (mem+ r14 128))
        '(lea eax (mem+ r15 128))
        '(xor al al)
        '(xor cl al)
        '(xor dl al)
        '(xor bl al)
        '(xor ah al)
        '(xor ch al)
        '(xor dh al)
        '(xor bh al)
        '(xor al al)
        '(xor cl al)
        '(xor dl al)
        '(xor bl al)
        '(xor spl al)
        '(xor bpl al)
        '(xor sil al)
        '(xor dil al)
        '(xor r8b al)
        '(xor r9b al)
        '(xor r10b al)
        '(xor r11b al)
        '(xor r12b al)
        '(xor r13b al)
        '(xor r14b al)
        '(xor r15b al)
        '(xor r15b cl)
        '(xor r15b dl)
        '(xor r15b bl)
        '(xor r15b spl)
        '(xor r15b bpl)
        '(xor r15b sil)
        '(xor r15b dil)
        '(xor r15b r8b)
        '(xor r15b r9b)
        '(xor r15b r10b)
        '(xor r15b r11b)
        '(xor r15b r12b)
        '(xor r15b r13b)
        '(xor r15b r14b)
        '(xor r15b r15b))

(test64 '#vu8(#x4c #x89 #x2c #xc5 #x00 #x40 #x23 #x00)
        '(mov (mem64+ #x234000 (* rax 8)) r13))

;;; Test sign-extended immediates
(test64 '#vu8(#x24 #xF0
                   #x66 #x25 #xF0 #xFF
                   #x25 #xF0 #xFF #xFF #xFF
                   #x48 #x25 #xF0 #xFF #xFF #xFF
                   #x80 #x20 #xF0
                   #x66 #x81 #x20 #xF0 #xFF
                   #x81 #x20 #xF0 #xFF #xFF #xFF
                   #x48 #x81 #x20 #xF0 #xFF #xFF #xFF
                   #x66 #x83 #x20 #xF0
                   #x83 #x20 #xF0
                   #x48 #x83 #x20 #xF0)
        '(and al #xF0)
        '(and ax #xFFF0)
        '(and eax #xFFFFFFF0)
        '(and rax #xFFFFFFFFFFFFFFF0)
        '(and (mem8+ rax) #xF0)
        '(and (mem16+ rax) #xFFF0)
        '(and (mem32+ rax) #xFFFFFFF0)
        '(and (mem64+ rax) #xFFFFFFFFFFFFFFF0)
        '(and (mem16+ rax) #xFFF0)
        '(and (mem32+ rax) #xFFFFFFF0)
        '(and (mem64+ rax) #xFFFFFFFFFFFFFFF0))

(test64 '#vu8(#x24 #xF
                   #x66 #x25 #xFF #xF
                   #x25 #xFF #xFF #xFF #xF
                   #x48 #x25 #xFF #xFF #xFF #xFF
                   #x80 #x20 #xF
                   #x66 #x81 #x20 #xFF #xF
                   #x81 #x20 #xFF #xFF #xFF #xF
                   #x48 #x81 #x20 #xFF #xFF #xFF #xFF
                   #x66 #x83 #x20 #xF
                   #x83 #x20 #xF
                   #x48 #x83 #x20 #xF)
        '(and al #xF)
        '(and ax #xFFF)
        '(and eax #xFFFFFFF)
        '(and rax #xFFFFFFFFFFFFFFFF)
        '(and (mem8+ rax) #xF)
        '(and (mem16+ rax) #xFFF)
        '(and (mem32+ rax) #xFFFFFFF)
        '(and (mem64+ rax) #xFFFFFFFFFFFFFFFF)
        '(and (mem16+ rax) #xF)
        '(and (mem32+ rax) #xF)
        '(and (mem64+ rax) #xF))

(test64 '#vu8(#x24 #xf0
                   #x66 #x83 #xe0 #xf0
                   #x83 #xe0 #xf0
                   #x48 #x83 #xe0 #xf0
                   #x80 #x20 #xf0
                   #x66 #x83 #x20 #xf0
                   #x83 #x20 #xf0
                   #x48 #x83 #x20 #xf0)
        '(and al #xF0)
        '(and ax #xFFF0)
        '(and eax #xFFFFFFF0)
        '(and rax #xFFFFFFFFFFFFFFF0)
        '(and (mem8+ rax) #xF0)
        '(and (mem16+ rax) #xFFF0)
        '(and (mem32+ rax) #xFFFFFFF0)
        '(and (mem64+ rax) #xFFFFFFFFFFFFFFF0))


;;; AVX
(test64 '#vu8(#xC4 #xE2 #x69 #x2C #x00
                   #xC4 #xE2 #x69 #x2E #x18
                   #xC4 #xE2 #x69 #x2D #x00
                   #xC4 #xE2 #x69 #x2F #x18
                   #xC4 #xE3 #x71 #x48 #xC2 #x31
                   #xC4 #xE3 #x71 #x49 #xC2 #x31
                   #xC4 #xE3 #xF1 #x48 #x00 #x21
                   #xC4 #xE3 #x71 #x49 #x00 #x31
                   #xC4 #xE3 #x71 #x4A #x00 #x30)
        '(vmaskmovps xmm0 xmm2 (mem128+ rax))
        '(vmaskmovps (mem128+ rax) xmm2 xmm3)
        '(vmaskmovpd xmm0 xmm2 (mem128+ rax))
        '(vmaskmovpd (mem128+ rax) xmm2 xmm3)
        '(vpermiltd2ps xmm0 xmm1 xmm2 xmm3)
        '(vpermiltd2pd xmm0 xmm1 xmm2 xmm3)
        '(vpermiltd2ps xmm0 xmm1 xmm2 (mem128+ rax))
        '(vpermiltd2pd xmm0 xmm1 (mem128+ rax) xmm3)
        '(vblendvps xmm0 xmm1 (mem128+ rax) xmm3))

;;; All AMD SSE5 instructions
(test64 '#vu8(#x0F #x25 #x2D #x08 #x00 #x42
                   #x0F #x25 #x2C #x08 #x00 #x42
                   #x0F #x25 #x2F #x08 #x00 #x42
                   #x0F #x25 #x2E #x08 #x00 #x42
                   #x0F #x7A #x30 #x00
                   #x0F #x7A #x31 #x00
                   #x0F #x24 #x01 #x18 #x00
                   #x0F #x24 #x01 #x20 #x08
                   #x0F #x24 #x05 #x10 #x00
                   #x0F #x24 #x05 #x18 #x08
                   #x0F #x24 #x00 #x18 #x00
                   #x0F #x24 #x00 #x20 #x08
                   #x0F #x24 #x04 #x10 #x00
                   #x0F #x24 #x04 #x18 #x08
                   #x0F #x24 #x03 #x18 #x00
                   #x0F #x24 #x03 #x20 #x08
                   #x0F #x24 #x07 #x10 #x00
                   #x0F #x24 #x07 #x18 #x08
                   #x0F #x24 #x02 #x18 #x00
                   #x0F #x24 #x02 #x20 #x08
                   #x0F #x24 #x06 #x10 #x00
                   #x0F #x24 #x06 #x18 #x08
                   #x0F #x24 #x09 #x18 #x00
                   #x0F #x24 #x09 #x20 #x08
                   #x0F #x24 #x0D #x10 #x00
                   #x0F #x24 #x0D #x18 #x08
                   #x0F #x24 #x08 #x18 #x00
                   #x0F #x24 #x08 #x20 #x08
                   #x0F #x24 #x0C #x10 #x00
                   #x0F #x24 #x0C #x18 #x08
                   #x0F #x24 #x0B #x18 #x00
                   #x0F #x24 #x0B #x20 #x08
                   #x0F #x24 #x0F #x10 #x00
                   #x0F #x24 #x0F #x18 #x08
                   #x0F #x24 #x0A #x18 #x00
                   #x0F #x24 #x0A #x20 #x08
                   #x0F #x24 #x0E #x10 #x00
                   #x0F #x24 #x0E #x18 #x08
                   #x0F #x24 #x11 #x18 #x00
                   #x0F #x24 #x11 #x20 #x08
                   #x0F #x24 #x15 #x10 #x00
                   #x0F #x24 #x15 #x18 #x08
                   #x0F #x24 #x10 #x18 #x00
                   #x0F #x24 #x10 #x20 #x08
                   #x0F #x24 #x14 #x10 #x00
                   #x0F #x24 #x14 #x18 #x08
                   #x0F #x24 #x13 #x18 #x00
                   #x0F #x24 #x13 #x20 #x08
                   #x0F #x24 #x17 #x10 #x00
                   #x0F #x24 #x17 #x18 #x08
                   #x0F #x24 #x12 #x18 #x00
                   #x0F #x24 #x12 #x20 #x08
                   #x0F #x24 #x16 #x10 #x00
                   #x0F #x24 #x16 #x18 #x08
                   #x0F #x24 #x19 #x18 #x00
                   #x0F #x24 #x19 #x20 #x08
                   #x0F #x24 #x1D #x10 #x00
                   #x0F #x24 #x1D #x18 #x08
                   #x0F #x24 #x18 #x18 #x00
                   #x0F #x24 #x18 #x20 #x08
                   #x0F #x24 #x1C #x10 #x00
                   #x0F #x24 #x1C #x18 #x08
                   #x0F #x24 #x1B #x18 #x00
                   #x0F #x24 #x1B #x20 #x08
                   #x0F #x24 #x1F #x10 #x00
                   #x0F #x24 #x1F #x18 #x08
                   #x0F #x24 #x1A #x18 #x00
                   #x0F #x24 #x1A #x20 #x08
                   #x0F #x24 #x1E #x10 #x00
                   #x0F #x24 #x1E #x18 #x08
                   #x0F #x7A #x11 #x00
                   #x0F #x7A #x10 #x00
                   #x0F #x7A #x13 #x00
                   #x0F #x7A #x12 #x00
                   #x0F #x24 #x22 #x18 #x00
                   #x0F #x24 #x22 #x20 #x08
                   #x0F #x24 #x26 #x10 #x00
                   #x0F #x24 #x26 #x18 #x08
                   #x0F #x25 #x4C #x08 #x00 #x42
                   #x0F #x25 #x4D #x08 #x00 #x42
                   #x0F #x25 #x4E #x08 #x00 #x42
                   #x0F #x25 #x4F #x08 #x00 #x42
                   #x0F #x25 #x6C #x08 #x00 #x42
                   #x0F #x25 #x6D #x08 #x00 #x42
                   #x0F #x25 #x6E #x08 #x00 #x42
                   #x0F #x25 #x6F #x08 #x00 #x42
                   #x0F #x24 #x21 #x18 #x00
                   #x0F #x24 #x21 #x20 #x08
                   #x0F #x24 #x25 #x10 #x00
                   #x0F #x24 #x25 #x18 #x08
                   #x0F #x24 #x20 #x18 #x00
                   #x0F #x24 #x20 #x20 #x08
                   #x0F #x24 #x24 #x10 #x00
                   #x0F #x24 #x24 #x18 #x08
                   #x0F #x7A #x42 #x00
                   #x0F #x7A #x43 #x00
                   #x0F #x7A #x41 #x00
                   #x0F #x7A #x4B #x00
                   #x0F #x7A #x52 #x00
                   #x0F #x7A #x53 #x00
                   #x0F #x7A #x51 #x00
                   #x0F #x7A #x5B #x00
                   #x0F #x7A #x56 #x00
                   #x0F #x7A #x57 #x00
                   #x0F #x7A #x46 #x00
                   #x0F #x7A #x47 #x00
                   #x0F #x7A #x61 #x00
                   #x0F #x7A #x63 #x00
                   #x0F #x7A #x62 #x00
                   #x0F #x24 #x9E #x08 #x00
                   #x0F #x24 #x9F #x08 #x00
                   #x0F #x24 #x97 #x08 #x00
                   #x0F #x24 #x8E #x08 #x00
                   #x0F #x24 #x8F #x08 #x00
                   #x0F #x24 #x87 #x08 #x00
                   #x0F #x24 #x86 #x08 #x00
                   #x0F #x24 #x85 #x08 #x00
                   #x0F #x24 #x96 #x08 #x00
                   #x0F #x24 #x95 #x08 #x00
                   #x0F #x24 #xA6 #x08 #x00
                   #x0F #x24 #xB6 #x08 #x00
                   #x0F #x24 #x23 #x18 #x00
                   #x0F #x24 #x23 #x20 #x08
                   #x0F #x24 #x27 #x10 #x00
                   #x0F #x24 #x27 #x18 #x08
                   #x0F #x24 #x40 #x08 #x00
                   #x0F #x24 #x40 #x08 #x08
                   #x0F #x7B #x40 #x00 #x42
                   #x0F #x24 #x42 #x08 #x00
                   #x0F #x24 #x42 #x08 #x08
                   #x0F #x7B #x42 #x00 #x42
                   #x0F #x24 #x43 #x08 #x00
                   #x0F #x24 #x43 #x08 #x08
                   #x0F #x7B #x43 #x00 #x42
                   #x0F #x24 #x41 #x08 #x00
                   #x0F #x24 #x41 #x08 #x08
                   #x0F #x7B #x41 #x00 #x42
                   #x0F #x24 #x48 #x08 #x00
                   #x0F #x24 #x48 #x08 #x08
                   #x0F #x24 #x4A #x08 #x00
                   #x0F #x24 #x4A #x08 #x08
                   #x0F #x24 #x4B #x08 #x00
                   #x0F #x24 #x4B #x08 #x08
                   #x0F #x24 #x49 #x08 #x00
                   #x0F #x24 #x49 #x08 #x08
                   #x0F #x24 #x44 #x08 #x00
                   #x0F #x24 #x44 #x08 #x08
                   #x0F #x24 #x46 #x08 #x00
                   #x0F #x24 #x46 #x08 #x08
                   #x0F #x24 #x47 #x08 #x00
                   #x0F #x24 #x47 #x08 #x08
                   #x0F #x24 #x45 #x08 #x00
                   #x0F #x24 #x45 #x08 #x08
                   #x66 #x0F #x38 #x17 #x00
                   #x66 #x0F #x3A #x09 #x00 #x42
                   #x66 #x0F #x3A #x08 #x00 #x42
                   #x66 #x0F #x3A #x0B #x00 #x42
                   #x66 #x0F #x3A #x0A #x00 #x42)
        '(compd xmm0 xmm1 (mem128+ rax) #x42)
        '(comps xmm0 xmm1 (mem128+ rax) #x42)
        '(comsd xmm0 xmm1 (mem64+ rax) #x42)
        '(comss xmm0 xmm1 (mem32+ rax) #x42)
        '(cvtph2ps xmm0 (mem128+ rax))
        '(cvtps2ph (mem128+ rax) xmm0)
        '(fmaddpd xmm0 xmm0 xmm3 (mem128+ rax))
        '(fmaddpd xmm0 xmm0 (mem128+ rax) xmm4)
        '(fmaddpd xmm0 xmm2 (mem128+ rax) xmm0)
        '(fmaddpd xmm0 (mem128+ rax) xmm3 xmm0)
        '(fmaddps xmm0 xmm0 xmm3 (mem128+ rax))
        '(fmaddps xmm0 xmm0 (mem128+ rax) xmm4)
        '(fmaddps xmm0 xmm2 (mem128+ rax) xmm0)
        '(fmaddps xmm0 (mem128+ rax) xmm3 xmm0)
        '(fmaddsd xmm0 xmm0 xmm3 (mem64+ rax))
        '(fmaddsd xmm0 xmm0 (mem64+ rax) xmm4)
        '(fmaddsd xmm0 xmm2 (mem64+ rax) xmm0)
        '(fmaddsd xmm0 (mem64+ rax) xmm3 xmm0)
        '(fmaddss xmm0 xmm0 xmm3 (mem32+ rax))
        '(fmaddss xmm0 xmm0 (mem32+ rax) xmm4)
        '(fmaddsd xmm0 xmm2 (mem32+ rax) xmm0)
        '(fmaddsd xmm0 (mem32+ rax) xmm3 xmm0)
        '(fmsubpd xmm0 xmm0 xmm3 (mem128+ rax))
        '(fmsubpd xmm0 xmm0 (mem128+ rax) xmm4)
        '(fmsubpd xmm0 xmm2 (mem128+ rax) xmm0)
        '(fmsubpd xmm0 (mem128+ rax) xmm3 xmm0)
        '(fmsubps xmm0 xmm0 xmm3 (mem128+ rax))
        '(fmsubps xmm0 xmm0 (mem128+ rax) xmm4)
        '(fmsubps xmm0 xmm2 (mem128+ rax) xmm0)
        '(fmsubps xmm0 (mem128+ rax) xmm3 xmm0)
        '(fmsubsd xmm0 xmm0 xmm3 (mem64+ rax))
        '(fmsubsd xmm0 xmm0 (mem64+ rax) xmm4)
        '(fmsubsd xmm0 xmm2 (mem64+ rax) xmm0)
        '(fmsubsd xmm0 (mem64+ rax) xmm3 xmm0)
        '(fmsubss xmm0 xmm0 xmm3 (mem32+ rax))
        '(fmsubss xmm0 xmm0 (mem32+ rax) xmm4)
        '(fmsubsd xmm0 xmm2 (mem32+ rax) xmm0)
        '(fmsubsd xmm0 (mem32+ rax) xmm3 xmm0)
        '(fnmaddpd xmm0 xmm0 xmm3 (mem128+ rax))
        '(fnmaddpd xmm0 xmm0 (mem128+ rax) xmm4)
        '(fnmaddpd xmm0 xmm2 (mem128+ rax) xmm0)
        '(fnmaddpd xmm0 (mem128+ rax) xmm3 xmm0)
        '(fnmaddps xmm0 xmm0 xmm3 (mem128+ rax))
        '(fnmaddps xmm0 xmm0 (mem128+ rax) xmm4)
        '(fnmaddps xmm0 xmm2 (mem128+ rax) xmm0)
        '(fnmaddps xmm0 (mem128+ rax) xmm3 xmm0)
        '(fnmaddsd xmm0 xmm0 xmm3 (mem64+ rax))
        '(fnmaddsd xmm0 xmm0 (mem64+ rax) xmm4)
        '(fnmaddsd xmm0 xmm2 (mem64+ rax) xmm0)
        '(fnmaddsd xmm0 (mem64+ rax) xmm3 xmm0)
        '(fnmaddss xmm0 xmm0 xmm3 (mem32+ rax))
        '(fnmaddss xmm0 xmm0 (mem32+ rax) xmm4)
        '(fnmaddsd xmm0 xmm2 (mem32+ rax) xmm0)
        '(fnmaddsd xmm0 (mem32+ rax) xmm3 xmm0)
        '(fnmsubpd xmm0 xmm0 xmm3 (mem128+ rax))
        '(fnmsubpd xmm0 xmm0 (mem128+ rax) xmm4)
        '(fnmsubpd xmm0 xmm2 (mem128+ rax) xmm0)
        '(fnmsubpd xmm0 (mem128+ rax) xmm3 xmm0)
        '(fnmsubps xmm0 xmm0 xmm3 (mem128+ rax))
        '(fnmsubps xmm0 xmm0 (mem128+ rax) xmm4)
        '(fnmsubps xmm0 xmm2 (mem128+ rax) xmm0)
        '(fnmsubps xmm0 (mem128+ rax) xmm3 xmm0)
        '(fnmsubsd xmm0 xmm0 xmm3 (mem64+ rax))
        '(fnmsubsd xmm0 xmm0 (mem64+ rax) xmm4)
        '(fnmsubsd xmm0 xmm2 (mem64+ rax) xmm0)
        '(fnmsubsd xmm0 (mem64+ rax) xmm3 xmm0)
        '(fnmsubss xmm0 xmm0 xmm3 (mem32+ rax))
        '(fnmsubss xmm0 xmm0 (mem32+ rax) xmm4)
        '(fnmsubsd xmm0 xmm2 (mem32+ rax) xmm0)
        '(fnmsubsd xmm0 (mem32+ rax) xmm3 xmm0)
        '(frczpd xmm0 (mem128+ rax))
        '(frczps xmm0 (mem128+ rax))
        '(frczsd xmm0 (mem64+ rax))
        '(frczss xmm0 (mem32+ rax))
        '(pcmov xmm0 xmm0 xmm3 (mem128+ rax))
        '(pcmov xmm0 xmm0 (mem128+ rax) xmm4)
        '(pcmov xmm0 xmm2 (mem128+ rax) xmm0)
        '(pcmov xmm0 (mem128+ rax) xmm3 xmm0)
        '(pcomb xmm0 xmm1 (mem128+ rax) #x42)
        '(pcomw xmm0 xmm1 (mem128+ rax) #x42)
        '(pcomd xmm0 xmm1 (mem128+ rax) #x42)
        '(pcomq xmm0 xmm1 (mem128+ rax) #x42)
        '(pcomub xmm0 xmm1 (mem128+ rax) #x42)
        '(pcomuw xmm0 xmm1 (mem128+ rax) #x42)
        '(pcomud xmm0 xmm1 (mem128+ rax) #x42)
        '(pcomuq xmm0 xmm1 (mem128+ rax) #x42)
        '(permpd xmm0 xmm0 xmm3 (mem128+ rax))
        '(permpd xmm0 xmm0 (mem128+ rax) xmm4)
        '(permpd xmm0 xmm2 (mem128+ rax) xmm0)
        '(permpd xmm0 (mem128+ rax) xmm3 xmm0)
        '(permps xmm0 xmm0 xmm3 (mem128+ rax))
        '(permps xmm0 xmm0 (mem128+ rax) xmm4)
        '(permps xmm0 xmm2 (mem128+ rax) xmm0)
        '(permps xmm0 (mem128+ rax) xmm3 xmm0)
        '(phaddbd xmm0 (mem128+ rax))
        '(phaddbq xmm0 (mem128+ rax))
        '(phaddbw xmm0 (mem128+ rax))
        '(phadddq xmm0 (mem128+ rax))
        '(phaddubd xmm0 (mem128+ rax))
        '(phaddubq xmm0 (mem128+ rax))
        '(phaddubw xmm0 (mem128+ rax))
        '(phaddudq xmm0 (mem128+ rax))
        '(phadduwd xmm0 (mem128+ rax))
        '(phadduwq xmm0 (mem128+ rax))
        '(phaddwd xmm0 (mem128+ rax))
        '(phaddwq xmm0 (mem128+ rax))
        '(phsubbw xmm0 (mem128+ rax))
        '(phsubdq xmm0 (mem128+ rax))
        '(phsubwd xmm0 (mem128+ rax))
        '(pmacsdd xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmacsdqh xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmacsdql xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmacssdd xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmacssdqh xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmacssdql xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmacsswd xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmacssww xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmacswd xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmacsww xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmadcsswd xmm0 xmm1 (mem128+ rax) xmm0)
        '(pmadcswd xmm0 xmm1 (mem128+ rax) xmm0)
        '(pperm xmm0 xmm0 xmm3 (mem128+ rax))
        '(pperm xmm0 xmm0 (mem128+ rax) xmm4)
        '(pperm xmm0 xmm2 (mem128+ rax) xmm0)
        '(pperm xmm0 (mem128+ rax) xmm3 xmm0)
        '(protb xmm0 xmm1 (mem128+ rax))
        '(protb xmm0 (mem128+ rax) xmm1)
        '(protb xmm0 (mem128+ rax) #x42)
        '(protd xmm0 xmm1 (mem128+ rax))
        '(protd xmm0 (mem128+ rax) xmm1)
        '(protd xmm0 (mem128+ rax) #x42)
        '(protq xmm0 xmm1 (mem128+ rax))
        '(protq xmm0 (mem128+ rax) xmm1)
        '(protq xmm0 (mem128+ rax) #x42)
        '(protw xmm0 xmm1 (mem128+ rax))
        '(protw xmm0 (mem128+ rax) xmm1)
        '(protw xmm0 (mem128+ rax) #x42)
        '(pshab xmm0 xmm1 (mem128+ rax))
        '(pshab xmm0 (mem128+ rax) xmm1)
        '(pshad xmm0 xmm1 (mem128+ rax))
        '(pshad xmm0 (mem128+ rax) xmm1)
        '(pshaq xmm0 xmm1 (mem128+ rax))
        '(pshaq xmm0 (mem128+ rax) xmm1)
        '(pshaw xmm0 xmm1 (mem128+ rax))
        '(pshaw xmm0 (mem128+ rax) xmm1)
        '(pshlb xmm0 xmm1 (mem128+ rax))
        '(pshlb xmm0 (mem128+ rax) xmm1)
        '(pshld xmm0 xmm1 (mem128+ rax))
        '(pshld xmm0 (mem128+ rax) xmm1)
        '(pshlq xmm0 xmm1 (mem128+ rax))
        '(pshlq xmm0 (mem128+ rax) xmm1)
        '(pshlw xmm0 xmm1 (mem128+ rax))
        '(pshlw xmm0 (mem128+ rax) xmm1)
        '(ptest xmm0 (mem128+ rax))
        '(roundpd xmm0 (mem128+ rax) #x42)
        '(roundps xmm0 (mem128+ rax) #x42)
        '(roundsd xmm0 (mem64+ rax) #x42)
        '(roundss xmm0 (mem32+ rax) #x42))

;;; All available JMPs
(test16 '#vu8(#xEB #x20
                   #xE9 #x1D #x00
                   #x66 #xE9 #x17 #x00 #x00 #x00
                   #xFF #x21
                   #x66 #xFF #x21
                   #xEA #x34 #x12 #x42 #x00
                   #x66 #xEA #x78 #x56 #x34 #x12 #x42 #x00
                   #xFF #x29
                   #x66 #xFF #x29)
        '(jmp (+ ip #x20))
        '(jmp (+ ip #x1D))
        '(jmp (+ ip #x17))
        '(jmp (mem16+ bx di))
        '(jmp (mem32+ bx di))
        '(jmpf (: #x42 #x1234))
        '(jmpf (: #x42 #x12345678))
        '(jmpf (mem16:16+ bx di))
        '(jmpf (mem16:32+ bx di)))

(test32 '#vu8(#xEB #x24
                   #x66 #xE9 #x20 #x00
                   #xE9 #x1B #x00 #x00 #x00
                   #x67 #x66 #xFF #x21
                   #x67 #xFF #x21
                   #xEA #x34 #x12 #x00 #x00 #x42 #x00
                   #xEA #x78 #x56 #x34 #x12 #x42 #x00
                   #x67 #xFF #x29
                   #x67 #xFF #x29)
        '(jmp (+ eip #x24))
        '(jmp (+ eip #x20))
        '(jmp (+ eip #x1B))
        '(jmp (mem16+ bx di))
        '(jmp (mem32+ bx di))
        '(jmpf (: #x42 #x1234))
        '(jmpf (: #x42 #x12345678))
        '(jmpf (mem16:32+ bx di))
        '(jmpf (mem16:32+ bx di)))

(test64 '#vu8(#xEB #x0E
                   #xE9 #x09 #x00 #x00 #x00
                   #xFF #x20
                   #xFF #x28
                   #xFF #x28
                   #x48 #xFF #x28 )
        '(jmp (+ rip #xE))
        '(jmp (+ rip #x9))
        '(jmp (mem64+ rax))
        '(jmpf (mem16:32+ rax))
        '(jmpf (mem16:32+ rax))
        '(jmpf (mem16:64+ rax)))

(test64 '#vu8(#xEB #x17
                   #xE9 #x12 #x00 #x00 #x00
                   #xFF #x20
                   #xFF #x28
                   #xFF #x28
                   #x48 #xFF #x28
                   #x0F #xB8 #xEA #xFF #xFF #xFF
                   #x0F #x00 #x30)
        '(jmp (+ rip #x17))
        '(jmp (+ rip #x12))
        '(jmp (mem64+ rax))
        '(jmpf (mem16:32+ rax))
        '(jmpf (mem16:32+ rax))
        '(jmpf (mem16:64+ rax))
        '(jmpe (+ rip #x-16))
        '(jmpe (mem32+ rax)))

;;; Various

(test64 '#vu8(#x66 #x0F #xBE #xD0
                   #x0F #xBE #xD0
                   #x48 #x0F #xBE #xD0
                   #x0F #xBF #xD0
                   #x48 #x0F #xBF #xD0
                   #x48 #x63 #xC0
                   #x66 #x0F #xB6 #xD0
                   #x0F #xB6 #xD0
                   #x48 #x0F #xB6 #xD0
                   #x0F #xB7 #xD0
                   #x48 #x0F #xB7 #xD0)
        '(movsx dx al)
        '(movsx edx al)
        '(movsx rdx al)
        '(movsx edx ax)
        '(movsx rdx ax)
        '(movsxd rax eax)
        '(movzx dx al)
        '(movzx edx al)
        '(movzx rdx al)
        '(movzx edx ax)
        '(movzx rdx ax))

(test64 '#vu8(#x0F #x23 #xC0
                   #x44 #x0F #x23 #xF8
                   #x0F #x21 #xC0
                   #x41 #x0F #x21 #xDF)
        '(mov dr0 rax)
        '(mov dr15 rax)
        '(mov rax dr0)
        '(mov r15 dr3))

(test64 '#vu8(#xA1 #x30 #x30 #x30 #x30 #x30 #x30 #x30 #x30
                   #xA0 #x30 #x30 #x30 #x30 #x30 #x30 #x30 #x30
                   #x48 #xA1 #x30 #x30 #x30 #x30 #x30 #x30 #x30 #x30
                   #x8B #x04 #x25 #x30 #x30 #x30 #x30)
        '(mov eax (mem32+ #x3030303030303030))
        '(mov al (mem8+ #x3030303030303030))
        '(mov rax (mem64+ #x3030303030303030))
        '(mov eax (mem32+ #x30303030)))

(test64 '#vu8(#x66 #x0F #x00 #xC0
                   #x0F #x00 #xC0
                   #x48 #x0F #x00 #xC0
                   #x0F #x00 #x04 #x25 #x00 #x00 #x00 #x00)
        '(sldt ax)
        '(sldt eax)
        '(sldt rax)
        '(sldt (mem16+ 0)))

(test64 '#vu8(#x0F #x38 #x00 #xC7
                   #x0F #x0F #xDC #x9E
                   #x0F #x0F #xDC #xBB)
        '(pshufb mm0 mm7)
        '(pfadd mm3 mm4)
        '(pswapd mm3 mm4))

(test64 '#vu8(#xC4 #xE3 #x69 #x49 #xC #x25 #x0 #x0 #x0 #x0 #x4E
                   #xC4 #xE3 #xE9 #x49 #xC #x25 #x0 #x0 #x0 #x0 #x3D
                   #xC4 #xE3 #x6D #x49 #xC #x25 #x0 #x0 #x0 #x0 #x4C
                   #xC4 #xE3 #xED #x49 #xC #x25 #x0 #x0 #x0 #x0 #x3B)
        '(vpermil2pd xmm1 xmm2 (mem128+ 0) xmm4 14)
        '(vpermil2pd xmm1 xmm2 xmm3 (mem128+ 0) 13)
        '(vpermil2pd ymm1 ymm2 (mem256+ 0) ymm4 12)
        '(vpermil2pd ymm1 ymm2 ymm3 (mem256+ 0) 11))

(test64 '#vu8(#x66 #xF #x55 #xC #x25 #x0 #x0 #x0 #x0
                   #xC5 #xE9 #x55 #xC #x25 #x0 #x0 #x0 #x0
                   #xC5 #xED #x55 #xC #x25 #x0 #x0 #x0 #x0
                   #xC4 #xE2 #x79 #x18 #xC #x25 #x0 #x0 #x0 #x0
                   #xC4 #xE2 #x7D #x18 #x38
                   #xC4 #x62 #x7D #x19 #x40 #x42
                   #xC4 #x42 #x7D #x1A #x3F)
        '(andnpd xmm1 (mem128+ 0))
        '(vandnpd xmm1 xmm2 (mem128+ 0))
        '(vandnpd ymm1 ymm2 (mem256+ 0))
        '(vbroadcastss xmm1 (mem32+ 0))
        '(vbroadcastss ymm7 (mem32+ rax))
        '(vbroadcastsd ymm8 (mem64+ rax #x42))
        '(vbroadcastf128 ymm15 (mem128+ r15)))

(test64 '#vu8(#xC4 #xE3 #x6D #x18 #xCB #x42
                   #xC4 #xE3 #x6D #x18 #xC #x25 #x0 #x0 #x0 #x0 #x42)
        '(vinsertf128 ymm1 ymm2 xmm3 #x42)
        '(vinsertf128 ymm1 ymm2 (mem128+ 0) #x42))

(test64 '#vu8(#xC4 #xE3 #x61 #x69 #x4 #x25 #x0 #x0 #x0 #x0 #x10
                   #xC4 #xE3 #xE9 #x69 #x4 #x25 #x0 #x0 #x0 #x0 #x10)
        '(vfmaddpd xmm0 xmm1 (mem128+ 0) xmm3)
        '(vfmaddpd xmm0 xmm1 xmm2 (mem128+ 0)))

(test64 '#vu8(#x67 #x8B #x00
                   #x8B #x00
                   #x67 #x48 #x8B #x00
                   #x48 #x8B #x00
                   #x67 #x45 #x8B #x3F
                   #x45 #x8B #x3F
                   #x67 #x4D #x8B #x3F
                   #x4D #x8B #x3F
                   #x67 #x8B #x40 #x01
                   #x67 #x8B #x44 #xD8 #x1)
        '(mov eax (mem32+ eax))
        '(mov eax (mem32+ rax))
        '(mov rax (mem64+ eax))
        '(mov rax (mem64+ rax))
        '(mov r15d (mem32+ r15d))
        '(mov r15d (mem32+ r15))
        '(mov r15 (mem64+ r15d))
        '(mov r15 (mem64+ r15))
        '(mov eax (mem32+ eax #x1))
        '(mov eax (mem32+ eax #x1 (* ebx #x8))))

(test64 '#vu8(#xC5 #xFE #xE6 #xC1
                   #xC4 #xE2 #x01 #x2F #x00
                   #xC4 #x62 #x7D #x2F #x38)
        '(vcvtdq2pd ymm0 xmm1)
        '(vmaskmovpd (mem128+ rax) xmm15 xmm0)
        '(vmaskmovpd (mem256+ rax) ymm0 ymm15))

(test64 '#vu8(#xF #x12 #x1
                  #xF #x12 #xC1
                  #xF #x16 #x1
                  #xF #x16 #xC1
                  #xF #x13 #x1
                  #xF #x17 #x1
                  #xC5 #xF0 #x12 #x1
                  #xC5 #xF0 #x12 #xC2
                  #xC5 #xF0 #x16 #x1
                  #xC5 #xF0 #x16 #xC2
                  #xC5 #xF8 #x13 #x1
                  #xC5 #xF8 #x17 #x1)
        '(movlps xmm0 (mem64+ rcx))
        '(movhlps xmm0 xmm1)
        '(movhps xmm0 (mem64+ rcx))
        '(movlhps xmm0 xmm1)
        '(movlps (mem64+ rcx) xmm0)
        '(movhps (mem64+ rcx) xmm0)
        '(vmovlps xmm0 xmm1 (mem64+ rcx))
        '(vmovhlps xmm0 xmm1 xmm2)
        '(vmovhps xmm0 xmm1 (mem64+ rcx))
        '(vmovlhps xmm0 xmm1 xmm2)
        '(vmovlps (mem64+ rcx) xmm0)
        '(vmovhps (mem64+ rcx) xmm0))

(test64 '#vu8(#x2E #x75 #xFD
                   #x3E #x75 #xFA)
        '(jnz.spnt (+ rip #x-3))
        '(jnz.sptk (+ rip #x-6)))

(test64 '#vu8(#xF0 #x4C #x0F #xB1 #x63 #x07)
        '(lock.cmpxchg (mem64+ rbx #x7) r12))

(test64 '#vu8(#xF3 #x0F #xA7 #xD8
                   #xF3 #x48 #xAB
                   #xF3 #xA7
                   #xF2 #x48 #xAF)
        '(rep.xcryptctr)
        '(rep.stosq (mem64+ rdi) rax)
        '(repz.cmpsd (mem32+ rsi) (mem32+ rdi))
        '(repnz.scasq rax (mem64+ rdi)))
