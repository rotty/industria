#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
;; Copyright © 2008, 2009, 2010 Göran Weinholt <goran@weinholt.se>
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
        (srfi :78 lightweight-testing)
        (weinholt disassembler x86))

(define (test mode input)
  (let ((port (open-bytevector-input-port input))
        (bytes-returned 0))
    (let lp ((insrs '()))
      (let ((i (get-instruction
                port mode
                (lambda (_ . bytes)
                  (set! bytes-returned
                        (+ (length bytes)
                           bytes-returned))))))
        (cond ((eof-object? i)
               (unless (port-eof? port)
                 (error 'test "After disassembly there are bytes unread."
                        (get-bytevector-all port)))
               (unless (= bytes-returned (bytevector-length input))
                 (error 'test "There are bytes missing in the collector function."
                        bytes-returned (bytevector-length input)))
               (reverse insrs))
              (else
               (lp (cons i insrs))))))))

(define-syntax test64
  (lambda (x)
    (syntax-case x ()
      ((_ bytes insrs ...)
       #'(check (test 64 bytes) => (list insrs ...))))))

(define-syntax test32
  (lambda (x)
    (syntax-case x ()
      ((_ bytes insrs ...)
       #'(check (test 32 bytes) => (list insrs ...))))))

(define-syntax test16
  (lambda (x)
    (syntax-case x ()
      ((_ bytes insrs ...)
       #'(check (test 16 bytes) => (list insrs ...))))))

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
        '(rep.lods al (mem8+ rsi))
        '(rep.lods eax (mem32+ rsi))
        '(rep.lods rax (mem64+ rsi)))

(test64 '#vu8(#xF3 #x6E
                   #xF3 #x66 #x6F
                   #xF3 #x6F
                   #x6E
                   #x66 #x6F
                   #x6F)
        '(rep.outs dx (mem8+ rsi))
        '(rep.outs dx (mem16+ rsi))
        '(rep.outs dx (mem32+ rsi))
        '(outs dx (mem8+ rsi))
        '(outs dx (mem16+ rsi))
        '(outs dx (mem32+ rsi)))

(test64 '#vu8(#xF3 #xAA
                   #xF3 #x66 #xAB
                   #xF3 #xAB
                   #xF3 #x48 #xAB
                   #x66 #xAB)
        '(rep.stos (mem8+ rdi) al)
        '(rep.stos (mem16+ rdi) ax)
        '(rep.stos (mem32+ rdi) eax)
        '(rep.stos (mem64+ rdi) rax)
        '(stos (mem16+ rdi) ax))

(test64 '#vu8(#xF3 #xA6
                   #xF2 #xA6
                   #xF3 #x48 #xA7
                   #xF2 #x66 #xA7
                   #xA6)
        '(repz.cmps (mem8+ rsi) (mem8+ rdi))
        '(repnz.cmps (mem8+ rsi) (mem8+ rdi))
        '(repz.cmps (mem64+ rsi) (mem64+ rdi))
        '(repnz.cmps (mem16+ rsi) (mem16+ rdi))
        '(cmps (mem8+ rsi) (mem8+ rdi)))

(test64 '#vu8(#xF2 #x66 #xAF
                   #xF3 #xAE
                   #x48 #xAF)
        '(repnz.scas ax (mem16+ rdi))
        '(repz.scas al (mem8+ rdi))
        '(scas rax (mem64+ rdi)))

(test64 '#vu8(#xf3 #xae
                   #xf3 #xaa
                   #xf3 #x6c
                   #xf3 #xa6
                   #xf3 #xa4
                   #xf3 #xac
                   #xf3 #x6e)
        ;;repz scas %es:(%rdi),%al
        '(repz.scas al (mem8+ rdi))
        ;;rep stos %al,%es:(%rdi)
        '(rep.stos (mem8+ rdi) al)
        ;;rep insb (%dx),%es:(%rdi)
        '(rep.ins (mem8+ rdi) dx)
        ;;repz cmpsb %es:(%rdi),%ds:(%rsi)
        '(repz.cmps (mem8+ rsi) (mem8+ rdi))
        ;;rep movsb %ds:(%rsi),%es:(%rdi)
        '(rep.movs (mem8+ rdi) (mem8+ rsi))
        ;;rep lods %ds:(%rsi),%al
        '(rep.lods al (mem8+ rsi))
        ;;rep outsb %ds:(%rsi),(%dx)
        '(rep.outs dx (mem8+ rsi)))

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
        '(jmpf (far #x42 #x1234))
        '(jmpf (far #x42 #x12345678))
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
        '(jmpf (far #x42 #x1234))
        '(jmpf (far #x42 #x12345678))
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
        '(rep.stos (mem64+ rdi) rax)
        '(repz.cmps (mem32+ rsi) (mem32+ rdi))
        '(repnz.scas rax (mem64+ rdi)))

;;; Test the special handling of NOP/PAUSE
(test16 '#vu8(#x90
              #x66 #x90
              #x48
              #x90
              #xF3 #x90
              #x87 #xC0)
        '(nop)
        '(xchg eax eax)
        '(dec ax)
        '(nop)
        '(pause)
        '(xchg ax ax))

(test32 '#vu8(#x90
              #x66 #x90
              #x48
              #x90
              #xF3 #x90
              #x87 #xC0)
        '(nop)
        '(xchg ax ax)
        '(dec eax)
        '(nop)
        '(pause)
        '(xchg eax eax))

(test64 '#vu8(#x90 
              #x66 #x90 
              #x48 #x90 
              #xF3 #x90
              #x87 #xC0
              #x41 #x90
              #x66 #x41 #x90)
        '(nop)
        '(xchg ax ax)
        '(xchg rax rax)
        '(pause)
        '(xchg eax eax)
        '(xchg r8d eax)
        '(xchg r8w ax))

(check-report)
