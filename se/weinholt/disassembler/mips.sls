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

;; Disassembler for some of MIPS II (big-endian).

;; The instruction reference I primarily used was Appendix A of
;; Patterson, Hennessy: Computer Organization and Design, The
;; Hardware/Software Interface. Third edition, revised printing.
;; Morgan Kaufmann Publishers, 2005. The appendix (written by a
;; Microsoft stooge) contains numerous typos, just like the rest of
;; the book. It's rather incredible that it was published at all,
;; considering that it contains the equivalent of FIXMEs (p. 550),
;; can't get facts straight (e.g., the maximum instruction length of
;; x86 varies between 15 and 17 (p. 140, 142), the FastMATH's page
;; size is sometimes 4kB but then "really" 16kB (p. 524, 528)),
;; contains more fluff (e.g. "Indian villager using the simputer")
;; than Joe Sixpack's belly button, and is in general poorly written
;; and difficult to learn from. The inconsistencies make it impossible
;; to trust anything written in this book. But go ahead, buy this
;; book. You will cherish the fact that half of it is written in a
;; different style and the $1.00 bounty for technical errors is sure
;; to make you a very rich man! Try googling bgczall.

;; And that's why this disassembler might give wrong disassembly.

;; cvt.d.w and cvt.s.w are not implemented, because the opcode map in
;; the book couldn't fit them (what, FPU instructions have an fmt
;; field?) and then I couldn't be bothered.

;; TODO: call the collect routine, use the same illegal instruction
;; behavior as the x86 disassembler. The collect routine could
;; possibly indicate the instruction format.

(library (se weinholt disassembler mips)
  (export get-instruction)
  (import (rnrs))

  (define (print . x)
    (when #f
      (for-each display x) (newline)))

  (define opcodes
    '#(op0
       op1 (j target) (jal target)
       (beq rs rt label) (bne rs rt label) (blez rs label) (bgtz rs label)
       ;; 08
       (addi rt rs imm) (addiu rt rs imm) (slti rt rs imm) (sltiu rt rs imm)
       (andi rt rs imm) (ori rt rs imm) (xori rt rs imm) (lui rt imm)
       ;; 10
       fp fp fp fp
       (beql rs rt label) (bnel rs rt label) (blezl rs label) (bgtzl rs label)
       #f #f #f #f op1c #f #f #f
       ;; 20
       (lb rt address) (lh rt address) (lwl rt address) (lw rt address)
       (lbu rt address) (lhu rt address) (lwr rt address) #f
       (sb rt address) (sh rt address) (swl rt address) (sw rt address)
       #f #f (swr rt address) (cache imm16:20 address)
       ;; 30
       (ll rt address) (lwc1 ft address) (lwc2 ft address) (lwc3 ft address) #f (ldc1 ft address) (ldc2 ft address) #f
       (sc rt address) (swc1 ft address) (swc2 ft address) (swc3 ft address) #f (sdc1 ft address) (sdc2 ft address) #f))

  (define opcodes-op0
    '#((sll rd rt shamt) movf/t (srl rd rt shamt) (sra rd rt shamt)
       (sllv rd rt rs) #f (srlv rd rt rs) (srav rd rt rs)
       ;; 08
       (jr rs) (jalr rs rd) (movz rd rs rt) (movn rd rs rt) (syscall) (break code) #f (sync)
       ;; 10
       (mfhi rd) (mthi rs) (mflo rd) (mtlo rs) #f #f #f #f
       (mult rs rt) (multu rs rt) (div rs rt) (divu rs rt) #f #f #f #f
       ;; 20
       (add rd rs rt) (addu rd rs rt)
       (sub rd rs rt) (subu rd rs rt)
       (and rd rs rt) (or rd rs rt) (xor rd rs rt) (nor rd rs rt)
       #f #f (slt rd rs rt) (sltu rd rs rt) #f #f #f #f
       ;; 30
       (tge rs rt) (tgeu rs rt) (tlt rs rt) (tltu rs rt) (teq rs rt) #f (tne rs rt) #f
       #f #f #f #f #f #f #f #f))

  (define opcodes-op1
    '#((bltz rs label) (bgez rs label) (bltzl rs label) (bgezl rs label) #f #f #f #f
       ;; 08
       (tgei rs imms) (tgeiu rs imms) (tlti rs imms) (tltiu rs imms) (teqi rs imms) #f (tnei rs imms) #f
       ;; 10
       (bltzal rs label) (bgezal rs label) (bltzall rs label) (bgezall rs label) #f #f #f #f
       #f #f #f #f #f #f #f #f))

  (define opcodes-fp
    '#((add. fd fs ft) (sub. fd fs ft) (mul. fd fs ft) (div. fd fs ft)
       (sqrt. fd fs) (abs. fd fs) (mov. fd fs) (neg. fd fs)
       #f #f #f #f
       (round.w. fd fs) (trunc.w. fd fs) (ceil.w. fd fs) (floor.w. fd fs)
       ;; 10
       #f movf/t. (movz. fd fs rt) (movn. fd fs rt) #f #f #f #f
       #f #f #f #f #f #f #f #f
       ;; 20
       (cvt.s. fd fs) (cvt.d. fd fs) #f #f (cvt.w. fd fs) #f #f #f
       #f #f #f #f #f #f #f #f
       ;; 30
       (c.f. ccd fs ft) (c.un. ccd fs ft) (c.eq. ccd fs ft) (c.ueq. ccd fs ft)
       (c.olt. ccd fs ft) (c.ult. ccd fs ft) (c.ole. ccd fs ft) (c.ule. ccd fs ft)
       (c.sf. ccd fs ft) (c.ngle. ccd fs ft) (c.seq. ccd fs ft) (c.ngl. ccd fs ft)
       (c.lt. ccd fs ft) (c.nge. ccd fs ft) (c.le. ccd fs ft) (c.ngt. ccd fs ft)))

  (define opcodes-op1c
    '#((madd rs rt) (maddu rs rt) (mul rd rs rt) #f (msub rs rt) (msubu rs rt) #f #f
       #f #f #f #f #f #f #f #f
       ;; 10
       #f #f #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f
       ;; 20
       (clz rd rs) (clo rd rs) #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f
       ;; 30
       #f #f #f #f #f #f #f #f
       #f #f #f #f #f #f #f #f))

  (define (get-u32 port)
    (let ((bv (get-bytevector-n port 4)))
      (and (bytevector? bv)
           (= (bytevector-length bv) 4)
           (bytevector-u32-ref bv 0 (endianness big)))))

  (define (reg x)
    (vector-ref '#($zero $at $v0 $v1 $a0 $a1 $a2 $a3
                         $t0 $t1 $t2 $t3 $t4 $t5 $t6 $t7
                         $s0 $s1 $s2 $s3 $s4 $s5 $s6 $s7
                         $t8 $t9 $k0 $k1 $gp $sp $fp $ra)
                x))

  (define (cpreg x)
    (string->symbol (string-append "$" (number->string x))))

  (define (freg x)
    (string->symbol (string-append "$f" (number->string x))))

  (define (fccreg x)
    (string->symbol (string-append "$fcc" (number->string x))))

  (define (format-instruction instr encoding)
    (cons (car instr)
          (map (lambda (op)
                 (case op
                   ((rs) (reg (encoding-rs encoding)))
                   ((rt) (reg (encoding-rt encoding)))
                   ((rd) (reg (encoding-rd encoding)))

                   ((rs/cp) (cpreg (encoding-rt encoding)))
                   ((rt/cp) (cpreg (encoding-rt encoding)))
                   ((rd/cp) (cpreg (encoding-rd encoding)))

                   ((ft) (freg (bitwise-bit-field encoding 16 21)))
                   ((fs) (freg (bitwise-bit-field encoding 11 16)))
                   ((fd) (freg (bitwise-bit-field encoding 6 11)))

                   ((shamt) (encoding-shamt encoding))
                   ((imm) (bitwise-bit-field encoding 0 16))
                   ((imms) (if (bitwise-bit-set? encoding 15)
                               (- (bitwise-bit-field encoding 0 16) #x10000)
                               (bitwise-bit-field encoding 0 16)))
                   ((imm16:20) (bitwise-bit-field encoding 16 21))
                   ((target) (* 4 (bitwise-bit-field encoding 0 26)))
                   ((label) (list '$pc (* 4 (bitwise-bit-field encoding 0 16))))
                   ((address) (list (reg (bitwise-bit-field encoding 21 26))
                                    (bitwise-bit-field encoding 0 16)))
                   ((code) (bitwise-bit-field encoding 16 26))
                   ((cct) (fccreg (bitwise-bit-field encoding 18 21)))
                   ((ccd) (fccreg (bitwise-bit-field encoding 8 11)))))
               (cdr instr))))

  (define (encoding-opcode x) (bitwise-bit-field x 26 32))
  (define (encoding-rs x) (bitwise-bit-field x 21 26))
  (define (encoding-rt x) (bitwise-bit-field x 16 21))
  (define (encoding-rd x) (bitwise-bit-field x 11 16))
  (define (encoding-shamt x) (bitwise-bit-field x 6 11))
  (define (encoding-funct x) (bitwise-bit-field x 0 6))

  (define (fix-fp instruction suffix)
    ;; There are numerous pseudoinstructions that could be put here
    (cons (string->symbol (string-append (symbol->string (car instruction)) suffix))
          (if (and (not (null? (cdr instruction)))
                   (eq? '$fcc0 (cadr instruction)))
              (cddr instruction)
              (cdr instruction))))

  (define (get-instruction port collect)
    (define (decode encoding)
      (let lp ((instr (vector-ref opcodes (encoding-opcode encoding))))
        (cond ((zero? encoding)
               '(nop))

              ((eq? instr 'op0)
               (lp (vector-ref opcodes-op0 (encoding-funct encoding))))

              ((eq? instr 'op1)
               (lp (vector-ref opcodes-op1 (encoding-rt encoding))))

              ((eq? instr 'op1c)
               (lp (vector-ref opcodes-op1c (encoding-funct encoding))))

              ((eq? instr 'movf/t.)
               (lp (if (bitwise-bit-set? encoding 16)
                       '(movt. fd fs cct)
                       '(movf. fd fs cct))))

              ((eq? instr 'movf/t)
               (lp (if (bitwise-bit-set? encoding 16)
                       '(movt rd rs cct)
                       '(movf rd rs cct))))

              ((eq? instr 'fp)
               (let ((z (fxand #x3 (encoding-opcode encoding))))
                 (print ";floating point, rs: #x" (number->string (encoding-rs encoding) 16))
                 (case (encoding-rs encoding)
                   ((0 2 4 6)
                    (let ((op (/ (encoding-rs encoding) 2)))
                      (lp (list (string->symbol (string-append
                                                 (list-ref '("mfc" "cfc" "mtc" "ctc") op)
                                                 (number->string z)))
                                'rt
                                (if (and (= z 1) (memq op '(0 2)))
                                    'fs 'rd/cp)))))

                   ((8)
                    (lp (cons (string->symbol
                               (string-append
                                "bc"
                                (number->string z)
                                (case (bitwise-bit-field encoding 16 18)
                                  ((0) "f")
                                  ((1) "t")
                                  ((2) "fl")
                                  ((3) "fl"))))
                              '(label))))
                   ((16)
                    (cond ((zero? z)
                           (lp (case (bitwise-bit-field encoding 0 5)
                                 ((1) '(tlbr))
                                 ((2) '(tlbwi))
                                 ((6) '(tlbwr))
                                 ((8) '(tlbp))
                                 ((24) '(eret))
                                 ((31) '(deret))
                                 (else #f))))
                          (else
                           (print ";fp.s: #x" (number->string (encoding-funct encoding) 16))
                           (fix-fp (lp (vector-ref opcodes-fp (encoding-funct encoding)))
                                   "s"))))
                   ((17)
                    (print ";fp.d: #x" (number->string (encoding-funct encoding) 16))
                    (fix-fp (lp (vector-ref opcodes-fp (encoding-funct encoding)))
                            "d"))

                   (else
                    '(illegal-instruction)))))

              ((not instr)
               (print ";Encoding: #x" (number->string encoding 16)
                      " opcode: #x" (number->string (encoding-opcode encoding) 16))
               (when (zero? (bitwise-bit-field encoding 26 32))
                 (print ";funct: #x" (number->string (encoding-funct encoding) 16)))
               '(illegal-instruction))

              (else
               (print ";Encoding: #x" (number->string encoding 16)
                      " opcode: #x" (number->string (encoding-opcode encoding) 16))
               (format-instruction instr encoding)))))
    (cond ((get-u32 port) =>
           decode)
          (else
           (eof-object)))))


#;(let ((p (open-file-input-port "/home/weinholt/code/mips/test.raw")))
    (let lp ()
      (let ((instr (get-instruction p #f)))
        (unless (eof-object? instr)
          (display instr)
          (newline)
          (lp)))))
