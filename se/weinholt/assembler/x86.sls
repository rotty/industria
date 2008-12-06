;; -*- mode: scheme; coding: utf-8 -*-
;; Assembler for the Intel x86-16/32/64 instruction set.
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

;;; Goals

;; One goal is to be friendly to compiler writers, and not necessarily
;; to people writing assembler by hand. This can be a hard friendship,
;; e.g. the assembler should *never* truncate immediates. It should
;; not accept instructions that could lead to machine code the
;; compiler did not precisely specify.

;; 16-bit mode is left out.

;;; Documentation

;; See documentation/x86.txt

;;; TODO

;; Optimize: Jz, Jb and RIP-relative displacements.

;; FIXME: when evaluating expressions and a label is unknown in the
;; second pass, give an error.

;; TODO: SSE5 (DREX byte), AVX (VEX prefix), etc

;; FIXME: unify the names for address size, operand size, data size,
;; addressing mode....

(library (se weinholt assembler x86 (1 0 0))
    (export assemble)
    (import (rnrs)
            (se weinholt assembler x86-operands (1 0 (>= 0)))
            (se weinholt assembler x86-misc (1 0 (>= 0)))
            (se weinholt disassembler x86-opcodes (1 0 (>= 0))))

  (define debug #t)

  (define (print . x)
    (when debug
      (for-each display x) (newline)))

  (define (list-prefix? prefix list)
    (cond ((null? prefix)
           #t)
          ((eq? (car prefix) (car list))
           (list-prefix? (cdr prefix)
                         (cdr list)))
          (else #f)))

  (define (string-index s c)
    (let lp ((i 0))
      (cond ((= (string-length s) i) #f)
            ((char=? (string-ref s i) c) i)
            (else (lp (+ i 1))))))

  (define (string-split1 s c)
    (let ((i (string-index s c)))
      (and i (list (substring s 0 i)
                   (substring s (+ 1 i) (string-length s))))))

;;;

  (define min-s8 (- (expt 2 7)))
  (define max-u8 (- (expt 2 8) 1))

  (define min-s16 (- (expt 2 15)))
  (define max-u16 (- (expt 2 16) 1))

  (define REX.bare #b01000000)
  (define REX.W    #b01001000)
  (define REX.R    #b01000100)
  (define REX.X    #b01000010)
  (define REX.B    #b01000001)

  (define segment-overrides
    '#(#x26 #x2E #x36 #x3E #x64 #x65))

  (define-syntax prefix-byte
    (lambda (x)
      (syntax-case x (operand address rep repz repnz lock)
        ((_ operand) #x66)
        ((_ address) #x67)
        ((_ rep) #xF3)
        ((_ repz) #xF3)
        ((_ repnz) #xF2)
        ((_ lock) #xF0))))

;;; Operand syntax handling

  (define (memory-base-only mem)
    ;; Returns #f if the addressing mode has a disp or index,
    ;; otherwise returns the index of the base register.
    (and (expression-in-range? (memory-expr mem) 0 0)
         (= (memory-scale mem) 1)
         (not (memory-index mem))
         (memory-base mem)
         (register-index (memory-base mem))))

  (define opsyntaxen
    (let ((tmp (make-eq-hashtable)))
      (hashtable-set! tmp 'Mdq
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (memory? o)
                              (eqv? (memory-datasize o) 128)))
                       'mem
                       'Mdq))
      (hashtable-set! tmp 'Mq
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (memory? o)
                              (eqv? (memory-datasize o) 64)))
                       'mem
                       'Mq))
      (hashtable-set! tmp 'Md
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (memory? o)
                              (eqv? (memory-datasize o) 32)))
                       'mem
                       'Md))
      (hashtable-set! tmp 'Mw
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (memory? o)
                              (eqv? (memory-datasize o) 16)))
                       'mem
                       'Mw))
      (hashtable-set! tmp 'Ms
                      (vector
                       #f
                       (lambda (o opsize mode)
                         ;; Segment descriptor
                         (and (memory? o)
                              (not (memory-datasize o))))
                       'mem
                       'Ms))

      ;; xmm
      (hashtable-set! tmp 'Vpd
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eq? (register-type o) 'xmm)))
                       'reg
                       'Vpd))
      (hashtable-set! tmp 'Wpd
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (cond ((register? o)
                                (eq? (register-type o) 'xmm))
                               ((memory? o)
                                (memv (memory-datasize o) '(#f 128)))
                               (else #f)))
                       'r/m
                       'Wpd))


      (hashtable-set! tmp '*st
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eq? (register-type o) 'x87)))
                       'r/m
                       '*st))
      (hashtable-set! tmp '*st0
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eq? (register-type o) 'x87)
                              (zero? (register-index o))))
                       #f
                       '*st0))

      (hashtable-set! tmp 'Ev
                      (vector
                       'operand-size
                       (lambda (o opsize mode)
                         (cond ((register? o)
                                (memv (register-type o) '(16 32 64)))
                               ((memory? o)
                                ;; FIXME: Or unsized data?
                                (memv (memory-datasize o) '(#f 16 32 64)))
                               (else #f)))
                       'r/m             ;register is encoded in r/m and REX.B
                       'Ev))
      (hashtable-set! tmp 'Eq/w
                      (vector
                       'operand-size64
                       (lambda (o opsize mode)
                         (cond ((register? o) (memv (register-type o) '(16 64)))
                               ((memory? o) (memv (memory-datasize o) '(#f 16 64)))
                               (else #f)))
                       'r/m
                       'Eq/w))
      (hashtable-set! tmp 'Ew
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (cond ((register? o) (eqv? (register-type o) 16))
                               ((memory? o) (memv (memory-datasize o) '(#f 16)))
                               (else #f)))
                       'r/m
                       'Ew))
      (hashtable-set! tmp 'Eb
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (cond ((register? o)
                                (memq (register-type o) '(8 rex8 norex8)))
                               ((memory? o)
                                ;; FIXME: Or unsized data?
                                (memq (memory-datasize o) '(#f 8 rex8 norex8)))
                               (else #f)))
                       'r/m
                       'Eb))

      (hashtable-set! tmp 'Gv
                      (vector
                       'operand-size
                       (lambda (o opsize mode)
                         (and (register? o)
                              (memv (register-type o) '(16 32 64))))
                       'reg             ;register is encoded in ModR/M.reg etc
                       'Gv))
      (hashtable-set! tmp 'Gb
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eqv? (register-type o) 8)))
                       'reg             ;register is encoded in ModR/M.reg etc
                       'Gb))

      ;; These are very limited: must be ES:DI, ES:EDI or RDI.
      (hashtable-set! tmp 'Yv
                      (vector
                       'operand-size
                       (lambda (o opsize mode)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 16 32 64))
                              (eqv? (memory-base-only o) 7) ;rDI
                              ;; Check ES
                              (case mode
                                ((64) (not (memory-segment o)))
                                (else (and (register? (memory-segment o))
                                           (zero? (register-index (memory-segment o))))))))
                       #f
                       'Yv))
      (hashtable-set! tmp 'Yb
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 8))
                              (eqv? (memory-base-only o) 7) ;rDI
                              ;; Check ES
                              (case mode
                                ((64) (not (memory-segment o)))
                                (else (and (register? (memory-segment o))
                                           (zero? (register-index (memory-segment o))))))))
                       #f
                       'Yb))

      (hashtable-set! tmp 'Xv
                      (vector
                       'operand-size
                       (lambda (o opsize mode)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 16 32 64))
                              (eqv? (memory-base-only o) 6))) ;rSI
                       #f               ;implicit
                       'Xv))

      (hashtable-set! tmp 'Xb
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 8))
                              (eqv? (memory-base-only o) 6))) ;rSI
                       #f               ;implicit
                       'Xb))


      ;;
      (hashtable-set! tmp 'Rd/q
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eqv? (register-type o) mode)))
                       'r/m
                       'Rd/q))

      (hashtable-set! tmp 'Cd/q
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eqv? (register-type o) 'creg)))
                       'reg
                       'Cd/q))

      (hashtable-set! tmp 'Dd/q
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eqv? (register-type o) 'dreg)))
                       'reg
                       'Dd/q))


      ;; Immediates
      (hashtable-set! tmp 'Iz
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (or (expression? o)
                             ;; FIXME: it's never an integer...
                             (and (integer? o)
                                  (case opsize
                                    ((64 #f)
                                     ;; This immediate will be encoded
                                     ;; using 32 bits and then the
                                     ;; processor will sign-extend it to
                                     ;; 64 bits. Here is the easy and dumb
                                     ;; way to test if a constant will fit
                                     ;; in this encoding.
                                     (let* ((unsigned (if (negative? o) (+ #xffffffffffffffff o) o))
                                            (trunc (bitwise-and #xffffffff unsigned))
                                            (sign-extended (if (bitwise-bit-set? trunc 31)
                                                               (bitwise-ior #xffffffff00000000 trunc)
                                                               trunc)))
                                       (= unsigned sign-extended)))
                                    ((32) (<= (- (expt 2 31)) o (- (expt 2 32) 1)))
                                    ((16) (<= (- (expt 2 15)) o (- (expt 2 16) 1)))
                                    (else #f)))))
                       'immZ
                       'Iz))
      (hashtable-set! tmp 'Iv
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (or (expression? o)
                             ;; FIXME: it's never an integer...
                             (and (integer? o)
                                  (case opsize
                                    ((64) (<= (- (expt 2 63)) o (- (expt 2 64) 1)))
                                    ((32) (<= (- (expt 2 31)) o (- (expt 2 32) 1)))
                                    ((16) (<= (- (expt 2 15)) o (- (expt 2 16) 1)))
                                    (else #f)))))
                       'imm
                       'Iv))
      (hashtable-set! tmp 'Ib
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (expression? o)
                              (expression-in-range? o min-s8 max-u8)))
                       'imm8
                       'Ib))
      (hashtable-set! tmp 'Iw
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (expression? o)
                              (expression-in-range? o min-s16 max-u16)))
                       'imm16
                       'Iw))

      ;; Implicitly encoded registers
      (hashtable-set! tmp '*AL
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eqv? (register-type o) 8)
                              (= (register-index o) 0)))
                       #f               ;implicit
                       '*AL))
      (hashtable-set! tmp '*CL
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eqv? (register-type o) 8)
                              (= (register-index o) 2)))
                       #f               ;implicit
                       '*CL))
      (hashtable-set! tmp '*eAX
                      (vector
                       'operand-size
                       (lambda (o opsize mode)
                         (and (register? o)
                              (memv (register-type o) '(16 32))
                              (= (register-index o) 0)))
                       #f               ;implicit
                       '*eAX))
      (hashtable-set! tmp '*DX
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (and (register? o)
                              (eqv? (register-type o) 16)
                              (= (register-index o) 2)))
                       #f               ;implicit
                       '*DX))
      (hashtable-set! tmp '*rAX
                      (vector
                       'operand-size
                       (lambda (o opsize mode)
                         (and (register? o)
                              (memv (register-type o) '(16 32 64))
                              (= (register-index o) 0)))
                       #f               ;implicit
                       '*rAX))
      (hashtable-set! tmp '*rAX/r8
                      (vector
                       'operand-size
                       (lambda (o opsize mode)
                         (and (register? o)
                              (memv (register-type o) '(16 32 64))
                              (= (bitwise-and (register-index o) #b111) 0)))
                       #f               ;implicit
                       '*rAX/r8))
      (hashtable-set! tmp '*rBX/r11
                      (vector
                       'operand-size
                       (lambda (o opsize mode)
                         (and (register? o)
                              (memv (register-type o) '(16 32 64))
                              (= (bitwise-and (register-index o) #b111) 3)))
                       #f               ;implicit
                       '*rBX/r11))

      (hashtable-set! tmp '*unity
                      (vector
                       'operand-size
                       (lambda (o opsize mode)
                         (eqv? o 1))
                       #f
                       '*unity))

      ;; Jump offset

      (hashtable-set! tmp 'Jz
                      (vector
                       'operand-size64
                       (lambda (o opsize mode)
                         (expression? o))
                       'destZ
                       'Jz))

      (hashtable-set! tmp 'Ap
                      (vector
                       #f
                       (lambda (o opsize mode)
                         (far-pointer? o))
                       'seg:off
                       'Ap))

      tmp))

  (define (translate-opsyntax opsyntax)
    (let ((o (hashtable-ref opsyntaxen opsyntax #f)))
      (unless o
        (print "Unimplemented opsyntax: " opsyntax))
      ;;       (unless o
      ;;         (error 'translate-opsyntax "Unimplemented operand syntax" opsyntax))
      ;;       o
      (or o opsyntax)))

  (define (opsyntax-default-segment=? opsyntax seg)
    (case (vector-ref opsyntax 3)
      ((Yb Yv Yz) (= seg 0))            ;ES default
      ((Xb Xv Xz) (= seg 3))            ;DS default
      (else #f)))

  (define (opsyntax-requires-operand-size-override? opsyntax)
    (memq (vector-ref opsyntax 0) '(operand-size)))

  (define (opsyntax-encoding-position opsyntax)
    ;; Returns #f if the operand is implicit in the opcode. Returns
    ;; reg or r/m when the operand is encoded in ModR/M.
    (vector-ref opsyntax 2))

  (define (operand-compatible-with-opsyntax? operand opsyntax opsize mode)
    ;; FIXME: no need to change into boolean here?
    (if ((vector-ref opsyntax 1) operand opsize mode) #t #f))

  (define (opsyntax-default-operand-size opsyntax mode)
    (if (and (eq? (vector-ref opsyntax 0) 'operand-size64)
             (= mode 64))
        64
        #f))

;;; Opcode map transformation

  (define (walk-opcodes f instr bytes)
    (cond
     ((not instr)
      #f)

     ((and (list? instr) (eq? (car instr) '*prefix*))
      #f)

     ((list? instr)
      (f instr (reverse bytes)))

     ((eq? (vector-ref instr 0) 'Group)
      (letrec ((walk-modr/m-table
                (lambda (table mod)
                  (vector-for-each
                   (lambda (i reg)
                     (if (and (vector? i) (= (vector-length i) 8))
                         (vector-for-each
                          (lambda (i r/m)
                            (walk-opcodes
                             f i (cons (make-modr/m mod reg r/m)
                                       bytes)))
                          i
                          '#(0 1 2 3 4 5 6 7))
                         (walk-opcodes f i (cons (list 'reg= reg) bytes))))
                   table
                   '#(0 1 2 3 4 5 6 7)))))
        (walk-modr/m-table (vector-ref instr 2) #b00)
        (if (> (vector-length instr) 3)
            (walk-modr/m-table (vector-ref instr 3) #b11)
            '())))

     ((eq? (vector-ref instr 0) 'Prefix)
      (walk-opcodes f (vector-ref instr 1) bytes)
      (walk-opcodes f (vector-ref instr 2) (append bytes (list (list 'prefix #xF3))))
      (walk-opcodes f (vector-ref instr 3) (append bytes (list (list 'prefix #x66))))
      (walk-opcodes f (vector-ref instr 4) (append bytes (list (list 'prefix #xF2)))))

     ((eq? (vector-ref instr 0) 'Datasize)
      (walk-opcodes f (vector-ref instr 1) (append bytes (list 'data16)))
      (walk-opcodes f (vector-ref instr 2) (append bytes (list 'data32)))
      (walk-opcodes f (vector-ref instr 3) (append bytes (list 'data64))))

     ((eq? (vector-ref instr 0) 'Addrsize)
      (walk-opcodes f (vector-ref instr 2) (append bytes (list 'addr32)))
      (walk-opcodes f (vector-ref instr 3) (append bytes (list 'addr64))))

     ((eq? (vector-ref instr 0) 'Mode)
      (walk-opcodes f (vector-ref instr 1) (append bytes (list 'legacy-mode)))
      (walk-opcodes f (vector-ref instr 2) (append bytes (list 'long-mode))))

     ((eq? (vector-ref instr 0) 'VEX)   ;FIXME: handle this
      (walk-opcodes f (vector-ref instr (if (= (vector-length instr) 3) 2 3))
                    (append bytes (list 'vex.256)))
      (walk-opcodes f (vector-ref instr 2) (append bytes (list 'vex.128)))
      (walk-opcodes f (vector-ref instr 1) bytes))

     ((eq? (vector-ref instr 0) 'Mem/reg) ;FIXME: handle this
      (walk-opcodes f (vector-ref instr 1) (append bytes (list 'mem)))
      (walk-opcodes f (vector-ref instr 2) (append bytes (list 'reg))))

     (else
      (do ((index 0 (+ index 1)))
          ((= index 256))
        (walk-opcodes f (vector-ref instr index)
                      (cons index bytes))))))

  (define (template-opsyntax x)
    (vector-ref x 0))

  (define (template-encoding x)
    (vector-ref x 1))

  (define (encoding-ModR/M encoding)
    (cond ((null? encoding)
           #f)
          ((and (list? (car encoding))
                (eq? (caar encoding) 'reg=))
           (make-modr/m 0 (cadar encoding) 0))
          (else
           (encoding-ModR/M (cdr encoding)))))

  (define (encoding-mode-is-acceptable? mode encoding)
    (cond ((memq 'legacy-mode encoding)
           (= mode 32))
          ((memq 'long-mode encoding)
           (= mode 64))
          (else #t)))

  (define (encoding-opcode-bytes encoding)
    (filter integer? encoding))

  (define (encoding-needs-VEX? encoding)
    (or (memq 'vex.128 encoding)
        (memq 'vex.256 encoding)))

  (define (encoding-VEX.L encoding)
    (cond ((memq 'vex.128 encoding) 0)
          ((memq 'vex.256 encoding) 1)
          (else (error 'encoding-VEX.L
                       "Encoding does not specify VEX at all"
                       encoding))))

  (define (encoding-sse-prefix encoding)
    (cond ((null? encoding)
           #f)
          ((and (list? (car encoding))
                (eq? (caar encoding) 'prefix))
           (cadar encoding))
          (else
           (encoding-sse-prefix (cdr encoding)))))

  (define (encoding-operand-size encoding)
    (cond ((memq 'data16 encoding) 16)
          ((memq 'data32 encoding) 32)
          ((memq 'data64 encoding) 64)
          (else #f)))

  (define (encoding-address-size encoding)
    (cond ((memq 'addr32 encoding) 32)
          ((memq 'addr64 encoding) 64)
          (else #f)))

;;; Instruction lookup

  (define instructions
    (let ((tmp (make-eq-hashtable)))
      (walk-opcodes (lambda (instruction encoding)
                      (let ((mnemonic (car instruction)))
                        ;;(print instruction " -- " encoding)
                        (hashtable-update!
                         tmp mnemonic
                         (lambda (old)
                           (cons (vector (map translate-opsyntax (cdr instruction))
                                         encoding)
                                 old))
                         '())))
                    opcodes '())
      (for-each (lambda (m)
                  (hashtable-set! tmp (car m) (hashtable-ref tmp (cdr m) #f)))
                mnemonic-aliases)
      tmp))

  (define pseudo-instructions
    (let ((tmp (make-eq-hashtable)))
      (for-each (lambda (p)
                  (let ((real (car p))
                        (immediate (cadr p))
                        (pseudo (caddr p)))
                    (hashtable-set! tmp pseudo (cons real immediate))))
                pseudo-mnemonics)
      tmp))

  (define shorthand-instructions
    (let ((tmp (make-eq-hashtable)))
      (for-each (lambda (p) (hashtable-set! tmp (car p) (cdr p)))
                '((fadd . (faddp st1 st0)) ;from 387intel.txt
                  (faddp . (faddp st1 st0))
                  (fcmovb . (fcmovb st0 st1))
                  (fcmovbe . (fcmovbe st0 st1))
                  (fcmove . (fcmove st0 st1))
                  (fcmovnb . (fcmovnb st0 st1))
                  (fcmovnbe . (fcmovnbe st0 st1))
                  (fcmovne . (fcmovne st0 st1))
                  (fcmovnu . (fcmovnu st0 st1))
                  (fcmovu . (fcmovu st0 st1))
                  (fcom . (fcom st0 st1))
                  (fcomi . (fcomi st0 st1))
                  (fcomip . (fcomip st0 st1))
                  (fcomp . (fcomp st0 st1))
                  (fdiv . (fdivp st1 st0))
                  (fdivp . (fdivp st1 st0))
                  (fdivr . (fdivrp st1 st0))
                  (fdivrp . (fdivrp st1 st0))
                  (fld . (fld st0 st1))
                  (fmul . (fmulp st1 st0))
                  (fmulp . (fmulp st1 st0))
                  (fst . (fst st1))
                  (fstp . (fstp st1))
                  (fsub . (fsubp st1 st0))
                  (fsubp . (fsubp st1 st0))
                  (fsubr . (fsubrp st1 st0))
                  (fsubrp . (fsubrp st1 st0))
                  (fucom . (fucom st1 st0))
                  (fucomi . (fucomi st0 st1))
                  (fucomip . (fucomip st0 st1))
                  (fucomp . (fucomp st1))
                  (fxch . (fxch st0 st1))))

      tmp))

  (define (find-instruction-encoding instr mode prefixes)
    ;; This function takes an instruction in the input format and
    ;; finds a suitable encoding for it. It handles instruction
    ;; prefixes and pseudo mnemonics.
    (let ((mnemonic (car instr))
          (operands (cdr instr)))
      (define (bailout msg)
        (error 'find-instruction-encoding msg instr mode))
      (define (try-prefix unknown-mnemonic?)
        (cond ((string-split1 (symbol->string mnemonic) #\.) =>
               (lambda (mnemonics)
                 (let ((mnemonics (map string->symbol mnemonics)))
                   (define (use-prefix name)
                     (find-instruction-encoding (cons (cadr mnemonics) operands)
                                                mode (cons name prefixes)))
                   (unless (= (length mnemonics) 2) (bailout "There are too many dots in the mnemonic"))
                   (cond ((eq? (car mnemonics) 'lock)
                          (unless (memq (cadr mnemonics) lock-instructions)
                            (bailout "This instruction does not support the LOCK prefix"))
                          (unless (and (not (null? operands)) (list? (car operands)))
                            (bailout "The LOCK prefix requires a memory destination operand"))
                          (use-prefix (prefix-byte lock)))
                         ((eq? (car mnemonics) 'rep)
                          (unless (memq (cadr mnemonics) rep-instructions)
                            (bailout "This instruction does not support the REP prefix"))
                          (use-prefix (prefix-byte rep)))
                         ((memq (car mnemonics) '(repz repe))
                          (unless (memq (cadr mnemonics) repz-instructions)
                            (bailout "This instruction does not support the REPZ prefix"))
                          (use-prefix (prefix-byte repz)))
                         ((memq (car mnemonics) '(repnz repne))
                          (unless (memq (cadr mnemonics) repz-instructions)
                            (bailout "This instruction does not support the REPNZ prefix"))
                          (use-prefix (prefix-byte repnz)))
                         (else (bailout))))))
              (unknown-mnemonic? (bailout "Unknown mnemonic"))
              (else (bailout "Wrong number of operands"))))
      (define (try-pseudo unknown-mnemonic?)
        (cond ((hashtable-ref pseudo-instructions mnemonic #f) =>
               (lambda (pseudo)
                 ;; Replace the mnemonic and append an immediate
                 (find-instruction-encoding
                  (cons (car pseudo)
                        (append (cdr instr)
                                (list (cdr pseudo)))) mode prefixes)))
              ((and (null? operands)
                    (hashtable-ref shorthand-instructions mnemonic #f)) =>
                    (lambda (shorthand)
                      (find-instruction-encoding shorthand mode prefixes)))
              (else (try-prefix unknown-mnemonic?))))
      (cond ((hashtable-ref instructions mnemonic #f) =>
             (lambda (templates)
               (let ((templates (filter (lambda (x)
                                          (= (length (template-opsyntax x))
                                             (length operands)))
                                        templates)))
                 (if (null? templates)
                     (try-pseudo #f)
                     (let ((operands (translate-operands operands mode)))
                       ;; TODO: a better idea might be to enumerate
                       ;; every possible way to encode each
                       ;; instruction, i.e. all operand sizes with
                       ;; operand size prefix included etc. Put all
                       ;; this in a hashtable, where the key is the
                       ;; mnemonic and how the operands could be
                       ;; encoded. Pre-determine which encoding is the
                       ;; most optimal for all combinations of
                       ;; operands. Encoding an instruction then is
                       ;; then like dispatching a method in a rather
                       ;; strange language with dispatching on
                       ;; function types. Just translate the types of
                       ;; the operands in the instruction and look it
                       ;; up in the hashtable mentioned earlier. The
                       ;; opsyntax table needs a list of example
                       ;; operands that are acceptable as input, one
                       ;; of each type. These can also be used in
                       ;; documentation. And lookup is O(1).
                       (print "% " operands)
                       (let lp ((templates templates))
                         (if (null? templates)
                             (error 'find-instruction-encoding
                                    "There is no implemented encoding for this combination of operands"
                                    instr operands mode)
                             (let* ((template (car templates))
                                    (eos (encoding-operand-size (template-encoding template)))
                                    (eas (encoding-address-size (template-encoding template)))
                                    (os (instruction-operand-size eos operands (template-opsyntax template)))
                                    (as (instruction-address-size eas operands)))
                               (print "- " (template-opsyntax template) " - " (template-encoding template))
                               (if (and (encoding-mode-is-acceptable? mode (template-encoding template))
                                        (instruction-encodable? operands template mode os))
                                   (let ((dos (instruction-default-operand-size (template-opsyntax template) mode))
                                         (das mode))
                                     (values dos das os as prefixes operands
                                             (template-opsyntax template) (template-encoding template)))
                                   (lp (cdr templates)))))))))))
            (else (try-pseudo #t)))))

  (define (instruction-encodable? operands template mode os)
    (call/cc
     (lambda (return)
       ;;        (print template)
       ;; This operand size and address size stuff is somewhat tricky,
       ;; and can likely be improved a lot. They are needed in order
       ;; to emit the right operand/address size override prefix. The
       ;; opsyntax table knows if an operand must have the same size
       ;; as the instruction operand size attribute. If it does, then
       ;; the size of the given operand is checked here. The template
       ;; encoding can also require that an operand size override be
       ;; emitted, and that is equivalent to having the mnemonic give
       ;; the size of the operation.
       (let* ((opsyntax (template-opsyntax template)))
         (and (for-all vector? opsyntax) ;FIXME: unimplemented opsyntax
              (cond ((for-all (lambda (operand opsyntax)
                                (operand-compatible-with-opsyntax? operand opsyntax os mode))
                              operands opsyntax)
                     (when (and (exists opsyntax-requires-operand-size-override? opsyntax)
                                (not os))
                       (error 'instruction-encodable?
                              "This instruction needs an explicit operand size" operands))
                     #t)
                    (else #f)))))))

  (define (operand-size operand opsyntax)
    (and (vector? opsyntax)             ;FIXME:temporary:unimplemented opsyntax
         (opsyntax-requires-operand-size-override? opsyntax)
         (cond ((register? operand)
                (register-type operand))
               ((memory? operand)
                (memory-datasize operand))
               ((expression? operand)
                (expression-operand-size operand))
               (else #f))))

  (define (address-size operand)
    (and (memory? operand) (memory-addressing-mode operand)))

  (define (instruction-operand-size default operands opsyntaxen)
    ;; Finds the operand size for the instruction, which is used to
    ;; decide if an operand size override needs to be emitted and so
    ;; on. The operands and opsyntaxen have already been parsed.
    (let ((sizes (filter (lambda (x)
                           (memv x '(16 32 64)))
                         (cons default (map operand-size operands opsyntaxen)))))
      (cond ((null? sizes) #f)
            (else
             (unless (apply = sizes)
               (error 'instruction-operand-size
                      "Incompatible operand sizes used" operands opsyntaxen))
             (car sizes)))))

  (define (instruction-default-operand-size opsyntaxen mode)
    (let ((sizes (filter (lambda (x)
                           (memv x '(16 32 64)))
                         (map (lambda (o) (opsyntax-default-operand-size o mode)) opsyntaxen))))
      (if (null? sizes) 32 (car sizes))))


  (define (instruction-address-size default operands)
    (let ((sizes (filter number? (cons default (map address-size operands)))))
      (if (null? sizes) #f (car sizes))))

;;; Instruction encoding

  ;; Instructions are a combination of mnemonic and operands. The
  ;; operands are registers, memory or expressions.

  (define (encode-operands! operands opsyntax os as state)
    ;; This function encodes only immediates and displacements.

    ;; FIXME: handle different operand sizes

    ;; FIXME: handle the sign extension stuff...

    (define (encode-operand! operand opsyntax)
      ;; return #(value bits) if ip-relative, bytevector if not.
      (cond ((expression? operand)
             (let ((value (eval-expression operand (assembler-state-labels state))))
               (unless value
                 (print "I CAN'T GET NO SATISFACTION! (expr=" operand ")")
                 (assembler-state-relocs-set! state #t))
               (case (opsyntax-encoding-position opsyntax)
                 ((imm) (number->bytevector (or value 0) os))
                 ((imm8) (number->bytevector (or value 0) 8))
                 ((imm16) (number->bytevector (or value 0) 16))
                 ((immZ)
                  ;; If the operand size is 64 bit, then the
                  ;; immediate value here is encoded in 32
                  ;; bits and sign-extended.
                  (number->bytevector (or value 0) (if (= os 64) 32 os)))
                 ((destZ)
                  (vector (or value 0) 32))
                 ((#f) #f)
                 (else
                  (error 'put-instruction "Unimplemented encoding position" operand opsyntax)))))
            ((far-pointer? operand)
             (let ((offset (eval-expression (far-pointer-offset operand)
                                            (assembler-state-labels state))))
               (unless offset
                 (print "Far pointer doesn't get satisfaction either: " operand))
               ;; FIXME: 16-bit mode? And what do they look like in 64-bit mode?
               (let ((bv (make-bytevector (+ 4 2))))
                 (bytevector-u32-set! bv 0 (or offset 0) (endianness little))
                 (bytevector-u16-set! bv 4 (far-pointer-seg operand) (endianness little))
                 bv)))))
    (map encode-operand! operands opsyntax))


  ;; prefixes | opcode bytes | ModR/M | SIB | displacement | immediates
  ;; opcode bytes | ModR/M | SIB | DREX | displacement | immediates
  ;; VEX | opcode | ModR/M | SIB | displacement | /is4 | immediates

  (define (put-instruction instr state)
    ;; FIXME: detect *3dnow* and so on from the user's side
    (let ((port (assembler-state-port state))
          (mode (assembler-state-mode state))
          (pos (port-position (assembler-state-port state))))
      (call-with-values (lambda () (find-instruction-encoding instr mode '()))
        (lambda (dos das os as prefixes operands* opsyntax* encoding)
          (print "\n%%%%%%%%%% can encode now, mnemonic=" (car instr)
                 " operand-size=" (list dos os)
                 " address-size=" (list das as)
                 " prefixes=" prefixes
                 " encoding=" encoding)

          (for-each (lambda (b) (put-u8 port b)) prefixes)

          ;; Emit address size and operand size overrides
          (when (and (= das 64) (eqv? as 32))
            (put-u8 port (prefix-byte address)))
          (when (or (and (= dos 64) (eqv? os 16))
                    (and (= dos 32) (eqv? os 16))
                    (and (= dos 16) (eqv? os 32)))
            (put-u8 port (prefix-byte operand)))
          (when (and (eqv? os 32) (= dos 64))
            (error 'put-instruction
                   "32-bit operand sizes are not encodable for this instruction in 64-bit mode" instr))
          (when (and (eqv? os 64) (< mode 64))
            (error 'put-instruction
                   "64-bit operand sizes are only available in 64-bit mode" instr))

          (let lp ((operands operands*)
                   (opsyntax opsyntax*)
                   (REX (if (and (eqv? os 64) (not (= dos 64))) REX.W 0))
                   (ModR/M (encoding-ModR/M encoding))
                   (SIB #f)
                   (disp #f))

            (cond ((null? operands)
                   ;; Emit the instruction
                   (cond ((encoding-sse-prefix encoding) =>
                          (lambda (b) (put-u8 port b))))
                   (unless (zero? REX) (put-u8 port REX))
                   (for-each (lambda (b) (put-u8 port b))
                             (encoding-opcode-bytes encoding))
                   (when ModR/M
                     (put-u8 port ModR/M)
                     (when SIB (put-u8 port SIB)))
                   ;; At this point only displacement and immediates
                   ;; remain. These can be rIP-relative, which means
                   ;; we first need to find out the size of these
                   ;; values before we output them.

                   (let* ((imms (cons disp (encode-operands! operands* opsyntax* os as state)))
                          (size (fold-left (lambda (x y)
                                             (+ x (cond ((vector? y)
                                                         (fxarithmetic-shift-right (vector-ref y 1) 3))
                                                        ((bytevector? y)
                                                         (bytevector-length y))
                                                        (else 0))))
                                           (- (port-position (assembler-state-port state)) pos)
                                           imms)))
                     (print "size of immediates etc: " size " and they are: " imms)

                     (for-each
                      (lambda (y)
                        (cond ((vector? y)
                               (put-bytevector port
                                               (number->bytevector
                                                (- (vector-ref y 0) (assembler-state-ip state) size)

                                                (vector-ref y 1))))

                              ((bytevector? y)
                               (put-bytevector port y))))
                      imms))

                   (cons (car instr) operands*))

                  ((memory? (car operands))
                   (let ((o (car operands)))
                     (print "memory operand: " (car operands) " :: " (car opsyntax))
                     ;; Emit segment override
                     (when (memory-segment o)
                       (let ((seg (register-index (memory-segment o))))
                         (unless (opsyntax-default-segment=? (car opsyntax) seg)
                           (put-u8 port (vector-ref segment-overrides seg)))))
                     (cond ((opsyntax-encoding-position (car opsyntax))
                            (let ((disp (eval-expression (memory-expr o)
                                                         (assembler-state-labels state))))
                              (unless disp
                                (print "No satisfaction: " disp)
                                (assembler-state-relocs-set! state #t))
                              (call-with-values
                                  (lambda ()
                                    (encode-memory (memory-addressing-mode o)
                                                   (or disp #x100) ;bigger than disp8
                                                   (memory-scale o)
                                                   (memory-index o)
                                                   (memory-base o)))
                                (lambda (disp SIB ModR/M* REX*)
                                  (lp (cdr operands)
                                      (cdr opsyntax)
                                      (fxior REX REX*)
                                      (fxior (or ModR/M 0) ModR/M*)
                                      SIB disp)))))
                           (else
                            ;; Implicit
                            (lp (cdr operands)
                                (cdr opsyntax)
                                REX ModR/M SIB disp)))))

                  ((register? (car operands))
                   (print "register operand: " (car operands) " :: " (car opsyntax))
                   (let ((index (register-index (car operands))))
                     (case (opsyntax-encoding-position (car opsyntax))
                       ((r/m)
                        (lp (cdr operands)
                            (cdr opsyntax)
                            (if (> index 7) (fxior REX REX.B) REX)
                            (fxior (or ModR/M 0) (make-modr/m #b11 0 index))
                            SIB disp))
                       ((reg)
                        (lp (cdr operands)
                            (cdr opsyntax)
                            (if (> index 7) (fxior REX REX.R) REX)
                            (fxior (or ModR/M 0) (make-modr/m 0 index 0))
                            SIB disp))
                       ((#f)
                        (lp (cdr operands) (cdr opsyntax) REX ModR/M SIB disp))
                       (else
                        (error 'put-instruction "Unimplemented register operand type"
                               (car operands)
                               (car opsyntax))))))

                  ((or (integer? (car operands)) (expression? (car operands))
                       (far-pointer? (car operands)))
                   (lp (cdr operands) (cdr opsyntax) REX ModR/M SIB disp))

                  (else
                   (error 'put-instruction "Unimplemented operand type"
                          (car operands)
                          (car opsyntax)))))))))

  (define-record-type assembler-state
    (fields (mutable mode)
            (mutable port)
            (mutable ip)
            (mutable labels)
            (mutable relocs)
            (mutable comm)))

  (define (put-immediate imm type state)
    (let ((size (case type
                  ((%u8) 8)
                  ((%u16) 16)
                  ((%u32) 32)
                  ((%u64) 64))))
      (cond ((bytevector? imm)
             (put-bytevector (assembler-state-port state) imm)
             imm)
            ((expression? imm)
             (let ((value (eval-expression imm (assembler-state-labels state))))
               (unless value
                 (print "Unknown label (expr=" imm ")")
                 (assembler-state-relocs-set! state #t))
               (put-bytevector (assembler-state-port state)
                               (number->bytevector (or value 0) size))))

            (else
             (error 'put-immediate "An expression was expected" imm)))))

  ;; NOPs of size 0 to 15. On AMD K8/K10: Do not use more than three
  ;; legacy prefixes per opcode. On Core2: use as many as needed.

  ;; Software Optimization Guide for AMD64 Processors (rev: 3.06)
  (define amd64-nops
    '#(#vu8()
           #vu8(#x90)
           #vu8(#x66 #x90)
           #vu8(#x66 #x66 #x90)
           #vu8(#x66 #x66 #x66 #x90)
           #vu8(#x66 #x66 #x90 #x66 #x90)
           #vu8(#x66 #x66 #x90 #x66 #x66 #x90)
           #vu8(#x66 #x66 #x66 #x90 #x66 #x66 #x90)
           #vu8(#x66 #x66 #x66 #x90 #x66 #x66 #x66 #x90)
           #vu8(#x66 #x66 #x90 #x66 #x66 #x90 #x66 #x66 #x90)))

  ;; Software Optimization Guide for AMD Family 10h Processors (rev:
  ;; 3.06)
  (define amd64-10h-nops
    '#(#vu8()
           #vu8(#x90)
           #vu8(#x66 #x90)
           #vu8(#x0f #x1f #x00)
           #vu8(#x0f #x1f #x40 #x00)
           #vu8(#x0f #x1f #x44 #x00 #x00)
           #vu8(#x66 #x0f #x1f #x44 #x00 #x00)
           #vu8(#x0f #x1f #x80 #x00 #x00 #x00 #x00)
           #vu8(#x0f #x1f #x84 #x00 #x00 #x00 #x00 #x00)
           #vu8(#x66 #x0f #x1f #x84 #x00 #x00 #x00 #x00 #x00)
           #vu8(#x66 #x66 #x0f #x1f #x84 #x00 #x00 #x00 #x00 #x00)
           #vu8(#x66 #x66 #x66 #x0f #x1f #x84 #x00 #x00 #x00 #x00 #x00)))

  ;; Intel® 64 and IA-32 Architectures Optimization Reference Manual
  ;; (November 2007)
  (define intel32-nops
    '#(#vu8()
           #vu8(#x90)
           #vu8(#x89 #xC0)            ;REG
           #vu8(#x8D #x40 #x00)       ;REG
           #vu8(#x0F #x1F #x40 #x00)
           #vu8(#x0F #x1F #x44 #x00 #x00)
           #vu8(#x8D #x80 #x00 #x00 #x00 #x00) ;REG
           #vu8(#x0F #x1F #x80 #x00 #x00 #x00 #x00)
           #vu8(#x0F #x1F #x84 #x00 #x00 #x00 #x00 #x00)
           #vu8(#x66 #x0F #x1F #x84 #x00 #x00 #x00 #x00 #x00)))

  (define (choose-nops table n reg mode)
    ;; Generate a list of bytevectors containing NOP instructions of
    ;; total size n. reg is between 0 and 7 and specifies the
    ;; register with the oldest value.
    (let lp ((n n)
             (bvs '()))
      (if (zero? n) bvs
          (let ((pad (min (- (vector-length table) 1) n)))
            (print "pad: " pad)
            (lp (- n pad)
                (cons (vector-ref table pad) bvs))))))



  (define (assemble! instr state)
    (print "! " instr)
    (case (car instr)
      ((%label)
       (hashtable-set! (assembler-state-labels state)
                       (cadr instr)
                       (assembler-state-ip state))
       instr)
      ((%mode)
       (unless (or (memv (cadr instr) '(32 64)))
         (error 'assemble! "Bad %mode" instr))
       (assembler-state-mode-set! state (cadr instr))
       instr)
      ((%origin)
       (assembler-state-ip-set! state (cadr instr))
       instr)
      ((%comm)
       ;; (%comm label size alignment)
       (assembler-state-comm-set! state (cons (cdr instr)
                                              (assembler-state-comm state)))
       instr)
      ((%u8 %u16 %u32 %u64)
       (let ((pos (port-position (assembler-state-port state)))
             (operands (translate-operands (cdr instr) (assembler-state-mode state))))
         (let ((i (map (lambda (b) (put-immediate b (car instr) state))
                       operands)))
           (assembler-state-ip-set! state (+ (assembler-state-ip state)
                                             (- (port-position (assembler-state-port state)) pos)))
           (cons (car instr) operands))))
      ((%vu8)
       (put-bytevector (assembler-state-port state)
                       (cadr instr))
       (assembler-state-ip-set! state (+ (assembler-state-ip state)
                                         (bytevector-length (cadr instr))))
       instr)
      ((%utf8z)
       (let ((bv (string->utf8 (string-append (cadr instr) "\x0;"))))
         (put-bytevector (assembler-state-port state) bv)
         (assembler-state-ip-set! state (+ (assembler-state-ip state)
                                           (bytevector-length bv)))
         instr))
      ((%align)
       ;; FIXME: handle different modes properly here
       ;; (%align <alignment>)
       ;; (%align <alignment> <byte>)
       ;; (%align <alignment> <non-rex-default-operand-size-register>)
       (let ((pad (- (cadr instr)
                     (mod (assembler-state-ip state)
                          (cadr instr)))))
         (cond ((= (length instr) 2)
                (for-each (lambda (bv) (put-bytevector (assembler-state-port state) bv))
                          (choose-nops amd64-10h-nops pad 0
                                       (assembler-state-mode state))))
               ((number? (caddr instr))
                (put-bytevector (assembler-state-port state)
                                (make-bytevector pad (caddr instr))))
               (else
                ;; FIXME: let a register be specified here
                (error 'assemble! "Bad alignment operation"
                       instr)))
         (assembler-state-ip-set! state (+ (assembler-state-ip state) pad)))
       instr)

      ((%section)
       (when (eq? (cadr instr) 'bss)
         ;; %comm statements are used here
         (for-each
          (lambda (comm)
            (let ((label (car comm))
                  (size (cadr comm))
                  (alignment (caddr comm)))
              ;; Alignment
              (let ((pad (- alignment
                            (mod (assembler-state-ip state)
                                 alignment))))
                ;; Label
                (hashtable-set! (assembler-state-labels state)
                                label
                                (assembler-state-ip state))
                ;; Size
                (assembler-state-ip-set! state (+ (assembler-state-ip state) pad size)))))
          (assembler-state-comm state)))
       instr)

      (else
       (let ((pos (port-position (assembler-state-port state))))
         (let ((i (put-instruction instr state)))
           (assembler-state-ip-set! state (+ (assembler-state-ip state)
                                             (- (port-position (assembler-state-port state)) pos)))
           i)))))

  (define (assemble code)
    (let ((state (make-assembler-state 16
                                       #f
                                       0
                                       (make-eq-hashtable)
                                       #f
                                       '())))
      (let lp ((code code))
        (call-with-values open-bytevector-output-port
          (lambda (tmpport extract)
            (assembler-state-port-set! state tmpport)

            (let ((newcode (map (lambda (i) (assemble! i state)) code)))

              (print "% new code: ")
              (for-each (lambda (i) (print "- " i)) newcode)
              (print "% labels: ")
              (call-with-values (lambda () (hashtable-entries (assembler-state-labels state)))
                (lambda (keys vals)
                  (vector-for-each (lambda (k v)
                                     (print "- " k " => " v))
                                   keys vals)))
              ;; Loop until all labels are known and FIXME: until
              ;; labels aren't changing. Optimize displacements
              ;; somehow...
              (cond ((assembler-state-relocs state)
                     (print "Some labels are unknown! Assembling again...")
                     (set! state (make-assembler-state 16
                                                       #f
                                                       0
                                                       (assembler-state-labels state)
                                                       #f
                                                       '()))
                     (lp newcode))
                    (else
                     (print "Assembly complete.")
                     (extract)))))))))


;;   (begin
;;     (if (file-exists? "/tmp/hmm")
;;         (delete-file "/tmp/hmm"))
;;     (let ((p (open-file-output-port "/tmp/hmm"))
;;           (header-magic #x1BADB002)
;;           (flags #x00010002)
;;           (bootloader-magic #x2BADB002))
;;       (put-bytevector p
;;                       (assemble `((%mode 64)
;;                                   (%origin 0)
;;                                   (%label start)
;;                                   (%comm stack 1 8)
;;                                   ;; (mov (mem32+ start) 0)
;;                                   (mov eax bss)
;;                                   (mov eax end-bss)
;;                                   (%label bss)
;;                                   (%section bss)
;;                                   (%label end-bss)
;;                                   )))
;;       (close-port p)
;;       (system "objdump -b binary -m i386:x86-64 -M intel -D /tmp/hmm")
;;       (system "/var/tmp/bin/ndisasm -b 64 /tmp/hmm")
;;       (system "~/code/industria/programs/fcdisasm --nocolor -b 64 /tmp/hmm")

;; ;;       (system "objdump -b binary -m i386 -M intel -D /tmp/hmm")
;; ;;       (system "/var/tmp/bin/ndisasm -b 32 /tmp/hmm")
;; ;;       (system "~/code/industria/programs/fcdisasm --nocolor -b 32 /tmp/hmm")

;;       ))



    )
