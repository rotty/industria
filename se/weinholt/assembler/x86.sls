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

;; FIXME: unify the names for address size, operand size, data size,
;; addressing mode....

;;; Goals

;; One goal is to be friendly to compiler writers, and not necessarily
;; to people writing assembler by hand. This can be a hard friendship,
;; e.g. the assembler should *never* truncate immediates. It should
;; not accept instructions that could lead to machine code the
;; compiler did not precisely specify.




(library (se weinholt assembler x86 (1 0 0))
    (export put-instruction)
    (import (rnrs)
            (se weinholt assembler x86-operands (1 0 (>= 0)))
            (se weinholt assembler x86-misc (1 0 (>= 0)))
            (se weinholt disassembler x86-opcodes (1 (<= 1) (>= 1))))

  (define debug #t)

  (define (print . x) (for-each display x) (newline))

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

  (define REX.bare #b01000000)
  (define REX.W    #b01001000)
  (define REX.R    #b01000100)
  (define REX.X    #b01000010)
  (define REX.B    #b01000001)

  (define segment-overrides
    '#(#x26 #x2E #x36 #x3E #x64 #x65))

;;; Operand syntax handling

  (define opsyntaxen
    (let ((tmp (make-eq-hashtable)))
      (hashtable-set! tmp 'Mdq
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 128))))
                       'mem             ;encoded as memory with ModR/M, SIB, etc
                       'Mdq))
      (hashtable-set! tmp 'Mq
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 64))))
                       'mem             ;encoded as memory with ModR/M, SIB, etc
                       'Mq))

      ;; xmm
      (hashtable-set! tmp 'Vpd
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (register? o)
                              (eq? (register-type o) 'xmm)))
                       'reg
                       'Vpd))
      (hashtable-set! tmp 'Wpd
                      (vector
                       #f
                       (lambda (o opsize)
                         (cond ((register? o)
                                (eq? (register-type o) 'xmm))
                               ((memory? o)
                                (memv (memory-datasize o) '(#f 128)))
                              (else #f)))
                       'r/m
                       'Wpd))

      (hashtable-set! tmp 'Ev
                      (vector
                       'operand-size
                       (lambda (o opsize)
                         (cond ((register? o)
                                (memv (register-type o) '(16 32 64)))
                               ((memory? o)
                                ;; FIXME: Or unsized data?
                                (memv (memory-datasize o) '(#f 16 32 64)))
                               (else #f)))
                       'r/m             ;register is encoded in r/m and REX.B
                       'Ev))
      (hashtable-set! tmp 'Eb
                      (vector
                       #f
                       (lambda (o opsize)
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
                       (lambda (o opsize)
                         (and (register? o)
                              (memv (register-type o) '(16 32 64))))
                       'reg             ;register is encoded in ModR/M.reg etc
                       'Gv))

      ;; These are very limited: must be ES:DI, ES:EDI or RDI.
      (hashtable-set! tmp 'Yv
                      (vector
                       'operand-size
                       (lambda (o opsize)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 16 32 64))
                              ;; Make sure this is rDI
                              (not (memory-disp o))
                              (not (memory-SIB o))
                              (zero? (memory-REX o))
                              (= (memory-ModR/M o) 7)
                              ;; Check ES. FIXME: this depends on machine target mode, not addressing mode. save that in the memory record
                              (case (memory-addressing-mode o)
                                ((64) (not (memory-segment o)))
                                (else (and (register? (memory-segment o))
                                           (zero? (register-index (memory-segment o))))))))
                       #f               ;implicit
                       'Yv))
      (hashtable-set! tmp 'Yb
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 8))
                              (not (memory-disp o))
                              (not (memory-SIB o))
                              (zero? (memory-REX o))
                              (= (memory-ModR/M o) 7)
                              ;; Check ES
                              (case (memory-addressing-mode o)
                                ((64) (not (memory-segment o)))
                                (else (and (register? (memory-segment o))
                                           (zero? (register-index (memory-segment o))))))))
                       #f               ;implicit
                       'Yb))

      (hashtable-set! tmp 'Xv
                      (vector
                       'operand-size
                       (lambda (o opsize)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 16 32 64))
                              ;; Make sure this is rSI
                              (not (memory-disp o))
                              (not (memory-SIB o))
                              (zero? (memory-REX o))
                              (= (memory-ModR/M o) 6)
                              ;; Require a segment override for legacy mode
                              (or (= (memory-addressing-mode o) 64)
                                  (memory-segment o))))
                       #f               ;implicit
                       'Xv))

      (hashtable-set! tmp 'Xb
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (memory? o)
                              (memv (memory-datasize o) '(#f 8))
                              (not (memory-disp o))
                              (not (memory-SIB o))
                              (zero? (memory-REX o))
                              (= (memory-ModR/M o) 6)
                              ;; Require a segment override for legacy mode
                              (or (= (memory-addressing-mode o) 64)
                                  (memory-segment o))))
                       #f               ;implicit
                       'Xb))


      ;;
      (hashtable-set! tmp 'Rd/q
                      (vector
                       #f
                       (lambda (o opsize)
                         (let ((mode 64)) ;FIXME: requires mode
                           (and (register? o)
                                (eqv? (register-type o) mode))))
                       'r/m
                       'Rd/q))

      (hashtable-set! tmp 'Cd/q
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (register? o)
                              (eqv? (register-type o) 'creg)))
                       'reg
                       'Cd/q))

      (hashtable-set! tmp 'Dd/q
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (register? o)
                              (eqv? (register-type o) 'dreg)))
                       'reg
                       'Dd/q))


      ;; Immediates
      (hashtable-set! tmp 'Iz
                      (vector
                       #f
                       (lambda (o opsize)
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
                                (else #f))))
                       'immZ
                       'Iz))
      (hashtable-set! tmp 'Iv
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (integer? o)
                              (case opsize
                                ((64) (<= (- (expt 2 63)) o (- (expt 2 64) 1)))
                                ((32) (<= (- (expt 2 31)) o (- (expt 2 32) 1)))
                                ((16) (<= (- (expt 2 15)) o (- (expt 2 16) 1)))
                                (else #f))))
                       'imm
                       'Iv))
      (hashtable-set! tmp 'Ib
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (integer? o)
                              (<= (- (expt 2 7)) o (- (expt 2 8) 1))))
                       'imm8
                       'Ib))
      (hashtable-set! tmp 'Iw
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (integer? o)
                              (<= (- (expt 2 15)) o (- (expt 2 16) 1))))
                       'imm16
                       'Iw))

      ;; Implicitly encoded registers
      (hashtable-set! tmp '*AL
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (register? o)
                              (eqv? (register-type o) 8)
                              (= (register-index o) 0)))
                       #f               ;implicit
                       '*AL))
      (hashtable-set! tmp '*eAX
                      (vector
                       'operand-size
                       (lambda (o opsize)
                         (and (register? o)
                              (memv (register-type o) '(16 32))
                              (= (register-index o) 0)))
                       #f               ;implicit
                       '*eAX))
      (hashtable-set! tmp '*DX
                      (vector
                       #f
                       (lambda (o opsize)
                         (and (register? o)
                              (eqv? (register-type o) 16)
                              (= (register-index o) 2)))
                       #f               ;implicit
                       '*DX))
      (hashtable-set! tmp '*rAX
                      (vector
                       'operand-size
                       (lambda (o opsize)
                         (and (register? o)
                              (memv (register-type o) '(16 32 64))
                              (= (register-index o) 0)))
                       #f               ;implicit
                       '*rAX))
      (hashtable-set! tmp '*rAX/r8
                      (vector
                       'operand-size
                       (lambda (o opsize)
                         (and (register? o)
                              (memv (register-type o) '(16 32 64))
                              (= (bitwise-and (register-index o) #b111) 0)))
                       #f               ;implicit
                       '*rAX/r8))

      tmp))

  (define (translate-opsyntax opsyntax)
    (let ((o (hashtable-ref opsyntaxen opsyntax #f)))
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
    (eq? (vector-ref opsyntax 0) 'operand-size))

  (define (opsyntax-encoding-position opsyntax)
    ;; Returns #f if the operand is implicit in the opcode. Returns
    ;; reg or r/m when the operand is encoded in ModR/M.
    (vector-ref opsyntax 2))

  (define (operand-compatible-with-opsyntax? operand opsyntax opsize)
    ;; FIXME: no need to change into boolean here
    (if ((vector-ref opsyntax 1) operand opsize) #t #f))


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
      (walk-opcodes f (vector-ref instr 1) (append bytes (list 'addr16)))
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
           (or (= mode 32) (= mode 16)))
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
    (cond ((memq 'addr16 encoding) 16)
          ((memq 'addr32 encoding) 32)
          ((memq 'addr64 encoding) 64)
          (else #f)))

;;;

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

  (define (find-instruction-encoding instr mode prefixes)
    ;; This function takes an instruction in the input format and
    ;; finds a suitable encoding for it. It handles instruction
    ;; prefixes and pseudo mnemonics.
    (let ((mnemonic (car instr))
          (operands (cdr instr)))
      (define (bailout msg)
        (error 'find-instruction-encoding msg instr mode))
      (define (try-prefix)
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
                          (use-prefix 'lock))
                         ((eq? (car mnemonics) 'rep)
                          (unless (memq (cadr mnemonics) rep-instructions)
                            (bailout "This instruction does not support the REP prefix"))
                          (use-prefix 'rep))
                         ((memq (car mnemonics) '(repz repe))
                          (unless (memq (cadr mnemonics) repz-instructions)
                            (bailout "This instruction does not support the REPZ prefix"))
                          (use-prefix 'repz))
                         ((memq (car mnemonics) '(repnz repne))
                          (unless (memq (cadr mnemonics) repz-instructions)
                            (bailout "This instruction does not support the REPNZ prefix"))
                          (use-prefix 'repnz))
                         ((memq (cadr mnemonics) '(sptk spnt))
                          (unless (memq (car mnemonics) branch-hint-instructions)
                            (bailout "This instruction can not take a branch hint"))
                          (find-instruction-encoding (cons (car mnemonics) operands)
                                                     mode (cons (cadr mnemonics) prefixes)))
                         (else (bailout))))))
              (else (bailout "Unknown mnemonic"))))
      (define (try-pseudo)
        (cond ((hashtable-ref pseudo-instructions mnemonic #f) =>
               (lambda (pseudo)
                 ;; Replace the mnemonic and append an immediate
                 (find-instruction-encoding
                  (cons (car pseudo)
                        (append (cdr instr)
                                (list (cdr pseudo)))) mode prefixes)))
              (else (try-prefix))))
      (cond ((hashtable-ref instructions mnemonic #f) =>
             (lambda (templates)
               (let ((templates (filter (lambda (x)
                                          (= (length (template-opsyntax x))
                                             (length operands)))
                                        templates)))
                 (cond ((null? templates) (try-pseudo))
                       (else
                        (let ((operands (translate-operands operands mode)))
                          ;; TODO: a better idea might be to enumerate
                          ;; every possible way to encode each
                          ;; instruction, i.e. all operand sizes with
                          ;; operand size prefix included etc. Put all
                          ;; this in a hashtable, where the key is the
                          ;; mnemonic and how the operands could be
                          ;; encoded. Pre-determine which encoding is
                          ;; the most optimal for all combinations of
                          ;; operands. Encoding an instruction then is
                          ;; then like dispatching a method in a
                          ;; rather strange language with dispatching
                          ;; on function types. Just translate the
                          ;; types of the operands in the instruction
                          ;; and look it up in the hashtable mentioned
                          ;; earlier. The opsyntax table needs a list
                          ;; of example operands that are acceptable
                          ;; as input, one of each type. These can
                          ;; also be used in documentation. And lookup
                          ;; is O(1).
                          (when debug
                            (print "% " operands))
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
                                  (when debug
                                    (print "- " (template-opsyntax template) " - " (template-encoding template)))
                                  (if (and (encoding-mode-is-acceptable? mode (template-encoding template))
                                           (instruction-encodable? operands template mode os))
                                      (values os as prefixes operands
                                              (template-opsyntax template) (template-encoding template))
                                      (lp (cdr templates))))))))))))
            (else (try-pseudo)))))

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
                                (operand-compatible-with-opsyntax? operand opsyntax os))
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

  (define (instruction-address-size default operands)
    (let ((sizes (filter number? (cons default (map address-size operands)))))
      (if (null? sizes) #f (car sizes))))

  ;; prefixes | opcode bytes | ModR/M | SIB | displacement | immediates
  ;; opcode bytes | ModR/M | SIB | DREX | displacement | immediates
  ;; VEX | opcode | ModR/M | SIB | displacement | /is4 | immediates

  (define (put-instruction instr port mode)
    ;; FIXME: detect *3dnow* and so on from the user's side
    (call-with-values (lambda () (find-instruction-encoding instr mode '()))
      (lambda (os as prefixes operands opsyntax encoding)
        (when debug
          (print "can encode now, operand-size=" os
                 " address-size=" as
                 " prefixes=" prefixes
                 " encoding=" encoding "\n"))

        ;; Emit address size and operand size overrides
        (when (or (and (= mode 64) (eqv? as 32))
                  (and (= mode 32) (eqv? as 16))
                  (and (= mode 16) (eqv? as 32)))
          (put-u8 port #x67))
        (when (or (and (= mode 64) (eqv? os 16))
                  (and (= mode 32) (eqv? os 16))
                  (and (= mode 16) (eqv? os 32)))
          (put-u8 port #x66))
        (when (and (< mode 64) (eqv? os 64))
          (error 'put-instruction
                 "64-bit operand sizes are only available in 64-bit mode" instr))

        (let lp ((operands operands)
                 (opsyntax opsyntax)
                 (REX (if (eqv? os 64) REX.W 0))
                 (ModR/M (encoding-ModR/M encoding))
                 (SIB #f)
                 (disp #f)
                 (immediates '()))

          (cond ((null? operands)
                 ;; Emit the instruction
                 (cond ((encoding-sse-prefix encoding) =>
                        (lambda (b) (put-u8 port b))))
                 (unless (zero? REX) (put-u8 port REX))
                 (for-each (lambda (b) (put-u8 port b))
                           (encoding-opcode-bytes encoding))
                 (when ModR/M (put-u8 port ModR/M))
                 (when SIB (put-u8 port SIB))
                 (when disp (put-bytevector port disp))
                 (for-each (lambda (bv) (put-bytevector port bv))
                           immediates))

                ((memory? (car operands))
                 (let ((o (car operands)))
                   (when debug
                     (print "memory operand: " (car operands) " :: " (car opsyntax)))
                   ;; Emit segment override
                   (when (memory-segment o)
                     (let ((seg (register-index (memory-segment o))))
                       (unless (opsyntax-default-segment=? (car opsyntax) seg)
                         (put-u8 port (vector-ref segment-overrides seg)))))
                   (cond ((opsyntax-encoding-position (car opsyntax))
                          (lp (cdr operands)
                              (cdr opsyntax)
                              (fxior REX (memory-REX o))
                              (fxior (or ModR/M 0) (memory-ModR/M o))
                              (memory-SIB o)
                              (memory-disp o)
                              immediates))
                         (else
                          ;; Implicit
                          (lp (cdr operands)
                              (cdr opsyntax)
                              REX ModR/M SIB disp immediates)))))

                ((register? (car operands))
                 (when debug
                   (print "register operand: " (car operands) " :: " (car opsyntax)))
                 (let ((index (register-index (car operands))))
                   (case (opsyntax-encoding-position (car opsyntax))
                     ((r/m)
                      (lp (cdr operands)
                          (cdr opsyntax)
                          (if (> index 7) (fxior REX REX.B) REX)
                          (fxior (or ModR/M 0) (make-modr/m #b11 0 index))
                          SIB disp immediates))
                     ((reg)
                      (lp (cdr operands)
                          (cdr opsyntax)
                          (if (> index 7) (fxior REX REX.R) REX)
                          (fxior (or ModR/M 0) (make-modr/m 0 index 0))
                          SIB disp immediates))
                     ((#f)
                      (lp (cdr operands) (cdr opsyntax) REX ModR/M SIB disp immediates))
                     (else
                      (error 'put-instruction "Unimplemented register operand type"
                             (car operands)
                             (car opsyntax))))))

                ((integer? (car operands))
                 (when debug
                   (print "is immediate: " (car operands) " :: " (car opsyntax)))
                 (let* ((o (car operands))
                        (imm
                         (case (opsyntax-encoding-position (car opsyntax))
                           ((imm) (number->bytevector o os))
                           ((imm8) (number->bytevector o 8))
                           ((imm16) (number->bytevector o 16))
                           ((immZ)
                            ;; If the operand size is 64 bit, then the
                            ;; immediate value here is encoded in 32
                            ;; bits and sign-extended.
                            (case os
                              ((64)
                               ;; FIXME: what's up with the mask here?
                               (number->bytevector (bitwise-and #xffffffff o) 32))
                              ((16 32)
                               (number->bytevector (bitwise-and #xffffffff o) os))))
                           (else
                            (print "teach me how to encode this immediate")))))
                   (lp (cdr operands) (cdr opsyntax) REX ModR/M SIB disp (cons imm immediates))))
                (else
                 (error 'put-instruction "Unimplemented operand type"
                        (car operands)
                        (car opsyntax))))))))


;;   (when #f
;;     (begin
;;       (print "\n\n\n")
;;       (if (file-exists? "/tmp/hmm")
;;           (delete-file "/tmp/hmm"))
;;       (let ((p (open-file-output-port "/tmp/hmm")))
;;         (for-each (lambda (i)
;;                     (put-instruction i p 64))
;;                   '( ;; (stos (mem+ edi es) al)
;;                     ;; (stos (mem+ rdi) al)
;;                     ;; (stos (mem+ rdi) ax)
;;                     ;; (stos (mem+ rdi) eax)
;;                     ;; (stos (mem+ rdi) rax)
;;                     ;; (movs (mem+ rdi) (mem32+ rsi))
;;                     ;; (mov ax (mem+ r14 12 (* r15 4)))
;;                     ;; (sti)
;;                     ;; (mov (mem8+ rax) #xff)
;;                     ;; (mov (mem16+ rax) #xffff)
;;                     ;; (mov (mem32+ rax) #xffffffff)
;;                     ;; (mov (mem64+ rax) #x-7fffffff)
;;                     ;; (addpd xmm14 xmm15)
;;                     ;; (addpd xmm0 (mem+ r14))
;;                     (mov cr15 r15)
;;                     ))
;;         (close-port p))
;;       (system "objdump -b binary -m i386:x86-64 -M intel -D /tmp/hmm")
;;       (system "ndisasm -b 64 /tmp/hmm")
;;       (system "~/code/industria/programs/fcdisasm --nocolor -b 64 /tmp/hmm"))


    ))
