#!/usr/bin/env scheme-script
;; -*- mode: scheme; coding: utf-8 -*-
;; Demo for (se weinholt x86 assembler)
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

;; This program assembles a multiboot kernel image that can be loaded
;; by GNU GRUB or SYSLINUX's mboot module.

(import (rnrs)
        (se weinholt assembler x86 (1 (>= 0) (>= 0))))

(define << fxarithmetic-shift-left)

(define (assemble-demo)
  (define header-magic #x1BADB002)
  (define flags (bitwise-ior (<< 1 16))) ;non-ELF binary
  (define checksum (bitwise-and (- (+ header-magic flags)) #xffffffff))
  (define stack-size 256)

  ;; VGA registers
  (define Status1 #x3da)
  (define DACWrite #x3c8)
  (define DACData #x3c9)

  (define bar-length 64)

  (define color-table (make-bytevector (* 4 bar-length) 0))

  (define PI (angle -1))

  ;; Fill out the color table with a green copper bar
  (do ((i 0 (+ i 1)))
      ((= i (- bar-length 1)))
    (let* ((red 0)
           (green (exact
                   (round
                    (* (sin (* i (/ PI bar-length)))
                       63))))
           (blue 0))

      (bytevector-u32-set! color-table (* i 4)
                           (fxior (<< blue 16)
                                  (<< green 8)
                                  red)
                           (endianness little))))

  (assemble
   `((%mode 32)
     (%origin #x100000)
     (%section text)
     (%label text)
     (jmp start)

;;; Multiboot header
     (%align 4)
     (%label multiboot-header)
     (%u32 ,header-magic ,flags ,checksum)
     (%u32 multiboot-header text bss bss-end start)

;;; Code starts here
     (%align 16 #x90)                   ;align for easier disassembly
     (%label start)
     (cmp eax #x2BADB002)
     (jne reboot)                       ;bad bootloader
     (%comm stack ,stack-size 16)
     (mov esp (+ stack ,stack-size))

     ;; Clear the screen
     (mov edi #xb8000)
     (mov ecx ,(/ (* 80 25 2) 4))
     (xor eax eax)
     (rep.stos (mem+ es edi) eax)

     (mov esi message)
     (mov edi #xb8000)
     (%label next-char)
     (mov al (mem+ esi))
     (test al al)
     (jz main)
     (movs (mem8+ es edi) (mem8+ ds esi))
     (mov al 10)                        ;green
     (stos (mem8+ es edi) al)
     (jmp next-char)

     ;; The copper bar effect!
     (%label main)

     (in al #x64)
     (test al 1)
     (jz draw-copper)
     (in al #x60)
     (cmp al 1)                         ;press ESC to reboot
     (je reboot)

     (%label draw-copper)

     (mov ecx 100)
     (mov edi 1)
     (mov ebp -1)

     (call vrstart)
     (call vrend)

     ;; Delay for ecx scanlines
     (mov esi ecx)
     (%label delay)
     (call hrstart)
     (call hrend)
     (dec esi)
     (jnz delay)

     (xor esi esi)

     (%label next-line)
     (call hrstart)
     (call change-color)
     (call hrend)
     (inc esi)
     (cmp esi ,bar-length)
     (jb next-line)

     (jmp main)

     ;; Change the background color using the color table, with esi as
     ;; an index into the table.
     (%label change-color)
     (mov al 0)                         ;palette index
     (mov edx ,DACWrite)
     (out dx al)
     (mov eax (mem+ color-table (* esi 4)))
     (mov edx ,DACData)
     (out dx al)                        ;red
     (shr eax 8)
     (out dx al)                        ;green
     (shr eax 8)
     (out dx al)                        ;blue
     (ret)

     ;; Loop until vertical retrace starts
     (%label vrstart)
     (mov dx ,Status1)
     (in al dx)
     (test al #b1000)
     (jnz vrstart)
     (ret)

     ;; Loop until vertical retrace ends
     (%label vrend)
     (mov dx ,Status1)
     (in al dx)
     (test al #b1000)
     (jz vrend)
     (ret)

     ;; Loop until a horizontal retrace starts
     (%label hrstart)
     (mov dx ,Status1)
     (in al dx)
     (test al #b1)
     (jnz hrstart)
     (ret)

     ;; Loop until a horizontal retrace ends
     (%label hrend)
     (mov dx ,Status1)
     (in al dx)
     (test al #b1)
     (jz hrend)
     (ret)

     (%label reboot)
     ;; Reboot via the keyboard: Computer Archeology 101
     (mov al #xfe)
     (out #x64 al)
     (hlt)
     (jmp reboot)

     (%label data)
     (%section data)
     (%label color-table)
     (%vu8 ,color-table)
     (%label message)
     (%utf8z
      "This is a copper bar effect. It requires good VGA hardware. Press ESC to reboot.")

;;; Uninitialized data gets allocated here
     (%label bss)
     (%section bss)
     (%label bss-end))))

(define fn "x86-demo.image")

(if (file-exists? fn)
    (delete-file fn))

(let ((p (open-file-output-port fn)))
  (put-bytevector p (assemble-demo))
  (close-port p))
