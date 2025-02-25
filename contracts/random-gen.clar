;; Oracle: Verifiable Randomness Generator
;; A Clarity utility that combines multiple entropy sources to generate verifiably random numbers

;; Error codes
(define-constant ERR_INVALID_INTERVAL (err u100))
(define-constant ERR_ZERO_INTERVAL (err u101))
(define-constant ERR_BLOCK_SECURITY (err u102))

;; Define data variables
(define-data-var randomness-pool (buff 32) 0x0000000000000000000000000000000000000000000000000000000000000000)
(define-data-var previous-block uint u0)
(define-data-var sequence-counter uint u0)

;; Convert uint to buffer (simple implementation for entropy)
(define-private (uint-to-buffer (input uint))
  (let
    (
      (byte-0 (mod input u256))
      (byte-1 (mod (/ input u256) u256))
      (byte-2 (mod (/ input u65536) u256))
      (byte-3 (mod (/ input u16777216) u256))
    )
    (concat 
      (concat 
        (uint-to-byte byte-0)
        (uint-to-byte byte-1))
      (concat 
        (uint-to-byte byte-2)
        (uint-to-byte byte-3)))
  )
)

;; Convert integer (0-255) to a single byte buffer
(define-private (uint-to-byte (value uint))
  (unwrap-panic (element-at 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff value))
)

;; Combine entropy sources into a single hash
(define-private (mix-entropy-sources (user-input (buff 32)))
  (let 
    (
      ;; Get Stacks block header hashes (recent + previous)
      (current-block-hash (unwrap-panic (get-stacks-block-info? header-hash (- stacks-block-height u1))))
      (older-block-hash (unwrap-panic (get-stacks-block-info? header-hash (- stacks-block-height u2))))
      
      ;; Current transaction data - use burn block info
      (burn-block-hash (unwrap-panic (get-burn-block-info? header-hash (- burn-block-height u1))))
      
      ;; Use tx-sender as an entropy source 
      (caller-bytes (unwrap-panic (to-consensus-buff? tx-sender)))
      
      ;; Current state
      (current-pool (var-get randomness-pool))
      (current-sequence (var-get sequence-counter))
      (sequence-bytes (uint-to-buffer current-sequence))
      
      ;; Combine all entropy sources
      (mixed-entropy (sha256 (concat 
                                (concat current-block-hash older-block-hash)
                                (concat 
                                  (concat burn-block-hash caller-bytes)
                                  (concat current-pool (sha256 sequence-bytes))))))
    )
    mixed-entropy
  )
)


;; Get a byte from a buffer at specified index
(define-private (extract-byte-at (buffer (buff 32)) (position uint))
  (default-to 0x00 (element-at buffer position))
)

;; Extract number from buffer
(define-private (buffer-to-uint (random-buffer (buff 32)))
  (let 
    (
      (byte-0 (byte-to-uint (extract-byte-at random-buffer u0)))
      (byte-1 (byte-to-uint (extract-byte-at random-buffer u1)))
      (byte-2 (byte-to-uint (extract-byte-at random-buffer u2)))
      (byte-3 (byte-to-uint (extract-byte-at random-buffer u3)))
      (byte-4 (byte-to-uint (extract-byte-at random-buffer u4)))
      (byte-5 (byte-to-uint (extract-byte-at random-buffer u5)))
      (byte-6 (byte-to-uint (extract-byte-at random-buffer u6)))
      (byte-7 (byte-to-uint (extract-byte-at random-buffer u7)))
    )
    (+ byte-0 
      (+ (* byte-1 u256) 
        (+ (* byte-2 u65536) 
          (+ (* byte-3 u16777216) 
            (+ (* byte-4 u4294967296) 
              (+ (* byte-5 u1099511627776) 
                (+ (* byte-6 u281474976710656) 
                  (* byte-7 u72057594037927936))))))))
  )
)

;; Convert buffer byte to uint
(define-private (byte-to-uint (byte (buff 1)))
  (unwrap-panic (index-of 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff byte))
)

;; Public functions

;; Get a random uint value between 0 and max-value (inclusive)
(define-public (generate-random (user-input (buff 32)) (max-value uint))
  (begin
    ;; Verify the range is valid
    (asserts! (> max-value u0) ERR_ZERO_INTERVAL)
    
    ;; Prevent same-block attacks
    (asserts! (> stacks-block-height (var-get previous-block)) ERR_BLOCK_SECURITY)
    (var-set previous-block stacks-block-height)
    
    ;; Generate raw random value
    (let 
      (
        (entropy-sample (mix-entropy-sources user-input))
        (raw-number (buffer-to-uint entropy-sample))
        (bounded-result (mod raw-number (+ max-value u1)))
      )
      
      ;; Update state for future randomness
      (var-set sequence-counter (+ (var-get sequence-counter) u1))
      (var-set randomness-pool (sha256 (concat (var-get randomness-pool) entropy-sample)))
      
      ;; Return the scaled random value
      (ok bounded-result)
    )
  )
)

;; Get a random value within a specific range (min-value to max-value, inclusive)
(define-public (generate-random-in-range (user-input (buff 32)) (min-value uint) (max-value uint))
  (begin
    ;; Verify the range is valid
    (asserts! (>= max-value min-value) ERR_INVALID_INTERVAL)
    
    ;; Get random value from 0 to (max-value - min-value)
    (let 
      (
        (range-size (- max-value min-value))
        (random-offset (unwrap-panic (generate-random user-input range-size)))
      )
      ;; Adjust to the required range by adding min-value
      (ok (+ min-value random-offset))
    )
  )
)

;; Get the current entropy pool state (for verification)
(define-read-only (get-entropy-state)
  (var-get randomness-pool)
)