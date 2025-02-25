# Oracle: Verifiable Randomness Generator

EntropyOracle is a Clarity smart contract designed to generate verifiably random numbers on the Stacks blockchain. It combines multiple entropy sources to create secure, unpredictable randomness for decentralized applications.

## Features

- Combines multiple entropy sources for enhanced security
- Protection against same-block attack vectors
- Supports generation of random numbers within specified ranges
- Maintains an internal entropy pool that improves over time
- Verifiable randomness with transparent source code

## How It Works

EntropyOracle uses the following entropy sources to generate randomness:

1. User-provided seed (sanitized to prevent manipulation)
2. Current and previous Stacks block header hashes
3. Current burn block hash information
4. Contract caller identity
5. Internal sequence counter
6. Persistent entropy pool

These sources are mixed using cryptographic hashing to produce unpredictable, verifiable random values that cannot be manipulated by miners, users, or contract creators.

## Usage

### Generate Random Number (0 to max)

```clarity
;; Returns a random number between 0 and max-value (inclusive)
(contract-call? .entropy-oracle generate-random 0x7391f0fbd6ab84365142556d72c8baac93f9843d18530769d0af1117912e4ae3 u100)
```

### Generate Random Number in Range

```clarity
;; Returns a random number between min-value and max-value (inclusive)
(contract-call? .entropy-oracle generate-random-in-range 0x7391f0fbd6ab84365142556d72c8baac93f9843d18530769d0af1117912e4ae3 u50 u100)
```

### Get Current Entropy State

```clarity
;; Returns the current state of the entropy pool (for verification)
(contract-call? .entropy-oracle get-entropy-state)
```

## Error Handling

The contract defines several error codes:

- `ERR_INVALID_INTERVAL (u100)`: Returned when an invalid interval is provided (min > max)
- `ERR_ZERO_INTERVAL (u101)`: Returned when a zero-sized interval is provided
- `ERR_BLOCK_SECURITY (u102)`: Returned when attempting to generate multiple random values in the same block
- `ERR_INVALID_INPUT (u103)`: Returned when input validation fails

## Security Considerations

- The contract prevents multiple calls in the same block to avoid exploitation
- User input is sanitized to prevent direct manipulation
- Multiple entropy sources are combined to ensure unpredictability
- The entropy pool evolves with each call, improving over time
