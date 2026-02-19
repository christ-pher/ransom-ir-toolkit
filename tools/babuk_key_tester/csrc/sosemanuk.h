/*
 * sosemanuk.h -- Sosemanuk stream cipher (eSTREAM Profile 1)
 *
 * This is a standalone header for the Sosemanuk stream cipher used by
 * Babuk/Mario ransomware to encrypt file contents.  Sosemanuk combines
 * a reduced Serpent block cipher (for key scheduling) with an LFSR+FSM
 * stream generator.
 *
 * Reference: C. Berbain, O. Billet, A. Canteaut, N. Courtois, H. Gilbert,
 *            L. Goubin, A. Gouget, L. Granboulan, C. Lauradoux, M. Minier,
 *            T. Pornin, H. Sibert.  "Sosemanuk, a fast software-oriented
 *            stream cipher."  eSTREAM, ECRYPT Stream Cipher Project.
 *
 * Public domain / eSTREAM reference implementation.
 */

#ifndef SOSEMANUK_H
#define SOSEMANUK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Serpent-derived key schedule
 *
 * Sosemanuk uses 25 rounds of Serpent (rounds 0..24) to derive 100
 * 32-bit subkeys (4 words per round).  These subkeys are stored in
 * the key schedule structure and reused during IV initialization.
 * ----------------------------------------------------------------------- */

typedef struct {
    uint32_t subkeys[100];      /* 25 rounds * 4 words */
} sosemanuk_key_schedule;


/* -----------------------------------------------------------------------
 * Stream generator state
 *
 * The Sosemanuk state consists of:
 *   - 10 LFSR cells (s1..s10), each 32 bits, over GF(2^32).
 *   - 2 FSM registers R1, R2 (32 bits each).
 *
 * Together these produce 32 bits of keystream per clock step, output
 * in 20-word (80-byte) blocks for efficiency.
 * ----------------------------------------------------------------------- */

typedef struct {
    uint32_t lfsr[10];          /* s1 .. s10 (LFSR cells) */
    uint32_t r1;                /* FSM register R1 */
    uint32_t r2;                /* FSM register R2 */
} sosemanuk_state;


/* -----------------------------------------------------------------------
 * API
 * ----------------------------------------------------------------------- */

/*
 * sosemanuk_schedule -- Expand a cipher key into the internal key schedule.
 *
 * key      Pointer to the raw key bytes (16 or 32 bytes).
 * key_len  Key length in bytes.  Must be 16 or 32.
 * ksc      Output key schedule structure.
 */
void sosemanuk_schedule(const unsigned char *key,
                        size_t key_len,
                        sosemanuk_key_schedule *ksc);

/*
 * sosemanuk_init -- Initialise the stream state from a key schedule and IV.
 *
 * state    Output stream generator state (LFSR + FSM).
 * ksc      Key schedule previously computed by sosemanuk_schedule().
 * iv       128-bit (16-byte) initialisation vector.
 */
void sosemanuk_init(sosemanuk_state *state,
                    const sosemanuk_key_schedule *ksc,
                    const unsigned char *iv);

/*
 * sosemanuk_prng -- Generate keystream bytes.
 *
 * state    Stream state (modified in place).
 * out      Output buffer receiving the keystream.
 * len      Number of keystream bytes to produce.
 */
void sosemanuk_prng(sosemanuk_state *state,
                    unsigned char *out,
                    size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SOSEMANUK_H */
