package EzPassMan


import "core:os"
import "core:fmt"
import "core:time"
import "core:crypto/argon2id"
import "core:crypto/aead"

import "core:encoding/endian"
import "core:slice"
import "core:strings"


PasswordAlgo :: enum u16 {
    argon2id,
}

aeadAlgo :: enum u16 {
	AES_GCM_128,
	AES_GCM_192,
	AES_GCM_256,
	CHACHA20POLY1305,
	XCHACHA20POLY1305,
	AEGIS_128L,
	AEGIS_128L_256, // AEGIS-128L (256-bit tag)
	AEGIS_256,
	AEGIS_256_256, // AEGIS-256 (256-bit tag)
	DEOXYS_II_256,
}

algo_from_algo :: proc(algo: aeadAlgo) -> aead.Algorithm {
    switch algo {
        case .AES_GCM_128: {return .AES_GCM_128}
        case .AES_GCM_192: {return .AES_GCM_192}
        case .AES_GCM_256: {return .AES_GCM_256}
        case .CHACHA20POLY1305: {return .CHACHA20POLY1305}
        case .XCHACHA20POLY1305: {return .XCHACHA20POLY1305}
        case .AEGIS_128L: {return .AEGIS_128L}
        case .AEGIS_128L_256: {return .AEGIS_128L_256}
        case .AEGIS_256: {return .AEGIS_256}
        case .AEGIS_256_256:{return .AEGIS_256_256}
        case .DEOXYS_II_256: {return .DEOXYS_II_256}
    }

    return .AES_GCM_256
}

Vault :: struct {                                   // size offset  alignment
    magic_bytes:    [8]u8,                          // 8    0       1
    version:        [4]u16,                         // 8    8       2
    password_algo:  PasswordAlgo,                   // 2    16      2
    aead_algo:      aeadAlgo,                       // 2    18      2
    password_salt:  [16]u8,                         // 16   20      1
    password_hasher_params: argon2id.Parameters,    // 16   36      4
    aead_tag:       [64]u8,                         // 64   52      1
    aead_iv:        [32]u8,                         // 32   116     1
    aead_aad:       [64]u8,                         // 64   148     1
    reserved:       [808]u8,                        // 808  212     1
    number_of_entries: u32,                         // 4    1020    4
    entries:        [MAX_ENTRIES]Entry,                  // big  1024    256        
}


MAX_ENTRIES :: 10_000
SALT_SIZE :: 16
TAG_SIZE :: 32
PASSWORD_HASH_SIZE :: 32
IV_SIZE :: 12

Entry :: struct {
    record: [256]u8,
    username: [256]u8,
    password: [256]u8,
    note: [256]u8,
}

Status :: enum {
    Success,
    Failure,
    Too_Long_Password,
}

validate_blob :: proc(blob: []u8) -> bool {
    // TODO
    return true
}

// The Vault pointer points to the same bytes as the vault_file. Make sure you don't free the vault_file.
open_vault :: proc(password: string, vault_file: []u8) -> (^Vault, Status) {

    vault_file := vault_file

    if len(password) > 255 {
        return nil, .Too_Long_Password
    }
    vault: ^Vault
    vault = transmute(^Vault)raw_data(vault_file)

    encrypted_entries := slice.to_bytes(vault.entries[:])
    password_hash : [32]u8
    password_bytes : [256]u8
    copy(password_bytes[:len(password)], password)
    alloc_error := argon2id.derive(
        &vault.password_hasher_params, 
        password_bytes[:len(password)], 
        vault.password_salt[:], 
        password_hash[:]
    )

    if alloc_error != .None {
        return nil, .Failure
    }

    ctx : aead.Context
    aead_algo := algo_from_algo(vault.aead_algo)
    aead.open_oneshot(
        aead_algo, 
        encrypted_entries, 
        password_hash[:aead.KEY_SIZES[aead_algo]], 
        vault.aead_iv[:aead.IV_SIZES[aead_algo]],
        vault.aead_aad[:],
        encrypted_entries,
        vault.aead_tag[:],
    )


}

main :: proc() {
    pull := os.Process_Desc{
        working_dir = "./vault",
        command = {"git", "pull"},
    }

    commit := os.Process_Desc{
        working_dir = "./vault",
        command = {"git", "commit"},
    }

    push := os.Process_Desc{
        working_dir = "./vault",
        command = {"git", "push"},
    }

}