/*
EZPASSMAN VAULT FORMAT

-------------
all numbers left endian unless otherwise specified
HEADER
Byte 0  :   32  -> The bytes {0x45, 0x5A, 0x50, 0x4D}. Any file that does not start with these bytes will be deemed invalid
Byte 32 :   48  -> The version id as 4x u16 [major_version, minor_version, year, reserved byte]
Byte 48 :   64  -> Algorithms used in sealing this vault identified by two 16 bit numbers [password_hash, aead]
                    Password hashing algorithms
                        0x00 = Argon2id
                    aead algorithms
                        0x00 = ChaChaPoly1305
Byte 64 :   96  -> Password hash salt (latter bits zero in case of shorter than 16 byte salt)
Byte 96 :   112 -> Password hashing algorithm parameters as 32 bit numbers (memory_size, passes, paralellism, reserved)   
Byte 112:   176 -> aead tag (latter bytes zeroed in case of shorter than 64 byte tag)
Byte 176:   192 -> aead iv (latter bytes zeroed in case of iv less than 16 bytes)
Byte 192:   256 -> aead ad
Byte 256:   512 -> Reserved

BODY
Byte 512: end   -> 10.000 Entry structs. Each struct is four utf-8 strings, with a maximum byte size listed below.
                    Number of entries determined by version.
                    Current version [0,0,2026]: 10.000 entries
                    Entry struct {
                        256 byte entry_id string (website name, f.x)
                        256 byte username
                        256 byte password
                        256 byte note
                    }
-------------

*/



package EzPassMan


import "core:os"
import "core:fmt"
import "core:time"
import "core:crypto/argon2id"
import "core:crypto/aead"

import "core:encoding/endian"

MAX_ENTRIES :: 10_000
SALT_SIZE :: 16
TAG_SIZE :: 32
IV_SIZE :: 12

Vault :: distinct [dynamic ; MAX_ENTRIES]Entry

Entry :: struct {
    record: string,
    username: string,
    password: string,
    note: string,
}

Status :: enum {
    Success,
    Failure,
}

validate_blob :: proc(blob: []u8) -> bool {
    // TODO
    return true
}

VaultParams :: struct {
    pass_hash_params: argon2id.Parameters,
    salt: [SALT_SIZE]u8,
    tag: [TAG_SIZE]u8,
    iv: [IV_SIZE]u8,
    ad: [256]u8
}

read_params :: proc(encrypted_bloc: []u8) -> (VaultParams, Status) {

    params : VaultParams

    blob_is_valid := validate_blob(encrypted_bloc)
    if !blob_is_valid {
        return params, .Failure
    }

    params.pass_hash_params.memory_size, _ = endian.get_u32(encrypted_bloc[96:100], .Little)
    params.pass_hash_params.passes, _ = endian.get_u32(encrypted_bloc[100:104], .Little)
    params.pass_hash_params.parallelism, _ = endian.get_u32(encrypted_bloc[104:108], .Little)

    copy(params.salt[:], encrypted_bloc[64:64 + SALT_SIZE])

    copy(params.tag[:], encrypted_bloc[112:112 + TAG_SIZE])

    copy(params.iv[:], encrypted_bloc[176:176 + IV_SIZE])

    copy(params.ad[:], encrypted_bloc[192:256])

    return params, .Success
}

// The lifetime of the vault_file must outlive the Vault struct since the Vault struct holds pointers into the Vault
open_vault :: proc(password: string, vault_file: []u8) -> (^Vault, Status) {
    
    hash_params, _ := read_params(vault_file)
    vault := new(Vault)

    password_hash : [TAG_SIZE]u8
    alloc_error := argon2id.derive(
        &hash_params.pass_hash_params, 
        transmute([]u8)password[:], 
        hash_params.salt[:], 
        password_hash[:], 
        ad = hash_params.ad[:],
    )

    decryption_failed := aead.open_oneshot(
        .CHACHA20POLY1305, 
        vault_file[512:], 
        password_hash[0:aead.KEY_SIZES[.CHACHA20POLY1305]], 
        hash_params.iv[0:aead.IV_SIZES[.CHACHA20POLY1305]],
        hash_params.ad[:],
        vault_file[512:],
        hash_params.tag[:]
    )

    if decryption_failed {
        return vault, .Failure
    }

    if alloc_error != .None {
        return nil, .Failure
    }

    return vault, .Success
    
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