package EzPassMan

import "core:crypto"
import "core:crypto/argon2id"
import "core:crypto/aead"
import "core:slice"
import "core:fmt"
import "core:mem"

import ss "smallstrings"


MAX_ENTRIES :: 10_000
SALT_SIZE :: 16
TAG_SIZE :: 32
PASSWORD_HASH_SIZE :: 32
IV_SIZE :: 12


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

Vault :: struct {   
    locked: b64,                                    
    magic_bytes:    [8]u8,                          
    version:        [4]u16,                         
    password_algo:  PasswordAlgo,                   
    aead_algo:      aeadAlgo,                       
    password_salt:  [16]u8,                         
    password_hasher_params: argon2id.Parameters,    
    aead_tag:       [64]u8,                         
    aead_iv:        [32]u8,                         
    aead_aad:       [64]u8,                         
    reserved:       [800]u8,                        
    number_of_entries: u32,                         
    entries:        [MAX_ENTRIES]Entry,                     
}



AAD : [64]u8 : {
    0x45,0x6E,0x63,0x72,0x79,0x70,0x74,0x65,0x64,0x20,
    0x62,0x79,0x20,0x76,0x65,0x72,0x73,0x69,0x6F,0x6E,
    0x20,0x78,0x78,0x2E,0x78,0x78,0x2E,0x78,0x78,0x2E,
    0x78,0x78,0x20,0x6F,0x66,0x20,0x45,0x7A,0x50,0x61,
    0x73,0x73,0x4D,0x61,0x6E,0x2E,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
}

EzString :: ss.SmallString(255)

Entry :: struct {
    id: EzString,
    username: EzString,
    password: EzString,
    note: EzString,
}

NullEntry :: Entry{
    id = EzString{len = 0, data = 0},
    username = EzString{len = 0, data = 0},
    password = EzString{len = 0, data = 0},
    note = EzString{len = 0, data = 0},
}

print_entry :: proc(entry: ^Entry) {
    fmt.println(ss.as_string(&entry.id))
    fmt.print("\t")
    fmt.println(ss.as_string(&entry.username))
    fmt.print("\t")
    fmt.println(ss.as_string(&entry.password))
    fmt.print("\t")
    fmt.println(ss.as_string(&entry.note))
}

Status :: enum {
    Success,
    Failure,
    Wrong_Password,
    Too_Long_Password,
}

hash_password :: proc(password: string, hash_params: ^argon2id.Parameters, salt: []u8) -> ([32]u8, Status) {
    password_hash : [32]u8
    password_bytes : [256]u8
    copy(password_bytes[:len(password)], password)
    alloc_error := argon2id.derive(
        hash_params, 
        password_bytes[:len(password)], 
        salt[:], 
        password_hash[:]
    )

    if alloc_error != .None {
        return 0, .Failure
    }

    return password_hash, .Success
}

blob_is_valid :: proc(blob: []u8) -> bool {

    magic_bytes: [8]u8 = {'E', 'Z', 'P', 'A', 'S', 'S', 'M', 'N'}
    
    if len(blob) != size_of(Vault) {
        return false
    } else if !slice.equal(blob[8:16], magic_bytes[:]) {
        return false
    }

    return true
}

blob_to_vault :: proc(blob: []u8) -> (^Vault, Status) {
    if blob_is_valid(blob) {
        return cast(^Vault)(&blob[0]), .Success
    } else {
        return nil, .Failure
    }
}


open_vault :: proc(vault: ^Vault, password: string) -> (Status) {
    if len(password) > 255 {
        return .Too_Long_Password
    }

    if !vault.locked {
        return .Failure
    }

    new_vault := new(Vault)
    new_vault^ = vault^

    encrypted_entries := slice.to_bytes(vault.entries[:])
    password_hash, pass_hash_status := hash_password(password, &vault.password_hasher_params, vault.password_salt[:])
    if pass_hash_status != .Success {
        return .Failure
    }

    entry_buffer := slice.to_bytes(new_vault.entries[:])

    ctx : aead.Context
    aead_algo := algo_from_algo(vault.aead_algo)
    opened_successfully := aead.open_oneshot(
        aead_algo, 
        entry_buffer, 
        password_hash[:aead.KEY_SIZES[aead_algo]], 
        new_vault.aead_iv[:aead.IV_SIZES[aead_algo]],
        new_vault.aead_aad[:],
        encrypted_entries,
        new_vault.aead_tag[:aead.TAG_SIZES[aead_algo]],
    )

    
    if opened_successfully == false {
        free(new_vault)
        return .Failure
    } else {
        vault^ = new_vault^
        vault.locked = false
        destroy_vault(new_vault)
        return .Success
    }
}

destroy_vault :: proc(vault: ^Vault) {
    new_vault_bytes := slice.bytes_from_ptr(rawptr(vault), size_of(Vault))
    slice.zero(new_vault_bytes)
    free(vault)
}

lock_vault :: proc(vault: ^Vault, password: string) -> Status {
    password_hash, pass_hash_status := hash_password(password, &vault.password_hasher_params, vault.password_salt[:])
    if pass_hash_status != .Success {
        return .Failure
    }

    vault_entries_bytes := slice.to_bytes(vault.entries[:])
    algo := algo_from_algo(vault.aead_algo)
    aead.seal_oneshot(
        algo, 
        vault_entries_bytes, 
        vault.aead_tag[:aead.TAG_SIZES[algo]], 
        password_hash[:aead.KEY_SIZES[algo]], 
        vault.aead_iv[:aead.IV_SIZES[algo]],
        vault.aead_aad[:],
        vault_entries_bytes,
    )

    vault.locked = true

    return .Success

}

random_bytes :: proc($N: int) -> [N]u8 {
    bytes : [N]u8
    crypto.rand_bytes(bytes[:])
    return bytes
}

make_new_vault :: proc() -> ^Vault {
    vault: ^Vault = new(Vault, context.allocator)
    vault.locked = false
    vault.magic_bytes = {'E', 'Z', 'P', 'A', 'S', 'S', 'M', 'N'}
    vault.version = {0,0,0,0}
    vault.password_algo = .argon2id
    vault.aead_algo = .AES_GCM_256
    vault.password_salt = random_bytes(16)
    vault.password_hasher_params = argon2id.PARAMS_OWASP
    vault.aead_tag = 0
    vault.aead_iv = random_bytes(32)
    vault.aead_aad = AAD
    // vault.reserved = 
    vault.number_of_entries = 0
    // vault.entries = 

    return vault
}


read_entry :: proc(vault: ^Vault, id: EzString) -> (Entry, int) {
    if vault.locked {
        return NullEntry, -1
    }
    result := NullEntry
    num_found := 0
    index := -1
    for i in 0..<int(vault.number_of_entries) {
        if vault.entries[i].id == id {
            result = vault.entries[i]
            index = i
            num_found += 1
        }
    }
    assert(num_found < 2)

    if num_found == 0 {
        return NullEntry, index
    } else {
        return result, index
    }
}

add_entry :: proc(vault: ^Vault, entry: Entry) -> Status {
    if vault.locked {
        return .Failure
    }
    old_entry, index := read_entry(vault, entry.id)
    if old_entry == NullEntry {
        vault.entries[vault.number_of_entries] = entry
        vault.number_of_entries += 1
        return .Success
    } else {
        return .Failure
    }
}

update_entry :: proc(vault: ^Vault, new_entry: Entry) -> Status {
    if vault.locked {
        return .Failure
    }
    old_entry, index := read_entry(vault, new_entry.id)
    if old_entry == NullEntry {
        return .Failure
    } else {
        vault.entries[index] = new_entry
        return .Success
    }
}

delete_entry :: proc(vault: ^Vault, id: EzString) -> Status {
    if vault.locked {
        return .Failure
    }
    _, index := read_entry(vault, id)
    if index < 0 {
        return .Failure
    } else {
        vault.entries[index] = vault.entries[vault.number_of_entries]
        vault.entries[vault.number_of_entries] = NullEntry
        return .Success
    }
}
