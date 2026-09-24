package EzPassMan

import "core:crypto"
import "core:crypto/argon2id"
import "core:crypto/aead"
import "core:slice"
import "core:fmt"
// import "core:mem"
import "core:strings"

import ss "smallstrings"


MAX_ENTRIES :: 1_000
SALT_SIZE :: 16
TAG_SIZE :: 32
PASSWORD_HASH_SIZE :: 32
IV_SIZE :: 12


KeyString :: ss.SmallString(255)

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

// This is just to insure the vault spec from accidentally changing with updates to the odin core crypto lib. 
// Ensures consistent algo numbering
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
    is_locked: b64,                                    
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

cmp_entries :: proc(i, j: Entry) -> slice.Ordering {
    i, j := i, j
    i_string := ss.as_string(&i.id)
    j_string := ss.as_string(&j.id)


    switch strings.compare(i_string, j_string) {
        case -1: return .Less
        case 0: return .Equal
        case 1: return .Greater
    }

    return .Less
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

hash_password :: proc(password: EzString, hash_params: ^argon2id.Parameters, salt: []u8) -> ([32]u8, Status) {
    password := password
    password_hash : [32]u8
    alloc_error := argon2id.derive(
        hash_params, 
        password.data[:], 
        salt[:], 
        password_hash[:]
    )

    if alloc_error != .None {
        return 0, .Failure
    }

    return password_hash, .Success
}

// TODO: Add more validation rules and checks
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

open_vault :: proc(vault: ^Vault, password: EzString) -> (Status) {

    if !vault.is_locked {
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
        vault.is_locked = false
        destroy_vault(new_vault)
        return .Success
    }
}

destroy_vault :: proc(vault: ^Vault) {
    new_vault_bytes := slice.bytes_from_ptr(rawptr(vault), size_of(Vault))
    slice.zero(new_vault_bytes)
    free(vault)
}

lock_vault :: proc(vault: ^Vault, password: EzString) -> Status {
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

    vault.is_locked = true

    return .Success
}

random_bytes :: proc($N: int) -> [N]u8 {
    bytes : [N]u8
    crypto.rand_bytes(bytes[:])
    return bytes
}

make_new_vault :: proc() -> ^Vault {
    vault: ^Vault = new(Vault, context.allocator)
    vault.is_locked = false
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

make_sample_vault :: proc() -> ^Vault {
    test_vault := make_new_vault()

    id := ss.from_string("Google: ", 255)
    username := ss.from_string("googlygoo: ", 255)
    password := ss.from_string("Totally secure baby ", 255)
    note := ss.from_string("This is a google account, herp derp", 255)
    add_entry( test_vault, Entry{ id = id, username = username, password = password, note = note } )

    id = ss.from_string("Amazon", 255)
    username = ss.from_string("Bezos!!!", 255)
    password = ss.from_string("Mackenzie XOXO", 255)
    note = ss.from_string("Fuck Elon, I wanna be a trillionaire!", 255)
    add_entry( test_vault, Entry{ id = id, username = username, password = password, note = note } )

    id = ss.from_string("Netflix", 255)
    username = ss.from_string("legit@not_fake.com", 255)
    password = ss.from_string("12345", 255)
    note = ss.from_string("Gotta watch Vikings, I guess", 255)
    add_entry( test_vault, Entry{ id = id, username = username, password = password, note = note } )

    id = ss.from_string("Twitter", 255)
    username = ss.from_string("MuskyMusk", 255)
    password = ss.from_string("TO THE MOON!", 255)
    note = ss.from_string("Maybe I can make an electric spaceship! Hmmmmm", 255)
    add_entry( test_vault, Entry{ id = id, username = username, password = password, note = note } )

    id = ss.from_string("X", 255)
    username = ss.from_string("unknown", 255)
    password = ss.from_string("Not very secure", 255)
    note = ss.from_string("Isn't this already on the list somewhere?", 255)
    add_entry( test_vault, Entry{ id = id, username = username, password = password, note = note } )

    id = ss.from_string("McMaster-Carr", 255)
    username = ss.from_string("Carmack69420", 255)
    password = ss.from_string("BestOfTheBest", 255)
    note = ss.from_string("I don't have any children...", 255)
    add_entry( test_vault, Entry{ id = id, username = username, password = password, note = note } )

    id = ss.from_string("jai", 255)
    username = ss.from_string("J_Blow", 255)
    password = ss.from_string("Witness Me!", 255)
    note = ss.from_string("Grump grump grump", 255)
    add_entry( test_vault, Entry{ id = id, username = username, password = password, note = note } )

    id = ss.from_string("Molly Rocket", 255)
    username = ss.from_string("Casey MuMu", 255)
    password = ss.from_string("Vector Vector Vector", 255)
    note = ss.from_string("Enhance all the computers", 255)
    add_entry( test_vault, Entry{ id = id, username = username, password = password, note = note } )

    lock_vault(test_vault, ss.from_string("1234", 255))

    return test_vault
}

print_vault :: proc(vault: ^Vault, verbose: bool) {
    
    if verbose == true {    
            fmt.println("vault.locked: ", vault.is_locked)
            fmt.println("vault.magic_bytes: ", vault.magic_bytes)
            fmt.println("vault.version: ", vault.version)
            fmt.println("vault.password_algo: ", vault.password_algo)
            fmt.println("vault.aead_algo: ", vault.aead_algo)
            fmt.println("vault.password_salt: ", vault.password_salt)
            fmt.println("vault.password_hasher_params: ", vault.password_hasher_params)
            fmt.println("vault.aead_tag: ", vault.aead_tag)
            fmt.println("vault.aead_iv: ", vault.aead_iv)
            fmt.println("vault.aead_aad: ", vault.aead_aad)
            fmt.println("vault.number_of_entries: ", vault.number_of_entries)
    }
    fmt.println("------------ENTRIES--------------")
    
    if vault.is_locked {
        fmt.println("Vault is locked\nNo entries can be printed")
    } else {
        for &entry in vault.entries[:vault.number_of_entries] {
            print_entry(&entry)
        }

    }

    fmt.println("---------------------------------")
}

read_entry :: proc(vault: ^Vault, id: EzString) -> (Entry, int) {
    if vault.is_locked {
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
    if vault.is_locked {
        return .Failure
    }

    if vault.number_of_entries == 0 {
        vault.entries[0] = entry
        vault.number_of_entries += 1
        return .Success
    } else if vault.number_of_entries == 1000 {
        return .Failure
    }

    searching := true
    temp : Entry
    bubble := entry
    for i in 0..<vault.number_of_entries + 1 {
        
        if searching {
            if i == vault.number_of_entries {
                vault.entries[i] = entry
                vault.number_of_entries += 1
                return .Success
            }
            switch ss.cmp(entry.id, vault.entries[i].id) {
                case .Less: searching = false
                case .Equal: return .Failure
                case .Greater: continue
            }
        }
        temp = vault.entries[i]
        vault.entries[i] = bubble
        bubble = temp
    }

    vault.number_of_entries += 1
    return .Success

    // old_entry, index := read_entry(vault, entry.id)
    // if old_entry == NullEntry {
    //     vault.entries[vault.number_of_entries] = entry
    //     vault.number_of_entries += 1
    //     return .Success
    // } else {
    //     return .Failure
    // }
}

update_entry :: proc(vault: ^Vault, new_entry: Entry) -> Status {
    if vault.is_locked {
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
    if vault.is_locked {
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

bubble_sort_vault_entries :: proc(vault: ^Vault) {
    for i in 0..<vault.number_of_entries-1 {
        switch cmp_entries(vault.entries[i], vault.entries[i+1]) {
            case .Less: continue
            case .Equal: assert(false, "hit an equal entry in edit path")
            case .Greater:  {
                vault.entries[i], vault.entries[i+1] = vault.entries[i+1], vault.entries[i]
            }
        }
    }
}