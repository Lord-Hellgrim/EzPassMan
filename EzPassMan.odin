package EzPassMan

import "core:crypto"

import "core:os"
import "core:crypto/argon2id"
import "core:crypto/aead"
import "core:slice"
import "core:bufio"
import "core:fmt"
import "core:time"
import "core:io"
import "core:unicode/utf8"
import "core:mem"

import       "core:c/libc"
import win32 "core:sys/windows"

import ss "smallstrings"


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

print_vault :: proc(vault: ^Vault, verbose: bool) {
    
    if verbose == true {    
            fmt.println("vault.locked: ", vault.locked)
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
    
    if vault.locked {
        fmt.println("Vault is locked\nNo entries can be printed")
    } else {
        for &entry in vault.entries[:vault.number_of_entries] {
            print_entry(&entry)
        }

    }

    fmt.println("---------------------------------")
}


MAX_ENTRIES :: 10_000
SALT_SIZE :: 16
TAG_SIZE :: 32
PASSWORD_HASH_SIZE :: 32
IV_SIZE :: 12

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

SubCommand :: enum {
    id,
    username,
    password,
    note,
    generate,
}

Command :: enum {
    start,
    main_menu,
    view_vault,
    add_entry,
    delete_entry,
    update_entry,
    entering_password,
}

AppState :: struct {
    user_id: string,
    verbose_vault: bool,
    command : Command,
    subcommand: SubCommand,
    help: bool,
    vault_fetched: time.Time,
    vault_synced: bool,
    password: string,
}

get_latest_vault :: proc(current_vault: ^Vault, user_id: string) {
    // make noise connection to server and fetch vault
}

upload_vault :: proc(current_vault: ^Vault, user_id: string) {

}


orig_mode: win32.DWORD

enable_raw_mode :: proc() {
		// Get a handle to the standard input.
	stdin := win32.GetStdHandle(win32.STD_INPUT_HANDLE)
	assert(stdin != win32.INVALID_HANDLE_VALUE)

	// Get the original terminal mode.
	ok := win32.GetConsoleMode(stdin, &orig_mode)
	assert(ok == true)

	// Reset to the original attributes at the end of the program.
	libc.atexit(disable_raw_mode)

	// Copy, and remove the
	// ENABLE_ECHO_INPUT (so what is typed is not shown) and
	// ENABLE_LINE_INPUT (so we get each input instead of an entire line at once) flags.
	raw := orig_mode
	raw &= ~win32.ENABLE_ECHO_INPUT
	raw &= ~win32.ENABLE_LINE_INPUT
	ok = win32.SetConsoleMode(stdin, raw)
	assert(ok == true)
}

disable_raw_mode :: proc "c" () {
    stdin := win32.GetStdHandle(win32.STD_INPUT_HANDLE)
	assert_contextless(stdin != win32.INVALID_HANDLE_VALUE)

	win32.SetConsoleMode(stdin, orig_mode)
}

get_password :: proc(allocator := context.allocator) -> string {

	fmt.print("Enter password: ")

    enable_raw_mode()
    defer disable_raw_mode()

	buf := make([dynamic]byte, allocator)
	in_stream := os.to_stream(os.stdin)

	for {
		// Read a single character at a time.
		ch, sz, err := io.read_rune(in_stream)
		switch {
		case err != nil:
			fmt.eprintfln("\nError: %v", err)
			os.exit(1)

		// End line
		case ch == '\n': // Posix
			fallthrough
		case ch == '\r': // Windows
			fmt.println()
			return string(buf[:])

		// Backspace
		case ch == '\u007f': // Posix
			fallthrough
		case ch == '\b':     // Windows
			_, bs_sz := utf8.decode_last_rune(buf[:])	
			if bs_sz > 0 {
				resize(&buf, len(buf)-bs_sz)
				// Replace last star with a space.
				fmt.print("\b \b")
			}
		case:
			bytes, _ := utf8.encode_rune(ch)
			append(&buf, ..bytes[:sz])

			fmt.print('*')
		}
	}
}

render_app :: proc(state: ^AppState, vault: ^Vault) {
    if state.help {
        fmt.println("fetch: Fetches the latest version of your vault from your current global backup")
        fmt.println("Upload: Uploads current vault version to global backup")
        fmt.println("open: Opens/decrypts the vault in memory. Will prompt you for a password")
        fmt.println("lock: Locks/encrypts the vault in memory")
        fmt.println("view: Prints the id's of all entries in the vault")
        fmt.println("read [entry id]: Prints the entry username and copies the password to the clipboard")
        fmt.println("add: Adds an entry via the \"Add Wizard\"")
        fmt.println("update: Updates an entry via the \"Update Wizard\"")
        fmt.println("delete: Deletes an entry. WARNING - IRREVERSIBLE ACTION!!")
        fmt.println("help: Prints this message again")
        fmt.println("verbose 0/1: Sets verbose explanations on (1) or off (0)")
        fmt.println("quit: If you have made changes to the vault but not yet uploaded it, this command will print a warning.")
        fmt.println("   otherwise, exits the program")
        state.help = false
        return
    }
    switch state.command {
        case .start: {fmt.println("Please enter user id:")}
        case .main_menu: {
            fmt.println("Welcome to EzPassMan")
            fmt.println("Current vault status: ")
            if vault.locked {
                fmt.println("   LOCKED")
            } else {
                fmt.println("   OPEN")
            }
            fmt.println("Current vault was fetched at: ", state.vault_fetched)
            if state.vault_synced == true {
                fmt.println("Current vault has not been changed")
            } else {
                fmt.println("There are unsynced changes to this local vault.\nClosing the program without syncing will cause those changes to be lost")
            }

            fmt.println("Available commands are: fetch, upload, open, lock, view, add, update, delete, help, verbose, quit")
        }
        case .view_vault:
            print_vault(vault, state.verbose_vault)
            fmt.println()
            fmt.println("Available commands are: fetch, upload, open, lock, view, add, update, delete, help, verbose, quit")

        case .add_entry:
        case .update_entry:
        case .delete_entry:
        case .entering_password:
    }
}

process_input :: proc(state: ^AppState, vault: ^Vault, line: string) {
    switch line {
        case "fetch": {
            #partial switch state.command {
                case .main_menu, .view_vault: {get_latest_vault(vault, state.user_id)}
                case: {fmt.println("Invalid command")}
            }
            
        }
        case "upload": {
            #partial switch state.command {
                case .main_menu, .view_vault: {upload_vault(vault, state.user_id)}
                case:
            }
        }
        case "open": {
            #partial switch state.command {
                case .main_menu, .view_vault: {
                    state.password = get_password()
                    fmt.println(state.password)
                    status := open_vault(vault, state.password)
                    switch status {
                        case .Success: {
                            fmt.println("Vault opened")
                    }
                        case.Wrong_Password: fmt.println("Wrong password")
                        case .Failure: fmt.println("CORRUPT VAULT")
                        case .Too_Long_Password: fmt.println("Invalid password. Must be less than 256 bytes.")
                    }
                }
                case: fmt.println("Invalid command")
            }
        }
        case "lock": {
            lock_vault(vault, state.password)
        }
        case "view": {
            state.command = .view_vault
        }
        case "add": {
            state.command = .add_entry
        }
        case "update": {

        }
        case "delete": {

        }
        case "help": {

        }
        case "verbose": {

        }
        case: {
            #partial switch state.command {
                case .add_entry, .update_entry: {
                    switch state.subcommand {
                        case .id:
                        case .username:
                        case .password:
                        case .note:
                        case .generate:
                    }
                }
                case: fmt.println("Invalid command")
            }
            
        }
    }
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

    test_vault := make_new_vault()

    add_entry(
        test_vault, 
        Entry{
            id = ss.from_string("first id", 255), 
            username = ss.from_string("first uesrname", 255), 
            password = ss.from_string("first password", 255), 
            note = ss.from_string("first note", 255), 
        }
    )

    add_entry(
        test_vault, 
        Entry{
            id = ss.from_string("second id", 255), 
            username = ss.from_string("second uesrname", 255), 
            password = ss.from_string("second password", 255), 
            note = ss.from_string("second note", 255), 
        }
    )

    lock_vault(test_vault, "1234")

    app_state := AppState{
        verbose_vault = false,
        command = .main_menu
    }

    scanner: bufio.Scanner
    stdin := os.to_stream(os.stdin)
    bufio.scanner_init(&scanner, stdin, context.temp_allocator)

    for {
        
        render_app(&app_state, test_vault)
        fmt.printf("> ")
        if !bufio.scan(&scanner) {
            break
        }
        line := bufio.scanner_text(&scanner)
        if line == "quit" {
            break
        }
        process_input(&app_state, test_vault, line)
        
    }

    if err := bufio.scanner_error(&scanner); err != nil {
        fmt.eprintln("error scanning input: %v", err)
    }

    free_all(context.temp_allocator)


}