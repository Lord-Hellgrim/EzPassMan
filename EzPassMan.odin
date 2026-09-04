package EzPassMan

import "core:os"
import "core:bufio"
import "core:strings"
import "core:fmt"
import "core:time"
import "core:io"
import "core:unicode/utf8"
import "core:c"

import       "core:c/libc"
import win32 "core:sys/windows"

import ss "smallstrings"

import mu "vendor:microui"
import rl "vendor:raylib"

KeyString :: ss.SmallString(255)

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
    user_id: ss.SmallString(255),
    verbose_vault: bool,
    command : Command,
    subcommand: SubCommand,
    help: bool,
    vault_fetched: time.Time,
    vault_synced: bool,
    password: string,
    ui_state: UiState,
}

make_sample_vault :: proc() -> ^Vault {
    test_vault := make_new_vault()

    add_entry(
        test_vault, 
        Entry{
            id = ss.from_string("first id", 255), 
            username = ss.from_string("first username", 255), 
            password = ss.from_string("first password", 255), 
            note = ss.from_string("first note", 255), 
        }
    )

    add_entry(
        test_vault, 
        Entry{
            id = ss.from_string("second id", 255), 
            username = ss.from_string("second username", 255), 
            password = ss.from_string("second password", 255), 
            note = ss.from_string("second note", 255), 
        }
    )

    lock_vault(test_vault, "1234")

    return test_vault

}

get_latest_vault :: proc(current_vault: ^Vault, user_id: ss.SmallString(255)) {
    // make noise connection to server and fetch vault
   
}

upload_vault :: proc(current_vault: ^Vault, user_id: ss.SmallString(255)) {

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


// measure_text_width :: proc(font: microui.Font, str: string) -> i32 {
//     return 0
// }

// measure_text_height :: proc(font: microui.Font) -> i32 {
//     return 0
// }


// main :: proc() {

//     // -------------MICROUI------------------------------------------


//     // ------------ TERMINAL UI -------------------------------------


//     // pull := os.Process_Desc{
//     //     working_dir = "./vault",
//     //     command = {"git", "pull"},
//     // }

//     // commit := os.Process_Desc{
//     //     working_dir = "./vault",
//     //     command = {"git", "commit"},
//     // }

//     // push := os.Process_Desc{
//     //     working_dir = "./vault",
//     //     command = {"git", "push"},
//     // }

//     // test_vault := make_new_vault()

//     // add_entry(
//     //     test_vault, 
//     //     Entry{
//     //         id = ss.from_string("first id", 255), 
//     //         username = ss.from_string("first uesrname", 255), 
//     //         password = ss.from_string("first password", 255), 
//     //         note = ss.from_string("first note", 255), 
//     //     }
//     // )

//     // add_entry(
//     //     test_vault, 
//     //     Entry{
//     //         id = ss.from_string("second id", 255), 
//     //         username = ss.from_string("second uesrname", 255), 
//     //         password = ss.from_string("second password", 255), 
//     //         note = ss.from_string("second note", 255), 
//     //     }
//     // )

//     // lock_vault(test_vault, "1234")

//     // app_state := AppState{
//     //     verbose_vault = false,
//     //     command = .main_menu
//     // }

//     // scanner: bufio.Scanner
//     // stdin := os.to_stream(os.stdin)
//     // bufio.scanner_init(&scanner, stdin, context.temp_allocator)

//     // for {
        
//     //     render_app(&app_state, test_vault)
//     //     fmt.printf("> ")
//     //     if !bufio.scan(&scanner) {
//     //         break
//     //     }
//     //     line := bufio.scanner_text(&scanner)
//     //     if line == "quit" {
//     //         break
//     //     }
//     //     process_input(&app_state, test_vault, line)
        
//     // }

//     // if err := bufio.scanner_error(&scanner); err != nil {
//     //     fmt.eprintln("error scanning input: %v", err)
//     // }

//     // free_all(context.temp_allocator)


// }