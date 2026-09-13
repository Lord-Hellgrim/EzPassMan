package EzPassMan

import "core:c"
import "core:fmt"
import "core:strconv"
import "core:strings"
import "core:thread"
import "core:sync"
import "core:time"

import "core:nbio"

import mu "microui_modified"
import ss "smallstrings"


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

UiState :: struct {
    mu_ctx: mu.Context,
    log_buf:         [1<<16]byte,
    log_buf_len:     int,
    log_buf_updated: bool,
    bg: mu.Color,
    atlas_texture: RenderTexture2D,
    image: Image,
    screen_width: c.int,
    screen_height: c.int,
    key_map: [mu.Key][2]KeyboardKey,
    mouse_buttons_map : [mu.Mouse]MouseButton,
    screen_texture: RenderTexture2D,
	font: Font,
	scale_text_buffer : [4]u8,
	scale_text_len : int,
	password_text_buffer: [1024]u8,
	password_text_len: int,
	scroll_state: f32,
	entry_id_text_state: TextBox_State,
	username_text_state: TextBox_State,
	password_text_state: TextBox_State,
	note_text_state: TextBox_State,
}

TextBox_State :: struct {
	buf: [255]u8,
	len: int,
}

initialize_ui_state :: proc(state: ^UiState) {
	state.key_map = [mu.Key][2]KeyboardKey{
		.SHIFT     = {.LEFT_SHIFT,   .RIGHT_SHIFT},
		.CTRL      = {.LEFT_CONTROL, .RIGHT_CONTROL},
		.ALT       = {.LEFT_ALT,     .RIGHT_ALT},
		.BACKSPACE = {.BACKSPACE,    .KEY_NULL},
		.DELETE    = {.DELETE,       .KEY_NULL},
		.RETURN    = {.ENTER,        .KP_ENTER},
		.LEFT      = {.LEFT,         .KEY_NULL},
		.RIGHT     = {.RIGHT,        .KEY_NULL},
		.HOME      = {.HOME,         .KEY_NULL},
		.END       = {.END,          .KEY_NULL},
		.A         = {.A,            .KEY_NULL},
		.X         = {.X,            .KEY_NULL},
		.C         = {.C,            .KEY_NULL},
		.V         = {.V,            .KEY_NULL},
	}

	state.mouse_buttons_map = [mu.Mouse]MouseButton{
		.LEFT    = .LEFT,
		.RIGHT   = .RIGHT,
		.MIDDLE  = .MIDDLE,
	}

	state.screen_height = 540
	state.screen_width = 1024
}

uiw :: proc(state: UiState, x: i32) -> i32 {
	return state.screen_width/100 * x * i32(state.font.font_scale)/100*x
}


set_ui_scale :: proc(state: ^UiState) {
	ctx := &state.mu_ctx
	mu.layout_row(
		ctx,
		{uiw(state^, 50), state.screen_width/8},
		measure_text_height(ctx.style.font),
	)
	mu.label(ctx, "Set ui scale")
	if .SUBMIT in mu.textbox(ctx, state.scale_text_buffer[:], &state.scale_text_len, opt = {.NO_SCROLL}) {
		mu.set_focus(ctx, ctx.last_id)
		str := transmute(string)state.scale_text_buffer[:state.scale_text_len]
		scale, ok := strconv.parse_int(str)
		if ok {
			state.font.font_scale = f32(scale)/10
		} else {
		}
		state.scale_text_len = 0
	}
	mu.label(ctx, "")

}

load_latest_vault_task :: proc(task: thread.Task) {
	data := cast(^BackgroundData)task.data
	get_latest_vault(data.vault_ptr, data.user_id)
}

BackgroundData :: struct {
	vault_ptr: ^Vault,
	user_id: KeyString,
}

ez_app_windows :: proc(ui_state: ^UiState, app_state: ^AppState) {
	ctx := &ui_state.mu_ctx

	user_input := new(UserInput)

	text_buffer : [256]u8
	text_buffer_len : int

	scale_text_buffer : [4]u8
	scale_text_buffer_len : int

	vault := make_sample_vault()

	starting := true
	entering_password_starting := true

	panel_split: i32 = 5
	panel_width := ui_state.screen_width / panel_split

	for !WindowShouldClose() {
		free_all(context.temp_allocator)
		process_user_input(user_input, ui_state)

		mu.begin(ctx)

		{//------------------------------------- Side Panel -----------------------------------------------
			mu.begin_window(ctx, "Side panel", mu.Rect{0,0,panel_width, ui_state.screen_height}, opt = {.NO_SCROLL, .NO_INTERACT, .NO_TITLE}) 
			defer mu.end_window(ctx)

			if app_state.command == .start {
				
			} else {
				mu.layout_row(
					ctx,
					{measure_text_width(ctx.style.font, "Add Entry")*2},
					measure_text_height(ctx.style.font)
				)
				if .SUBMIT in mu.button(ctx, "Add Entry",.NONE, {}) {
					app_state.command = .add_entry
					ui_state.scroll_state = 0
				}
				if .SUBMIT in mu.button(ctx, "View Vault",.NONE, {}) {
					app_state.command = .view_vault
					ui_state.scroll_state = 0
				}
				if .SUBMIT in mu.button(ctx, "Update Entry",.NONE, {}) {
					app_state.command = .update_entry
					ui_state.scroll_state = 0
				}
				if .SUBMIT in mu.button(ctx, "Delete Entry",.NONE, {}) {
					app_state.command = .delete_entry
					ui_state.scroll_state = 0
				}
			}
		} // -------------------------End of side panel -----------------------------------------------------

		if mu.window(ctx, "START", mu.Rect{panel_width, 0 , panel_width*(panel_split-1), ui_state.screen_height}, {.NO_RESIZE, .NO_CLOSE, .NO_INTERACT, .NO_TITLE}) {
			// mu.layout_row(ctx, {panel_start, 2, panel_width}, ui_state.screen_height)
			
			// set_ui_scale(ui_state)

			switch app_state.command {
				case .start: {
					mu.layout_row(
						ctx,
						{
							measure_text_width(ctx.style.font, "Enter User Id")*2,

						},
						measure_text_height(ctx.style.font),
					)
					mu.label(ctx, "Enter User id")
					res := mu.textbox(ctx, text_buffer[:], &text_buffer_len, {.ALIGN_CENTER})
					if starting {
						mu.set_focus(ctx, ctx.last_id)
						starting = false
					}
					if .SUBMIT in res{
						mu.set_focus(ctx, ctx.last_id)
						text_buffer_len = 0
						app_state.command = .view_vault
						ui_state.scroll_state = 0
					}
	
				}
				case .main_menu: {
					unreachable()
					// mu.layout_row(
					// 	ctx,
					// 	{measure_text_width(ctx.style.font, "Add Entry")*2},
					// 	measure_text_height(ctx.style.font)
					// )
					// if .SUBMIT in mu.button(ctx, "Add Entry_X",.NONE, {.ALIGN_CENTER}) {
					// 	app_state.command = .add_entry
					// 	ui_state.scroll_state = 0
					// }
					// if .SUBMIT in mu.button(ctx, "View Vault_X",.NONE, {.ALIGN_CENTER}) {
					// 	app_state.command = .view_vault
					// 	ui_state.scroll_state = 0
					// }
					// if .SUBMIT in mu.button(ctx, "Update Entry_X",.NONE, {.ALIGN_CENTER}) {
					// 	app_state.command = .update_entry
					// 	ui_state.scroll_state = 0
					// }
					// if .SUBMIT in mu.button(ctx, "Delete Entry_X",.NONE, {.ALIGN_CENTER}) {
					// 	app_state.command = .delete_entry
					// 	ui_state.scroll_state = 0
					// }
					// if app_state.vault_synced {
	
					// } else {
					// 	get_latest_vault(vault, app_state.user_id)
					// }
				}
				case .view_vault: {
					
					if vault.locked {
						
						mu.layout_row(
							ctx, 
							{measure_text_width(ctx.style.font, "VAULT IS LOCKED. ENTER PASSWORD")*2},
							measure_text_height(ctx.style.font)*2,
						)
						mu.label(ctx, "VAULT IS LOCKED. ENTER PASSWORD")
						password_box_result := mu.textbox(ctx, app_state.ui_state.password_text_buffer[:], &app_state.ui_state.password_text_len, opt = {.ALIGN_CENTER}, local_style = .PasswordText)
						mu.set_focus(ctx, ctx.last_id)
						if .SUBMIT in password_box_result {
							if entering_password_starting {
								entering_password_starting = false
							}
							password := strings.clone_from_bytes(app_state.ui_state.password_text_buffer[:app_state.ui_state.password_text_len])
							open_vault(vault, password)
							app_state.password = password
						}
					} else {
						
						for i in 0..<vault.number_of_entries {
							mu.layout_row(
								ctx,
								{
									measure_text_width(ctx.style.font, "LOOOOOOOOOOOOOOOOOOOOOOOONG"),
									measure_text_width(ctx.style.font, "Copy password"),
								},
								measure_text_height(ctx.style.font)*2
								)

							if .SUBMIT in mu.button(ctx, ss.as_string(&vault.entries[i].id)) {}
							{mu.layout_column(ctx)
								mu.layout_row(ctx, {200}, measure_text_height(ctx.style.font)+10)
								mu.push_id_string(ctx, ss.as_string(&vault.entries[i].username))
								if .SUBMIT in mu.button(ctx, "Copy username") {}
								mu.pop_id(ctx)
								mu.push_id_string(ctx, ss.as_string(&vault.entries[i].id))
								if .SUBMIT in mu.button(ctx, "Copy password") {
									set_clipboard(ss.to_cstring(vault.entries[i].password))
								}
								mu.pop_id(ctx)
							}
							mu.label(ctx, "")
						}
					}
				}
				case .add_entry: {
					mu.layout_row(ctx, {300, 100, 100}, 100)
					{mu.layout_column(ctx)
						mu.layout_row(ctx, {300}, 40)
						mu.label(ctx, "Entry ID")
						mu.label(ctx, "Username")
						mu.label(ctx, "Password")
						mu.label(ctx, "Note")
					}
					{mu.layout_column(ctx)
						mu.layout_row(ctx, {300}, 40)
						if .SUBMIT in mu.textbox(ctx, app_state.ui_state.entry_id_text_state.buf[:], &app_state.ui_state.entry_id_text_state.len) {
							
						}
						if .SUBMIT in mu.textbox(ctx, app_state.ui_state.username_text_state.buf[:], &app_state.ui_state.username_text_state.len) {
							
						}
						if .SUBMIT in mu.textbox(ctx, app_state.ui_state.password_text_state.buf[:], &app_state.ui_state.password_text_state.len) {
							
						}
						if .SUBMIT in mu.textbox(ctx, app_state.ui_state.note_text_state.buf[:], &app_state.ui_state.note_text_state.len) {
							
						}
					}
				}
				case .delete_entry: {
	
				}
				case .update_entry: {
	
				}
				case .entering_password: {
	
				}
	
			}
		}

		mu.end(ctx)

		render(ui_state)
	}
}

main :: proc() {

	app_state := new(AppState)

    ui_state := new(UiState)
	initialize_ui_state(ui_state)

	ui_state.bg = {90, 95, 100, 255}
    initialize_renderer(ui_state)
    defer destroy_renderer(ui_state)
	defer clear_clipboard("Clipboard was cleared by EzPassMan. You're welcome ;)")
    ez_app_windows(ui_state, app_state)

}


// -------------------Networking code -----------------------------------------------------

get_latest_vault :: proc(current_vault: ^Vault, user_id: ss.SmallString(255)) {
    // make noise connection to server and fetch vault
   
}

upload_vault :: proc(current_vault: ^Vault, user_id: ss.SmallString(255)) {

}
