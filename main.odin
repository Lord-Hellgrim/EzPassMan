package EzPassMan

import "core:c"
import "core:fmt"
import "core:strconv"
import "core:strings"
import "core:thread"
import "core:crypto"
import "core:time"
import "core:slice"
import "base:intrinsics"

import "core:nbio"

import mu "microui_modified"
import ss "smallstrings"


RowTable :: struct($N: int, $K: typeid, $V: typeid) where intrinsics.type_is_comparable(K) {
	[N]Row(K, V)
}

Row :: struct($K: typeid, $V: typeid) where intrinsics.type_is_comparable(K) {
	key: K,
	value: V,
}

ColumnTable :: struct($N: int, $K: typeid, $V: typeid) where intrinsics.type_is_comparable(K) {
	[N]K,
	[N]V,
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
    edit_entry,
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
	scroll_state: f32,
	text_bufs: [BufId]TextBox_State,
	filter_checkbox: FilterState,
	password_gen_boxes: PassGenState,
	// scale_text_buffer : TextBox_State,
	// password_text_buffer: TextBox_State,
	// entry_id_text_state: TextBox_State,
	// username_text_state: TextBox_State,
	// password_text_state: TextBox_State,
	// note_text_state: TextBox_State,
	// filter_text_state: TextBox_State,
}

BufId :: enum {
	scale,
	password,
	entry_id,
	username,
	note,
	filter,
}

clear_text_buffers :: proc(ui: ^UiState) {
	for &buffer in ui.text_bufs {
		zero_text_buffer(&buffer)
	}
	// zero_text_buffer(&ui.scale_text_buffer )
	// zero_text_buffer(&ui.password_text_buffer)
	// zero_text_buffer(&ui.entry_id_text_state)
	// zero_text_buffer(&ui.username_text_state)
	// zero_text_buffer(&ui.password_text_state)
	// zero_text_buffer(&ui.note_text_state)
	// zero_text_buffer(&ui.filter_text_state)
}
TextBox_State :: struct {
	buf: [255]u8,
	len: int,
}

FilterState :: enum {
	contains,
	starts_with,
	ends_with,
}

PassGenState :: struct {
	numbers: b8,
	special: b8,
	uppers: b8,
	len: u8
}



zero_text_buffer :: proc(text_buffer: ^TextBox_State) {
	slice.zero(text_buffer.buf[:])
	text_buffer.len = 0
}


initialize_ui :: proc(state: ^UiState) {
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

uiw :: proc(state: ^UiState, x: f32) -> i32 {
	return i32(x*f32(state.screen_width))
}

set_ui_scale :: proc(state: ^UiState) {
	ctx := &state.mu_ctx
	mu.layout_row(
		ctx,
		{uiw(state, 50), state.screen_width/8},
		measure_text_height(ctx.style.font),
	)
	mu.label(ctx, "Set ui scale")
	if .SUBMIT in mu.textbox(ctx, state.text_bufs[.scale].buf[:], &state.text_bufs[.scale].len, opt = {.NO_SCROLL}) {
		mu.set_focus(ctx, ctx.last_id)
		str := transmute(string)state.text_bufs[.scale].buf[:state.text_bufs[.scale].len]
		scale, ok := strconv.parse_int(str)
		if ok {
			state.font.font_scale = f32(scale)/10
		} else {
		}
		state.text_bufs[.scale].len = 0
	}
	mu.label(ctx, "")
}

load_latest_vault_task :: proc(task: thread.Task) {
	data := cast(^BackgroundData)task.data
	get_latest_vault(data.vault_ptr, data.user_id)
}

generate_password :: proc(ui: ^UiState) {
    base := "abcdefghijklmnopqrstuvwxyz" //26
    caps := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" //26
    numbers := "0123456789"				 //10
    special :="!@#$%^&*()-_=+"			 //14

	temp_buf : [255]u8
	temp := temp_buf[:ui.password_gen_boxes.len]
	
	defer slice.zero(temp)
	crypto.rand_bytes(temp)

	zero_text_buffer(&ui.text_bufs[.password])

	alphabet : EzString
	ss.extend_with_string(&alphabet, base)
	if ui.password_gen_boxes.uppers {
		ss.extend_with_string(&alphabet, caps)
	}
	if ui.password_gen_boxes.numbers {
		ss.extend_with_string(&alphabet, numbers)		
	}
	if ui.password_gen_boxes.special {
		ss.extend_with_string(&alphabet, special)
	}

	for i in 0..<len(temp) {
		infinity_guard := 0
		for temp[i] > 255 - (255 % alphabet.len) && infinity_guard < 10_000 {
			crypto.rand_bytes(temp[i:i])
			infinity_guard += 1
		}
		ui.text_bufs[.password].buf[i] = alphabet.data[u8(i) % alphabet.len]
	}
}

BackgroundData :: struct {
	vault_ptr: ^Vault,
	user_id: KeyString,
}

ez_app_windows :: proc(app_state: ^AppState) {
	ctx := &app_state.ui_state.mu_ctx
	ui := &app_state.ui_state

	user_input := new(UserInput)

	vault := make_sample_vault()

	starting := true
	entering_password_starting := true

	panel_split: i32 = 5
	
	// loc: i32 = 0
	for !WindowShouldClose() {
		// loc += 1
		free_all(context.temp_allocator)
		process_user_input(user_input, ui)
		
		ui.screen_width = get_screen_width()
		ui.screen_height = get_screen_height()
		
		panel_width := ui.screen_width / panel_split

		mu.begin(ctx)


		{//------------------------------------- Side Panel -----------------------------------------------
			mu.begin_window(ctx, "Side panel", mu.Rect{0,0,uiw(ui, 0.2), ui.screen_height}, opt = {.NO_CLOSE, .NO_INTERACT, .NO_TITLE}) 
			defer mu.end_window(ctx)

			if app_state.command == .start {
				
			} else {
				mu.layout_row(
					ctx,
					{uiw(ui, 0.15)},
					measure_text_height(ctx.style.font)*2
				)
				if app_state.command == .view_vault {
					if .SUBMIT in mu.button(ctx, "Add Entry",.NONE, {}) {
						app_state.command = .add_entry
						ui.scroll_state = 0
					}
				} else {
					if .SUBMIT in mu.button(ctx, "View Vault",.NONE, {}) {
						app_state.command = .view_vault
						ui.scroll_state = 0
					}
				}
				if !vault.is_locked {
					if .SUBMIT in mu.button(ctx, "Lock Vault", .NONE, {}) {
						lock_vault(vault, app_state.password)
					}
				}
				mu.label(ctx, "Filter by")
				mu.textbox(ctx, ui.text_bufs[.filter].buf[:], &ui.text_bufs[.filter].len)
				mu.layout_row(ctx, {uiw(ui, 0.19)}, 50)
				starts_with := ui.filter_checkbox == FilterState.starts_with
				contains := ui.filter_checkbox == FilterState.contains
				ends_with := ui.filter_checkbox == FilterState.ends_with

				if .CHANGE in mu.checkbox(ctx, "Starts with", &starts_with, local_style = .RadioButton) {
					ui.filter_checkbox = .starts_with
				}
				if .CHANGE in mu.checkbox(ctx, "Contains", &contains, local_style = .RadioButton) {
					ui.filter_checkbox = .contains
				}
				if .CHANGE in mu.checkbox(ctx, "Ends with", &ends_with, local_style = .RadioButton) {
					ui.filter_checkbox = .ends_with
				}
			}
		} // -------------------------End of side panel -----------------------------------------------------

		if mu.window(ctx, "START", mu.Rect{uiw(ui, 0.2), 0 , uiw(ui, 0.8), ui.screen_height}, {.NO_CLOSE, .NO_INTERACT, .NO_TITLE}) {
			switch app_state.command {
				case .start: {
					mu.layout_row(
						ctx,
						{
							uiw(ui, 0.4),
						},
						measure_text_height(ctx.style.font),
					)
					mu.label(ctx, "Enter User id")
					res := mu.textbox(ctx, ui.text_bufs[.username].buf[:], &ui.text_bufs[.username].len, {.ALIGN_CENTER})
					if starting {
						mu.set_focus(ctx, ctx.last_id)
						starting = false
					}
					if .SUBMIT in res{
						mu.set_focus(ctx, ctx.last_id)
						zero_text_buffer(&ui.text_bufs[.username])
						app_state.command = .view_vault
						ui.scroll_state = 0
					}
				}
				case .view_vault: {
					if vault.is_locked {
						mu.layout_row(
							ctx, 
							{uiw(ui, 0.8)},
							measure_text_height(ctx.style.font)*2,
						)
						mu.label(ctx, "VAULT IS LOCKED. ENTER PASSWORD")
						password_box_result := mu.textbox(ctx, ui.text_bufs[.password].buf[:], &ui.text_bufs[.password].len, opt = {.ALIGN_CENTER}, local_style = .PasswordText)
						if entering_password_starting {
							mu.set_focus(ctx, ctx.last_id)
							entering_password_starting = false
						}
						if .SUBMIT in password_box_result {
							password := strings.clone_from_bytes(ui.text_bufs[.password].buf[:ui.text_bufs[.password].len])
							open_vault(vault, password)
							app_state.password = password
							clear_text_buffers(ui)
						}
					} else {
						for i in 0..<vault.number_of_entries {
							entry_id: string = strings.clone_from_bytes(vault.entries[i].id.data[:vault.entries[i].id.len], allocator = context.temp_allocator)
							filter := strings.clone_from_bytes(ui.text_bufs[.filter].buf[:ui.text_bufs[.filter].len], allocator = context.temp_allocator)
							switch ui.filter_checkbox {
								case .contains: {
									if !strings.contains(entry_id, filter) {
										continue
									}
								}
								case .starts_with: {
									if !strings.starts_with(entry_id, filter) {
										continue
									}
								}
								case .ends_with: {
									if !strings.ends_with(entry_id, filter) {
										continue
									}
								}
							}
							mu.layout_row(
								ctx,
								{
									measure_text_width(ctx.style.font, "LOOOOOOOOOOOOOOOOOOOOOOOONG"),
									measure_text_width(ctx.style.font, "Copy password"),
								},
								measure_text_height(ctx.style.font)*2
								)
							if .SUBMIT in mu.button(ctx, ss.as_string(&vault.entries[i].id)) {
								app_state.command = .edit_entry;
							}
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

						mu.textbox(ctx, ui.text_bufs[.entry_id].buf[:], &ui.text_bufs[.entry_id].len)
						mu.textbox(ctx, ui.text_bufs[.username].buf[:], &ui.text_bufs[.username].len)
						mu.textbox(ctx, ui.text_bufs[.password].buf[:], &ui.text_bufs[.password].len)
						mu.textbox(ctx, ui.text_bufs[.note].buf[:], &ui.text_bufs[.note].len)

						mu.layout_row(ctx, {uiw(ui, 0.19)}, 50)
						starts_with := ui.filter_checkbox == FilterState.starts_with
						contains := ui.filter_checkbox == FilterState.contains
						ends_with := ui.filter_checkbox == FilterState.ends_with

						if .CHANGE in mu.checkbox(ctx, "Starts with", &starts_with, local_style = .RadioButton) {
							ui.filter_checkbox = .starts_with
						}
						if .CHANGE in mu.checkbox(ctx, "Contains", &contains, local_style = .RadioButton) {
							ui.filter_checkbox = .contains
						}
						if .CHANGE in mu.checkbox(ctx, "Ends with", &ends_with, local_style = .RadioButton) {
							ui.filter_checkbox = .ends_with
						}

						if .SUBMIT in mu.button(ctx, "GENERATE PASSWORD") {
							generate_password(ui)
						}

						if .SUBMIT in mu.button(ctx, "ADD") {
							new_entry := Entry {
								id = EzString{len = u8(ui.text_bufs[.entry_id].len), data = ui.text_bufs[.entry_id].buf},
								username = EzString{len = u8(ui.text_bufs[.username].len), data = ui.text_bufs[.username].buf},
								password = EzString{len = u8(ui.text_bufs[.password].len), data = ui.text_bufs[.password].buf},
								note = EzString{len = u8(ui.text_bufs[.note].len), data = ui.text_bufs[.note].buf},
							}
							add_entry(vault, new_entry)
							slice.sort_by_cmp(vault.entries[:], cmp_entries)
						}
					}
				}
				case .delete_entry: {
	
				}
				case .edit_entry: {
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
						if .SUBMIT in mu.textbox(ctx, ui.text_bufs[.entry_id].buf[:], &ui.text_bufs[.entry_id].len) {
							
						}
						if .SUBMIT in mu.textbox(ctx, ui.text_bufs[.username].buf[:], &ui.text_bufs[.username].len) {
							
						}
						if .SUBMIT in mu.textbox(ctx, ui.text_bufs[.password].buf[:], &ui.text_bufs[.password].len) {
							
						}
						if .SUBMIT in mu.textbox(ctx, ui.text_bufs[.note].buf[:], &ui.text_bufs[.note].len) {
							
						}
					}
				}
				case .entering_password: {
	
				}
				case .main_menu: {

				}
	
			}
		}

		mu.end(ctx)

		render(ui)
	}
}

main :: proc() {

	app_state := new(AppState)

	initialize_ui(&app_state.ui_state)

	app_state.ui_state.bg = {90, 95, 100, 255}
    initialize_renderer(&app_state.ui_state)
    defer destroy_renderer(&app_state.ui_state)
	defer clear_clipboard("Clipboard was cleared by EzPassMan. You're welcome ;)")
    ez_app_windows(app_state)

}


// -------------------Networking code -----------------------------------------------------

get_latest_vault :: proc(current_vault: ^Vault, user_id: ss.SmallString(255)) {
    // make noise connection to server and fetch vault
   
}

upload_vault :: proc(current_vault: ^Vault, user_id: ss.SmallString(255)) {

}
