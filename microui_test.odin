package EzPassMan

import "core:c"
import "core:fmt"
import "core:strconv"
import "core:strings"
import "core:thread"
import "core:sync"

import "core:nbio"

import mu "vendor:microui"

import ss "smallstrings"

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
	state.screen_width = 960
}


set_ui_scale :: proc(state: ^UiState) {
	ctx := &state.mu_ctx
	mu.layout_row(
		ctx,
		{measure_text_width(ctx.style.font, "Set ui scale   "), -20},
		measure_text_height(ctx.style.font),
	)
	mu.label(ctx, "Set ui scale")
	if .SUBMIT in mu.textbox(ctx, state.scale_text_buffer[:], &state.scale_text_len) {
		mu.set_focus(ctx, ctx.last_id)
		str := transmute(string)state.scale_text_buffer[:state.scale_text_len]
		scale, ok := strconv.parse_int(str)
		if ok {
			state.font.font_scale = f32(scale)/10
		} else {
			fmt.println("here")
			fmt.println(scale)
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

main :: proc() {

	app_state := new(AppState)

    ui_state := new(UiState)
	initialize_ui_state(ui_state)

	// thread_pool : thread.Pool
	// thread.pool_init(&thread_pool, context.allocator, 4)
	// thread.pool_start(&thread_pool)
	
	
	// background_data := BackgroundData{vault_ptr = vault, user_id = app_state.user_id}
	
	// thread.pool_add_task(&thread_pool, context.allocator, load_latest_vault_task, vault)
	
	ui_state.bg = {90, 95, 100, 255}
    initialize_renderer(ui_state)
    defer destroy_renderer(ui_state)
    ctx := &ui_state.mu_ctx
    
	user_input := new(UserInput)
	
	text_buffer : [256]u8
	text_buffer_len : int
	
	scale_text_buffer : [4]u8
	scale_text_buffer_len : int
	
	vault := new(Vault)

	for !WindowShouldClose() {
		free_all(context.temp_allocator)
		process_user_input(user_input, ui_state)

		mu.begin(ctx)

		
		switch app_state.command {
			case .start: {
				if mu.window(ctx, "START", mu.Rect{0,0,ui_state.screen_width, ui_state.screen_height}, {.NO_RESIZE, .NO_CLOSE, .NO_INTERACT}) {
					set_ui_scale(ui_state)
					mu.layout_row(
						ctx, 
						{measure_text_width(ctx.style.font, "Enter User Id")*2},
						measure_text_height(ctx.style.font)
					)
					mu.label(ctx, "Enter User id")
					id_submitted := false
					if .SUBMIT in mu.textbox(ctx, text_buffer[:], &text_buffer_len) {
						mu.set_focus(ctx, ctx.last_id)
						text_buffer_len = 0
						id_submitted = true
					}
					if id_submitted == true {
						user_id, valid_utf8 := ss.from_slice(text_buffer[:text_buffer_len], 255)
						if !valid_utf8 {
							mu.label(ctx, "invalid utf8 entered")
						}

					}
					
				}
			}
			case .main_menu: {
				get_latest_vault(vault, app_state.user_id)
			}
			case .view_vault: {

			}
			case .add_entry: {

			}
			case .delete_entry: {

			}
			case .update_entry: {

			}
			case .entering_password: {

			}

		}

		mu.end(ctx)

		render(ui_state)
	}
}

u8_slider :: proc(ctx: ^mu.Context, val: ^u8, lo, hi: u8) -> (res: mu.Result_Set) {
	mu.push_id(ctx, uintptr(val))

	@static tmp: mu.Real
	tmp = mu.Real(val^)
	res = mu.slider(ctx, &tmp, mu.Real(lo), mu.Real(hi), 0, "%.0f", {.ALIGN_CENTER})
	val^ = u8(tmp)
	mu.pop_id(ctx)
	return
}

write_log :: proc(state : ^UiState, str: string) {
	state.log_buf_len += copy(state.log_buf[state.log_buf_len:], str)
	state.log_buf_len += copy(state.log_buf[state.log_buf_len:], "\n")
	state.log_buf_updated = true
}

read_log :: proc(state : ^UiState) -> string {
	return string(state.log_buf[:state.log_buf_len])
}
reset_log :: proc(state : ^UiState) {
	state.log_buf_updated = true
	state.log_buf_len = 0
}


all_windows :: proc(state : ^UiState) {
	@static opts := mu.Options{.NO_CLOSE}

    ctx := &state.mu_ctx

	if mu.window(ctx, "Demo Window", {0, 0, 300, 450}, opts) {
		if .ACTIVE in mu.header(ctx, "Window Info") {
			win := mu.get_current_container(ctx)
			mu.layout_row(ctx, {54, -1}, 0)
			mu.label(ctx, "Position:")
			mu.label(ctx, fmt.tprintf("%d, %d", win.rect.x, win.rect.y))
			mu.label(ctx, "Size:")
			mu.label(ctx, fmt.tprintf("%d, %d", win.rect.w, win.rect.h))
		}

		if .ACTIVE in mu.header(ctx, "Window Options") {
			mu.layout_row(ctx, {120, 120, 120}, 0)
			for opt in mu.Opt {
				state := opt in opts
				if .CHANGE in mu.checkbox(ctx, fmt.tprintf("%v", opt), &state)  {
					if state {
						opts += {opt}
					} else {
						opts -= {opt}
					}
				}
			}
		}

		if .ACTIVE in mu.header(ctx, "Test Buttons", {.EXPANDED}) {
			mu.layout_row(ctx, {86, -110, -1})
			mu.label(ctx, "Test buttons 1:")
			if .SUBMIT in mu.button(ctx, "Button 1") { write_log(state, "Pressed button 1") }
			if .SUBMIT in mu.button(ctx, "Button 2") { write_log(state, "Pressed button 2") }
			mu.label(ctx, "Test buttons 2:")
			if .SUBMIT in mu.button(ctx, "Button 3") { write_log(state, "Pressed button 3") }
			if .SUBMIT in mu.button(ctx, "Button 4") { write_log(state, "Pressed button 4") }
		}

		if .ACTIVE in mu.header(ctx, "Tree and Text", {.EXPANDED}) {
			mu.layout_row(ctx, {140, -1})
			mu.layout_begin_column(ctx)
			if .ACTIVE in mu.treenode(ctx, "Test 1") {
				if .ACTIVE in mu.treenode(ctx, "Test 1a") {
					mu.label(ctx, "Hello")
					mu.label(ctx, "world")
				}
				if .ACTIVE in mu.treenode(ctx, "Test 1b") {
					if .SUBMIT in mu.button(ctx, "Button 1") { write_log(state, "Pressed button 1") }
					if .SUBMIT in mu.button(ctx, "Button 2") { write_log(state, "Pressed button 2") }
				}
			}
			if .ACTIVE in mu.treenode(ctx, "Test 2") {
				mu.layout_row(ctx, {53, 53})
				if .SUBMIT in mu.button(ctx, "Button 3") { write_log(state, "Pressed button 3") }
				if .SUBMIT in mu.button(ctx, "Button 4") { write_log(state, "Pressed button 4") }
				if .SUBMIT in mu.button(ctx, "Button 5") { write_log(state, "Pressed button 5") }
				if .SUBMIT in mu.button(ctx, "Button 6") { write_log(state, "Pressed button 6") }
			}
			if .ACTIVE in mu.treenode(ctx, "Test 3") {
				@static checks := [3]bool{true, false, true}
				mu.checkbox(ctx, "Checkbox 1", &checks[0])
				mu.checkbox(ctx, "Checkbox 2", &checks[1])
				mu.checkbox(ctx, "Checkbox 3", &checks[2])

			}
			mu.layout_end_column(ctx)

			mu.layout_begin_column(ctx)
			mu.layout_row(ctx, {-1})
			mu.text(ctx,
				"Lorem ipsum dolor sit amet, consectetur adipiscing "+
				"elit. Maecenas lacinia, sem eu lacinia molestie, mi risus faucibus "+
				"ipsum, eu varius magna felis a nulla.",
			)
			mu.layout_end_column(ctx)
		}

		if .ACTIVE in mu.header(ctx, "Background Colour", {.EXPANDED}) {
			mu.layout_row(ctx, {-78, -1}, 68)
			mu.layout_begin_column(ctx)
			{
				mu.layout_row(ctx, {46, -1}, 0)
				mu.label(ctx, "Red:");   u8_slider(ctx, &state.bg.r, 0, 255)
				mu.label(ctx, "Green:"); u8_slider(ctx, &state.bg.g, 0, 255)
				mu.label(ctx, "Blue:");  u8_slider(ctx, &state.bg.b, 0, 255)
			}
			mu.layout_end_column(ctx)

			r := mu.layout_next(ctx)
			mu.draw_rect(ctx, r, state.bg)
			mu.draw_box(ctx, mu.expand_rect(r, 1), ctx.style.colors[.BORDER])
			mu.draw_control_text(ctx, fmt.tprintf("#%02x%02x%02x", state.bg.r, state.bg.g, state.bg.b), r, .TEXT, {.ALIGN_CENTER})
		}
	}



	if mu.window(ctx, "Log Window", {350, 40, 300, 200}, opts) {
		mu.layout_row(ctx, {-1}, -28)
		mu.begin_panel(ctx, "Log")
		mu.layout_row(ctx, {-1}, -1)
		mu.text(ctx, read_log(state))
		if state.log_buf_updated {
			panel := mu.get_current_container(ctx)
			panel.scroll.y = panel.content_size.y
			state.log_buf_updated = false
		}
		mu.end_panel(ctx)

		@static buf: [128]byte
		@static buf_len: int
		submitted := false
		mu.layout_row(ctx, {-70, -1})
		if .SUBMIT in mu.textbox(ctx, buf[:], &buf_len) {
			mu.set_focus(ctx, ctx.last_id)
			submitted = true
		}
		if .SUBMIT in mu.button(ctx, "Submit") {
			submitted = true
		}
		if submitted {
			write_log(state, string(buf[:buf_len]))
			buf_len = 0
		}
	}

	if mu.window(ctx, "Style Window", {350, 250, 300, 240}) {
		@static colors := [mu.Color_Type]string{
			.TEXT         = "text",
			.BORDER       = "border",
			.WINDOW_BG    = "window bg",
			.TITLE_BG     = "title bg",
			.TITLE_TEXT   = "title text",
			.PANEL_BG     = "panel bg",
			.BUTTON       = "button",
			.BUTTON_HOVER = "button hover",
			.BUTTON_FOCUS = "button focus",
			.BASE         = "base",
			.BASE_HOVER   = "base hover",
			.BASE_FOCUS   = "base focus",
			.SCROLL_BASE  = "scroll base",
			.SCROLL_THUMB = "scroll thumb",
			.SELECTION_BG = "selection bg",
		}

		sw := i32(f32(mu.get_current_container(ctx).body.w) * 0.14)
		mu.layout_row(ctx, {80, sw, sw, sw, sw, -1})
		for label, col in colors {
			mu.label(ctx, label)
			u8_slider(ctx, &ctx.style.colors[col].r, 0, 255)
			u8_slider(ctx, &ctx.style.colors[col].g, 0, 255)
			u8_slider(ctx, &ctx.style.colors[col].b, 0, 255)
			u8_slider(ctx, &ctx.style.colors[col].a, 0, 255)
			mu.draw_rect(ctx, mu.layout_next(ctx), ctx.style.colors[col])
		}
	}
}