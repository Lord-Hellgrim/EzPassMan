package EzPassMan

import "core:strings"
import "core:c"
import "core:unicode/utf8"
import "core:fmt"

import rl "vendor:raylib"
import mu "vendor:microui"


RenderTexture2D :: rl.RenderTexture2D
Image :: rl.Image
KeyboardKey :: rl.KeyboardKey
MouseButton :: rl.MouseButton
WindowShouldClose :: rl.WindowShouldClose
GetMousePosition :: rl.GetMousePosition
GetFontDefault :: rl.GetFontDefault


UserInput :: struct {
    keys_pressed : [dynamic;32]KeyboardKey,
    mouse_x : i32,
    mouse_y : i32,
    mouse_down : bool,
	mouse_released : bool,
	mouse_wheel_pos : [2]f32,
}

Font :: struct {
	base: rl.Font,
	font_scale: f32,
}

process_user_input :: proc(user_input: ^UserInput, state: ^UiState) {
	ctx := &state.mu_ctx
    mouse := rl.GetMousePosition()
    user_input.mouse_x = i32(mouse.x)
    user_input.mouse_y = i32(mouse.y)
	mu.input_mouse_move(ctx, user_input.mouse_x, user_input.mouse_y)

	mouse_wheel_pos := rl.GetMouseWheelMoveV()
	mu.input_scroll(ctx, i32(user_input.mouse_wheel_pos.x) * 30, i32(user_input.mouse_wheel_pos.y) * -30)
	
	user_input.mouse_down = rl.IsMouseButtonDown(rl.MouseButton.LEFT)
	
	for button_rl, button_mu in state.mouse_buttons_map {
		switch {
		case rl.IsMouseButtonPressed(button_rl):
			mu.input_mouse_down(ctx, user_input.mouse_x, user_input.mouse_y, button_mu)
		case rl.IsMouseButtonReleased(button_rl):
			mu.input_mouse_up  (ctx, user_input.mouse_x, user_input.mouse_y, button_mu)
		}
	}

	for keys_rl, key_mu in state.key_map {
		for key_rl in keys_rl {
			switch {
			case key_rl == .KEY_NULL:
				// ignore
			case rl.IsKeyPressed(key_rl), rl.IsKeyPressedRepeat(key_rl):
				mu.input_key_down(ctx, key_mu)
			case rl.IsKeyReleased(key_rl):
				mu.input_key_up  (ctx, key_mu)
			}
		}
	}

	{
		buf: [512]byte
		n: int
		for n < len(buf) {
			c := rl.GetCharPressed()
			if c == 0 {
				break
			}
			b, w := utf8.encode_rune(c)
			n += copy(buf[n:], b[:w])
		}
		mu.input_text(ctx, string(buf[:n]))
	}
}

measure_text_width :: proc(font: mu.Font, text: string) -> i32 {
	actual_font := transmute(^Font)font
	text := strings.clone_to_cstring(text, context.temp_allocator)
	size := rl.MeasureTextEx(actual_font.base, text, f32(actual_font.base.baseSize)*actual_font.font_scale, actual_font.font_scale)
	
	return i32(size.x)
}

measure_text_height :: proc(font: mu.Font) -> i32 {
	actual_font := transmute(^Font)font
	text: cstring = "EzPassMan"
	size := rl.MeasureTextEx(actual_font.base, text, f32(actual_font.base.baseSize)*actual_font.font_scale, actual_font.font_scale)

	return i32(size.y)
}


initialize_renderer :: proc(state: ^UiState) {
	if state.screen_height == 0 {
		state.screen_height = 600
	}
	if state.screen_width == 0 {
		state.screen_width = 800
	}
	rl.SetConfigFlags({.WINDOW_RESIZABLE})
    rl.InitWindow(state.screen_width, state.screen_height, "EzPassMan")
	rl.SetTargetFPS(60)
    
	ctx := &state.mu_ctx
	mu.init(ctx,
		set_clipboard = proc(user_data: rawptr, text: string) -> (ok: bool) {
			cstr := strings.clone_to_cstring(text)
			rl.SetClipboardText(cstr)
			delete(cstr)
			return true
		},
		get_clipboard = proc(user_data: rawptr) -> (text: string, ok: bool) {
			cstr := rl.GetClipboardText()
			if cstr != nil {
				text = string(cstr)
				ok = true
			}
			return
		},
	)

	ctx.text_width = measure_text_width
	ctx.text_height = measure_text_height

	roboto_regular := rl.LoadFont("Roboto-Regular.ttf")

	state.font = Font{base = roboto_regular, font_scale = 1}
	
	ctx.style.font = transmute(mu.Font)(&state.font)

	// state.atlas_texture = rl.LoadRenderTexture(c.int(mu.DEFAULT_ATLAS_WIDTH), c.int(mu.DEFAULT_ATLAS_HEIGHT))
    
	// state.image = rl.GenImageColor(c.int(mu.DEFAULT_ATLAS_WIDTH), c.int(mu.DEFAULT_ATLAS_HEIGHT), rl.Color{0, 0, 0, 0})
    
	// for alpha, i in mu.default_atlas_alpha {
    //     x := i % mu.DEFAULT_ATLAS_WIDTH
	// 	y := i / mu.DEFAULT_ATLAS_WIDTH
	// 	color := rl.Color{255, 255, 255, alpha}
	// 	rl.ImageDrawPixel(&state.image, c.int(x), c.int(y), color)
	// }
    
	// rl.BeginTextureMode(state.atlas_texture)
	// rl.UpdateTexture(state.atlas_texture.texture, rl.LoadImageColors(state.image))
	// rl.EndTextureMode()
    
	state.screen_texture = rl.LoadRenderTexture(state.screen_width, state.screen_height)
}

destroy_renderer :: proc(state: ^UiState) {
    rl.CloseWindow()
    rl.UnloadRenderTexture(state.atlas_texture)
    rl.UnloadImage(state.image)
    rl.UnloadRenderTexture(state.screen_texture)

}

render :: proc (state: ^UiState) {
    ctx := &state.mu_ctx
	render_texture :: proc "contextless" (renderer: rl.RenderTexture2D, dst: ^rl.Rectangle, src: mu.Rect, color: rl.Color, state: ^UiState) {
		dst.width = f32(src.w)
		dst.height = f32(src.h)

		rl.DrawTextureRec(
			texture  = state.atlas_texture.texture,
			source   = {f32(src.x), f32(src.y), f32(src.w), f32(src.h)},
			position = {dst.x, dst.y},
			tint     = color,
		)
	}
	to_rl_color :: proc "contextless" (in_color: mu.Color) -> (out_color: rl.Color) {
		return {in_color.r, in_color.g, in_color.b, in_color.a}
	}

	height := rl.GetScreenHeight()

	rl.BeginTextureMode(state.screen_texture)
	rl.EndScissorMode()
	rl.ClearBackground(to_rl_color(state.bg))

	command_backing: ^mu.Command
	for variant in mu.next_command_iterator(ctx, &command_backing) {
		switch cmd in variant {
		case ^mu.Command_Text:
			text := strings.clone_to_cstring(cmd.str, context.temp_allocator)
			actual_font := transmute(^Font)ctx.style.font
			rl.DrawTextEx(actual_font.base,
				text,
				rl.Vector2(cmd.pos),
				f32(actual_font.base.baseSize)*actual_font.font_scale,
				actual_font.font_scale,
				rl.WHITE,
			)
			// dst := rl.Rectangle{f32(cmd.pos.x), f32(cmd.pos.y), 0, 0}
			// for ch in cmd.str {
			// 	if ch&0xc0 != 0x80 {
			// 		r := min(int(ch), 127)
			// 		src := mu.default_atlas[mu.DEFAULT_ATLAS_FONT + r]
			// 		render_texture(state.screen_texture, &dst, src, to_rl_color(cmd.color), state)
			// 		dst.x += dst.width
			// 	}
			// }
		case ^mu.Command_Rect:
			// rl.DrawRectangleRounded(rl.Rectangle{f32(cmd.rect.x), f32(cmd.rect.y), f32(cmd.rect.w), f32(cmd.rect.h)}, 10, 5, to_rl_color(cmd.color))
			rl.DrawRectangle(cmd.rect.x, cmd.rect.y, cmd.rect.w, cmd.rect.h, to_rl_color(cmd.color))
		case ^mu.Command_Icon:
			src := mu.default_atlas[cmd.id]
			x := cmd.rect.x + (cmd.rect.w - src.w)/2
			y := cmd.rect.y + (cmd.rect.h - src.h)/2
			render_texture(state.screen_texture, &rl.Rectangle {f32(x), f32(y), 0, 0}, src, to_rl_color(cmd.color), state)
		case ^mu.Command_Clip:
			rl.BeginScissorMode(cmd.rect.x, height - (cmd.rect.y + cmd.rect.h), cmd.rect.w, cmd.rect.h)
		case ^mu.Command_Jump:
			unreachable()
		}
	}
	rl.EndTextureMode()
	rl.BeginDrawing()
	rl.ClearBackground(rl.RAYWHITE)
	rl.DrawTextureRec(
		texture  = state.screen_texture.texture,
		source   = {0, 0, f32(state.screen_width), -f32(state.screen_height)},
		position = {0, 0},
		tint     = rl.WHITE,
	)
	rl.EndDrawing()
}
