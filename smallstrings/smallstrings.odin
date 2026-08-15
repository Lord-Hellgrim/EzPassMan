package smallstrings


import "core:slice"
import "core:strings"


SmallString :: struct($N: u8) {
    len: u8,
    data: [N]byte,
}


// Adds the first len bytes of to_add.data to dst.data. Bytes beyond the cap of dst are not copied.
extend_in_place :: proc(dst: ^SmallString($N), to_add: SmallString($M)) {

    num_chars := to_add.len
    if num_chars > N - dst.len {
        status := .not_enough_space_for_all_chars
        num_chars = N-dst.len
    }

    copy(dst[dst.len:], to_add[:num_chars])

}

extend_with_string :: proc(dst: ^SmallString($N), src: string) {
    num_chars := len(src)
    if num_chars > N - dst.len {
        num_chars = N-dst.len
    }

    copy(dst[dst.len:], src[:num_chars])
}

equal :: proc(a: SmallString($N), b: SmallString($M)) -> bool {
    m := min(a.len, b.len)
    return slice.equal(a[:min], b[:min])
}

// returns a view of the data section of the SmallString. Does not copy
as_string :: proc(s: SmallString($N)) -> string {
    return transmute(string)runtime.Raw_String{&s.data[0], s.len}
}
