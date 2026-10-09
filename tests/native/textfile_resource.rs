use std::ffi::{c_char, c_void, CString};
#[repr(C)]
struct File {
    opaque: [u8; 0],
}
#[repr(C)]
struct Value {
    opaque: [u8; 0],
}
#[repr(C)]
struct Bytes {
    data: *const u8,
    length: u64,
}
extern "C" {
    fn sn_text_file_open(path: *const c_char) -> *mut File;
    fn sn_text_file_write_line(file: *mut File, text: *const c_char);
    fn sn_text_file_rewind(file: *mut File);
    fn sn_text_file_dispose(file: *mut File);
    fn sn_sdk_text_file_retain(file: *mut File) -> *mut File;
    fn sn_sdk_text_file_release(file: *mut File);
    fn sn_sdk_text_file_fp(file: *mut File) -> *mut c_void;
    fn sn_sdk_text_file_is_open(file: *mut File) -> i32;
    fn sn_sdk_text_file_path(file: *mut File, out: *mut *mut Value) -> u32;
    fn sn_abi_v1_bytes(value: *const Value, out: *mut Bytes) -> u32;
    fn sn_abi_v1_release(value: *mut Value);
    fn sn_abi_v1_retain(value: *mut Value) -> *mut Value;
    fn sn_abi_v1_string_copy(text: *const c_char, out: *mut *mut Value) -> u32;
    fn sn_sdk_text_file_open_abi(path: *const Value, out: *mut *mut Value) -> u32;
    fn sn_sdk_text_file_path_abi(file: *const Value, out: *mut *mut Value) -> u32;
    fn sn_sdk_text_file_read_line_abi(file: *const Value, out: *mut *mut Value) -> u32;
    fn sn_sdk_text_file_read_lines_abi(file: *const Value, out: *mut *mut Value) -> u32;
    fn sn_abi_v1_value_array_get(array: *const Value, index: u64, out: *mut *mut Value) -> u32;
    fn sn_sdk_text_file_dispose_abi(file: *const Value) -> u32;
    fn sn_sdk_text_file_is_open_abi(file: *const Value, out: *mut i32) -> u32;
}
fn main() {
    unsafe {
        let path = CString::new("sdk-native-rust-resource.txt").unwrap();
        let file = sn_text_file_open(path.as_ptr());
        assert!(!file.is_null() && !sn_sdk_text_file_fp(file).is_null());
        assert_eq!(sn_sdk_text_file_is_open(file), 1);
        let alias = sn_sdk_text_file_retain(file);
        assert_eq!(alias, file);
        sn_sdk_text_file_release(file);
        let line = CString::new("alpha").unwrap();
        sn_text_file_write_line(alias, line.as_ptr());
        drop(line);
        sn_text_file_rewind(alias);
        let mut value = std::ptr::null_mut();
        assert_eq!(sn_sdk_text_file_path(alias, &mut value), 0);
        sn_text_file_dispose(alias);
        assert_eq!(sn_sdk_text_file_is_open(alias), 0);
        assert!(sn_sdk_text_file_fp(alias).is_null());
        sn_sdk_text_file_release(alias);
        let mut bytes = Bytes {
            data: std::ptr::null(),
            length: 0,
        };
        assert_eq!(sn_abi_v1_bytes(value, &mut bytes), 0);
        assert_eq!(
            std::slice::from_raw_parts(bytes.data, bytes.length as usize),
            path.to_bytes()
        );
        sn_abi_v1_release(value);
        assert_eq!(std::fs::read(path.to_str().unwrap()).unwrap(), b"alpha\n");
        std::fs::remove_file(path.to_str().unwrap()).unwrap();
        std::fs::write("sdk-typed-rust.txt", b"typed\nsecond\nthird").unwrap();
        let path = CString::new("sdk-typed-rust.txt").unwrap();
        let mut input = std::ptr::null_mut();
        assert_eq!(sn_abi_v1_string_copy(path.as_ptr(), &mut input), 0);
        let mut file = std::ptr::null_mut();
        assert_eq!(sn_sdk_text_file_open_abi(input, &mut file), 0);
        sn_abi_v1_release(input);
        let alias = sn_abi_v1_retain(file);
        sn_abi_v1_release(file);
        let mut opened = -1;
        assert_eq!(sn_sdk_text_file_is_open_abi(alias, &mut opened), 0);
        assert_eq!(opened, 1);
        let mut line = std::ptr::null_mut();
        assert_eq!(sn_sdk_text_file_read_line_abi(alias, &mut line), 0);
        assert_eq!(sn_abi_v1_bytes(line, &mut bytes), 0);
        assert_eq!(
            std::slice::from_raw_parts(bytes.data, bytes.length as usize),
            b"typed"
        );
        let mut lines = std::ptr::null_mut();
        assert_eq!(sn_sdk_text_file_read_lines_abi(alias, &mut lines), 0);
        let mut owned_line = std::ptr::null_mut();
        assert_eq!(sn_abi_v1_value_array_get(lines, 0, &mut owned_line), 0);
        sn_abi_v1_release(lines);
        let mut owned_path = std::ptr::null_mut();
        assert_eq!(sn_sdk_text_file_path_abi(alias, &mut owned_path), 0);
        assert_eq!(sn_sdk_text_file_dispose_abi(alias), 0);
        assert_eq!(sn_sdk_text_file_dispose_abi(alias), 0);
        assert_eq!(sn_sdk_text_file_is_open_abi(alias, &mut opened), 0);
        assert_eq!(opened, 0);
        sn_abi_v1_release(alias);
        assert_eq!(sn_abi_v1_bytes(owned_path, &mut bytes), 0);
        assert_eq!(
            std::slice::from_raw_parts(bytes.data, bytes.length as usize),
            path.to_bytes()
        );
        assert_eq!(sn_abi_v1_bytes(owned_line, &mut bytes), 0);
        assert_eq!(
            std::slice::from_raw_parts(bytes.data, bytes.length as usize),
            b"second"
        );
        sn_abi_v1_release(owned_line);
        sn_abi_v1_release(owned_path);
        sn_abi_v1_release(line);
        std::fs::remove_file("sdk-typed-rust.txt").unwrap();
        println!("SDK native TextFile: pass");
    }
}
