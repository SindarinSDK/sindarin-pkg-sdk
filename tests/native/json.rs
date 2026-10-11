use std::ffi::{c_char, CStr};
#[repr(C)] struct Json { rc: i32, obj: i64, handle: i64, is_root: i32 }
extern "C" {
    fn sn_json_parse(text: *mut c_char) -> *mut Json;
    fn sn_json_get(value: *mut Json, key: *mut c_char) -> *mut Json;
    fn sn_json_set(value: *mut Json, key: *mut c_char, item: *mut Json);
    fn sn_json_new_int(value: i64) -> *mut Json;
    fn sn_json_as_int(value: *mut Json) -> i64;
    fn sn_json_to_string(value: *mut Json) -> *mut c_char;
    fn sn_json_dispose(value: *mut Json);
    fn sn_sdk_json_retain(value: *mut Json) -> *mut Json;
    fn sn_sdk_json_copy(value: *const Json) -> *mut Json;
    fn sn_sdk_json_refs(value: *mut Json) -> i32;
    fn sn_sdk_json_release(value: *mut Json);
    fn free(value: *mut std::ffi::c_void);
}
fn text(value: &[u8]) -> *mut c_char { value.as_ptr() as *mut c_char }
fn main() { unsafe {
    assert_eq!(std::mem::size_of::<Json>(), 32);
    let root = sn_json_parse(text(b"{\"child\":{\"count\":7}}\0"));
    let alias = sn_sdk_json_retain(root);
    assert_eq!(alias, root);
    assert_eq!(sn_sdk_json_refs(root), 2);
    let child = sn_json_get(root, text(b"child\0"));
    let copy = sn_sdk_json_copy(root);
    assert_ne!(copy, root);
    assert_ne!((*copy).obj, (*root).obj);
    let copy_child = sn_json_get(copy, text(b"child\0"));
    let value = sn_json_new_int(19);
    sn_json_set(copy_child, text(b"count\0"), value);
    sn_sdk_json_release(value);
    let count = sn_json_get(child, text(b"count\0"));
    assert_eq!(sn_json_as_int(count), 7);
    sn_sdk_json_release(count);
    let count = sn_json_get(copy_child, text(b"count\0"));
    assert_eq!(sn_json_as_int(count), 19);
    sn_sdk_json_release(count);
    sn_sdk_json_release(copy_child);
    sn_sdk_json_release(copy);
    let saved = sn_json_to_string(child);
    sn_sdk_json_release(alias);
    sn_json_dispose(root);
    sn_json_dispose(root);
    sn_sdk_json_release(root);
    let count = sn_json_get(child, text(b"count\0"));
    assert_eq!(sn_json_as_int(count), 7);
    sn_sdk_json_release(count);
    sn_sdk_json_release(child);
    assert_eq!(CStr::from_ptr(saved).to_bytes(), b"{\"count\":7}");
    free(saved.cast());
    println!("SDK canonical Json Rust: pass");
} }
