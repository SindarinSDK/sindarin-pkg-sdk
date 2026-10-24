use std::ffi::{c_char, c_void, CStr, CString};
#[repr(C)]
struct Record { credits: i32, root: i64, node: i64, is_root: i32, handle: i64 }
extern "C" {
    fn sn_yaml_parse(text: *const c_char) -> *mut Record;
    fn sn_yaml_get(value: *mut Record, key: *const c_char) -> *mut Record;
    fn sn_yaml_value(value: *mut Record) -> *mut c_char;
    fn sn_sdk_yaml_retain(value: *mut Record) -> *mut Record;
    fn sn_sdk_yaml_release(value: *mut Record);
    fn sn_sdk_yaml_copy(value: *mut Record) -> *mut Record;
    fn sn_sdk_yaml_refs(value: *mut Record) -> i32;
    fn free(value: *mut c_void);
}
struct Yaml(*mut Record);
impl Drop for Yaml { fn drop(&mut self) { unsafe { sn_sdk_yaml_release(self.0) } } }
impl Yaml {
    fn text(&self) -> Vec<u8> { unsafe {
        let text = sn_yaml_value(self.0);
        assert!(!text.is_null());
        let bytes = CStr::from_ptr(text).to_bytes().to_vec();
        free(text.cast());
        bytes
    } }
}
fn main() { unsafe {
    assert_eq!(std::mem::size_of::<Record>(), 40);
    assert!(sn_sdk_yaml_retain(std::ptr::null_mut()).is_null());
    assert_eq!(sn_sdk_yaml_refs(std::ptr::null_mut()), 0);
    sn_sdk_yaml_release(std::ptr::null_mut());
    let source = CString::new("name: first\n").unwrap();
    let root = Yaml(sn_yaml_parse(source.as_ptr()));
    let alias = Yaml(sn_sdk_yaml_retain(root.0));
    assert_eq!(sn_sdk_yaml_refs(root.0), 2);
    let key = CString::new("name").unwrap();
    let child = Yaml(sn_yaml_get(root.0, key.as_ptr()));
    assert_eq!((*child.0).handle, 0);
    drop(root);
    drop(alias);
    assert_eq!(child.text(), b"first");
    let copy = Yaml(sn_sdk_yaml_copy(child.0));
    assert_ne!((*child.0).node, (*copy.0).node);
    drop(child);
    assert_eq!(copy.text(), b"first");
    println!("SDK canonical Yaml Rust: pass");
} }
