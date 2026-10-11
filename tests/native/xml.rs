use std::ffi::{c_char, CStr};
#[repr(C)] struct Xml { rc: i32, doc: i64, node: i64, is_root: i32, handle: i64 }
extern "C" {
    fn sn_xml_parse(text: *mut c_char) -> *mut Xml;
    fn sn_xml_first_child(value: *mut Xml) -> *mut Xml;
    fn sn_xml_name(value: *mut Xml) -> *mut c_char;
    fn sn_xml_set_name(value: *mut Xml, name: *mut c_char);
    fn sn_xml_dispose(value: *mut Xml);
    fn sn_sdk_xml_copy(value: *const Xml) -> *mut Xml;
    fn sn_sdk_xml_retain(value: *mut Xml) -> *mut Xml;
    fn sn_sdk_xml_release(value: *mut Xml);
    fn free(pointer: *mut std::ffi::c_void);
}
fn text(value: &[u8]) -> *mut c_char { value.as_ptr() as *mut c_char }
fn main() { unsafe {
    assert_eq!(std::mem::size_of::<Xml>(), 40);
    let root = sn_xml_parse(text(b"<root><child/></root>\0"));
    let alias = sn_sdk_xml_retain(root);
    let child = sn_xml_first_child(root);
    let copy = sn_sdk_xml_copy(root);
    assert_ne!((*copy).doc, (*root).doc);
    let copy_child = sn_xml_first_child(copy);
    sn_xml_set_name(copy_child, text(b"independent\0"));
    sn_sdk_xml_release(copy_child);
    sn_sdk_xml_release(copy);
    sn_sdk_xml_release(root);
    sn_xml_dispose(alias);
    sn_xml_dispose(alias);
    sn_sdk_xml_release(alias);
    let name = sn_xml_name(child);
    assert_eq!(CStr::from_ptr(name).to_bytes(), b"child");
    sn_sdk_xml_release(child);
    assert_eq!(CStr::from_ptr(name).to_bytes(), b"child");
    free(name.cast());
    println!("SDK canonical Xml Rust: pass");
} }
