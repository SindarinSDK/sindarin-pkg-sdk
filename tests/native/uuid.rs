use std::ffi::{c_char,CStr};
#[repr(C)] struct Uuid { rc:i32, high:i64, low:i64 }
extern "C" {
    fn sn_uuid_namespace_dns()->*mut Uuid;
    fn sn_sdk_uuid_retain(value:*mut Uuid)->*mut Uuid;
    fn sn_sdk_uuid_copy(value:*const Uuid)->*mut Uuid;
    fn sn_sdk_uuid_release(value:*mut Uuid);
    fn sn_sdk_uuid_refs(value:*mut Uuid)->i32;
    fn sn_uuid_v5(namespace:*mut Uuid,name:*mut c_char)->*mut Uuid;
    fn sn_uuid_to_string(value:*mut Uuid)->*mut c_char;
    fn sn_uuid_to_hex(value:*mut Uuid)->*mut c_char;
    fn sn_uuid_from_hex(value:*mut c_char)->*mut Uuid;
    fn sn_uuid_equals(a:*mut Uuid,b:*mut Uuid)->bool;
    fn free(value:*mut std::ffi::c_void);
}
fn main() { unsafe {
    assert_eq!(std::mem::size_of::<Uuid>(),24);
    let dns=sn_uuid_namespace_dns();assert!(!dns.is_null());assert_eq!(sn_sdk_uuid_refs(dns),1);
    assert!(sn_sdk_uuid_copy(std::ptr::null()).is_null());
    let copy=sn_sdk_uuid_copy(dns);assert_ne!(copy,dns);assert_eq!(sn_sdk_uuid_refs(copy),1);
    assert_eq!((*copy).high,(*dns).high);assert_eq!((*copy).low,(*dns).low);
    (*copy).high=3;assert_ne!((*copy).high,(*dns).high);sn_sdk_uuid_release(copy);
    let alias=sn_sdk_uuid_retain(dns);assert_eq!(alias,dns);assert_eq!(sn_sdk_uuid_refs(dns),2);
    let derived=sn_uuid_v5(alias,b"example.com\0".as_ptr() as *mut c_char);
    sn_sdk_uuid_release(alias);sn_sdk_uuid_release(dns);
    let text=sn_uuid_to_string(derived);assert_eq!(CStr::from_ptr(text).to_bytes(),b"cfbff0d1-9375-5685-968c-48ce8b15ae17");
    let hex=sn_uuid_to_hex(derived);let parsed=sn_uuid_from_hex(hex);assert!(sn_uuid_equals(derived,parsed));
    sn_sdk_uuid_release(derived);sn_sdk_uuid_release(parsed);
    assert_eq!(CStr::from_ptr(text).to_bytes(),b"cfbff0d1-9375-5685-968c-48ce8b15ae17");
    free(text.cast());free(hex.cast());
    println!("SDK canonical UUID Rust: pass");
} }
