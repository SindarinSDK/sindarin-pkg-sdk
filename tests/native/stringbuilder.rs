use std::ffi::{c_char,CStr};
#[repr(C)] struct Builder { rc:i32, buf:i64, cap:i64, len:i64 }
extern "C" {
 fn sn_text_new()->*mut Builder;
 fn sn_sdk_text_retain(value:*mut Builder)->*mut Builder;
 fn sn_sdk_text_copy(value:*const Builder)->*mut Builder;
 fn sn_sdk_text_release(value:*mut Builder);
 fn sn_sdk_text_refs(value:*mut Builder)->i32;
 fn sn_text_append(value:*mut Builder,text:*mut c_char);
 fn sn_text_to_string(value:*mut Builder)->*mut c_char;
 fn sn_text_dispose(value:*mut Builder);
 fn free(value:*mut std::ffi::c_void);
}
fn main(){unsafe{
 assert_eq!(std::mem::size_of::<Builder>(),32);
 let builder=sn_text_new();assert!(!builder.is_null());assert_eq!(sn_sdk_text_refs(builder),1);
 let alias=sn_sdk_text_retain(builder);assert_eq!(alias,builder);assert_eq!(sn_sdk_text_refs(builder),2);
 sn_text_append(alias,b"hello\0".as_ptr() as *mut c_char);assert_eq!((*builder).len,5);
 let copy=sn_sdk_text_copy(builder);assert_ne!(copy,builder);assert_ne!((*copy).buf,(*builder).buf);
 sn_text_append(copy,b"copy\0".as_ptr() as *mut c_char);assert_eq!((*builder).len,5);assert_eq!((*copy).len,9);sn_sdk_text_release(copy);
 let text=sn_text_to_string(builder);sn_sdk_text_release(alias);sn_sdk_text_release(builder);
 assert_eq!(CStr::from_ptr(text).to_bytes(),b"hello");free(text.cast());
 let builder=sn_text_new();sn_text_dispose(builder);sn_text_dispose(builder);assert_eq!((*builder).buf,0);sn_sdk_text_release(builder);
 println!("SDK canonical StringBuilder Rust: pass");
}}
