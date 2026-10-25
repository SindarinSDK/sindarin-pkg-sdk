use std::ffi::{c_char, c_void, CStr, CString};

#[repr(C)]
struct Stream { refs:i32, descriptor:i64, remote:*mut u8, internal:*mut u8 }
#[repr(C)]
struct Listener { refs:i32, descriptor:i64, port:i64 }
#[repr(C)]
struct Value { _opaque:[u8;0] }
#[repr(C)]
struct Array { data:*mut c_void, len:i64, cap:i64, width:usize,
    release:Option<unsafe extern "C" fn(*mut c_void)>,
    copy:Option<unsafe extern "C" fn(*const c_void,*mut c_void)>, tag:i32 }
unsafe extern "C" {
    fn sn_sdk_tcp_stream_create()->*mut Stream;
    fn sn_sdk_tcp_stream_retain(stream:*mut Stream)->*mut Stream;
    fn sn_sdk_tcp_stream_release(stream:*mut Stream);
    fn sn_sdk_tcp_stream_refs(stream:*mut Stream)->i32;
    fn sn_sdk_tcp_listener_create()->*mut Listener;
    fn sn_sdk_tcp_listener_retain(listener:*mut Listener)->*mut Listener;
    fn sn_sdk_tcp_listener_release(listener:*mut Listener);
    fn sn_sdk_tcp_listener_refs(listener:*mut Listener)->i32;
    fn sn_tcp_listener_bind(address:*mut c_char)->*mut Listener;
    fn sn_tcp_listener_get_port(listener:*mut Listener)->i64;
    fn sn_tcp_listener_accept(listener:*mut Listener)->*mut Stream;
    fn sn_tcp_stream_connect(address:*mut c_char)->*mut Stream;
    fn sn_tcp_stream_write_line(stream:*mut Stream,text:*mut c_char);
    fn sn_tcp_stream_read_line(stream:*mut Stream)->*mut c_char;
    fn sn_tcp_stream_read_all(stream:*mut Stream)->*mut Array;
    fn sn_tcp_stream_get_remote_address(stream:*mut Stream)->*mut c_char;
    fn sn_tcp_stream_dispose(stream:*mut Stream);
    fn sn_sdk_tcp_stream_storage_size()->u64;
    fn sn_sdk_tcp_listener_storage_size()->u64;
    fn sn_sdk_tcp_stream_field_offset(field:u32)->u64;
    fn sn_sdk_tcp_listener_field_offset(field:u32)->u64;
    fn sn_abi_v1_native_byte_array_adopt(array:*mut Array,out:*mut *mut Value)->u32;
    fn sn_abi_v1_release(value:*mut Value);
    fn free(value:*mut c_void);
}
unsafe fn roundtrip() {
    let bind=CString::new(":0").unwrap();
    let listener=sn_tcp_listener_bind(bind.as_ptr() as *mut c_char);
    let address=CString::new(format!("127.0.0.1:{}",sn_tcp_listener_get_port(listener))).unwrap();
    let client=sn_tcp_stream_connect(address.as_ptr() as *mut c_char);
    let server=sn_tcp_listener_accept(listener);
    assert_eq!(sn_sdk_tcp_stream_retain(server),server);assert_eq!(sn_sdk_tcp_stream_refs(server),2);
    sn_sdk_tcp_stream_release(server);assert_eq!(sn_sdk_tcp_stream_refs(server),1);
    let text=CString::new("hello").unwrap();sn_tcp_stream_write_line(client,text.as_ptr() as *mut c_char);
    sn_tcp_stream_dispose(client);sn_sdk_tcp_stream_release(client);
    let line=sn_tcp_stream_read_line(server);let remote=sn_tcp_stream_get_remote_address(server);
    let remainder=sn_tcp_stream_read_all(server);assert_eq!((*remainder).len,0);
    sn_sdk_tcp_stream_release(server);sn_sdk_tcp_listener_release(listener);
    assert_eq!(CStr::from_ptr(line).to_bytes(),b"hello");
    assert!(CStr::from_ptr(remote).to_bytes().starts_with(b"127.0.0.1:"));
    free(line.cast());free(remote.cast());
    let mut owned=std::ptr::null_mut();
    assert_eq!(sn_abi_v1_native_byte_array_adopt(remainder,&mut owned),0);
    sn_abi_v1_release(owned);
}
fn main() { unsafe {
    assert_eq!(sn_sdk_tcp_stream_storage_size(),std::mem::size_of::<Stream>() as u64);
    assert_eq!(sn_sdk_tcp_listener_storage_size(),std::mem::size_of::<Listener>() as u64);
    assert_eq!(sn_sdk_tcp_stream_field_offset(0),std::mem::offset_of!(Stream,descriptor) as u64);
    assert_eq!(sn_sdk_tcp_stream_field_offset(1),std::mem::offset_of!(Stream,remote) as u64);
    assert_eq!(sn_sdk_tcp_stream_field_offset(2),std::mem::offset_of!(Stream,internal) as u64);
    assert_eq!(sn_sdk_tcp_listener_field_offset(0),std::mem::offset_of!(Listener,descriptor) as u64);
    assert_eq!(sn_sdk_tcp_listener_field_offset(1),std::mem::offset_of!(Listener,port) as u64);
    let empty=sn_sdk_tcp_stream_create();assert_eq!((*empty).descriptor,0);
    assert!((*empty).remote.is_null() && (*empty).internal.is_null());sn_sdk_tcp_stream_release(empty);
    let zero=sn_sdk_tcp_listener_create();assert_eq!((*zero).descriptor,0);assert_eq!((*zero).port,0);
    sn_sdk_tcp_listener_release(zero);
    for _ in 0..16 {roundtrip();}
}
    let workers:Vec<_>=(0..4).map(|_|std::thread::spawn(||unsafe {
        let address=CString::new(":0").unwrap();
        for _ in 0..32 {
            let listener=sn_tcp_listener_bind(address.as_ptr() as *mut c_char);
            assert_eq!(sn_sdk_tcp_listener_retain(listener),listener);assert_eq!(sn_sdk_tcp_listener_refs(listener),2);
            sn_sdk_tcp_listener_release(listener);assert_eq!(sn_sdk_tcp_listener_refs(listener),1);
            sn_sdk_tcp_listener_release(listener);
        }
    })).collect();
    for worker in workers {worker.join().unwrap();}
    println!("SDK canonical TCP Rust: pass");
}
