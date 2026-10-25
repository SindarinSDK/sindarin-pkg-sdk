use std::ffi::{c_char, c_void, CStr, CString};

#[repr(C)]
struct Stream { refs:i32, descriptor:i64, ssl:i64, remote:*mut u8 }
#[repr(C)]
struct Listener { refs:i32, descriptor:i64, port:i64 }
#[repr(C)]
struct Value { _opaque:[u8;0] }
#[repr(C)]
struct Array { data:*mut c_void, len:i64, cap:i64, width:usize,
    release:Option<unsafe extern "C" fn(*mut c_void)>,
    copy:Option<unsafe extern "C" fn(*const c_void,*mut c_void)>, tag:i32 }
unsafe extern "C" {
    fn sn_sdk_tls_stream_create()->*mut Stream;
    fn sn_sdk_tls_stream_retain(value:*mut Stream)->*mut Stream;
    fn sn_sdk_tls_stream_release(value:*mut Stream);
    fn sn_sdk_tls_stream_refs(value:*mut Stream)->i32;
    fn sn_sdk_tls_listener_create()->*mut Listener;
    fn sn_sdk_tls_listener_retain(value:*mut Listener)->*mut Listener;
    fn sn_sdk_tls_listener_release(value:*mut Listener);
    fn sn_sdk_tls_listener_refs(value:*mut Listener)->i32;
    fn sn_tls_listener_bind(address:*mut c_char,certificate:*mut c_char,key:*mut c_char)->*mut Listener;
    fn sn_tls_listener_get_port(listener:*mut Listener)->i64;
    fn sn_tls_listener_accept(listener:*mut Listener)->*mut Stream;
    fn sn_tls_stream_connect(address:*mut c_char)->*mut Stream;
    fn sn_tls_stream_is_valid(stream:*mut Stream)->bool;
    fn sn_tls_stream_read(stream:*mut Stream,count:i64)->*mut Array;
    fn sn_tls_stream_write(stream:*mut Stream,data:*mut Array)->i64;
    fn sn_tls_stream_write_line(stream:*mut Stream,text:*mut c_char);
    fn sn_tls_stream_read_line(stream:*mut Stream)->*mut c_char;
    fn sn_tls_stream_read_all(stream:*mut Stream)->*mut Array;
    fn sn_tls_stream_get_remote_address(stream:*mut Stream)->*mut c_char;
    fn sn_tls_stream_dispose(stream:*mut Stream);
    fn sn_sdk_tls_stream_storage_size()->u64;
    fn sn_sdk_tls_listener_storage_size()->u64;
    fn sn_sdk_tls_stream_field_offset(field:u32)->u64;
    fn sn_sdk_tls_listener_field_offset(field:u32)->u64;
    fn sn_array_new(width:usize,capacity:i64)->*mut Array;
    fn sn_array_push(array:*mut Array,value:*const c_void);
    fn sn_abi_v1_native_byte_array_adopt(array:*mut Array,out:*mut *mut Value)->u32;
    fn sn_abi_v1_release(value:*mut Value);
    fn free(value:*mut c_void);
}
unsafe fn release_array(array:*mut Array) {
    let mut owned=std::ptr::null_mut();
    assert_eq!(sn_abi_v1_native_byte_array_adopt(array,&mut owned),0);
    sn_abi_v1_release(owned);
}
unsafe fn roundtrip(certificate:&CString,key:&CString) {
    let bind=CString::new("127.0.0.1:0").unwrap();
    let listener=sn_tls_listener_bind(bind.as_ptr().cast_mut(),certificate.as_ptr().cast_mut(),key.as_ptr().cast_mut());
    let address=CString::new(format!("localhost:{}",sn_tls_listener_get_port(listener))).unwrap();
    let server_address=listener as usize;
    let server=std::thread::spawn(move || unsafe {
        let listener=server_address as *mut Listener;
        let stream=sn_tls_listener_accept(listener);assert!(sn_tls_stream_is_valid(stream));
        sn_sdk_tls_listener_release(listener);
        let line=sn_tls_stream_read_line(stream);assert_eq!(CStr::from_ptr(line).to_bytes(),b"ping");
        let remote=sn_tls_stream_get_remote_address(stream);
        let values=[0u8,128,255,42];let data=sn_array_new(1,4);(*data).tag=6;
        for value in &values {sn_array_push(data,(value as *const u8).cast());}
        assert_eq!(sn_tls_stream_write(stream,data),4);
        let text=CString::new("é漢").unwrap();sn_tls_stream_write_line(stream,text.as_ptr().cast_mut());
        assert_eq!(sn_sdk_tls_stream_retain(stream),stream);assert_eq!(sn_sdk_tls_stream_refs(stream),2);
        sn_sdk_tls_stream_release(stream);assert_eq!(sn_sdk_tls_stream_refs(stream),1);
        sn_sdk_tls_stream_release(stream);
        assert_eq!(CStr::from_ptr(line).to_bytes(),b"ping");
        assert!(CStr::from_ptr(remote).to_bytes().starts_with(b"127.0.0.1:"));
        free(line.cast());free(remote.cast());release_array(data);
    });
    let stream=sn_tls_stream_connect(address.as_ptr().cast_mut());assert!(sn_tls_stream_is_valid(stream));
    let ping=CString::new("ping").unwrap();sn_tls_stream_write_line(stream,ping.as_ptr().cast_mut());
    let mut received=Vec::new();
    while received.len()<4 {
        let part=sn_tls_stream_read(stream,(4-received.len()) as i64);assert!((*part).len>0);
        received.extend_from_slice(std::slice::from_raw_parts((*part).data.cast::<u8>(),(*part).len as usize));
        release_array(part);
    }
    let line=sn_tls_stream_read_line(stream);let remote=sn_tls_stream_get_remote_address(stream);
    let remainder=sn_tls_stream_read_all(stream);assert_eq!((*remainder).len,0);
    sn_tls_stream_dispose(stream);sn_tls_stream_dispose(stream);assert!(!sn_tls_stream_is_valid(stream));
    sn_sdk_tls_stream_release(stream);
    assert_eq!(received,[0,128,255,42]);assert_eq!(CStr::from_ptr(line).to_str().unwrap(),"é漢");
    assert_eq!(CStr::from_ptr(remote).to_bytes(),address.as_bytes());
    free(line.cast());free(remote.cast());release_array(remainder);server.join().unwrap();
}
fn main() {
    let arguments:Vec<_>=std::env::args().collect();assert_eq!(arguments.len(),3);
    let certificate=CString::new(arguments[1].as_bytes()).unwrap();let key=CString::new(arguments[2].as_bytes()).unwrap();
    unsafe {
        assert_eq!(sn_sdk_tls_stream_storage_size(),std::mem::size_of::<Stream>() as u64);
        assert_eq!(sn_sdk_tls_listener_storage_size(),std::mem::size_of::<Listener>() as u64);
        assert_eq!(sn_sdk_tls_stream_field_offset(0),std::mem::offset_of!(Stream,descriptor) as u64);
        assert_eq!(sn_sdk_tls_stream_field_offset(1),std::mem::offset_of!(Stream,ssl) as u64);
        assert_eq!(sn_sdk_tls_stream_field_offset(2),std::mem::offset_of!(Stream,remote) as u64);
        assert_eq!(sn_sdk_tls_listener_field_offset(0),std::mem::offset_of!(Listener,descriptor) as u64);
        assert_eq!(sn_sdk_tls_listener_field_offset(1),std::mem::offset_of!(Listener,port) as u64);
        let empty=sn_sdk_tls_stream_create();assert_eq!((*empty).descriptor,0);assert_eq!((*empty).ssl,0);
        assert!((*empty).remote.is_null());sn_sdk_tls_stream_release(empty);
        let zero=sn_sdk_tls_listener_create();assert_eq!((*zero).descriptor,0);assert_eq!((*zero).port,0);sn_sdk_tls_listener_release(zero);
    }
    let workers:Vec<_>=(0..4).map(|_| {
        let certificate=certificate.clone();let key=key.clone();
        std::thread::spawn(move || unsafe {
            let address=CString::new("127.0.0.1:0").unwrap();
            for _ in 0..32 {
                let listener=sn_tls_listener_bind(address.as_ptr().cast_mut(),certificate.as_ptr().cast_mut(),key.as_ptr().cast_mut());
                assert_eq!(sn_sdk_tls_listener_retain(listener),listener);assert_eq!(sn_sdk_tls_listener_refs(listener),2);
                sn_sdk_tls_listener_release(listener);assert_eq!(sn_sdk_tls_listener_refs(listener),1);sn_sdk_tls_listener_release(listener);
            }
        })
    }).collect();
    for worker in workers {worker.join().unwrap();}
    for _ in 0..16 {unsafe {roundtrip(&certificate,&key);}}
    println!("SDK canonical TLS Rust: pass");
}
