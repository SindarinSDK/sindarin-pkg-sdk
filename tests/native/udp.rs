use std::ffi::{c_char, c_void, CStr, CString};

#[repr(C)]
struct Socket { refs:i32, descriptor:i64, port:i64 }
#[repr(C)]
struct Array { data:*mut c_void, len:i64, cap:i64, width:usize,
    release:Option<unsafe extern "C" fn(*mut c_void)>,
    copy:Option<unsafe extern "C" fn(*const c_void,*mut c_void)>, tag:i32 }
#[repr(C)]
struct ResultRecord { refs:i32, data:*mut Array, sender:*mut c_char }
unsafe extern "C" {
    fn sn_udp_socket_bind(address:*mut c_char)->*mut Socket;
    fn sn_udp_socket_send_to(socket:*mut Socket,data:*mut Array,address:*mut c_char)->i64;
    fn sn_udp_socket_receive_from(socket:*mut Socket,maximum:i64)->*mut ResultRecord;
    fn sn_udp_socket_get_port(socket:*mut Socket)->i64;
    fn sn_udp_socket_dispose(socket:*mut Socket);
    fn sn_sdk_udp_socket_retain(socket:*mut Socket)->*mut Socket;
    fn sn_sdk_udp_socket_release(socket:*mut Socket);
    fn sn_sdk_udp_socket_refs(socket:*mut Socket)->i32;
    fn sn_sdk_udp_result_retain(result:*mut ResultRecord)->*mut ResultRecord;
    fn sn_sdk_udp_result_release(result:*mut ResultRecord);
    fn sn_sdk_udp_result_refs(result:*mut ResultRecord)->i32;
    fn sn_udp_result_get_data(result:*mut ResultRecord)->*mut Array;
    fn sn_udp_result_get_sender(result:*mut ResultRecord)->*mut c_char;
    fn sn_sdk_udp_socket_storage_size()->u64;
    fn sn_sdk_udp_result_storage_size()->u64;
    fn sn_sdk_udp_socket_field_offset(field:u32)->u64;
    fn sn_sdk_udp_result_field_offset(field:u32)->u64;
    fn sn_array_new(width:usize,capacity:i64)->*mut Array;
    fn sn_array_push(array:*mut Array,value:*const c_void);
    fn free(pointer:*mut c_void);
}
unsafe fn cleanup_bytes(array:*mut Array) {
    // These owned C byte-array buffers have no managed element destructors.
    assert_eq!((*array).width,1);assert!((*array).release.is_none());
    free((*array).data);free(array.cast());
}
fn main() { unsafe {
    assert_eq!(sn_sdk_udp_socket_storage_size(),std::mem::size_of::<Socket>() as u64);
    assert_eq!(sn_sdk_udp_result_storage_size(),std::mem::size_of::<ResultRecord>() as u64);
    assert_eq!(sn_sdk_udp_socket_field_offset(0),std::mem::offset_of!(Socket,descriptor) as u64);
    assert_eq!(sn_sdk_udp_socket_field_offset(1),std::mem::offset_of!(Socket,port) as u64);
    assert_eq!(sn_sdk_udp_result_field_offset(0),std::mem::offset_of!(ResultRecord,data) as u64);
    assert_eq!(sn_sdk_udp_result_field_offset(1),std::mem::offset_of!(ResultRecord,sender) as u64);
    let bind=CString::new(":0").unwrap();
    let server=sn_udp_socket_bind(bind.as_ptr() as *mut c_char);
    let client=sn_udp_socket_bind(bind.as_ptr() as *mut c_char);
    assert!(!server.is_null() && !client.is_null());
    let address=CString::new(format!("127.0.0.1:{}",sn_udp_socket_get_port(server))).unwrap();
    let values=[0u8,255,65,128,10];let payload=sn_array_new(1,5);(*payload).tag=6;
    for value in &values {sn_array_push(payload,(value as *const u8).cast());}
    assert_eq!(sn_udp_socket_send_to(client,payload,address.as_ptr() as *mut c_char),5);
    let result=sn_udp_socket_receive_from(server,1024);
    let alias=sn_sdk_udp_result_retain(result);assert_eq!(alias,result);
    assert_eq!(sn_sdk_udp_result_refs(result),2);sn_sdk_udp_result_release(result);
    let received=sn_udp_result_get_data(alias);let sender=sn_udp_result_get_sender(alias);
    sn_sdk_udp_result_release(alias);
    assert_eq!((*received).len,5);
    assert_eq!(std::slice::from_raw_parts((*received).data.cast::<u8>(),5),values);
    assert!(CStr::from_ptr(sender).to_bytes().starts_with(b"127.0.0.1:"));
    free(sender.cast());cleanup_bytes(received);cleanup_bytes(payload);
    sn_udp_socket_dispose(client);sn_udp_socket_dispose(client);
    sn_sdk_udp_socket_release(client);sn_sdk_udp_socket_release(server);
}
    let threads:Vec<_>=(0..8).map(|_|std::thread::spawn(||unsafe {
        let address=CString::new(":0").unwrap();
        for _ in 0..32 {
            let socket=sn_udp_socket_bind(address.as_ptr() as *mut c_char);
            assert!(sn_udp_socket_get_port(socket)>0);
            assert_eq!(sn_sdk_udp_socket_retain(socket),socket);
            assert_eq!(sn_sdk_udp_socket_refs(socket),2);
            sn_sdk_udp_socket_release(socket);assert_eq!(sn_sdk_udp_socket_refs(socket),1);
            sn_sdk_udp_socket_release(socket);
        }
    })).collect();
    for thread in threads {thread.join().unwrap();}
    println!("SDK canonical UDP Rust: pass");
}
