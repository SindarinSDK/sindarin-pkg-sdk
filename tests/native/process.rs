use std::ffi::{c_char,c_void,CStr,CString};
use std::io::Write;
#[repr(C)] struct Process { rc:i32, code:i32, out:*mut c_char, err:*mut c_char }
extern "C" {
 fn sn_process_run_args(command:*mut c_char,args:*mut c_void)->*mut Process;
 fn sn_sdk_process_retain(value:*mut Process)->*mut Process;
 fn sn_sdk_process_copy(value:*const Process)->*mut Process;
 fn sn_sdk_process_release(value:*mut Process);
 fn sn_sdk_process_refs(value:*mut Process)->i32;
 fn sn_process_get_stdout(value:*mut Process)->*mut c_char;
 fn sn_process_get_stderr(value:*mut Process)->*mut c_char;
 fn sn_array_new(width:usize,capacity:i64)->*mut c_void;
 fn sn_array_push(value:*mut c_void,element:*const c_void);
 fn sn_test_process_array_free(value:*mut c_void);
 fn free(value:*mut c_void);
}
fn main(){
 if std::env::args().nth(1).as_deref()==Some("--child"){print!("captured stdout");eprint!("captured stderr");std::io::stdout().flush().unwrap();std::io::stderr().flush().unwrap();std::process::exit(7);}
 let mode=std::env::args().nth(1);
 if mode.as_deref()==Some("--large-error") || mode.as_deref()==Some("--large-output") {
  let out=vec![b'O';131072];let err=vec![b'E';131072];
  if mode.as_deref()==Some("--large-error"){std::io::stderr().write_all(&err).unwrap();std::io::stdout().write_all(&out).unwrap();}
  else {std::io::stdout().write_all(&out).unwrap();std::io::stderr().write_all(&err).unwrap();}
  std::io::stdout().flush().unwrap();std::io::stderr().flush().unwrap();std::process::exit(7);
 }
 unsafe{
  assert_eq!(std::mem::size_of::<Process>(),24);
  let command=CString::new(std::env::current_exe().unwrap().to_str().unwrap()).unwrap();let argument=CString::new("--child").unwrap();
  let args=sn_array_new(std::mem::size_of::<*mut c_char>(),1);let raw=argument.as_ptr();sn_array_push(args,(&raw as *const *const c_char).cast());
  let process=sn_process_run_args(command.as_ptr() as *mut c_char,args);sn_test_process_array_free(args);
  assert!(!process.is_null());assert_eq!((*process).code,7);assert_eq!(sn_sdk_process_refs(process),1);
  let alias=sn_sdk_process_retain(process);assert_eq!(alias,process);
  let copy=sn_sdk_process_copy(process);assert_ne!(copy,process);assert_ne!((*copy).out,(*process).out);sn_sdk_process_release(copy);
  let out=sn_process_get_stdout(alias);let err=sn_process_get_stderr(alias);sn_sdk_process_release(alias);sn_sdk_process_release(process);
  assert_eq!(CStr::from_ptr(out).to_bytes(),b"captured stdout");assert_eq!(CStr::from_ptr(err).to_bytes(),b"captured stderr");free(out.cast());free(err.cast());
  for mode in ["--large-error","--large-output"] {
   let arg=CString::new(mode).unwrap();let raw=arg.as_ptr();let args=sn_array_new(std::mem::size_of::<*const c_char>(),1);sn_array_push(args,(&raw as *const *const c_char).cast());
   let process=sn_process_run_args(command.as_ptr() as *mut c_char,args);sn_test_process_array_free(args);assert_eq!((*process).code,7);
   assert_eq!(CStr::from_ptr((*process).out).to_bytes(),vec![b'O';131072]);assert_eq!(CStr::from_ptr((*process).err).to_bytes(),vec![b'E';131072]);sn_sdk_process_release(process);
  }
  println!("SDK canonical Process Rust: pass");
 }
}
